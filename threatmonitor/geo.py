"""IP -> location/network, from the free DB-IP Lite databases (CC BY 4.0, https://db-ip.com).

The two .mmdb files are downloaded into the data folder on first start and refreshed monthly. Each file keeps its
month in the name, so a new one can be opened before the old one (still memory-mapped) is deleted.
"""
import asyncio
import datetime as dt
import gzip
import ipaddress
import logging
import shutil
import socket
import time
from functools import lru_cache

import aiohttp
import maxminddb

log = logging.getLogger("geo")

KINDS = ("city", "asn")
URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
MAX_AGE = 35 * 86400

# Companies that scan the whole internet for a living (search engines for exposed devices, research projects). Their
# hits are real but not aimed at us, and the dashboard counts them apart. Known by their network's name (matched on
# a part of it: they add ASNs) ...
SCANNERS = {
    "censys": "Censys", "onyphe": "ONYPHE", "modat": "Modat", "shodan": "Shodan", "shadowserver": "Shadowserver",
    "binaryedge": "BinaryEdge", "stretchoid": "Stretchoid", "rapid7": "Rapid7", "bitsight": "BitSight",
    "leakix": "LeakIX", "driftnet": "Driftnet", "internet measurement": "Internet Measurement",
    "alpha strike labs": "Alpha Strike Labs", "recyber": "ReCyber", "arbor networks": "NETSCOUT",
}
# ... or, for the servers they rent in someone else's network (Google's or Amazon's cloud), by the server's name in
# reverse DNS: the domain, or the part of it their scanners use. Collected from what reached the firewall.
SCANNER_HOSTS = {
    "censys-scanner.com": "Censys", "onyphe.net": "ONYPHE", "modat.io": "Modat", "shodan.io": "Shodan",
    "shadowserver.org": "Shadowserver", "shadowserver.io": "Shadowserver", "internet-measurement.com": "Driftnet",
    "binaryedge.ninja": "BinaryEdge", "stretchoid.com": "Stretchoid", "labs.rapid7.com": "Rapid7",
    "deepfield.net": "NETSCOUT", "internet-albedo.net": "NETSCOUT", "visionheight.com": "VisionHeight",
    "internet-census.org": "Internet Census", "criminalip.com": "Criminal IP", "criminalip.io": "Criminal IP",
    "scan.bufferover.run": "BufferOver", "sba-research.org": "SBA Research", "expanse.co": "Palo Alto Xpanse",
    "softsec.ruhr-uni-bochum.de": "Ruhr-Uni Bochum", "radar.qrator.net": "Qrator", "security.ipip.net": "IPIP.NET",
    "scanning.cybergreen.net": "CyberGreen", "scanning.cybcube.com": "CyberCube", "net.in.tum.de": "TU Munich",
    "netd.cs.tu-dresden.de": "TU Dresden", "cyberresilience.io": "Cyber Resilience", "intrinsec.com": "Intrinsec",
    "scanners.onlyscans.net": "OnlyScans", "research.a10protects.com": "A10 Networks", "domaintools.net": "DomainTools",
    # Infrawatch Limited (UK): "internet measurement and security research", opt-out@infrawat.ch. Its servers sit in
    # Hydra Communications' network; on 5 Nov they were ~1,000 knocks from ~800 addresses, mostly one each
    "infrawat.ch": "Infrawatch",
}


def scanner_of(org):
    """The scanning company a network belongs to, by the network's name, or None."""
    org = (org or "").lower()
    return next((name for key, name in SCANNERS.items() if key in org), None)


def scanner_host(host):
    """The scanning company a server belongs to, by its name in reverse DNS, or None."""
    host = (host or "").lower().rstrip(".")
    return next((name for d, name in SCANNER_HOSTS.items() if host == d or host.endswith("." + d)), None)


async def reverse_name(ip, pool, timeout=6):
    """The address's name in reverse DNS, if that name also points back to the address; "" if not, or if it has none.

    Anyone can put any name in the reverse DNS of their own addresses, but only the name's owner can point it back,
    so a server can't pass itself off as one of Shodan's. The lookups block, so they run on `pool`.
    """
    loop = asyncio.get_running_loop()
    try:
        host, _ = await asyncio.wait_for(
            loop.run_in_executor(pool, socket.getnameinfo, (ip, 0), socket.NI_NAMEREQD), timeout)
        infos = await asyncio.wait_for(loop.run_in_executor(pool, socket.getaddrinfo, host, None), timeout)
    except (OSError, UnicodeError, TimeoutError):
        return ""
    want = ipaddress.ip_address(ip)
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0].split("%")[0]) == want:
                return host.lower().rstrip(".")
        except ValueError:
            continue
    return ""


class Geo:
    def __init__(self, data_dir):
        self.dir = data_dir
        self.readers = {}
        self._open()

    @property
    def ready(self):
        return "city" in self.readers

    def _newest(self, kind):
        files = sorted(self.dir.glob(f"dbip-{kind}-lite-*.mmdb"))
        return files[-1] if files else None

    def _open(self):
        for kind in KINDS:
            path = self._newest(kind)
            if path is None:
                continue
            old = self.readers.get(kind)
            self.readers[kind] = maxminddb.open_database(str(path))
            if old is not None:
                old.close()
            for older in self.dir.glob(f"dbip-{kind}-lite-*.mmdb"):
                if older != path:
                    older.unlink(missing_ok=True)
        self.lookup.cache_clear()

    def _stale(self):
        out = []
        for kind in KINDS:
            path = self._newest(kind)
            if path is None or time.time() - path.stat().st_mtime > MAX_AGE:
                out.append(kind)
        return out

    async def refresh(self):
        """Download missing or month-old databases. Cheap when they are fresh."""
        stale = self._stale()
        if not stale:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        today = dt.date.today()
        last_month = today.replace(day=1) - dt.timedelta(days=1)
        months = [today.strftime("%Y-%m"), last_month.strftime("%Y-%m")]
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=900)) as session:
            for kind in stale:
                for month in months:  # a new month's file appears a day or two into the month
                    url = URL.format(kind=kind, month=month)
                    dest = self.dir / f"dbip-{kind}-lite-{month}.mmdb"
                    try:
                        await self._download(session, url, dest)
                        log.info("downloaded %s", url)
                        break
                    except Exception as e:  # noqa: BLE001 - try the previous month, else retry later
                        log.warning("download %s failed: %s", url, e)
        self._open()

    async def _download(self, session, url, dest):
        gz = dest.with_name(dest.name + ".gz.part")
        async with session.get(url) as r:
            r.raise_for_status()
            with open(gz, "wb") as f:
                async for chunk in r.content.iter_chunked(1 << 16):
                    f.write(chunk)
        await asyncio.to_thread(_gunzip, gz, dest)

    @lru_cache(maxsize=65536)
    def lookup(self, ip):
        city = self.readers.get("city")
        if city is None:
            return None
        try:
            rec = city.get(ip)
        except ValueError:
            return None
        if not rec or "location" not in rec:
            return None
        loc, country = rec["location"], rec.get("country", {})
        out = {
            "lat": round(loc["latitude"], 3), "lon": round(loc["longitude"], 3),
            "cc": country.get("iso_code", "??"),
            "country": country.get("names", {}).get("en", ""),
            "city": rec.get("city", {}).get("names", {}).get("en", ""),
            "asn": None, "org": "",
        }
        asn = self.readers.get("asn")
        if asn is not None:
            a = asn.get(ip) or {}
            out["asn"] = a.get("autonomous_system_number")
            out["org"] = a.get("autonomous_system_organization", "")
        return out


def _gunzip(src, dest):
    tmp = dest.with_name(dest.name + ".part")
    with gzip.open(src, "rb") as fi, open(tmp, "wb") as fo:
        shutil.copyfileobj(fi, fo, 1 << 20)
    src.unlink()
    maxminddb.open_database(str(tmp)).close()  # refuse a corrupt file before it takes the real name
    tmp.replace(dest)
