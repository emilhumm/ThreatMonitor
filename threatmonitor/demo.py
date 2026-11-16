"""Synthetic OPNsense syslog traffic, for trying the dashboard before OPNsense is pointed at it.

The lines are written in OPNsense's own formats and go through the same parser as real ones.
"""
import asyncio
import ipaddress
import random
import time

from .parse import is_global

WAN = "203.0.113.77"
LAN = [f"192.168.1.{n}" for n in (23, 41, 57, 102, 150)]
PORTS = [(22, 30), (23, 14), (3389, 10), (445, 8), (80, 8), (443, 6), (8080, 6), (5900, 4), (1433, 3), (3306, 3),
         (25, 3), (2375, 2), (6379, 2), (8443, 3), (7547, 2), (5060, 2), (37215, 1), (8291, 1), (5555, 2), (81, 2),
         (8088, 1), (9200, 1), (27017, 1), (11211, 1), (502, 1), (123, 1), (53, 2), (1900, 1), (161, 1)]
UDP_PORTS = {53, 123, 161, 1900, 5060, 11211}
SIGS = [
    (2010935, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2, 1433),
    (2010937, "ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 2, 3306),
    (2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, 22),
    (2009582, "ET SCAN NMAP -sS window 1024", "Attempted Information Leak", 2, 80),
    (2403343, "ET CINS Active Threat Intelligence Poor Reputation IP group 44", "Misc Attack", 2, 443),
    (2402000, "ET DROP Dshield Block Listed Source group 1", "Misc Attack", 2, 8080),
    (2034647, "ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1, 80),
    (2024792, "ET EXPLOIT Possible Huawei HG532 RCE (CVE-2017-17215)", "Attempted Administrator Privilege Gain", 1, 37215),
    (2027973, "ET SCAN Mirai Variant Telnet Brute Force", "Attempted Administrator Privilege Gain", 1, 23),
    (2025883, "ET EXPLOIT MVPower DVR Shell UCE", "Attempted Administrator Privilege Gain", 1, 60001),
]
OUT_SIGS = [
    (2018581, "ET MALWARE Possible Win32/Agent Tesla C2 Checkin", "A Network Trojan was detected", 1, 443),
    (2027758, "ET POLICY DNS Query to a *.top domain", "Potentially Bad Traffic", 2, 53),
]


def _pool(geo, n=400):
    """Random internet addresses that the geo database can place."""
    out = []
    while len(out) < n:
        ip = str(ipaddress.IPv4Address(random.getrandbits(32)))
        if is_global(ip) and geo.lookup(ip):
            out.append(ip)
    return out


def _hdr(prog, pid):
    t = time.localtime()  # RFC 3164 stamp, "Nov  2 19:05:01" (strftime's %e does not exist on Windows)
    return f"<134>{time.strftime('%b', t)} {t.tm_mday:>2} {time.strftime('%H:%M:%S', t)} OPNsense.home.arpa {prog}[{pid}]: "


def filterlog(src, dst, dport, iface="igb0"):
    proto = "udp" if dport in UDP_PORTS else "tcp"
    sport = random.randint(1024, 65535)
    if proto == "tcp":
        tail = f"6,tcp,40,{src},{dst},{sport},{dport},0,S,{random.getrandbits(31)},,1024,,"
    else:
        tail = f"17,udp,48,{src},{dst},{sport},{dport},28"
    return (_hdr("filterlog", 64123) +
            f"82,,,02f4bab031b57d1e30553ce08e0ec131,{iface},match,block,in,4,0x0,,{random.randint(40, 250)},"
            f"{random.randint(1, 65535)},0,none,{tail}")


def suricata(sig, src, dst, dport):
    sid, text, cls, prio, _ = sig
    proto = "UDP" if dport in UDP_PORTS else "TCP"
    return (_hdr("suricata", 7642) + f"[1:{sid}:3] {text} [Classification: {cls}] [Priority: {prio}] "
            f"{{{proto}}} {src}:{random.randint(1024, 65535)} -> {dst}:{dport}")


async def run(geo, handle, rate=3.0):
    while not geo.ready:
        await asyncio.sleep(2)
    pool = _pool(geo)
    weights = [1 / (i + 1) ** 0.8 for i in range(len(pool))]  # a few loud sources, a long quiet tail
    ports, port_w = zip(*PORTS)
    while True:
        await asyncio.sleep(random.expovariate(rate))
        src = random.choices(pool, weights)[0]
        r = random.random()
        if r < 0.04:  # port scan: one source walks through many ports quickly
            for port in random.sample(ports, random.randint(6, 16)):
                handle(filterlog(src, WAN, port), "demo")
                await asyncio.sleep(random.uniform(0.02, 0.12))
        elif r < 0.10:
            sig = random.choice(SIGS)
            handle(suricata(sig, src, WAN, sig[4]), "demo")
        elif r < 0.11:
            sig = random.choice(OUT_SIGS)
            handle(suricata(sig, random.choice(LAN), src, sig[4]), "demo")
        else:
            handle(filterlog(src, WAN, random.choices(ports, port_w)[0]), "demo")
