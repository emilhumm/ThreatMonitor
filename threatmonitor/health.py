"""Is the picture complete? Watches for the two ways the IDS can go blind without anyone noticing.

1. The WAN address changes (a PPPoE reconnect). Suricata only alerts on traffic to its "Home networks", which hold
   the old address, so alerts stop. Detected from the address that inbound firewall blocks are aimed at; cleared by
   the first IDS alert aimed at the new address, which proves Home networks were updated.
2. IDS alerts stop while the firewall keeps blocking, whatever the reason (crash, rules, the above).
"""
import json
import logging
import time

import aiohttp

from . import config

log = logging.getLogger("health")

WAN_CONFIRM_HITS = 5   # inbound blocks to a new address, with none to the old one in between, before it counts


class Health:
    def __init__(self, data_dir):
        self.file = data_dir / "health.json"
        try:
            d = json.loads(self.file.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            d = {}
        self.wan = d.get("wan") or {"ip": None, "since": None, "previous": None, "changed": None, "confirmed": True}
        self.last_ids = d.get("last_ids")
        self.blocks_since_ids = 0
        self._candidate = None
        self._active = {}

    def save(self):
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(json.dumps({"wan": self.wan, "last_ids": self.last_ids}), encoding="utf-8")

    def seen_wan(self, addr, now):
        """An inbound firewall block was aimed at this (global IPv4) address of ours."""
        w = self.wan
        if addr == w["ip"]:
            self._candidate = None
            return
        if w["ip"] is None:
            w.update(ip=addr, since=now)
            self.save()
            return
        c = self._candidate
        if c is None or c["ip"] != addr:
            c = self._candidate = {"ip": addr, "n": 0}
        c["n"] += 1
        if c["n"] >= WAN_CONFIRM_HITS:
            log.warning("WAN address changed: %s -> %s", w["ip"], addr)
            w.update(previous=w["ip"], ip=addr, since=now, changed=now, confirmed=False)
            self._candidate = None
            self.save()

    def event(self, ev, now):
        if ev["kind"] == "ids":
            self.last_ids = now
            self.blocks_since_ids = 0
            if not self.wan["confirmed"] and ev["way"] == "in" and ev["local"] == self.wan["ip"]:
                self.wan["confirmed"] = True
                self.save()
        elif ev["way"] == "in":
            self.blocks_since_ids += 1

    def warnings(self, now=None):
        now = now or time.time()
        out = {}
        w = self.wan
        if w["changed"] and not w["confirmed"]:
            at = time.strftime("%d %b %H:%M", time.localtime(w["changed"]))
            out["wan"] = (f"WAN address changed {w['previous']} → {w['ip']} ({at}). IDS alerts stay off until "
                          f"{w['ip']}/32 is in Suricata's Home networks (Services › Intrusion Detection › Settings, "
                          f"advanced mode).")
        quiet = now - self.last_ids if self.last_ids else 0
        if quiet > config.IDS_SILENT_MIN * 60 and self.blocks_since_ids >= config.IDS_SILENT_BLOCKS:
            out["ids"] = (f"No IDS alert for {int(quiet // 60)} min while the firewall blocked "
                          f"{self.blocks_since_ids} probes. Is Suricata running, and is {w['ip']}/32 in its "
                          f"Home networks?")
        return out

    async def check(self):
        """Run every minute: push a message when a warning appears or clears."""
        now_active = self.warnings()
        for key, text in now_active.items():
            if key not in self._active:
                await notify("ThreatMonitor: attention", text, "alert")
        for key in self._active.keys() - now_active.keys():
            await notify("ThreatMonitor: OK again",
                         "IDS alerts are arriving again." if key == "ids" else "Suricata alerts on the new WAN address.",
                         "info")
        self._active = now_active
        self.save()


async def notify(title, message, severity="alert"):
    url = config.NOTIFY_URL
    if not url:
        return
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            if "/api/webhook/" in url:  # Home Assistant: fields an automation can pass on to a phone
                r = await s.post(url, json={"title": title, "message": message, "severity": severity,
                                            "url": config.DASHBOARD_URL})
            else:  # ntfy: the body is the message, the title goes in a header
                r = await s.post(url, data=message.encode(), headers={"Title": title, "Tags": "warning"})
            r.raise_for_status()
    except Exception as e:  # noqa: BLE001 - a failed push must not stop the monitor
        log.warning("notify failed: %s", e)
