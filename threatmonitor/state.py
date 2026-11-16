"""Today's threat picture, kept in memory and snapshotted to disk so a restart keeps the day's counts."""
import datetime as dt
import heapq
import json
import logging
import time
from collections import Counter, deque

from .behaviour import ATTACKS, aims, what
from .geo import scanner_of
from .knocks import ATTACK, ATTEMPT, BLOCKED, FLAGGED, GAINS, LISTED, alone, packet_kind

log = logging.getLogger("state")

BUCKET = 10          # seconds per activity cell
WINDOW = 3600        # the activity grid covers the last hour
MAX_PORTS_PER_IP = 12
MAX_POINTS = 1500


def today():
    return dt.date.today().isoformat()


class State:
    def __init__(self, data_dir, name="state.json"):
        self.dir = data_dir
        self.name = name
        self.seq = 0
        self.reset(today())

    def reset(self, day):
        self.day = day
        self.totals = Counter()        # block / ids (events as logged); attempts, blocked, flagged... (knocks: GAINS)
        self.ips = {}                  # remote ip -> per-source stats
        self.countries = {}            # cc -> {"n", "name"}
        self.networks = {}             # asn -> {"n", "ips", "org", "scanner": company or None}; rebuilt from
        #                                self.ips on load, so not saved
        self.ports = Counter()         # target port ("22", or "ICMP") -> knocks
        self.port_svc = {}             # target port -> service name
        self.outbound = 0              # events where a LAN device was the one reaching out
        self.points = {}               # "lat,lon" -> globe spike
        self.changed = set()           # points changed since the last points_changed() (sent to the dashboards)
        self.buckets = {}              # bucket start (epoch) -> knocks {"block": not flagged, "ids": flagged}
        self.recent = deque(maxlen=150)
        self.kinds = Counter()         # blocked knocks by what they were: tcp / udp / ping / other (packet_kind)
        self.attack_sigs = Counter()   # the IDS rule of each knock it recognised as an attack -> knocks
        self.rules = Counter()         # blocked knocks by the firewall rule that blocked them (config.RULES)
        self.listed_by = Counter()     # knocks from a sender on a threat list, by what said so: a rule's name or "IDS"

    def roll(self):
        """At midnight the counts start again. The activity and the stream are kept: they show the last hour and
        the last events, not the day, and would otherwise go blank at 00:00."""
        day = today()
        if day == self.day:
            return False
        self.save()
        buckets, recent = self.buckets, self.recent
        self.reset(day)
        self.buckets, self.recent = buckets, recent
        return True

    def add(self, ev, gain=None):
        """Count one enriched event (ev["geo"] may be None) and give it an id. gain: what it adds to its knock (see
        knocks.py); an event that only joins a knock already counted (the IDS alert for a packet the firewall
        blocked) changes no count but the ones it adds to. Without it the event is a knock of its own."""
        self.roll()
        now = ev["ts"]
        self.seq += 1
        ev["id"] = self.seq
        kind = ev["kind"]
        if ev["way"] == "out":
            self.outbound += 1
            if ev.get("policy", kind == "block"):
                # our own network, noted by a rule (a device stopped on its way out, an external-IP lookup). Counted
                # as outbound, but the internet side is not an attacker: it stays out of the threat counts, lists,
                # globe and the threat stream.
                ev["ip_n"] = None
                return ev
        if gain is None:
            gain = alone(ev)
        new, flagged = gain & ATTEMPT, gain & FLAGGED
        if gain & BLOCKED:
            self.kinds[packet_kind(ev.get("proto"))] += 1
            self.rules[ev.get("rule_name") or "other"] += 1
        listed = gain & LISTED and (ev.get("rule_name") or "other" if kind == "block" else "IDS")
        if listed:
            self.listed_by[listed] += 1
        if gain & ATTACK:
            self.attack_sigs[ev.get("sig") or "?"] += 1
        self.totals[kind] += 1  # the events as logged
        for bit, name in GAINS:
            if gain & bit:
                self.totals[name] += 1
        port = str(ev["dport"]) if ev["dport"] is not None else ev["svc"]
        self.port_svc.setdefault(port, ev["svc"])

        # activity counts knocks, by when they started: "ids" the ones the IDS flagged, "block" the rest. A knock
        # the IDS flags after its block moves over
        b = int(ev.get("knock_ts", now) // BUCKET * BUCKET)
        cell = self.buckets.setdefault(b, {"block": 0, "ids": 0})
        if new:
            cell["ids" if flagged else "block"] += 1
        elif flagged and cell["block"] > 0:
            cell["block"] -= 1
            cell["ids"] += 1
        if len(self.buckets) > WINDOW // BUCKET + 30:
            cutoff = now - WINDOW - BUCKET
            for k in [k for k in self.buckets if k < cutoff]:
                del self.buckets[k]

        geo = ev.get("geo") or {}
        ip = ev["remote"]
        s = self.ips.get(ip)
        first = s is None
        if first:
            s = self.ips[ip] = {
                "ip": ip, "n": 0, "ids": 0, "first": now, "ports": {},
                "cc": geo.get("cc", "??"), "country": geo.get("country", ""), "city": geo.get("city", ""),
                "org": geo.get("org", ""), "asn": geo.get("asn"),
                "lat": geo.get("lat"), "lon": geo.get("lon"),  # where the dashboard's tour flies to
                "seen": ev.get("seen"),  # earlier days this address was seen on (from history), or None
            }
        ev["seen"] = s.get("seen")
        s["last"] = now
        if kind == "ids":
            s["sig"] = ev.get("sig")
        if flagged:
            s["ids"] += 1  # its knocks the IDS flagged
        if gain & ATTACK:
            s["atk"] = s.get("atk", 0) + 1  # its knocks the IDS recognised as an attack (see _attacks)
        if listed:
            s["listed"] = listed  # which list named it first
        if new:
            s["n"] += 1
            self.ports[port] += 1
            p = s["ports"]
            if ev["svc"] in p or len(p) < MAX_PORTS_PER_IP:
                p[ev["svc"]] = p.get(ev["svc"], 0) + 1
        ev["ip_n"] = s["n"]

        cc = geo.get("cc", "??")
        c = self.countries.setdefault(cc, {"n": 0, "name": geo.get("country", "Unknown"), "ips": 0})
        c["n"] += bool(new)
        c["ips"] += first
        if s["asn"]:
            net = self.networks.get(s["asn"])
            if net is None:
                net = self.networks[s["asn"]] = {"n": 0, "ips": 0, "org": s["org"], "scanner": scanner_of(s["org"])}
            net["n"] += bool(new)
            net["ips"] += first

        if "lat" in geo and (new or flagged):
            key = f'{geo["lat"]:.1f},{geo["lon"]:.1f}'
            pt = self.points.get(key)
            if pt is None:
                pt = self.points[key] = {"lat": geo["lat"], "lon": geo["lon"], "n": 0, "ids": 0,
                                         "cc": cc, "city": geo.get("city", ""), "country": geo.get("country", "")}
            pt["n"] += bool(new)
            pt["ids"] += bool(flagged)
            pt["last"] = now
            self.changed.add(key)
        self.recent.append(ev)
        return ev

    # --- views sent to the browser -------------------------------------------------------------------------

    def activity(self, now=None):
        now = now or time.time()
        end = int(now // BUCKET * BUCKET)
        start = end - WINDOW + BUCKET
        cells = []
        for b in range(start, end + BUCKET, BUCKET):
            c = self.buckets.get(b)
            cells.append([c["block"], c["ids"]] if c else [0, 0])
        return {"start": start, "step": BUCKET, "cells": cells}

    def stats(self):
        top_ips = heapq.nlargest(8, self.ips.values(), key=lambda s: s["n"])
        top_c = heapq.nlargest(8, self.countries.items(), key=lambda kv: kv[1]["n"])
        return {
            "day": self.day,
            # each knock once (attempts), and how many of them were blocked, flagged by the IDS, flagged by a
            # threat list or as an attack, or flagged but never blocked in the firewall log (unlogged); block and
            # ids are the events as logged
            "totals": {"block": self.totals["block"], "ids": self.totals["ids"], "out": self.outbound,
                       **{name: self.totals[name] for _, name in GAINS}, "unlogged": self.totals["unlogged"]},
            "unique": len(self.ips),
            "countries": len([c for c in self.countries if c != "??"]),
            "top_ips": [_ip_view(s, self.scanner(s)) for s in top_ips],
            "top_ports": [{"port": port if port.isdigit() else None, "svc": self.port_svc.get(port, port), "n": n}
                          for port, n in self.ports.most_common(8)],
            "top_countries": [{"cc": cc, "name": c["name"], "n": c["n"], "ips": c["ips"]} for cc, c in top_c],
            "scanners": self._scanners(),
            # knocks from addresses already seen on an earlier day ("seen", from the history when they first knock)
            "returning": sum(s["n"] for s in self.ips.values() if s.get("seen")),
            "blocked_kinds": dict(self.kinds), "attack_sigs": self.attack_sigs.most_common(3),
            "blocked_rules": self.rules.most_common(6), "listed_by": self.listed_by.most_common(),
            "aims": aims(self.ips.values()),  # what today's knocks were after (the Aims tab)
            "attacks": self._attacks(),
            "activity": self.activity(),
        }

    def _attacks(self):
        """Today's knocks recognised as attacks: by the IDS (the traffic itself was a scan, an exploit attempt, a
        protocol abused) or by what the sender did (behaviour.ATTACKS: it swept ports, went only for the ports IoT
        botnets want, or kept guessing passwords). Each knock once: all the knocks of a sender that behaved like that,
        and the IDS's attacks of the rest. On 5 Nov the IDS alone recognised 100 of 8,773; behaviour adds ~2,300. A
        research scanner's sweep is no attack: its "scanner" tag comes first. Shown as knocks "from hostile senders",
        with how many senders: a sweeper knocks once per port, so ~2,300 knocks were ~110 senders."""
        by, senders, total = Counter(), Counter(), 0
        for s in self.ips.values():
            label = what(s["n"], s["ports"], self.scanner(s), s.get("listed"), len(s["ports"]) >= MAX_PORTS_PER_IP)
            if label and label[0] in ATTACKS:
                by[label[0]] += s["n"]
                senders[label[0]] += 1
                total += s["n"]
            elif s.get("atk"):
                senders["ids"] += 1  # the rest: senders the IDS caught
                total += s["atk"]
        return {"all": total, "ids": self.totals["attack"], "behaviour": dict(by), "senders": dict(senders)}

    def scanner(self, s):
        """The scanning company an address belongs to, by its network or by its own name, or None."""
        net = self.networks.get(s["asn"]) if s.get("asn") else None
        return (net and net["scanner"]) or s.get("scanner")

    def _scanners(self):
        """Threats today from the companies that scan the whole internet, and the biggest three of them by name. An
        address counts when its network is one of theirs, or when its own name (reverse DNS, looked up by the server
        and kept as "scanner") says so: their servers in someone else's cloud."""
        by_name = Counter()
        for s in self.ips.values():
            who = self.scanner(s)
            if who:
                by_name[who] += s["n"]
        return {"n": sum(by_name.values()), "names": [name for name, _ in by_name.most_common(3)]}

    def globe_points(self):
        return heapq.nlargest(MAX_POINTS, self.points.values(), key=lambda p: p["n"])

    def points_changed(self):
        """The points that changed since the last call: what the dashboards need besides the full list in hello."""
        out = [self.points[k] for k in self.changed if k in self.points]
        self.changed.clear()
        return out

    # --- persistence ---------------------------------------------------------------------------------------

    @property
    def _file(self):
        return self.dir / self.name

    def save(self):
        data = {
            "day": self.day, "seq": self.seq, "totals": dict(self.totals), "ips": self.ips,
            "countries": self.countries, "ports": dict(self.ports), "port_svc": self.port_svc,
            "outbound": self.outbound, "points": self.points,
            "buckets": {str(k): v for k, v in self.buckets.items()}, "recent": list(self.recent),
            "kinds": dict(self.kinds), "attack_sigs": dict(self.attack_sigs),
            "rules": dict(self.rules), "listed_by": dict(self.listed_by),
        }
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self._file)

    def load(self):
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except ValueError as e:
            log.warning("ignoring unreadable %s: %s", self._file, e)
            return
        self.seq = data.get("seq", 0)
        if data.get("day") != self.day:
            return
        self.totals = Counter(data["totals"])
        self.ips = data["ips"]
        self.countries = data["countries"]
        for s in self.ips.values():  # each address keeps its network, so the per-network totals follow from them
            if s.get("asn"):
                org = s.get("org", "")
                net = self.networks.setdefault(s["asn"], {"n": 0, "ips": 0, "org": org, "scanner": scanner_of(org)})
                net["n"] += s["n"]
                net["ips"] += 1
        self.ports = Counter(data["ports"])
        self.port_svc = data.get("port_svc", {})
        self.outbound = data.get("outbound", 0)
        self.points = data["points"]
        self.buckets = {int(k): v for k, v in data["buckets"].items()}
        self.recent.extend(data["recent"])
        self.kinds, self.attack_sigs = Counter(data.get("kinds", {})), Counter(data.get("attack_sigs", {}))
        self.rules, self.listed_by = Counter(data.get("rules", {})), Counter(data.get("listed_by", {}))
        log.info("restored %s: %d events from %d sources", self.day, sum(self.totals.values()), len(self.ips))


def _ip_view(s, scanner):
    ports = sorted(s["ports"].items(), key=lambda kv: -kv[1])[:3]
    label = what(s["n"], s["ports"], scanner, s.get("listed"), len(s["ports"]) >= MAX_PORTS_PER_IP)
    return {k: s.get(k) for k in ("ip", "n", "ids", "cc", "country", "city", "org", "asn", "last", "sig", "seen",
                                  "lat", "lon", "host")} | {
        "ports": [p for p, _ in ports], "what": label and {"key": label[0], "text": label[1]}}
