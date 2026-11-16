import sqlite3
import time

from threatmonitor.behaviour import what
from threatmonitor.history import History, day_of
from threatmonitor.knocks import ATTACK, ATTEMPT, BLOCKED, FLAGGED, LISTED, Knocks
from threatmonitor.parse import ids_category, parse_line
from threatmonitor.state import State


def ev(ts, kind="block", remote="45.1.2.3", dport=22, sid=None, cat=None, way="in"):
    return {"ts": ts, "kind": kind, "remote": remote, "dport": dport, "sid": sid, "cat": cat, "way": way}


def test_a_block_and_its_ids_alerts_are_one_knock():
    k = Knocks()
    assert k.add(ev(100)) == ATTEMPT | BLOCKED
    assert k.add(ev(101, "ids", sid=1, cat="list")) == FLAGGED | LISTED   # the same packet, seen by the IDS
    assert k.add(ev(101, "ids", sid=2, cat="list")) == 0                  # a second list rule on it adds nothing new
    assert k.add(ev(101.5, "ids", sid=3, cat="attack")) == ATTACK
    assert k.add(ev(102)) == ATTEMPT | BLOCKED                            # another block: another packet
    assert k.add(ev(102, dport=23)) == ATTEMPT | BLOCKED                  # another port
    assert k.add(ev(110, "ids", sid=1, cat="list")) == ATTEMPT | FLAGGED | LISTED   # too late to be the same knock
    first = ev(200, "ids", remote="9.9.9.9", sid=1, cat="list")
    assert k.add(first) == ATTEMPT | FLAGGED | LISTED and not first["dup"]
    late = ev(201, remote="9.9.9.9")  # the IDS line can come in before the firewall's
    assert k.add(late) == BLOCKED and late["dup"] and late["knock_ts"] == 200


def test_a_block_by_a_list_rule_is_on_a_threat_list_once():
    k = Knocks()
    crowdsec = dict(ev(100), list_rule=True)
    assert k.add(crowdsec) == ATTEMPT | BLOCKED | LISTED
    assert k.add(ev(100.5, "ids", sid=1, cat="list")) == FLAGGED   # the IDS's list for the same packet: no second
    late = dict(ev(200, remote="9.9.9.9"), list_rule=True)
    assert k.add(ev(200, "ids", remote="9.9.9.9", sid=1, cat="list")) == ATTEMPT | FLAGGED | LISTED
    assert k.add(late) == BLOCKED                                  # the IDS's line came first: already listed

    s = State.__new__(State)
    s.reset(time.strftime("%Y-%m-%d"))
    s.seq = 0
    blocked = dict(ev(time.time(), remote="1.2.3.4"), list_rule=True, rule_name="CrowdSec", action="block",
                   proto="tcp", svc="SSH", geo=None)
    s.add(blocked, ATTEMPT | BLOCKED | LISTED)
    s.add(dict(ev(time.time(), "ids", remote="5.6.7.8", sid=1, cat="list"), action="alert", proto="tcp", svc="SSH",
               geo=None), ATTEMPT | FLAGGED | LISTED)
    st = s.stats()
    assert st["totals"]["listed"] == 2 and dict(st["listed_by"]) == {"CrowdSec": 1, "IDS": 1}
    assert st["blocked_rules"] == [("CrowdSec", 1)]
    assert {t["ip"]: t["what"]["text"] for t in st["top_ips"]} == {"1.2.3.4": "on a threat list (CrowdSec)",
                                                                    "5.6.7.8": "on the IDS threat lists"}


def test_attacks_by_the_ids_or_by_behaviour_count_each_knock_once():
    s = State.__new__(State)
    s.reset(time.strftime("%Y-%m-%d"))
    s.seq = 0
    now = time.time()
    add = lambda ip, svc, gain, kind="block", **kw: s.add(dict(ev(now, kind, remote=ip), action="block", proto="tcp",
                                                              svc=svc, geo=None, **kw), gain)
    for i, svc in enumerate(("SSH", "RDP", "VNC", "HTTP", "SMB", "MySQL")):  # a sweep: all 6 knocks are attacks
        add("1.1.1.1", svc, ATTEMPT | BLOCKED | (ATTACK if i == 0 else 0))  # one also by the IDS: still once
    add("2.2.2.2", "Telnet", ATTEMPT | BLOCKED)                      # only IoT botnet ports: an attack
    add("3.3.3.3", "HTTP", ATTEMPT | FLAGGED | ATTACK, kind="ids", sid=9, cat="attack")  # the IDS alone
    add("4.4.4.4", "HTTP", ATTEMPT | BLOCKED)                        # nothing recognised
    a = s.stats()["attacks"]
    assert a == {"all": 6 + 1 + 1, "ids": 2, "behaviour": {"sweep": 6, "botnet": 1},
                 "senders": {"sweep": 1, "botnet": 1, "ids": 1}}


def test_aims_sorts_knocks_by_what_they_were_after():
    from threatmonitor.behaviour import aims
    senders = [
        {"n": 9, "ports": {f"tcp/{p}": 1 for p in range(1000, 1006)} | {"SSH": 3}},  # a sweep: all of it mapping
        {"n": 4, "ports": {"SSH": 3, "RDP": 1}},
        {"n": 2, "ports": {"HTTP": 1, "Docker": 1}},
        {"n": 1, "ports": {"ICMP": 1}},
        {"n": 1, "ports": {"tcp/40001": 1}},                                         # a random port, once
        *({"n": 12, "ports": {"tcp/23053": 12}} for _ in range(2)),                   # two senders, one port, 24 times
    ]
    a = aims(senders)
    assert a["mapping"] == {"sweeps": 9, "pings": 1, "random": 1}
    assert a["aimed"] == [["Logins", 4, ["SSH", "RDP"]], ["Web", 1, ["HTTP"]], ["Other services", 1, ["Docker"]]]
    assert a["repeat"] == [["tcp/23053", 24, 2]]
    assert sum(a["mapping"].values()) + sum(g[1] for g in a["aimed"]) + sum(r[1] for r in a["repeat"]) == 9 + 4 + 2 + 1 + 1 + 24


def test_closing_finds_the_flagged_knocks_with_no_block():
    k = Knocks()
    k.add(ev(100))
    k.add(ev(100, "ids", sid=1, cat="list"))                   # blocked and flagged
    k.add(ev(100, "ids", remote="8.8.8.8", sid=1, cat="list"))  # flagged, never blocked
    k.add(ev(100, "ids", remote="7.7.7.7", sid=5, way="out"))  # outbound: nothing blocks it
    assert k.close(103) == []                                  # still open
    assert [x["t"] for x in k.close(105)] == [100] and not k.open


def test_rule_categories():
    assert ids_category("ET CINS Active Threat Intelligence Poor Reputation IP group 27") == "list"
    assert ids_category("ET DROP Spamhaus DROP Listed Traffic Inbound group 10") == "list"
    assert ids_category("ET INFO Session Traversal Utilities for NAT (STUN Binding Response)") == "info"
    assert ids_category("ET SCAN Suspicious inbound to mySQL port 3306") == "attack"
    assert ids_category("GPL DNS named version attempt") == "attack"
    assert ids_category(None) == "attack"


def test_eve_brings_the_protocol_and_the_site():
    eve = ('{"event_type":"alert","src_ip":"45.1.2.3","src_port":5555,"dest_ip":"203.0.113.77","dest_port":80,'
           '"proto":"TCP","app_proto":"http","http":{"hostname":"example.com","url":"/x"},'
           '"alert":{"signature_id":2009,"signature":"ET WEB_SERVER Something","severity":2}}')
    _, e = parse_line(f"<33>1 2026-11-04T19:05:01+01:00 fw suricata 7642 - - {eve}")
    assert (e["app"], e["target"], e["cat"]) == ("http", "example.com", "attack")
    tls = eve.replace('"app_proto":"http","http":{"hostname":"example.com","url":"/x"}', '"app_proto":"tls","tls":{"sni":"a.b"}')
    _, e = parse_line(f"<33>1 2026-11-04T19:05:01+01:00 fw suricata 7642 - - {tls}")
    assert (e["app"], e["target"]) == ("tls", "a.b")


def test_live_counts_count_each_knock_once(tmp_path):
    st, k = State(tmp_path), Knocks()
    now = time.time() - 30  # in the past: the activity grid ends at the current bucket
    geo = {"lat": 1.0, "lon": 2.0, "cc": "NL", "country": "Netherlands", "asn": 1, "org": "Org"}
    for e in (ev(now, dport=22), ev(now + 1, "ids", dport=22, sid=1, cat="list"),
              ev(now + 1, "ids", dport=22, sid=2, cat="list"), ev(now + 2, dport=23)):
        e.update(svc="SSH" if e["dport"] == 22 else "Telnet", sig="x", geo=geo, proto="tcp")
        st.add(e, k.add(e))
    t = st.stats()["totals"]
    assert (t["attempts"], t["blocked"], t["flagged"], t["listed"], t["block"], t["ids"]) == (2, 2, 1, 1, 2, 2)
    s = st.ips["45.1.2.3"]
    assert (s["n"], s["ids"], s["listed"]) == (2, 1, "IDS")  # which list named it
    cells = st.stats()["activity"]["cells"]
    assert [sum(c[0] for c in cells), sum(c[1] for c in cells)] == [1, 1]  # the knock the IDS flagged moved over
    assert st.globe_points()[0]["n"] == 2 and st.globe_points()[0]["ids"] == 1
    assert st.stats()["blocked_kinds"] == {"tcp": 2}


def test_what_the_blocked_knocks_were_and_which_attacks(tmp_path):
    st, k = State(tmp_path), Knocks()
    now = time.time() - 30
    for e in (dict(ev(now), proto="tcp"), dict(ev(now, remote="8.8.8.8", dport=None), proto="icmp"),
              dict(ev(now + 1, "ids", sid=7, cat="attack"), proto="tcp", sig="ET SCAN Suspicious inbound to MSSQL port 1433")):
        e.update(svc="x", geo=None)
        e.setdefault("sig", None)
        st.add(e, k.add(e))
    s = st.stats()
    assert s["blocked_kinds"] == {"tcp": 1, "ping": 1}
    assert s["attack_sigs"] == [("ET SCAN Suspicious inbound to MSSQL port 1433", 1)]
    st.save()
    again = State(tmp_path)
    again.load()
    assert again.stats()["blocked_kinds"] == s["blocked_kinds"]


def test_what_an_address_was_doing():
    assert what(5, {"SSH": 5}, scanner="Censys")[0] == "scanner"
    assert what(9, {s: 1 for s in ("SSH", "RDP", "HTTP", "SMB", "VNC", "FTP")})[0] == "sweep"
    assert what(3, {"Telnet": 2, "ADB": 1})[0] == "botnet"
    assert what(25, {"RDP": 25})[0] == "brute"
    assert what(4, {"RDP": 4}, listed=True)[0] == "listed"
    assert what(1, {"HTTP": 1})[0] == "once"
    assert what(4, {"HTTP": 4}) is None


OLD_SCHEMA = """
CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL, action TEXT,
  way TEXT, proto TEXT, remote TEXT NOT NULL, local TEXT, sport INTEGER, dport INTEGER, svc TEXT, iface TEXT, rule TEXT,
  sig TEXT, sid INTEGER, prio INTEGER, cls TEXT, cc TEXT, city TEXT, asn INTEGER, org TEXT);
CREATE TABLE ips (ip TEXT PRIMARY KEY, first REAL, last REAL, hits INTEGER, ids INTEGER, days INTEGER, last_day TEXT,
  cc TEXT, org TEXT);
CREATE TABLE daily (day TEXT PRIMARY KEY, block INTEGER NOT NULL DEFAULT 0, ids INTEGER NOT NULL DEFAULT 0,
  out INTEGER NOT NULL DEFAULT 0);
CREATE TABLE daily_ip (day TEXT, ip TEXT, hits INTEGER, ids INTEGER, cc TEXT, PRIMARY KEY (day, ip));
CREATE TABLE daily_port (day TEXT, port TEXT, svc TEXT, hits INTEGER, PRIMARY KEY (day, port));
CREATE TABLE daily_cc (day TEXT, cc TEXT, name TEXT, hits INTEGER, PRIMARY KEY (day, cc));
"""


def test_an_old_history_is_counted_in_knocks(tmp_path):
    path, t = tmp_path / "h.db", time.time() - 3600
    day = day_of(t)
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA)
    rows = [(t, "block", None, None), (t + 1, "ids", 1, "ET CINS Active Threat Intelligence Poor Reputation IP"),
            (t + 1, "ids", 2, "ET DROP Dshield Block Listed Source"), (t + 30, "block", None, None)]
    con.executemany("INSERT INTO events (ts, day, kind, way, remote, dport, svc, sid, sig, cc) VALUES "
                    "(?, ?, ?, 'in', '45.1.2.3', 22, 'SSH', ?, ?, 'NL')", [(ts, day, k, sid, sig) for ts, k, sid, sig in rows])
    con.execute("INSERT INTO daily VALUES (?, 2, 2, 0)", (day,))  # as logged: four events
    con.execute("INSERT INTO daily_ip VALUES (?, '45.1.2.3', 4, 2, 'NL')", (day,))
    con.execute("INSERT INTO daily_port VALUES (?, '22', 'SSH', 4)", (day,))
    con.execute("INSERT INTO daily_cc VALUES (?, 'NL', 'Netherlands', 4)", (day,))
    con.execute("INSERT INTO ips VALUES ('45.1.2.3', ?, ?, 4, 2, 1, ?, 'NL', 'Org')", (t, t + 30, day))
    con.commit()
    con.close()

    h = History(path, 365)
    con = h._rcon
    assert [r[0] for r in con.execute("SELECT gain FROM events ORDER BY ts, id")] == [
        ATTEMPT | BLOCKED, FLAGGED | LISTED, 0, ATTEMPT | BLOCKED]
    assert tuple(con.execute("SELECT block, ids, attempts, flagged, listed FROM daily").fetchone()) == (2, 2, 2, 1, 1)
    assert tuple(con.execute("SELECT hits, ids FROM daily_ip").fetchone()) == (2, 1)
    assert con.execute("SELECT hits FROM daily_port").fetchone()[0] == 2
    assert tuple(con.execute("SELECT hits, ids FROM ips").fetchone()) == (2, 1)
    h.close()
    h = History(path, 365)  # once only
    assert h._rcon.execute("SELECT attempts FROM daily").fetchone()[0] == 2
    h.close()


def test_a_late_block_or_a_pass_is_still_a_logged_line():
    k = Knocks()
    k.add(ev(100, "ids", remote="8.8.8.8", sid=1, cat="list"))
    assert k.other_line({**ev(100.5, remote="8.8.8.8"), "proto": "tcp", "flags": "R"}, "late")  # IDS first, then the line
    assert not k.other_line({**ev(200, remote="7.7.7.7"), "proto": "tcp", "action": "pass", "rule": "77"}, "pass")
    later = ev(201, "ids", remote="7.7.7.7", sid=1, cat="list")
    k.add(later)                                                     # the line first, then the IDS alert
    assert later["other"] == ("pass", "7.7.7.7 -> :22 tcp (pass, rule 77)")
    k.add(ev(300, "ids", remote="6.6.6.6", sid=1, cat="list"))      # no firewall line of any kind
    assert [x["t"] for x in k.close(400)] == [300]
