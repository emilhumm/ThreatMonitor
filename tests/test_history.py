import asyncio
import re
import sqlite3
import time

from threatmonitor import config, history
from threatmonitor.geo import SCANNER_HOSTS
from threatmonitor.history import SETTLED, History, aims_columns, day_bounds, day_of
from threatmonitor.server import Monitor

GEO = {"lat": 52.52, "lon": 13.4, "cc": "DE", "country": "Germany", "city": "Berlin", "asn": 1, "org": "Org"}


def ev(ts, remote="185.220.101.1", kind="block", way="in", dport=22, svc="SSH", **kw):
    return dict(ts=ts, kind=kind, action="block", way=way, proto="tcp", remote=remote, local="81.0.0.1",
                sport=40000, dport=dport, svc=svc, iface="pppoe0", rule="x", geo=GEO, **kw)


def a_day_back(ts):
    """The same time of day on the calendar day before: ts - 86400 is two days back just after the spring clock change."""
    t = time.localtime(ts)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday - 1, t.tm_hour, t.tm_min, t.tm_sec, 0, 0, -1))


def call(h, fn, *args):  # history queries run on its own thread, as the server runs them
    return asyncio.run(h.run(fn, *args))


def write(h, events, policy=()):
    for e in events:
        h.add(e)
    for e in policy:
        h.add_policy(e)
    asyncio.run(h.flush())


def test_rollups_seen_and_detail(tmp_path):
    h = History(tmp_path / "h.db", 365)
    now = time.time()
    yesterday = a_day_back(now)
    write(h, [ev(yesterday), ev(yesterday + 1, dport=23, svc="Telnet")])
    assert h.seen("185.220.101.1", day_of(now)) == {"first": yesterday, "days": 1}
    assert h.seen("185.220.101.1", day_of(yesterday)) is None  # only today so far: nothing earlier
    assert h.seen("1.2.3.4", day_of(now)) is None
    write(h, [ev(now), ev(now, remote="45.1.2.3", kind="ids", sig="ET DROP Dshield", sid=2402000)],
          policy=[ev(now, remote="1.1.1.1", way="out", dport=853, svc="tcp/853") for _ in range(30)])

    s = call(h, h.summary, 7)
    assert [r["block"] for r in s["series"][-2:]] == [2, 1]
    assert s["series"][-1]["ids"] == 1 and s["series"][-1]["out"] == 30 and s["series"][-1]["sources"] == 2
    assert s["totals"] == {"block": 3, "ids": 1, "out": 30, "sources": 2, "returning": 1, "attempts": 4, "flagged": 1,
                           "listed": 0, "attack": 0, "unlogged": 0}
    top = s["top_ips"][0]
    assert (top["ip"], top["hits"], top["days"], top["org"]) == ("185.220.101.1", 3, 2, "Org")
    assert s["top_sigs"][0]["sig"] == "ET DROP Dshield"
    assert s["devices"][0]["remote"] == "1.1.1.1" and s["devices"][0]["n"] == 30
    assert {p["port"]: p["hits"] for p in s["top_ports"]} == {"22": 3, "23": 1}

    d = call(h, h.ip_detail, "185.220.101.1")
    assert d["found"] and d["hits"] == 3 and d["days"] == 2 and len(d["daily"]) == 2 and len(d["events"]) == 3
    assert not call(h, h.ip_detail, "9.9.9.9")["found"]
    h.close()


def test_replies_to_our_own_traffic_move_out_of_the_threats(tmp_path):
    # as stored before parse.answers_us: a call relay's STUN replies to a call, as three inbound IDS knocks
    path, now = tmp_path / "h.db", time.time()
    h = History(path, 365)
    stun = []
    for i in range(3):
        e = ev(now + i, remote="52.114.233.29", kind="ids", dport=39705, svc="udp/39705", cat="info", sid=2016149,
               sig="ET INFO Session Traversal Utilities for NAT (STUN Binding Response)")
        e["sport"] = 3478
        stun.append(e)
    write(h, [ev(now), *stun])
    h.close()
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 1")  # a database from before the fix
    con.commit()
    con.close()

    h = History(path, 365)
    assert h.moved == {day_of(now): 3}
    s = call(h, h.summary, 1)
    assert {k: s["totals"][k] for k in ("block", "ids", "out", "attempts", "flagged", "sources")} == \
        {"block": 1, "ids": 0, "out": 3, "attempts": 1, "flagged": 0, "sources": 1}
    assert [t["ip"] for t in s["top_ips"]] == ["185.220.101.1"] and not s["top_sigs"]
    assert {p["port"] for p in s["top_ports"]} == {"22"}
    assert s["devices"][0]["remote"] == "52.114.233.29" and s["devices"][0]["n"] == 3  # our own traffic now
    assert not call(h, h.ip_detail, "52.114.233.29")["found"]
    h.close()
    assert History(path, 365).moved == {}  # once


def test_stored_blocks_by_list_rules_go_on_a_threat_list(tmp_path, monkeypatch):
    # as stored before list rules counted: a CrowdSec block alone, and one whose packet an IDS list rule also flagged
    path, now = tmp_path / "h.db", time.time()
    crowdsec = "855c22845f898770b30860cbb6f9867a"
    monkeypatch.setattr(config, "RULES", {**config.RULES, crowdsec: ("CrowdSec", True)})  # as TM_RULES would name it
    h = History(path, 365)
    write(h, [dict(ev(now, remote="1.1.1.9"), rule=crowdsec), dict(ev(now, remote="2.2.2.9"), rule=crowdsec),
              dict(ev(now + 0.5, remote="2.2.2.9", kind="ids", sid=2402000, cat="list", sig="ET DROP Dshield"),
                   gain=4 | 8),  # FLAGGED | LISTED, joined to the block's knock
              ev(now, remote="3.3.3.9")])  # the default deny: no list
    h.close()
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 2")
    con.commit()
    con.close()

    h = History(path, 365)
    assert h.relisted == {day_of(now): 1}  # only the lone CrowdSec block: the other knock was listed already
    assert call(h, h.summary, 1)["totals"]["listed"] == 2
    listed = h._rcon.execute("SELECT kind, rule FROM events WHERE gain & 8 > 0 ORDER BY remote").fetchall()
    assert [tuple(r) for r in listed] == [("block", crowdsec), ("ids", "x")]
    assert call(h, h.ip_detail, "1.1.1.9")["what"]["text"] == "on a threat list (CrowdSec)"
    h.close()


def test_what_they_were_after_per_day(tmp_path):
    h = History(tmp_path / "h.db", 365)
    now = time.time()
    yesterday = a_day_back(now)
    sweep = [ev(now, remote="9.9.9.9", dport=p, svc=f"tcp/{p}") for p in range(1000, 1006)]
    write(h, [ev(yesterday), ev(yesterday + 1, dport=3389, svc="RDP"), ev(now, dport=80, svc="HTTP"), *sweep])
    a = call(h, h.summary, 2)["aims"]  # as columns, one value per day
    assert a["days"] == [day_of(yesterday), day_of(now)]
    assert a["aimed"] == {"Logins": [2, 0], "Web": [0, 1]} and a["mapping"] == [0, 6] and a["repeat"] == [0, 0]
    assert set(a["svcs"]["Logins"]) == {"SSH", "RDP"} and a["svcs"]["Web"] == ["HTTP"]
    h.close()


def test_aims_columns_rank_services_by_days():
    day = lambda *aimed: {"mapping": {"sweeps": 1}, "repeat": [["tcp/9", 2, 1]], "aimed": list(aimed)}  # noqa: E731
    c = aims_columns(["d1", "d2", "d3"], [day(["Logins", 5, ["Telnet", "SSH"]]), day(["Logins", 3, ["SSH"]]),
                                          day(["Logins", 1, ["RDP", "Telnet", "VNC"]], ["Mail", 2, ["SMTP"]])])
    assert c["aimed"] == {"Logins": [5, 3, 1], "Mail": [0, 0, 2]}
    assert c["svcs"] == {"Logins": ["Telnet", "SSH", "RDP"], "Mail": ["SMTP"]}  # 2 days each: the first seen leads
    assert c["mapping"] == [1, 1, 1] and c["repeat"] == [2, 2, 2]


def test_a_scanner_added_to_the_list_counts_for_names_stored_before(tmp_path, monkeypatch):
    monkeypatch.delitem(SCANNER_HOSTS, "infrawat.ch")  # as the list was before Infrawatch
    h = History(tmp_path / "h.db", 365)
    h.add_name("154.16.44.11", "154-16-44-11.infrawat.ch", None)
    h.add_name("1.2.3.4", "host.example.net", None)
    write(h, [ev(time.time(), remote="154.16.44.11"), ev(time.time(), remote="1.2.3.4")])
    h.close()
    h = History(tmp_path / "h.db", 365)  # the same list: the names aren't gone through again
    assert call(h, h.ip_detail, "154.16.44.11")["scanner"] is None
    h.close()
    monkeypatch.undo()  # Infrawatch added
    h = History(tmp_path / "h.db", 365)
    assert call(h, h.ip_detail, "154.16.44.11")["scanner"] == "Infrawatch"
    assert call(h, h.ip_detail, "1.2.3.4")["scanner"] is None
    h.close()


def test_names_in_the_address_lookup(tmp_path):
    h = History(tmp_path / "h.db", 365)
    now = time.time()
    h.add_name("34.1.2.3", "red2.census.shodan.io", "Shodan")
    censys = ev(now, remote="167.94.138.1")
    censys["geo"] = dict(GEO, org="Censys, Inc.")
    write(h, [ev(now, remote="34.1.2.3"), censys])
    d = call(h, h.ip_detail, "34.1.2.3")
    assert (d["host"], d["scanner"]) == ("red2.census.shodan.io", "Shodan")
    d = call(h, h.ip_detail, "167.94.138.1")  # no name, but a scanner's network
    assert (d["host"], d["scanner"]) == (None, "Censys")
    assert not call(h, h.ip_detail, "185.220.101.1")["found"]
    h.close()


def test_prune_and_seed(tmp_path):
    h = History(tmp_path / "h.db", 30)
    old = time.time() - 40 * 86400
    write(h, [ev(old, remote="5.5.5.5"), ev(time.time())])
    call(h, h.prune)
    assert not call(h, h.ip_detail, "5.5.5.5")["found"]
    assert call(h, h.ip_detail, "185.220.101.1")["found"]
    assert not call(h, h.seed, "2026-11-02", {"block": 9}, 0, {}, {}, {}, {})  # not empty: never seeds over real data
    h.close()

    fresh = History(tmp_path / "f.db", 30)
    today = day_of(time.time())
    ips = {"7.7.7.7": {"n": 4, "ids": 1, "first": time.time(), "last": time.time(), "cc": "US", "org": "X"}}
    assert call(fresh, fresh.seed, today, {"block": 3, "ids": 1}, 2, ips, {"22": 4}, {"22": "SSH"},
                      {"US": {"n": 4, "name": "United States"}})
    s = call(fresh, fresh.summary, 1)
    assert s["totals"]["block"] == 3 and s["top_ips"][0]["ip"] == "7.7.7.7"
    fresh.close()


def test_yesterday_by_now(tmp_path):
    h = History(tmp_path / "h.db", 365)
    t = time.localtime()
    at = lambda days, hour, minute=0: time.mktime((t.tm_year, t.tm_mon, t.tm_mday + days, hour, minute, 0, 0, 0, -1))
    noon = at(0, 12)
    assert call(h, h.yesterday_by_now, noon) is None  # no history yet
    write(h, [ev(at(-1, 1)), ev(at(-1, 11, 59)), ev(at(-1, 12, 1)), ev(at(0, 8))])
    assert call(h, h.yesterday_by_now, noon) is None  # the history starts during yesterday: no fair comparison
    write(h, [ev(at(-2, 12))])
    assert call(h, h.yesterday_by_now, noon) == 2  # 01:00 and 11:59 yesterday; not 12:01, not today
    h.close()


def test_monitor_marks_returning_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    write(mon.history, [ev(time.time() - 3 * 86400)])  # an earlier visit
    line = ("<134>Nov  2 20:10:00 fw filterlog[1]: 82,,,x,pppoe0,match,block,in,4,0x0,,244,1,0,none,6,tcp,40,"
            "185.220.101.1,81.0.0.1,51234,22,0,S,1,,1024,,")
    mon.handle_line(line, "192.168.1.1")
    mon.handle_line(line, "192.168.1.1")
    assert mon.outbox[0]["seen"]["days"] == 1 and mon.outbox[1]["seen"]["days"] == 1
    assert mon.state.stats()["top_ips"][0]["seen"]["days"] == 1
    assert len(mon.history.queue) == 2
    mon.history.close()


def test_a_days_aims_are_kept_only_once_it_is_over(tmp_path, monkeypatch):
    h = History(tmp_path / "h.db", 365)
    start, end = day_bounds(day_of(time.time() - 86400))
    day, clock = day_of(start), [end - 1800]
    monkeypatch.setattr(history.time, "time", lambda: clock[0])
    write(h, [ev(end - 3600)])
    assert call(h, h.aims_on, day)["aimed"] == [["Logins", 1, ["SSH"]]]  # looked at while the day was on
    write(h, [ev(end - 600, remote="45.1.2.3")])
    clock[0] = end + SETTLED + 1
    assert call(h, h.aims_on, day)["aimed"] == [["Logins", 2, ["SSH"]]]  # not frozen at what it was then
    write(h, [ev(end - 300, remote="45.1.2.4")])
    assert call(h, h.aims_on, day)["aimed"] == [["Logins", 2, ["SSH"]]]  # over and settled: worked out once
    h.close()


def test_a_late_line_around_midnight_counts_its_day_once(tmp_path):
    h = History(tmp_path / "h.db", 365)
    midnight = day_bounds(day_of(time.time()))[0]
    for ts in (midnight - 10, midnight + 5, midnight - 2, midnight + 30):  # the third was held back
        write(h, [ev(ts)])
    r = h._rcon.execute("SELECT days, last_day, first, last FROM ips").fetchone()
    assert (r["days"], r["last_day"], r["first"], r["last"]) == (2, day_of(midnight), midnight - 10, midnight + 30)
    h.close()


def test_the_history_queries_read_only_what_they_ask_for(tmp_path):
    # without "+ip", ts ranges and the like, SQLite reads a whole table (a year: millions of rows, many seconds).
    # An empty-ish database already shows the plan it would take.
    h = History(tmp_path / "h.db", 365)
    now = time.time()
    write(h, [ev(now - 86400), ev(now), ev(now, remote="45.1.2.3", kind="ids", sig="ET X", sid=1)])
    sql = []
    h._rcon.set_trace_callback(sql.append)
    h._db.set_trace_callback(sql.append)  # this thread's connection, as the reader thread's would be
    for days in (7, 365):
        h.summary(days)
    h.ip_detail("185.220.101.1")
    h.yesterday_by_now(now)
    h.seen("185.220.101.1", day_of(now))
    h.today_events(day_of(now))
    h._rcon.set_trace_callback(None)
    h._db.set_trace_callback(None)
    full = re.compile(r"^SCAN (events|daily_ip)\b|^SCAN \w+ USING (COVERING )?INDEX (daily_ip_ip|events_\w+)")
    explained = 0
    for q in sql:
        if q.startswith("CREATE TEMP TABLE per_ip AS "):
            q = q.split(" AS ", 1)[1]
        elif "per_ip" in q or not q.startswith("SELECT"):
            continue
        plan = [r[3] for r in h._rcon.execute("EXPLAIN QUERY PLAN " + q)]
        assert not any(full.match(p) for p in plan), (q, plan)
        explained += 1
    assert explained > 15
    h.close()


def test_a_settled_days_aims_are_stored_and_survive_a_restart(tmp_path):
    h = History(tmp_path / "h.db", 365)
    day = day_of(time.time() - 3 * 86400)
    write(h, [ev(day_bounds(day)[0] + 3600)])
    first = call(h, h.aims_on, day)
    h.close()  # the store (handed to the writer) is done before it closes
    h = History(tmp_path / "h.db", 365)
    with h._rcon:
        h._rcon.execute("DELETE FROM events")  # not worked out again: read back
    assert call(h, h.aims_on, day) == first and first["aimed"] == [["Logins", 1, ["SSH"]]]
    h.close()


def test_a_write_that_fails_for_a_while_is_kept_for_the_next_try(tmp_path, monkeypatch):
    h = History(tmp_path / "h.db", 365)
    real, fail = h._write, [sqlite3.OperationalError("database or disk is full")]

    def flaky(*args):
        if fail:
            raise fail.pop()
        return real(*args)
    monkeypatch.setattr(h, "_write", flaky)
    now = time.time()
    write(h, [ev(now)], policy=[ev(now, remote="1.1.1.1", way="out", dport=853, svc="tcp/853")])
    assert len(h.queue) == 1 and h.failing == 1 and sum(h.policy.values()) == 1  # kept, not lost
    write(h, [ev(now + 1)])
    assert not h.queue and h.failing == 0 and h.failures == 1 and h.lost == 0
    assert h._rcon.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2

    fail.append(sqlite3.IntegrityError("a bad row"))  # the batch itself is wrong: a retry wouldn't help
    write(h, [ev(now + 2)])
    assert not h.queue and h.lost == 1
    h.close()


def test_a_rebuild_of_the_rollups_gives_what_the_writes_gave(tmp_path):
    h = History(tmp_path / "h.db", 365)
    d0 = day_bounds(day_of(time.time() - 3 * 86400))[0]
    write(h, [ev(d0 + 60)])  # the first day (seeded in real life): left alone by a rebuild
    for d in (1, 2):
        t = d0 + d * 86400 + 3600
        write(h, [ev(t), ev(t + 1, remote="45.1.2.3", dport=80, svc="HTTP"),
                  ev(t + 1, remote="45.1.2.3", kind="ids", dport=80, svc="HTTP", sig="ET X", sid=7),
                  ev(t + 2, remote="45.9.9.9", kind="ids", sig="ET Y", sid=8, way="out")],
              policy=[ev(t, remote="1.1.1.1", way="out", dport=853, svc="tcp/853") for _ in range(3)])
        h.add_unlogged(t)
        asyncio.run(h.flush())
    con = h._rcon
    tables = ("daily", "daily_ip", "daily_port", "daily_cc", "daily_sig")
    dump = lambda: {t: sorted(map(tuple, con.execute(f"SELECT * FROM {t}"))) for t in tables}  # noqa: E731
    written = dump()
    with con:
        for t in tables[1:]:  # roll-ups gone wrong after the first day
            con.execute(f"UPDATE {t} SET hits = hits + 5 WHERE day > ?", (day_of(d0),))
        con.execute("UPDATE daily SET attempts = 99, out = 0 WHERE day > ?", (day_of(d0),))
        h.rebuild_rollups(con, day_of(d0))
    assert dump() == written
    h.close()


def test_a_rebuild_drops_the_days_aims_so_they_follow_the_corrected_events(tmp_path):
    # a day's aims are kept once it is over; a migration that corrects its events must not leave them as they were
    h = History(tmp_path / "h.db", 365)
    d0 = day_bounds(day_of(time.time() - 3 * 86400))[0]
    write(h, [ev(d0 + 60)])  # the first day: left alone by a rebuild
    day, t = day_of(d0 + 86400), d0 + 86400 + 3600
    write(h, [ev(t, remote="1.1.1.1", dport=80, svc="HTTP"),
              ev(t + 1, remote="2.2.2.2", kind="ids", way="out", dport=443, svc="HTTPS", sid=1, cat="attack", sig="ET X")])
    assert call(h, h.aims_on, day)["aimed"] == [["Web", 2, ["HTTP", "HTTPS"]]]  # now kept, in daily_aims and in memory
    con = h._rcon
    with con:  # as a migration does: the outbound alert was our own device, so it goes, and the roll-ups follow
        con.execute("DELETE FROM events WHERE remote = '2.2.2.2'")
        h.rebuild_rollups(con, day)
    assert con.execute("SELECT COUNT(*) FROM daily_aims WHERE day >= ?", (day,)).fetchone()[0] == 0
    assert call(h, h.aims_on, day)["aimed"] == [["Web", 1, ["HTTP"]]]
    assert con.execute("SELECT attempts FROM daily WHERE day = ?", (day,)).fetchone()[0] == 1
    h.close()


def test_alerts_on_our_devices_tls_fingerprints_move_out_of_the_threats(tmp_path):
    # as stored before: a smart TV's streaming app matching abuse.ch's JA3 "Possible Adware", counted as attacks from Akamai
    path, now = tmp_path / "h.db", time.time()
    h = History(path, 365)
    write(h, [ev(now - 3 * 86400)])  # an earlier day: the first one in a history is never worked out again
    ja3 = dict(ev(now, remote="2.18.244.217", kind="ids", way="out", dport=443, svc="HTTPS", sid=2028371, cat="attack",
                  sig="ET JA3 Hash - [Abuse.ch] Possible Adware"), gain=1 | 4 | 16)  # ATTEMPT | FLAGGED | ATTACK
    write(h, [ev(now), ja3, dict(ja3, ts=now + 60)])
    h.close()
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 3")
    con.commit()
    con.close()

    h = History(path, 365)
    assert h.refiled == {day_of(now): 2} and not h.moved  # going out already: our network, not more outbound
    s = call(h, h.summary, 1)
    assert {k: s["totals"][k] for k in ("block", "ids", "out", "attempts", "flagged", "attack", "sources")} == \
        {"block": 1, "ids": 0, "out": 2, "attempts": 1, "flagged": 0, "attack": 0, "sources": 1}
    assert not s["top_sigs"] and s["devices"][0]["remote"] == "2.18.244.217" and s["devices"][0]["n"] == 2
    assert not call(h, h.ip_detail, "2.18.244.217")["found"]
    h.close()
    assert History(path, 365).refiled == {}  # once


def test_outbound_alerts_outside_the_threat_families_move_out_of_the_threats(tmp_path):
    # as stored before: a file-sharing client's alerts on 5 Nov made its peers attackers; a device of ours fetching a
    # Windows program from a bare address (ET HUNTING) is worth a look and stays a threat
    path, now = tmp_path / "h.db", time.time()
    h = History(path, 365)
    write(h, [ev(now - 3 * 86400)])  # an earlier day: the first one in a history is never worked out again
    p2p = dict(ev(now, remote="5.6.7.8", kind="ids", way="out", dport=6969, svc="tcp/6969", sid=2000357, cat="attack",
                  sig="ET P2P BitTorrent Announce"), gain=1 | 4 | 16)  # ATTEMPT | FLAGGED | ATTACK
    mz = dict(ev(now + 120, remote="194.36.32.209", kind="ids", way="out", dport=80, svc="HTTP", sid=2021076,
                 cat="attack", sig="ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response"), gain=1 | 4 | 16)
    write(h, [ev(now), p2p, dict(p2p, ts=now + 60, sig="GPL P2P BitTorrent announce request"), mz])
    h.close()
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 4")  # had the fingerprint move already
    con.commit()
    con.close()

    h = History(path, 365)
    assert h.refiled == {day_of(now): 2} and not h.moved
    s = call(h, h.summary, 1)
    assert {k: s["totals"][k] for k in ("block", "ids", "out", "attempts", "attack")} == \
        {"block": 1, "ids": 1, "out": 3, "attempts": 2, "attack": 1}  # out: the torrent alerts and the download
    assert [x["sig"] for x in s["top_sigs"]] == ["ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response"]
    assert not call(h, h.ip_detail, "5.6.7.8")["found"] and call(h, h.ip_detail, "194.36.32.209")["found"]
    assert h._rcon.execute("PRAGMA user_version").fetchone()[0] == 5
    h.close()
    assert History(path, 365).refiled == {}  # once
