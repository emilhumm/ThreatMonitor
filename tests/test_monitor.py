import asyncio
import json
import sqlite3
import time

from threatmonitor import config, server
from threatmonitor.server import Monitor

WAN = "81.0.0.1"
BLOCK = ("<134>Nov  2 20:10:00 fw filterlog[1]: 82,,,x,pppoe0,match,block,in,4,0x0,,244,1,0,none,6,tcp,40,"
         f"185.220.101.1,{WAN},51234,22,0,S,1,,1024,,")
LOOKUP = ("<33>Nov  2 20:10:01 fw suricata[1]: [1:2022082:2] ET POLICY External IP Lookup ip-api.com "
          f"[Classification: Device Retrieving External IP Address Detected] [Priority: 2] {{TCP}} {WAN}:51000 -> "
          "208.95.112.1:80")


def test_ids_alert_from_our_wan_is_outbound_and_teaches_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(BLOCK, "192.168.1.1")
    mon.handle_line(LOOKUP, "192.168.1.1")
    assert mon.home_ips == {WAN}
    ev = mon.outbox[-1]
    assert (ev["kind"], ev["way"], ev["remote"], ev["policy"]) == ("ids", "out", "208.95.112.1", True)
    t = mon.state.stats()["totals"]
    assert (t["block"], t["ids"], t["out"], t["attempts"]) == (1, 0, 1, 1)  # an IP lookup is noted, not a threat
    assert [i["ip"] for i in mon.state.stats()["top_ips"]] == ["185.220.101.1"]
    assert mon.history.policy and len(mon.history.queue) == 1

    again = Monitor(False)  # a restart remembers the WAN address, so the first line is already read right
    again.handle_line(LOOKUP, "192.168.1.1")
    assert again.outbox[-1]["way"] == "out"


def test_a_line_held_back_keeps_the_time_it_was_logged(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)

    def line(ago):
        lt = time.localtime(time.time() - ago)
        stamp = f"{time.strftime('%b', lt)} {lt.tm_mday:>2} {time.strftime('%H:%M:%S', lt)}"
        return BLOCK.replace("Nov  2 20:10:00", stamp)

    for ago in (60, 1, 3600):  # held back during a restart; on time; a firewall clock an hour off
        mon.handle_line(line(ago), "192.168.1.1")
    late, on_time, adrift = (time.time() - ev["ts"] for ev in mon.outbox)
    assert 59 < late < 62 and on_time < 1 and adrift < 1
    assert mon.lines["delayed"] == 1
    assert list(mon.to_name) == ["185.220.101.1"]  # its name is looked up once, when it first shows up today


CINS = ("<33>Nov  2 20:10:00 fw suricata[1]: [1:2403300:1] ET CINS Active Threat Intelligence Poor Reputation IP "
        "group 1 [Classification: Misc Attack] [Priority: 2] {TCP} 185.220.101.1:51234 -> " + WAN + ":22")


def test_a_blocked_packet_the_ids_flags_is_one_threat(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(BLOCK, "192.168.1.1")
    mon.handle_line(CINS, "192.168.1.1")  # the same packet, seen by the IDS
    mon.handle_line(CINS.replace("185.220.101.1", "193.176.31.1"), "192.168.1.1")  # flagged, but no block logged
    t = mon.state.stats()["totals"]
    assert (t["attempts"], t["blocked"], t["flagged"], t["listed"], t["block"], t["ids"]) == (2, 1, 2, 2, 1, 2)
    assert [e["dup"] for e in mon.outbox] == [False, True, False]
    mon.close_knocks(time.time() + 10)
    assert mon.state.totals["unlogged"] == 1

    # rebuilt from the history (as after a migration that changes stored events), today's counts come out the same
    asyncio.run(mon.history.flush())
    mon._recount_today()
    t = mon.state.stats()["totals"]
    assert (t["attempts"], t["blocked"], t["flagged"], t["listed"], t["unlogged"]) == (2, 1, 2, 2, 1)
    assert mon.state.ips["185.220.101.1"]["n"] == 1


def test_only_public_addresses_reach_the_wan_watch(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(BLOCK, "192.168.1.1")
    to_lan = BLOCK.replace(f",{WAN},", ",192.168.1.5,")  # e.g. a blocked port-forward, seen on the LAN side
    for _ in range(10):
        mon.handle_line(to_lan, "192.168.1.1")
    assert mon.health.wan["ip"] == WAN and not mon.health.warnings()


def stamped(line, ago):
    lt = time.localtime(time.time() - ago)
    return line.replace("Nov  2 20:10:00", f"{time.strftime('%b', lt)} {lt.tm_mday:>2} {time.strftime('%H:%M:%S', lt)}")


def test_a_late_firewall_line_held_back_still_meets_its_ids_alert(tmp_path, monkeypatch):
    # after a restart both come in a minute late; the firewall's line for the packet must pair with the alert,
    # or the knock counts as one the firewall never logged
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(stamped(CINS, 60), "192.168.1.1")
    mon.handle_line(stamped(BLOCK.replace(",S,", ",A,"), 60), "192.168.1.1")  # no SYN: a "late" block
    assert mon.lines["filterlog_late"] == 1 and mon.lines["late_flagged"] == 1


def test_midnight_starts_the_counts_again_but_keeps_the_last_hour(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(BLOCK, "192.168.1.1")
    mon.state.day = "2000-01-01"  # as if that line came in yesterday
    mon.handle_line(BLOCK.replace("185.220.101.1", "193.176.31.1"), "192.168.1.1")
    s = mon.state
    assert s.totals["attempts"] == 1 and list(s.ips) == ["193.176.31.1"]
    assert len(s.recent) == 2 and sum(c["block"] for c in s.buckets.values()) == 2  # the stream and activity stay


def test_a_dashboard_that_stops_reading_is_dropped_not_waited_for(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(server, "SEND_TIMEOUT", 0.2)
    mon = Monitor(False)

    class Ws:
        def __init__(self, asleep):
            self.asleep, self.got = asleep, []

        async def send_str(self, data):
            if self.asleep:  # a laptop asleep with the page open: its connection's buffer is full
                await asyncio.sleep(3600)
            self.got.append(data)

    class Transport:
        aborted = False

        def abort(self):
            self.aborted = True

    asleep, awake, cut = Ws(True), Ws(False), Transport()
    mon.clients = {asleep: cut, awake: Transport()}

    async def two():
        t0 = time.monotonic()
        for t in ("events", "stats"):
            await mon.broadcast({"t": t})
        return time.monotonic() - t0
    assert asyncio.run(two()) < 1
    assert len(awake.got) == 2 and asleep not in mon.clients and cut.aborted


def test_errors_are_counted_and_the_health_check_sees_a_stalled_pump(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)

    def broken(line, sender):
        raise ValueError(line)
    monkeypatch.setattr(mon, "handle_line", broken)
    for _ in range(3):
        mon.on_line("x", "192.168.1.1")  # skipped, not the end of the connection
    assert mon.errors["line"] == 3

    class Request:
        app = {server.MON: mon}
    assert asyncio.run(server.healthz(Request)).status == 200

    async def broken_tick(tick):
        raise RuntimeError("x")
    mon._tick = broken_tick

    async def pump_for(seconds):
        try:
            await asyncio.wait_for(mon.pump(), seconds)
        except TimeoutError:
            pass
    before = mon.alive
    asyncio.run(pump_for(0.6))
    assert mon.errors["pump"] >= 2 and mon.alive == before  # it keeps going, but isn't getting round
    mon.alive -= server.STALLED + 1
    assert asyncio.run(server.healthz(Request)).status == 503


def test_the_globe_gets_only_the_places_that_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    places = {"185.220.101.1": ("Berlin", 52.5, 13.4), "193.176.31.1": ("New York", 40.7, -74.0)}
    mon.geo.lookup = lambda ip: ip in places and dict(zip(("city", "lat", "lon"), places[ip]), cc="DE",
                                                      country="Germany", asn=1, org="Org")
    mon.handle_line(BLOCK, "192.168.1.1")
    mon.handle_line(BLOCK.replace("185.220.101.1", "193.176.31.1"), "192.168.1.1")
    assert len(mon.hello()["points"]) == 2
    msg = mon.points_msg()
    assert not msg["full"] and len(msg["items"]) == 2
    assert mon.points_msg() is None  # nothing changed: nothing sent
    mon.handle_line(BLOCK, "192.168.1.1")
    msg = mon.points_msg()
    assert [p["city"] for p in msg["items"]] == ["Berlin"] and msg["items"][0]["n"] == 2
    mon.state.day = mon._points_day = "2000-01-01"  # as if all that was yesterday: now past midnight, the counts
    mon.handle_line(BLOCK, "192.168.1.1")             # start over, and the dashboards get the whole (new) list
    msg = mon.points_msg()
    assert msg["full"] and [p["n"] for p in msg["items"]] == [1]


def test_the_web_app_serves_fresh_files_and_compressed_history(tmp_path, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SYSLOG_PORT", 0)
    monkeypatch.setattr(config, "BIND", "127.0.0.1")

    async def nothing(self):
        return None
    monkeypatch.setattr(server.Geo, "refresh", nothing)  # no GeoIP download in a test

    async def go():
        async with TestClient(TestServer(server.make_app(False))) as c:
            r = await c.get("/static/vendor/fonts/fonts.css")
            assert r.status == 200 and r.headers["Cache-Control"] == "no-cache"
            csp = (await c.get("/")).headers["Content-Security-Policy"]
            assert "script-src 'self';" in csp and f"ws://{c.host}:{c.port}" in csp
            evil = await c.get("/history", headers={"Host": "x; script-src *"})
            assert "script-src *" not in evil.headers["Content-Security-Policy"]
            r = await c.get("/api/history?days=7", headers={"Accept-Encoding": "gzip"})
            assert r.status == 200 and r.headers.get("Content-Encoding") == "gzip" and "aims" in await r.json()
            assert (await c.get("/healthz")).status == 200
            c.server.app[server.MON].history.failing = server.HISTORY_FAILING
            assert (await c.get("/healthz")).status == 503
            async with c.ws_connect("/ws") as ws:
                hello = await ws.receive_json()
                assert hello["t"] == "hello" and hello["build"] == server.web_build()
    asyncio.run(go())


TV = ('<174>Nov  5 20:05:52 fw suricata[1]: {"event_type":"alert","src_ip":"81.0.0.1","src_port":51000,'
      '"dest_ip":"2.18.244.217","dest_port":443,"proto":"TCP","direction":"to_server","app_proto":"tls",'
      '"tls":{"sni":"drod20p.akamaized.net"},"alert":{"signature_id":2028371,'
      '"signature":"ET JA3 Hash - [Abuse.ch] Possible Adware"},"flow":{"src_ip":"81.0.0.1","dest_ip":"2.18.244.217"}}')


def test_a_start_after_the_fingerprint_fix_takes_todays_out_of_the_threats(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mon = Monitor(False)
    mon.handle_line(BLOCK, "192.168.1.1")  # teaches our WAN address, so the TV's alert reads as going out
    monkeypatch.setattr(server, "is_policy", lambda ev: ev["kind"] == "block" and ev["way"] == "out")  # as before
    mon.handle_line(TV, "192.168.1.1")
    t = mon.state.stats()["totals"]
    assert (t["attempts"], t["attack"], t["out"]) == (2, 1, 1)  # counted as an attack from DR's video server
    asyncio.run(mon.history.flush())
    mon.state.save()
    mon.history.close()
    con = sqlite3.connect(tmp_path / "history.db")
    con.execute("PRAGMA user_version = 3")
    con.commit()
    con.close()
    monkeypatch.undo()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)

    again = Monitor(False)
    t = again.state.stats()["totals"]
    assert (t["attempts"], t["attack"], t["out"]) == (1, 0, 1)  # the block alone; going out once, not twice
    assert "2.18.244.217" not in again.state.ips and all(e["remote"] != "2.18.244.217" for e in again.state.recent)
    again.handle_line(TV, "192.168.1.1")  # from now on: our own network
    assert again.state.stats()["totals"]["attempts"] == 1


def test_a_stop_with_a_dashboard_open_still_saves_todays_counts(tmp_path, monkeypatch):
    # aiohttp waits for open requests before its cleanup, and a dashboard's connection never ends by itself: before,
    # Docker killed the server first and today's counts since the last save were lost
    from aiohttp import ClientSession
    from aiohttp import web as aioweb
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SYSLOG_PORT", 0)
    monkeypatch.setattr(config, "BIND", "127.0.0.1")

    async def nothing(self):
        return None
    monkeypatch.setattr(server.Geo, "refresh", nothing)

    async def stop_with_a_dashboard_open():
        app = server.make_app(False)
        runner = aioweb.AppRunner(app, shutdown_timeout=20)
        await runner.setup()
        site = aioweb.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        app[server.MON].handle_line(BLOCK, "192.168.1.1")
        async with ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ws") as ws:
            async def read():  # as a browser does: it answers the server's close at once
                async for _ in ws:
                    pass
            reader = asyncio.create_task(read())
            await asyncio.sleep(0.2)
            t0 = time.monotonic()
            await runner.cleanup()
            await reader
            return time.monotonic() - t0
    assert asyncio.run(stop_with_a_dashboard_open()) < 5
    assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["totals"]["attempts"] == 1
