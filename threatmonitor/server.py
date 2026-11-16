"""The running monitor: syslog lines in, enriched events out to every open dashboard over a WebSocket."""
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor

from aiohttp import WSCloseCode, WSMsgType, web

from . import config, demo, syslog
from .geo import Geo, reverse_name, scanner_host
from .health import Health
from .history import History
from .parse import is_policy, opens_connection, parse_line, parse_pass, stored_reply
from .knocks import ATTEMPT, Knocks, describe
from .state import State

log = logging.getLogger("monitor")

TICK = 0.25          # event batches go out this often
MAX_BATCH = 60       # events per batch; a burst beyond this is counted, not drawn
# A line can arrive late: over TCP, syslog holds the lines back while this server restarts and sends them after. One
# that arrives more than LATE seconds after it was logged keeps the time it was logged. Beyond MAX_LATE it's the two
# clocks that disagree rather than a line held back, so it keeps its arrival time
LATE = 5
MAX_LATE = 600
NAME_LOOKUPS = 8     # reverse DNS lookups at a time, for the addresses new today (see name_lookups)
SEND_TIMEOUT = 5     # seconds a dashboard gets to take a message; one that doesn't (asleep, gone) is dropped
STALLED = 30         # /healthz fails when the pump hasn't got through a round for this long
HISTORY_FAILING = 30  # ... or when this many history writes (one a second) failed in a row
ERROR_LOG_EVERY = 600  # a job that keeps failing logs its traceback once, then a line at most this often
# today's counts (state.json, 2-4 MB) are saved this many minutes apart: every minute was 3-5 GB a day written to the
# disk. A restart or deploy saves on its way out, and midnight saves too; only a crash loses up to this many minutes
# of the live counts (the history keeps every event)
SAVE_EVERY = 5
EVENT_FIELDS = ("id", "ts", "kind", "action", "way", "proto", "remote", "local", "dport", "svc", "sig", "prio",
                "cls", "ip_n", "seen", "policy", "gain", "dup", "knock_ts", "cat", "app", "target", "rule_name")


def event_view(ev):
    v = {k: ev.get(k) for k in EVENT_FIELDS}
    g = ev.get("geo")
    v["geo"] = {k: g[k] for k in ("lat", "lon", "cc", "country", "city", "org")} if g else None
    return v


def web_build():
    """An id of the dashboard's files as deployed (a hash of their contents). The page reloads itself when a
    reconnect brings a different one, so a deploy reaches the wall without anyone pressing F5."""
    h = hashlib.sha256()
    for p in sorted(config.WEB_DIR.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(config.WEB_DIR)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:12]


def _log_failure(task):
    """A background task that ended by an error says so at once (otherwise only at shutdown, if ever)."""
    if not task.cancelled() and task.exception() is not None:
        log.error("%s stopped", task.get_name(), exc_info=task.exception())


class Monitor:
    def __init__(self, demo_mode):
        self.demo = demo_mode
        self.geo = Geo(config.DATA_DIR)
        self.state = State(config.DATA_DIR, "state-demo.json" if demo_mode else "state.json")  # demo never mixes in
        self.state.load()
        self.clients = {}             # open dashboard -> its connection's transport (to cut one that stops reading)
        self.outbox = []
        self.dropped = 0
        self.lines = Counter()
        self.errors = Counter()       # where something failed -> times (see _failed)
        self._error_logged = {}       # where -> when its error was last logged
        self.alive = time.monotonic() # the pump's last full round (/healthz)
        self._flushing = None         # the history write under way, if any
        self._background = set()      # one-off tasks, kept until done (asyncio holds only weak references)
        self.build = web_build()      # sent in hello (see web_build)
        self._points_day = self.state.day  # the day of the last points sent: a new one means a full list
        self.senders = {}
        self.rejected = Counter()     # syslog from senders not in TM_SYSLOG_ALLOW
        self.unrecognised = deque(maxlen=10)
        self.samples = {}             # program -> its last lines that gave no event (filterlog excluded: mostly passes)
        self.home_ips = self._load_home_ips()   # our own global addresses, learned from inbound blocks
        self.home = self._initial_home()
        self.health = Health(config.DATA_DIR)
        self.history = History(config.DATA_DIR / ("history-demo.db" if demo_mode else "history.db"), config.KEEP_DAYS)
        self.knocks = Knocks()        # pairs a firewall block with the IDS alerts for the same packet (knocks.py)
        # the last firewall lines that are no threat of their own ("late" blocks, passes) for a packet the IDS flagged
        self.other_flagged = {"late": deque(maxlen=12), "pass": deque(maxlen=12)}
        self.ids_lines = deque(maxlen=8)  # the last IDS lines that made an event, as they came (for /api/debug)
        moved = self.history.moved.get(self.state.day, 0)  # today's inbound events a migration moved to our own network
        refiled = self.history.refiled.get(self.state.day, 0)  # ... and outbound ones, counted as outbound already
        relisted = self.history.relisted.get(self.state.day, 0)  # today's blocks by list rules, now on a threat list
        if (moved or refiled or relisted) and not demo_mode:
            self._recount_today(moved)
        for s in self.state.ips.values():  # a company added to geo.SCANNER_HOSTS counts for addresses named before
            if s.get("host"):
                s["scanner"] = scanner_host(s["host"])
        self.yday = None              # threats yesterday up to this time of day (from the history), or None
        # addresses whose name (reverse DNS) isn't looked up yet: today's from before a restart, then each new one
        self.to_name = deque() if demo_mode else deque(ip for ip, s in self.state.ips.items() if "host" not in s)
        self.named = Counter()        # lookups done: "named" / "unnamed"
        self.dns = ThreadPoolExecutor(max_workers=2 * NAME_LOOKUPS, thread_name_prefix="dns")

    def _other_line(self, ev, how):
        if self.knocks.other_line(ev, how):  # ... for the very packet an IDS alert was about
            self.lines[f"{how}_flagged"] += 1
            self.other_flagged[how].append(describe(ev))

    def _recount_today(self, moved=0):
        """Today's counts so far rebuilt from the history (it has every event of today, already marked with what each
        added to its knock), after a migration changed today's stored events: events moved out of the threats to our
        own network (replies to our own traffic, `moved` of them today, which become outbound; alerts on our
        devices' TLS fingerprints, outbound already), blocks by list rules marked as listed."""
        old, new = self.state, State(config.DATA_DIR, self.state.name)
        new.seq = old.seq
        for r in self.history.today_events(old.day):
            ev = dict(r, geo=self.geo.lookup(r["remote"]), seen=(old.ips.get(r["remote"]) or {}).get("seen"))
            if ev["kind"] == "block":
                ev["rule_name"], ev["list_rule"] = config.rule_of(ev["rule"])
            new.add(ev, r["gain"])
        # the stream as it was, less what is our own network now; outbound isn't all in the history, so it is carried over
        new.recent = deque((e for e in old.recent if not stored_reply(e) and not is_policy(e)), maxlen=old.recent.maxlen)
        new.outbound = old.outbound + moved
        for ip, s in new.ips.items():  # what the old counts knew beyond the history: names looked up
            for k in ("host", "scanner"):
                if k in old.ips.get(ip, {}):
                    s[k] = old.ips[ip][k]
        new.totals["unlogged"] = self.history.unlogged_on(old.day)
        self.state = new
        new.save()
        log.info("recounted today as %d knocks (%d events)", new.totals["attempts"],
                 new.totals["block"] + new.totals["ids"])

    def _failed(self, where):
        """Count an error in a background job and log it: the traceback the first time, then at most one line every
        ERROR_LOG_EVERY seconds, so a job that keeps failing doesn't fill the disk with logs."""
        self.errors[where] += 1
        now = time.monotonic()
        last = self._error_logged.get(where)
        if last is None:
            log.exception("%s failed", where)
        elif now - last >= ERROR_LOG_EVERY:
            log.error("%s still failing (%d times so far)", where, self.errors[where])
        else:
            return
        self._error_logged[where] = now

    def _spawn(self, coro, name):
        t = asyncio.get_running_loop().create_task(coro, name=name)
        self._background.add(t)
        t.add_done_callback(self._background.discard)
        t.add_done_callback(_log_failure)
        return t

    # --- input ---------------------------------------------------------------------------------------------

    def on_line(self, line, sender):
        """The syslog receiver's callback: a line that trips an error is counted and skipped, never the connection."""
        try:
            self.handle_line(line, sender)
        except Exception:  # noqa: BLE001
            self._failed("line")

    def _when(self, ev, now):
        """The time an event happened: when it was logged if the line came late (held back while this server
        restarted), else when it arrived (see LATE)."""
        logged = ev.pop("logged", None)
        if logged is None:
            self.lines["no_time"] += 1
        elif LATE < now - logged <= MAX_LATE:
            self.lines["delayed"] += 1
            return logged
        return now

    def handle_line(self, line, sender):
        now = time.time()
        self.state.roll()
        self.senders[sender] = now
        prog, ev = parse_line(line)
        if prog is None:
            self.lines["unrecognised"] += 1
            self.unrecognised.append(line[:400])
            return
        self.lines[prog if prog in ("filterlog", "suricata") else "other"] += 1
        if ev is None:
            if prog != "filterlog":
                self.samples.setdefault(prog, deque(maxlen=5)).append(line[:400])
            elif (p := parse_pass(line)) and p["way"] == "in" and p["remote"] not in self.home_ips:
                self.lines["filterlog_pass_in"] += 1  # let in: a port forward, a reply, a rule that allows it
                p["ts"] = self._when(p, now)  # as the IDS alert for it has, so the two still pair after a restart
                self._other_line(p, "pass")
            return
        if ev["kind"] == "ids":
            self.ids_lines.append(line[:1500])
            if ev.get("reply"):
                self.lines["ids_replies"] += 1  # turned round: an alert on an answer to our own traffic (answers_us)
        if not opens_connection(ev):
            self.lines["filterlog_late"] += 1  # see opens_connection
            ev["ts"] = self._when(ev, now)
            self._other_line(ev, "late")
            return
        if ev["remote"] in self.home_ips:
            # our own global address (the WAN, as the IDS sees outbound traffic after NAT, or an IPv6 LAN host)
            # is on the internet side: the other end is the remote one, or drop it if both ends are ours
            if not ev["local"] or ev["local"] in self.home_ips or not ipaddress.ip_address(ev["local"]).is_global:
                return
            ev["remote"], ev["local"], ev["way"] = ev["local"], ev["remote"], "out"
        elif ev["way"] == "in" and ev["kind"] == "block":
            # only an inbound firewall block says for certain that its destination is us; an IDS alert can run
            # from our WAN address to a server outside (e.g. an external-IP lookup), which would teach the wrong thing
            self._learn_home(ev["local"])
            if ev["local"] in self.home_ips and "." in ev["local"]:  # public IPv4 only: that is the WAN address
                self.health.seen_wan(ev["local"], now)
        self.health.event(ev, now)
        ev["ts"] = self._when(ev, now)
        ev["geo"] = self.geo.lookup(ev["remote"])
        if ev["kind"] == "block":  # which firewall rule, by name, and whether it blocks a threat list (config.RULES)
            ev["rule_name"], ev["list_rule"] = config.rule_of(ev.get("rule"))
        policy = ev["policy"] = is_policy(ev)  # our own network, noted by a rule: shown but not a threat
        if not policy and ev["remote"] not in self.state.ips:  # first time today: was it here on an earlier day?
            try:
                ev["seen"] = self.history.seen(ev["remote"], self.state.day)
            except sqlite3.Error as e:
                log.warning("history lookup failed: %s", e)
        ev["gain"] = 0 if policy else self.knocks.add(ev)
        if ev.get("other"):  # the IDS alert for a packet the firewall had logged as a "late" block or a pass
            how, what = ev.pop("other")
            self.lines[f"{how}_flagged"] += 1
            self.other_flagged[how].append(what)
        self.state.add(ev, ev["gain"])
        if ev["ip_n"] == 1 and ev["gain"] & ATTEMPT and not self.demo:
            self.to_name.append(ev["remote"])
        (self.history.add_policy if policy else self.history.add)(ev)
        self.outbox.append(ev)

    # --- home (where arcs land) ----------------------------------------------------------------------------

    @property
    def _home_file(self):
        return config.DATA_DIR / "home.json"

    def _initial_home(self):
        if config.HOME_LAT is not None and config.HOME_LON is not None:
            return {"lat": config.HOME_LAT, "lon": config.HOME_LON, "label": config.HOME_LABEL, "source": "config"}
        try:
            return json.loads(self._home_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            lat, lon = config.DEFAULT_HOME
            return {"lat": lat, "lon": lon, "label": config.HOME_LABEL, "source": "default"}

    @property
    def _home_ips_file(self):
        return config.DATA_DIR / "home_ips.json"

    def _load_home_ips(self):
        try:
            return set(json.loads(self._home_ips_file.read_text(encoding="utf-8")))
        except (FileNotFoundError, ValueError):
            return set()

    def _learn_home(self, addr):
        if not addr or addr in self.home_ips or not ipaddress.ip_address(addr).is_global:
            return
        if len(self.home_ips) < 256:
            self.home_ips.add(addr)
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)  # kept, so a restart knows them from the first line
            self._home_ips_file.write_text(json.dumps(sorted(self.home_ips)), encoding="utf-8")
        if self.home["source"] != "default" or ":" in addr:
            return
        g = self.geo.lookup(addr)
        if g:  # the WAN address, geolocated to the ISP's city: close enough for a globe
            self.home = {"lat": g["lat"], "lon": g["lon"], "label": g["city"] or config.HOME_LABEL, "source": "wan"}
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            self._home_file.write_text(json.dumps(self.home), encoding="utf-8")
            log.info("home set from WAN address: %s", self.home)
            self._broadcast_soon({"t": "home", "home": self.home})

    # --- output --------------------------------------------------------------------------------------------

    def feed(self):
        now = time.time()
        return {
            "mode": "demo" if self.demo else "syslog",
            "port": config.SYSLOG_PORT,
            "senders": [{"ip": ip, "ago": round(now - t, 1)} for ip, t in self.senders.items() if ip != "demo"],
            "rejected": dict(self.rejected.most_common(5)),
            "lines": dict(self.lines),
            "geo": self.geo.ready,
            "dropped": self.dropped,
            "names": dict(self.named, waiting=len(self.to_name)),
            "wan": self.health.wan["ip"],
            "warnings": [{"key": k, "text": t} for k, t in self.health.warnings(now).items()],
            "errors": dict(self.errors, **{k: n for k, n in (("history write", self.history.failures),
                                                             ("history lost", self.history.lost)) if n}),
        }

    def stats(self):
        return dict(self.state.stats(), yday=self.yday)

    def stats_msg(self):
        return {"t": "stats", "stats": self.stats(), "feed": self.feed(), "now": time.time()}

    def hello(self):
        recent = list(self.state.recent)[-40:]
        return {"t": "hello", "build": self.build, "home": self.home, "now": time.time(), "stats": self.stats(),
                "feed": self.feed(), "points": self.state.globe_points(), "recent": [event_view(e) for e in recent]}

    def points_msg(self):
        """The globe's places: only those that changed since the last message (the full list went out in hello),
        or the full list again when a new day started the counts over. Every 5 s, so ~2 KB, not ~190 KB."""
        full = self.state.day != self._points_day
        self._points_day = self.state.day
        if full:
            self.state.changed.clear()
            return {"t": "points", "items": self.state.globe_points(), "full": True}
        items = self.state.points_changed()
        return {"t": "points", "items": items, "full": False} if items else None

    def _broadcast_soon(self, msg):
        self._spawn(self.broadcast(msg), "broadcast")

    async def broadcast(self, msg):
        if not self.clients:
            return
        data = json.dumps(msg, separators=(",", ":"))
        await asyncio.gather(*(self._send(ws, data) for ws in list(self.clients)))

    async def _send(self, ws, data):
        """One dashboard's copy. A browser that stops reading (a laptop asleep with the page open) would otherwise
        hold up every other dashboard, and the pump with them, until its connection timed out (many minutes)."""
        try:
            await asyncio.wait_for(ws.send_str(data), SEND_TIMEOUT)
        except TimeoutError:
            transport = self.clients.pop(ws, None)
            if transport is not None:
                transport.abort()
            log.info("dropped a dashboard that stopped taking messages")
        except (ConnectionError, RuntimeError):
            self.clients.pop(ws, None)

    def close_knocks(self, now):
        for k in self.knocks.close(now):  # flagged by the IDS, but no block for it in the firewall log
            self.state.totals["unlogged"] += 1
            self.history.add_unlogged(k["t"])

    async def pump(self):
        tick = 0
        while True:
            await asyncio.sleep(TICK)
            tick += 1
            try:
                await self._tick(tick)
            except Exception:  # noqa: BLE001 - one bad round must not stop the dashboards
                self._failed("pump")
            else:
                self.alive = time.monotonic()

    async def _tick(self, tick):
        if self.outbox:
            batch, self.outbox = self.outbox, []
            if len(batch) > MAX_BATCH:
                self.dropped += len(batch) - MAX_BATCH
                batch = batch[-MAX_BATCH:]
            await self.broadcast({"t": "events", "items": [event_view(e) for e in batch]})
        if tick % 4 == 0:
            self.close_knocks(time.time())
            if self._flushing is None or self._flushing.done():  # in the background: the pump never waits on disk
                self._flushing = self._spawn(self.history.flush(), "history flush")
        if tick % 8 == 0:
            self.state.roll()  # midnight, even when no line comes in
            await self.broadcast(self.stats_msg())
        if tick % 20 == 0 and (msg := self.points_msg()):
            await self.broadcast(msg)

    async def minutely(self):
        """Push a message when a health warning appears or clears (its own task, so a slow webhook can't hold up the
        dashboards), and save today's counts every SAVE_EVERY minutes."""
        minute = 0
        while True:
            await asyncio.sleep(60)
            minute += 1
            try:
                if minute % SAVE_EVERY == 0:
                    self.state.save()
                await self.health.check()
            except Exception:  # noqa: BLE001
                self._failed("minutely")

    async def geo_updater(self):
        while True:
            try:
                await self.geo.refresh()
            except Exception:  # noqa: BLE001 - never let a download problem stop the monitor
                log.exception("geo refresh failed")
            await asyncio.sleep(6 * 3600)

    async def history_upkeep(self):
        """Seed an empty history with today's counts so far, then drop old events every 6 hours."""
        s = self.state
        if not self.demo:
            try:
                if await self.history.run(self.history.is_empty):  # only then the copies of today's counts are needed
                    await self.history.run(self.history.seed, s.day, dict(s.totals), s.outbound,
                                           json.loads(json.dumps(s.ips)), dict(s.ports), dict(s.port_svc),
                                           json.loads(json.dumps(s.countries)))
            except Exception:  # noqa: BLE001
                self._failed("history seed")
        while True:
            try:
                await self.history.run(self.history.prune)
            except Exception:  # noqa: BLE001
                self._failed("history prune")
            await asyncio.sleep(6 * 3600)

    async def name_lookups(self):
        """Look up the name (reverse DNS) of each address new today, a few at a time. A scanning company's servers
        often carry its name even when they sit in someone else's network, like Google's or Amazon's cloud, so this
        finds the scanners that the networks' names miss."""
        while True:
            batch = [self.to_name.popleft() for _ in range(min(NAME_LOOKUPS, len(self.to_name)))]
            if not batch:
                await asyncio.sleep(1)
                continue
            try:
                for ip, host in zip(batch, await asyncio.gather(*(reverse_name(ip, self.dns) for ip in batch))):
                    self.named["named" if host else "unnamed"] += 1
                    scanner = scanner_host(host)
                    s = self.state.ips.get(ip)
                    if s is not None:
                        s["host"], s["scanner"] = host, scanner
                    if host:
                        self.history.add_name(ip, host, scanner)
            except Exception:  # noqa: BLE001
                self._failed("name lookups")
                await asyncio.sleep(1)

    async def yesterday_updater(self):
        """Once a minute: how many threats yesterday had by this time of day, for "vs yesterday" on the dashboard."""
        while True:
            try:
                self.yday = await self.history.read(self.history.yesterday_by_now, time.time())
            except Exception:  # noqa: BLE001
                self._failed("yesterday's count")
            await asyncio.sleep(60)


# --- HTTP ------------------------------------------------------------------------------------------------------

MON = web.AppKey("mon", Monitor)
TASKS = web.AppKey("tasks", list)

async def index(request):
    return web.FileResponse(config.WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})


async def ws_handler(request):
    mon = request.app[MON]
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    await ws.send_str(json.dumps(mon.hello(), separators=(",", ":")))
    mon.clients[ws] = request.transport
    try:
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
    finally:
        mon.clients.pop(ws, None)
    return ws


async def api_stats(request):
    mon = request.app[MON]
    return web.json_response({"home": mon.home, "stats": mon.stats(), "feed": mon.feed()})


def deployed_version():
    """What deploy.sh wrote next to the code: the commit (git describe) and when; None when run from a checkout."""
    try:
        return (config.ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return None


async def api_debug(request):
    mon = request.app[MON]
    return web.json_response({"version": deployed_version(), "feed": mon.feed(), "home_ips": sorted(mon.home_ips),
                              "unrecognised": list(mon.unrecognised),
                              "no_event_samples": {p: list(d) for p, d in mon.samples.items()},
                              **{f"{how}_flagged": list(d) for how, d in mon.other_flagged.items()},
                              "ids_lines": list(mon.ids_lines)})


async def healthz(request):
    """Docker's health check: fails when the pump (events, stats, history writes) has stopped getting round, or the
    history can't be written."""
    mon = request.app[MON]
    stalled = time.monotonic() - mon.alive
    if stalled > STALLED:
        return web.Response(status=503, text=f"stalled for {stalled:.0f} s")
    if mon.history.failing >= HISTORY_FAILING:
        return web.Response(status=503, text=f"{mon.history.failing} history writes failed in a row")
    return web.Response(text="ok")


async def history_page(request):
    return web.FileResponse(config.WEB_DIR / "history.html", headers={"Cache-Control": "no-cache"})


async def api_history(request):
    mon = request.app[MON]
    try:
        days = max(1, min(int(request.query.get("days", "7")), mon.history.keep_days))
    except ValueError:
        raise web.HTTPBadRequest(text="days must be a whole number")
    await mon.history.flush()
    return _gzipped(web.json_response(await mon.history.read(mon.history.summary, days)))


async def api_ip(request):
    mon = request.app[MON]
    try:
        ip = str(ipaddress.ip_address(request.match_info["ip"].strip()))
    except ValueError:
        raise web.HTTPBadRequest(text="not an IP address")
    await mon.history.flush()
    return _gzipped(web.json_response(await mon.history.read(mon.history.ip_detail, ip)))


def _gzipped(response):
    response.enable_compression()  # when the browser accepts it: JSON shrinks to a fifth
    return response


async def _headers(request, response):
    """The page's files: the browser asks each time whether they changed (a 304 if not), so a deploy is picked up
    on the next load without version tokens in the URLs. The two pages: a Content-Security-Policy, a safety net for
    the text from the internet they show (host names, network names, IDS rule names; all escaped today): a script
    or style that slipped through couldn't load anything or send anything anywhere."""
    if request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-cache")
    elif request.path in ("/", "/history"):
        # the WebSocket by name too ('self' covers ws: only in newer browsers); the Host header is the client's own
        ws = f" ws://{request.host} wss://{request.host}" if _HOST.fullmatch(request.host or "") else ""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            f"font-src 'self'; connect-src 'self'{ws}; object-src 'none'; base-uri 'none'; form-action 'self'")


_HOST = re.compile(r"[A-Za-z0-9.\-]+(:\d+)?|\[[0-9A-Fa-f:]+\](:\d+)?")


def make_app(demo_mode):
    app = web.Application()
    mon = Monitor(demo_mode)
    app[MON] = mon
    app.router.add_get("/", index)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/debug", api_debug)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/history", history_page)
    app.router.add_get("/api/history", api_history)
    app.router.add_get("/api/ip/{ip}", api_ip)
    app.router.add_static("/static/", config.WEB_DIR)
    app.on_response_prepare.append(_headers)

    async def start(app):
        await syslog.start(config.BIND, config.SYSLOG_PORT, mon.on_line, config.SYSLOG_ALLOW,
                           lambda ip: mon.rejected.update([ip]))
        tasks = [mon.pump(), mon.minutely(), mon.geo_updater(), mon.history_upkeep(), mon.yesterday_updater(),
                 mon.name_lookups()]
        if demo_mode:
            tasks.append(demo.run(mon.geo, mon.on_line))
        app[TASKS] = [asyncio.create_task(t, name=t.__name__) for t in tasks]
        for t in app[TASKS]:
            t.add_done_callback(_log_failure)

    async def going(app):
        # first thing on a stop: close the dashboards' connections. aiohttp waits for open requests before the
        # cleanup below, up to a minute, and a dashboard's never ends by itself: Docker killed the server first, so
        # today's counts were never saved on the way out (a restart lost the minutes since the last save)
        await asyncio.gather(*(asyncio.wait_for(ws.close(code=WSCloseCode.GOING_AWAY, message=b"restarting"), 2)
                               for ws in list(mon.clients)), return_exceptions=True)

    async def stop(app):
        for t in app[TASKS]:
            t.cancel()
        mon.state.save()
        mon.health.save()
        if mon._flushing is not None:  # the write under way first, then what came after it
            await asyncio.gather(mon._flushing, return_exceptions=True)
        await mon.history.flush()
        mon.history.close()
        mon.dns.shutdown(wait=False, cancel_futures=True)

    app.on_startup.append(start)
    app.on_shutdown.append(going)
    app.on_cleanup.append(stop)
    return app
