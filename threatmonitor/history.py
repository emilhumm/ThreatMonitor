"""Long-term record in SQLite: every threat event, daily roll-ups for fast range views, and one row per address.

Writes are batched (about once a second) and run on one worker thread; the History page's queries run on another,
with its own connection, so a long one never holds up the writes (WAL mode lets them run side by side). The only
read on the event loop is the primary-key lookup "was this address seen on an earlier day?", which takes
microseconds.

Your own devices hitting outbound block rules are not threats: they are counted per minute in `policy`, not
stored one by one.
"""
import asyncio
import datetime as dt
import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from . import config
from .behaviour import aims, what
from .geo import SCANNER_HOSTS, scanner_host, scanner_of
from .knocks import ATTACK, ATTEMPT, FLAGGED, GAINS, LISTED, Knocks, alone
from .parse import ids_category, is_policy, stored_reply

log = logging.getLogger("history")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, day TEXT NOT NULL,
  kind TEXT NOT NULL, action TEXT, way TEXT, proto TEXT,
  remote TEXT NOT NULL, local TEXT, sport INTEGER, dport INTEGER, svc TEXT, iface TEXT, rule TEXT,
  sig TEXT, sid INTEGER, prio INTEGER, cls TEXT,
  cc TEXT, city TEXT, asn INTEGER, org TEXT, gain INTEGER, cat TEXT, app TEXT, target TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_remote ON events(remote, ts);
CREATE TABLE IF NOT EXISTS ips (
  ip TEXT PRIMARY KEY, first REAL, last REAL, hits INTEGER, ids INTEGER, days INTEGER, last_day TEXT,
  cc TEXT, org TEXT);
CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, block INTEGER NOT NULL DEFAULT 0,
  ids INTEGER NOT NULL DEFAULT 0, out INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
  flagged INTEGER NOT NULL DEFAULT 0, listed INTEGER NOT NULL DEFAULT 0, attack INTEGER NOT NULL DEFAULT 0,
  unlogged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS daily_ip (day TEXT, ip TEXT, hits INTEGER, ids INTEGER, cc TEXT, PRIMARY KEY (day, ip));
CREATE INDEX IF NOT EXISTS daily_ip_ip ON daily_ip(ip);
CREATE TABLE IF NOT EXISTS daily_port (day TEXT, port TEXT, svc TEXT, hits INTEGER, PRIMARY KEY (day, port));
CREATE TABLE IF NOT EXISTS daily_cc (day TEXT, cc TEXT, name TEXT, hits INTEGER, PRIMARY KEY (day, cc));
CREATE TABLE IF NOT EXISTS daily_sig (day TEXT, sid INTEGER, sig TEXT, hits INTEGER, PRIMARY KEY (day, sid));
CREATE TABLE IF NOT EXISTS policy (minute INTEGER, local TEXT, remote TEXT, dport INTEGER, n INTEGER,
  PRIMARY KEY (minute, local, remote, dport));
CREATE TABLE IF NOT EXISTS names (ip TEXT PRIMARY KEY, host TEXT, scanner TEXT, day TEXT);
CREATE TABLE IF NOT EXISTS daily_aims (day TEXT PRIMARY KEY, aims TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

EVENT_COLS = ("ts", "day", "kind", "action", "way", "proto", "remote", "local", "sport", "dport", "svc", "iface",
              "rule", "sig", "sid", "prio", "cls", "cc", "city", "asn", "org", "gain", "cat", "app", "target")
# added to the first schema: (table, column, type)
ADDED = (("events", "gain", "INTEGER"), ("events", "cat", "TEXT"), ("events", "app", "TEXT"),
         ("events", "target", "TEXT"), *(("daily", c, "INTEGER NOT NULL DEFAULT 0")
                                         for c in ("attempts", "flagged", "listed", "attack", "unlogged")))
DAILY_KNOCKS = ("attempts", "flagged", "listed", "attack", "unlogged")
# a day's events are all stored this long after it ends: a line can come up to 10 minutes late (server.MAX_LATE)
SETTLED = 660
MAX_QUEUE = 50000  # events kept in memory while writes fail (an hour or two); beyond that the oldest are dropped


def day_of(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def aims_columns(days, per_day):
    """The days' aims (behaviour.aims, one per day) as columns for the History page, which only needs per day the
    mapping and same-port totals and each group's knocks, plus each group's three services that were in its list on
    the most days (ties: the first seen). A year as a list of whole aims was ~250 KB; this is a tenth of it."""
    aimed, svcs = {}, {}
    for i, a in enumerate(per_day):
        for group, n, names in a["aimed"]:
            aimed.setdefault(group, [0] * len(days))[i] = n
            svcs.setdefault(group, Counter()).update(names)
    return {
        "days": days,
        "mapping": [sum(a["mapping"].values()) for a in per_day],
        "repeat": [sum(x[1] for x in a["repeat"]) for a in per_day],
        "aimed": aimed,
        "svcs": {g: [s for s, _ in sorted(c.items(), key=lambda kv: -kv[1])[:3]] for g, c in svcs.items()},
    }


def day_bounds(day):
    """A day's start and end (epoch seconds, local time). Queries ask for a ts range, which the events_ts index
    answers; "day = ?" would read every event."""
    d = dt.date.fromisoformat(day)
    return tuple(time.mktime(dt.datetime.combine(x, dt.time()).timetuple()) for x in (d, d + dt.timedelta(days=1)))


def port_key(ev):
    return str(ev["dport"]) if ev.get("dport") is not None else ev["svc"]


class History:
    def __init__(self, path, keep_days):
        self.path = path
        self.keep_days = keep_days
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="history")        # writes (run)
        self.rpool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="history-read")  # the page's questions (read)
        self._local = threading.local()
        self.queue = []
        self.policy = Counter()       # (minute, local, remote, dport) -> attempts
        self.policy_days = Counter()  # day -> attempts
        self.names = {}               # ip -> (name in reverse DNS, scanning company or None, day)
        self.unlogged = Counter()     # day -> knocks the IDS flagged that the firewall log has no block for
        self.moved = Counter()        # day -> stored inbound events a migration moved to our own network (_replies_out)
        self.refiled = Counter()      # day -> stored outbound ones it moved there, outbound already (_own_network_out)
        self.relisted = Counter()     # day -> stored blocks it marked as on a threat list (_list_rules)
        self._aims = {}               # day -> what its knocks were after (aims_on), once the day is over and settled
        self.failing = 0              # writes failed in a row (server's /healthz)
        self.failures = 0             # writes failed since the start
        self.lost = 0                 # events dropped after failed writes
        self._fail_logged = None
        path.parent.mkdir(parents=True, exist_ok=True)
        self._rcon = self._connect()  # the event loop's own connection: "seen before" lookups only
        self._rcon.executescript(SCHEMA)
        self._migrate(self._rcon)
        self._rescan_names(self._rcon)

    def _rescan_names(self, con):
        """Each stored name's scanning company by the list as it is now (geo.SCANNER_HOSTS), so a company added to it
        counts for the addresses already named too (Infrawatch, added on 5 Nov). Only when the list changed since
        the last start (its fingerprint is kept in meta): a year holds some 300,000 names."""
        mark = hashlib.sha256(repr(sorted(SCANNER_HOSTS.items())).encode()).hexdigest()
        r = con.execute("SELECT value FROM meta WHERE key = 'scanner_hosts'").fetchone()
        if r and r[0] == mark:
            return
        changes = []
        for r in con.execute("SELECT ip, host, scanner FROM names WHERE host IS NOT NULL AND host != ''"):
            if (now := scanner_host(r["host"])) != r["scanner"]:
                changes.append((now, r["ip"]))
        with con:
            con.executemany("UPDATE names SET scanner = ? WHERE ip = ?", changes)
            con.execute("INSERT OR REPLACE INTO meta VALUES ('scanner_hosts', ?)", (mark,))
        if changes:
            log.info("%d stored names now with a different scanning company", len(changes))

    def _migrate(self, con):
        """Bring an older database up to date: add the columns, then each one-off correction it hasn't had yet."""
        for table, col, kind in ADDED:
            if col not in {r[1] for r in con.execute(f"PRAGMA table_info({table})")}:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
        version = con.execute("PRAGMA user_version").fetchone()[0]
        if version < 1:
            self._count_knocks(con)
        if version < 2:
            self._replies_out(con)
        if version < 3:
            self._list_rules(con)
        if version < 5:
            self._own_network_out(con)

    def _count_knocks(self, con):
        """Version 1, from before knocks were counted once: mark every event already stored with what it added to its
        knock, taking the doubles out of the roll-ups."""
        rows = con.execute("SELECT id, ts, day, kind, way, remote, dport, svc, sid, sig, cc FROM events "
                           "ORDER BY ts, id").fetchall()
        knocks, marks = Knocks(), []
        per_day = Counter()                     # (day, name) -> knocks
        dup_hits, dup_ids = Counter(), Counter()   # (day, ip) -> events that were no knock of their own / no new flag
        dup_port, dup_cc, ip_hits, ip_ids = Counter(), Counter(), Counter(), Counter()
        for r in rows:
            cat = ids_category(r["sig"]) if r["kind"] == "ids" else None
            gain = knocks.add({"ts": r["ts"], "kind": r["kind"], "way": r["way"], "remote": r["remote"],
                               "dport": r["dport"], "sid": r["sid"], "cat": cat})
            for k in knocks.close(r["ts"]):
                per_day[(day_of(k["t"]), "unlogged")] += 1
            marks.append((gain, cat, r["id"]))
            for bit, name in GAINS:
                per_day[(r["day"], name)] += bool(gain & bit)
            if not gain & ATTEMPT:
                per_day[(r["day"], "doubles")] += 1
                dup_hits[(r["day"], r["remote"])] += 1
                dup_port[(r["day"], str(r["dport"]) if r["dport"] is not None else r["svc"])] += 1
                dup_cc[(r["day"], r["cc"] or "??")] += 1
                ip_hits[r["remote"]] += 1
            if r["kind"] == "ids" and not gain & FLAGGED:
                dup_ids[(r["day"], r["remote"])] += 1
                ip_ids[r["remote"]] += 1
        for k in knocks.close(float("inf")):
            per_day[(day_of(k["t"]), "unlogged")] += 1
        days = {d for d, _ in per_day}
        with con:
            con.executemany("UPDATE events SET gain = ?, cat = ? WHERE id = ?", marks)
            # a day seeded before events were kept has more in its counts than in events: attempts is what was
            # logged less the doubles found
            con.executemany(
                "UPDATE daily SET attempts = block + ids - ?, flagged = ?, listed = ?, attack = ?, unlogged = ? "
                "WHERE day = ?", [(per_day[(d, "doubles")], per_day[(d, "flagged")], per_day[(d, "listed")],
                                   per_day[(d, "attack")], per_day[(d, "unlogged")], d) for d in days])
            con.executemany("UPDATE daily_ip SET hits = hits - ?, ids = ids - ? WHERE day = ? AND ip = ?",
                            [(dup_hits[k], dup_ids[k], *k) for k in set(dup_hits) | set(dup_ids)])
            con.executemany("UPDATE daily_port SET hits = hits - ? WHERE day = ? AND port = ?",
                            [(n, *k) for k, n in dup_port.items()])
            con.executemany("UPDATE daily_cc SET hits = hits - ? WHERE day = ? AND cc = ?",
                            [(n, *k) for k, n in dup_cc.items()])
            con.executemany("UPDATE ips SET hits = hits - ?, ids = ids - ? WHERE ip = ?",
                            [(ip_hits[ip], ip_ids[ip], ip) for ip in set(ip_hits) | set(ip_ids)])
            con.execute("PRAGMA user_version = 1")
        log.info("counted %d stored events as %d knocks", len(rows), sum(n for (_, k), n in per_day.items()
                                                                        if k == "attempts"))

    def _replies_out(self, con):
        """Version 2, from before parse.answers_us: IDS notices on packets that answered our own traffic were stored
        as inbound threats, mostly the STUN replies of video calls (the call service's relays, from port 3478). They move to our
        own network's outbound traffic (the policy table) and out of every count (see parse.stored_reply)."""
        rows = [dict(r) for r in con.execute("SELECT id, ts, day, kind, way, cat, remote, local, sport, dport, svc, "
                                             "sid, cc, gain FROM events WHERE kind = 'ids' AND way = 'in' AND cat = 'info'")]
        rows = [r for r in rows if stored_reply(r)]
        daily, out = Counter(), Counter()            # (day, column) -> to take off; day -> to add to out
        d_ip, ips = {}, {}                           # (day, ip) / ip -> [hits, ids] to take off
        d_port, d_cc, d_sig, pol = Counter(), Counter(), Counter(), Counter()
        for r in rows:
            day, gain = r["day"], r["gain"] or 0
            new, flagged = int(gain & ATTEMPT > 0), int(gain & FLAGGED > 0)
            daily[(day, "ids")] += 1
            for bit, name in GAINS:
                daily[(day, name)] += bool(gain & bit)
            daily[(day, "unlogged")] += new          # a knock of the IDS's alone: it had counted as unlogged
            out[day] += 1
            for d, k in ((d_ip, (day, r["remote"])), (ips, r["remote"])):
                x = d.setdefault(k, [0, 0])
                x[0] += new
                x[1] += flagged
            d_port[(day, port_key(r))] += new
            d_cc[(day, r["cc"] or "??")] += new
            d_sig[(day, r["sid"])] += 1
            pol[(int(r["ts"] // 60 * 60), r["local"], r["remote"], r["sport"])] += 1  # turned round, as answers_us does
        cols = ("ids", *DAILY_KNOCKS)
        with con:
            con.executemany("DELETE FROM events WHERE id = ?", [(r["id"],) for r in rows])
            con.executemany(f"UPDATE daily SET {', '.join(f'{c} = max(0, {c} - ?)' for c in cols)}, out = out + ? "
                            "WHERE day = ?", [(*(daily[(d, c)] for c in cols), n, d) for d, n in out.items()])
            con.executemany("UPDATE daily_ip SET hits = hits - ?, ids = ids - ? WHERE day = ? AND ip = ?",
                            [(h, i, *k) for k, (h, i) in d_ip.items()])
            con.executemany("UPDATE ips SET hits = hits - ?, ids = ids - ? WHERE ip = ?",
                            [(h, i, ip) for ip, (h, i) in ips.items()])
            for table, key, d in (("daily_port", "port", d_port), ("daily_cc", "cc", d_cc), ("daily_sig", "sid", d_sig)):
                con.executemany(f"UPDATE {table} SET hits = hits - ? WHERE day = ? AND {key} = ?",
                                [(n, *k) for k, n in d.items()])
            # what is left of them: nothing, for addresses only ever seen answering (a call's relays are no returning
            # attackers), ports and countries only they had, and the STUN rule's line on the History page
            con.execute("DELETE FROM daily_ip WHERE hits <= 0 AND ids <= 0")
            con.execute("DELETE FROM ips WHERE hits <= 0 AND ids <= 0")
            for table in ("daily_port", "daily_cc", "daily_sig"):
                con.execute(f"DELETE FROM {table} WHERE hits <= 0")
            con.executemany("INSERT INTO policy VALUES (?, ?, ?, ?, ?) ON CONFLICT(minute, local, remote, dport) DO "
                            "UPDATE SET n = n + excluded.n", [(*k, n) for k, n in pol.items()])
            con.execute("PRAGMA user_version = 2")
        self.moved = out
        if rows:
            log.info("moved %d stored IDS notices on replies to our own traffic out of the threats", len(rows))

    def _list_rules(self, con):
        """Version 3, from when a block by a firewall rule for a threat list (config.RULES, ":list") started counting
        as "on a threat list": the stored ones get that mark where nothing in their knock had it yet (the knocks paired
        again, as they came), and the days' counts follow."""
        lists = {rid for rid, (_, is_list) in config.RULES.items() if is_list}
        knocks, blocks, has_listed = Knocks(), [], set()
        for r in con.execute("SELECT id, ts, day, kind, way, remote, dport, sid, cat, rule, gain FROM events "
                             "ORDER BY ts, id"):
            ev = {"ts": r["ts"], "kind": r["kind"], "way": r["way"], "remote": r["remote"], "dport": r["dport"],
                  "sid": r["sid"], "cat": r["cat"]}
            knocks.add(ev)
            knocks.close(r["ts"])
            knock = (r["remote"], r["dport"], ev["knock_ts"])
            if (r["gain"] or 0) & LISTED:
                has_listed.add(knock)
            if r["kind"] == "block" and r["rule"] in lists:
                blocks.append((knock, r["id"], r["day"], r["gain"] or 0))
        marks, per_day = [], Counter()
        for knock, id_, day, gain in blocks:
            if knock not in has_listed:
                has_listed.add(knock)
                marks.append((gain | LISTED, id_))
                per_day[day] += 1
        with con:
            con.executemany("UPDATE events SET gain = ? WHERE id = ?", marks)
            con.executemany("UPDATE daily SET listed = listed + ? WHERE day = ?", [(n, d) for d, n in per_day.items()])
            con.execute("PRAGMA user_version = 3")
        self.relisted = per_day
        if marks:
            log.info("marked %d stored blocks by threat-list rules as on a threat list", len(marks))

    def _own_network_out(self, con):
        """Versions 4 and 5, from before parse.is_policy took outbound alerts on a TLS fingerprint (JA3, version 4)
        and then every outbound alert outside the threat families (version 5) for our own network: on 5 Nov a smart
        TV's streaming app matched abuse.ch's "Possible Adware" 54 times, counted as attacks from the streaming service's
        servers, and a file-sharing client's 34 alerts made its peers attackers. They move to the policy table, and the roll-ups from
        the first day they were on are worked out again from the events (rebuild_rollups), the first migration done
        that way."""
        rows = [dict(r) for r in con.execute("SELECT id, ts, day, kind, way, sig, remote, local, dport, gain FROM events "
                                             "WHERE kind = 'ids' AND way = 'out'")]
        rows = [r for r in rows if is_policy(r)]
        pol, ips, out = Counter(), {}, Counter()
        for r in rows:
            pol[(int(r["ts"] // 60 * 60), r["local"], r["remote"], r["dport"])] += 1
            out[r["day"]] += 1
            x = ips.setdefault(r["remote"], [0, 0])
            x[0] += bool((r["gain"] or 0) & ATTEMPT)
            x[1] += bool((r["gain"] or 0) & FLAGGED)
        with con:
            if rows:
                con.executemany("DELETE FROM events WHERE id = ?", [(r["id"],) for r in rows])
                con.executemany("INSERT INTO policy VALUES (?, ?, ?, ?, ?) ON CONFLICT(minute, local, remote, dport) "
                                "DO UPDATE SET n = n + excluded.n", [(*k, n) for k, n in pol.items()])
                con.executemany("UPDATE ips SET hits = hits - ?, ids = ids - ? WHERE ip = ?",
                                [(h, i, ip) for ip, (h, i) in ips.items()])
                # an address known only from those (a video server, a torrent peer) is no returning attacker
                con.executemany("DELETE FROM ips WHERE ip = ? AND hits <= 0 AND ids <= 0", [(ip,) for ip in ips])
                self.rebuild_rollups(con, min(out))
            con.execute("PRAGMA user_version = 5")
        self.refiled.update(out)
        if rows:
            log.info("moved %d stored outbound IDS alerts on our own network's routine out of the threats", len(rows))

    def rebuild_rollups(self, con, since):
        """Work the per-day roll-ups (daily, daily_ip, daily_port, daily_cc, daily_sig) out again from the events and
        the policy table, for the days from `since` on, in the caller's transaction.

        For the next migration: correct the events, then call this. Everything stays in SQL, where the migrations
        above read rows into memory and adjust each roll-up by hand, which a year of events (millions) would not
        survive. Kept as they are: daily.unlogged (knocks with no event of their own), daily_cc's country names
        (events don't keep them), and the first day in the history, seeded with counts from before events were
        stored. The days' aims (daily_aims, and the copy in memory) go with the roll-ups: they are worked out again
        from the corrected events on the History page's next visit. tests/test_history.py checks that a rebuild
        gives what the writes gave."""
        first = con.execute("SELECT MIN(day) FROM daily").fetchone()[0]
        if first is not None and since <= first:
            since = (dt.date.fromisoformat(first) + dt.timedelta(days=1)).isoformat()
        start = day_bounds(since)[0]
        for table in ("daily_ip", "daily_port", "daily_sig", "daily_aims"):
            con.execute(f"DELETE FROM {table} WHERE day >= ?", (since,))
        self._aims = {day: a for day, a in self._aims.items() if day < since}
        con.execute("UPDATE daily_cc SET hits = 0 WHERE day >= ?", (since,))
        con.execute(f"UPDATE daily SET {', '.join(f'{c} = 0' for c in ('block', 'ids', 'out', *DAILY_KNOCKS[:-1]))} "
                    "WHERE day >= ?", (since,))
        # the first event's cc / svc / sig, as the writes keep them (SQLite: a bare column comes from the MIN(ts) row)
        con.execute("INSERT INTO daily_ip SELECT day, ip, hits, ids, cc FROM (SELECT day, remote AS ip, "
                    "SUM(gain & ? > 0) AS hits, SUM(gain & ? > 0) AS ids, cc, MIN(ts) FROM events WHERE ts >= ? "
                    "GROUP BY day, remote)", (ATTEMPT, FLAGGED, start))
        con.execute("INSERT INTO daily_port SELECT day, port, svc, hits FROM (SELECT day, "
                    "COALESCE(CAST(dport AS TEXT), svc) AS port, svc, SUM(gain & ? > 0) AS hits, MIN(ts) FROM events "
                    "WHERE ts >= ? GROUP BY day, port)", (ATTEMPT, start))
        con.execute("INSERT INTO daily_sig SELECT day, sid, sig, hits FROM (SELECT day, sid, sig, COUNT(*) AS hits, "
                    "MIN(ts) FROM events WHERE ts >= ? AND kind = 'ids' AND sid IS NOT NULL GROUP BY day, sid)", (start,))
        con.execute("INSERT INTO daily_cc SELECT day, COALESCE(cc, '??'), COALESCE(cc, '??'), SUM(gain & ? > 0) "
                    "FROM events WHERE ts >= ? GROUP BY day, COALESCE(cc, '??') "
                    "ON CONFLICT(day, cc) DO UPDATE SET hits = excluded.hits", (ATTEMPT, start))
        con.execute("INSERT INTO daily (day, block, ids, out, attempts, flagged, listed, attack) "
                    "SELECT day, SUM(kind = 'block'), SUM(kind = 'ids'), SUM(way = 'out'), SUM(gain & ? > 0), "
                    "SUM(gain & ? > 0), SUM(gain & ? > 0), SUM(gain & ? > 0) FROM events WHERE ts >= ? GROUP BY day "
                    "ON CONFLICT(day) DO UPDATE SET block = excluded.block, ids = excluded.ids, out = excluded.out, "
                    "attempts = excluded.attempts, flagged = excluded.flagged, listed = excluded.listed, "
                    "attack = excluded.attack", (ATTEMPT, FLAGGED, LISTED, ATTACK, start))
        con.executemany("INSERT INTO daily (day, out) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET out = out + excluded.out",
                        con.execute("SELECT date(minute, 'unixepoch', 'localtime'), SUM(n) FROM policy WHERE minute >= ? "
                                    "GROUP BY 1", (start,)).fetchall())

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA journal_size_limit=67108864")  # the WAL file shrinks back to 64 MB after a big write
        con.execute("PRAGMA temp_store=MEMORY")            # the page's GROUP BYs over a year sort in memory, not on disk
        con.execute("PRAGMA cache_size=-32768")            # up to 32 MB of pages per connection
        return con

    @property
    def _db(self):  # this worker thread's own connection (sqlite connections stay on the thread that made them)
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._local.con = self._connect()
        return con

    async def run(self, fn, *args):
        """On the writer thread: writes, prune, seed."""
        return await asyncio.get_running_loop().run_in_executor(self.pool, fn, *args)

    async def read(self, fn, *args):
        """On the reader thread: the History page's and the dashboard's questions, which can take seconds over a
        year of data and must not hold up the writes."""
        return await asyncio.get_running_loop().run_in_executor(self.rpool, fn, *args)

    # --- input (event loop) ---------------------------------------------------------------------------------

    def add(self, ev):
        g = ev.get("geo") or {}
        row = dict(ev, day=day_of(ev["ts"]), cc=g.get("cc"), city=g.get("city"), asn=g.get("asn"), org=g.get("org"),
                   country=g.get("country"))
        if row.get("gain") is None:
            row["gain"] = alone(ev)
        self.queue.append(row)

    def add_unlogged(self, ts):
        """A knock the IDS flagged that the firewall log has no block for (see knocks.py)."""
        self.unlogged[day_of(ts)] += 1

    def add_policy(self, ev):
        self.policy[(int(ev["ts"] // 60 * 60), ev["local"], ev["remote"], ev["dport"])] += 1
        self.policy_days[day_of(ev["ts"])] += 1

    def add_name(self, ip, host, scanner):
        self.names[ip] = (host, scanner, day_of(time.time()))

    def seen(self, ip, today):
        """Earlier days this address was seen on, or None: {"first": ts, "days": n}."""
        r = self._rcon.execute("SELECT first, days, last_day FROM ips WHERE ip = ?", (ip,)).fetchone()
        if r is None:
            return None
        earlier = r["days"] - (1 if r["last_day"] == today else 0)
        return {"first": r["first"], "days": earlier} if earlier > 0 else None

    async def flush(self):
        if not self.queue and not self.policy and not self.names and not self.unlogged:
            return
        batch, self.queue = self.queue, []
        pol, self.policy = self.policy, Counter()
        pol_days, self.policy_days = self.policy_days, Counter()
        names, self.names = self.names, {}
        unlogged, self.unlogged = self.unlogged, Counter()
        try:
            await self.run(self._write, batch, pol, pol_days, names, unlogged)
        except sqlite3.OperationalError:
            # the disk full, the database locked, an I/O error: these pass, so the batch waits for the next round
            self._failed(f"history write failed; {len(batch) + len(self.queue)} events wait for the next try")
            self.queue = batch + self.queue
            if len(self.queue) > MAX_QUEUE:  # the oldest go: the memory is not for ever
                self.lost += len(self.queue) - MAX_QUEUE
                del self.queue[:len(self.queue) - MAX_QUEUE]
            self.policy.update(pol)
            self.policy_days.update(pol_days)
            self.names = {**names, **self.names}
            self.unlogged.update(unlogged)
        except sqlite3.Error:  # something in the batch itself, which a retry wouldn't change
            self._failed(f"history write failed; {len(batch)} events lost")
            self.lost += len(batch)
        else:
            if self.failing:
                log.info("history writes work again, after %d failed tries", self.failing)
            self.failing = 0

    def _failed(self, what):
        """A failed write: the traceback the first time, then a line at most every 10 minutes."""
        self.failing += 1
        self.failures += 1
        now = time.monotonic()
        if self._fail_logged is None:
            log.exception(what)
        elif now - self._fail_logged >= 600:
            log.error("%s (%d failed tries so far)", what, self.failures)
        else:
            return
        self._fail_logged = now

    # --- worker thread -----------------------------------------------------------------------------------

    def _write(self, batch, pol, pol_days, names=None, unlogged=None):
        # the roll-ups count knocks (each once); block, ids and the IDS rules count the events as logged
        daily = Counter()                 # (day, column) -> n
        d_ip, d_port, d_cc, d_sig, ips = {}, {}, {}, {}, {}
        for e in batch:
            day, new, flagged = e["day"], int(e["gain"] & ATTEMPT > 0), int(e["gain"] & FLAGGED > 0)
            daily[(day, e["kind"])] += 1
            for bit, name in GAINS:
                daily[(day, name)] += bool(e["gain"] & bit)
            if e["way"] == "out":
                daily[(day, "out")] += 1
            x = d_ip.setdefault((day, e["remote"]), [0, 0, e["cc"]])
            x[0] += new
            x[1] += flagged
            d_port.setdefault((day, port_key(e)), [e["svc"], 0])[1] += new
            d_cc.setdefault((day, e["cc"] or "??"), [e.get("country") or "Unknown", 0])[1] += new
            if e["kind"] == "ids" and e.get("sid") is not None:
                d_sig.setdefault((day, e["sid"]), [e["sig"], 0])[1] += 1
            s = ips.get(e["remote"])
            if s is None:
                s = ips[e["remote"]] = {"first": e["ts"], "last": e["ts"], "hits": 0, "ids": 0, "day": day,
                                        "cc": e["cc"], "org": e["org"]}
            # a line that came late (around midnight, after a restart) can be older than the ones before it
            s["first"], s["last"], s["day"] = min(s["first"], e["ts"]), max(s["last"], e["ts"]), max(s["day"], day)
            s["hits"] += new
            s["ids"] += flagged
        for day, n in pol_days.items():
            daily[(day, "out")] += n
        for day, n in (unlogged or {}).items():
            daily[(day, "unlogged")] += n
        days = {d for d, _ in daily}
        cols = ("block", "ids", "out", *DAILY_KNOCKS)
        con = self._db
        with con:
            con.executemany(f"INSERT INTO events ({', '.join(EVENT_COLS)}) VALUES ({', '.join('?' * len(EVENT_COLS))})",
                            [tuple(e.get(c) for c in EVENT_COLS) for e in batch])
            con.executemany(
                f"INSERT INTO daily (day, {', '.join(cols)}) VALUES (?{', ?' * len(cols)}) ON CONFLICT(day) DO UPDATE "
                f"SET {', '.join(f'{c} = {c} + excluded.{c}' for c in cols)}",
                [(d, *(daily[(d, c)] for c in cols)) for d in days])
            con.executemany(
                "INSERT INTO daily_ip VALUES (?, ?, ?, ?, ?) ON CONFLICT(day, ip) DO UPDATE SET "
                "hits = hits + excluded.hits, ids = ids + excluded.ids",
                [(d, ip, h, i, cc) for (d, ip), (h, i, cc) in d_ip.items()])
            con.executemany(
                "INSERT INTO daily_port VALUES (?, ?, ?, ?) ON CONFLICT(day, port) DO UPDATE SET hits = hits + excluded.hits",
                [(d, p, svc, h) for (d, p), (svc, h) in d_port.items()])
            con.executemany(
                "INSERT INTO daily_cc VALUES (?, ?, ?, ?) ON CONFLICT(day, cc) DO UPDATE SET hits = hits + excluded.hits",
                [(d, cc, name, h) for (d, cc), (name, h) in d_cc.items()])
            con.executemany(
                "INSERT INTO daily_sig VALUES (?, ?, ?, ?) ON CONFLICT(day, sid) DO UPDATE SET hits = hits + excluded.hits",
                [(d, sid, sig, h) for (d, sid), (sig, h) in d_sig.items()])
            con.executemany(
                "INSERT INTO ips VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET "
                "first = min(first, excluded.first), last = max(last, excluded.last), hits = hits + excluded.hits, "
                "ids = ids + excluded.ids, days = days + (excluded.last_day > coalesce(last_day, '')), "
                "last_day = max(coalesce(last_day, ''), excluded.last_day), cc = excluded.cc, org = excluded.org",
                [(ip, s["first"], s["last"], s["hits"], s["ids"], s["day"], s["cc"], s["org"]) for ip, s in ips.items()])
            con.executemany(
                "INSERT INTO policy VALUES (?, ?, ?, ?, ?) ON CONFLICT(minute, local, remote, dport) DO UPDATE SET "
                "n = n + excluded.n", [(*k, n) for k, n in pol.items()])
            con.executemany(
                "INSERT INTO names VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET host = excluded.host, "
                "scanner = excluded.scanner, day = excluded.day", [(ip, *v) for ip, v in (names or {}).items()])

    def is_empty(self):
        return self._db.execute("SELECT 1 FROM daily LIMIT 1").fetchone() is None

    def seed(self, day, totals, outbound, ips, ports, port_svc, countries):
        """Once, into an empty database: today's counts so far (kept in state.json before history existed)."""
        con = self._db
        if not self.is_empty():
            return False
        with con:
            con.execute("INSERT INTO daily (day, block, ids, out, attempts) VALUES (?, ?, ?, ?, ?)",
                        (day, totals.get("block", 0), totals.get("ids", 0), outbound,
                         totals.get("attempts", totals.get("block", 0) + totals.get("ids", 0))))
            con.executemany("INSERT INTO daily_ip VALUES (?, ?, ?, ?, ?)",
                            [(day, ip, s["n"], s.get("ids", 0), s.get("cc")) for ip, s in ips.items()])
            con.executemany("INSERT INTO ips VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                            [(ip, s.get("first"), s.get("last"), s["n"], s.get("ids", 0), day, s.get("cc"), s.get("org"))
                             for ip, s in ips.items()])
            con.executemany("INSERT INTO daily_port VALUES (?, ?, ?, ?)",
                            [(day, p, port_svc.get(p, p), n) for p, n in ports.items()])
            con.executemany("INSERT INTO daily_cc VALUES (?, ?, ?, ?)",
                            [(day, cc, c.get("name"), c["n"]) for cc, c in countries.items()])
        log.info("seeded history with today's %d sources", len(ips))
        return True

    def prune(self):
        cut_ts = time.time() - self.keep_days * 86400
        cut_day = day_of(cut_ts)
        con = self._db
        with con:
            n = con.execute("DELETE FROM events WHERE ts < ?", (cut_ts,)).rowcount
            for table in ("daily", "daily_ip", "daily_port", "daily_cc", "daily_sig", "daily_aims", "names"):
                con.execute(f"DELETE FROM {table} WHERE day < ?", (cut_day,))
            con.execute("DELETE FROM policy WHERE minute < ?", (cut_ts,))
            con.execute("DELETE FROM ips WHERE last < ?", (cut_ts,))
        if n:
            log.info("pruned %d events older than %d days", n, self.keep_days)

    # --- the dashboard's question (worker thread) ---------------------------------------------------------

    def yesterday_by_now(self, now):
        """Threats yesterday up to the same time of day, for "vs yesterday" under the big number. None while the
        history doesn't reach back to yesterday's start: a day counted from midway would look like a quiet one."""
        t = time.localtime(now)
        start = time.mktime((t.tm_year, t.tm_mon, t.tm_mday - 1, 0, 0, 0, 0, 0, -1))
        until = time.mktime((t.tm_year, t.tm_mon, t.tm_mday - 1, t.tm_hour, t.tm_min, t.tm_sec, 0, 0, -1))
        con = self._db
        first = con.execute("SELECT MIN(ts) FROM events").fetchone()[0]
        if first is None or first > start:
            return None
        return con.execute("SELECT COUNT(*) FROM events WHERE ts >= ? AND ts <= ? AND gain & ? > 0",
                           (start, until, ATTEMPT)).fetchone()[0]

    # --- the History page's questions (worker thread) -----------------------------------------------------

    def summary(self, days):
        today = dt.date.today()
        start = (today - dt.timedelta(days=days - 1)).isoformat()
        con = self._db
        cols = ("block", "ids", "out", *DAILY_KNOCKS)
        rows = {r["day"]: dict(r) for r in con.execute(
            f"SELECT d.day, {', '.join(f'd.{c}' for c in cols)}, "
            "(SELECT COUNT(*) FROM daily_ip i WHERE i.day = d.day) AS sources FROM daily d WHERE d.day >= ?", (start,))}
        series = []
        for k in range(days):
            day = (today - dt.timedelta(days=days - 1 - k)).isoformat()
            series.append(rows.get(day) or {"day": day, **dict.fromkeys(cols, 0), "sources": 0})
        start_ts = day_bounds(start)[0]
        # each address over the period, once: the top ones, how many there were, how many came back, per country.
        # "+ip" keeps SQLite on the (day, ip) key, which reads only the period; grouping by the ip index reads it all
        con.execute("DROP TABLE IF EXISTS temp.per_ip")
        con.execute("CREATE TEMP TABLE per_ip AS SELECT ip, SUM(hits) AS hits, SUM(ids) AS ids, COUNT(*) AS days, "
                    "MAX(cc) AS cc FROM daily_ip WHERE day >= ? GROUP BY +ip", (start,))
        try:
            top_ips = [dict(r) for r in con.execute(
                "SELECT p.ip, p.hits, p.ids, p.days, p.cc, i.org, i.first, i.last "
                "FROM (SELECT * FROM per_ip ORDER BY hits DESC LIMIT 15) p LEFT JOIN ips i ON i.ip = p.ip "
                "ORDER BY p.hits DESC")]
            n_sources, returning = con.execute("SELECT COUNT(*), COALESCE(SUM(days >= 2), 0) FROM per_ip").fetchone()
            sources = {r[0]: r[1] for r in con.execute("SELECT cc, COUNT(*) FROM per_ip GROUP BY cc")}
        finally:
            con.execute("DROP TABLE temp.per_ip")
        for r in top_ips:
            r["what"] = self._what(r["ip"], r["org"], start_ts)
        countries = [dict(r, sources=sources.get(r["cc"], 0)) for r in con.execute(
            "SELECT cc, MAX(name) AS name, SUM(hits) AS hits FROM daily_cc WHERE day >= ? "
            "GROUP BY cc ORDER BY hits DESC LIMIT 10", (start,))]
        return {
            "days": days, "keep_days": self.keep_days,
            "oldest": con.execute("SELECT MIN(day) FROM daily").fetchone()[0],
            "series": series,
            "aims": aims_columns([r["day"] for r in series], [self.aims_on(r["day"]) for r in series]),
            "totals": {**{c: sum(r[c] for r in series) for c in cols}, "sources": n_sources, "returning": returning},
            "top_ips": top_ips,
            "top_ports": [dict(r) for r in con.execute(
                "SELECT port, MAX(svc) AS svc, SUM(hits) AS hits FROM daily_port WHERE day >= ? "
                "GROUP BY port ORDER BY hits DESC LIMIT 10", (start,))],
            "top_countries": countries,
            "top_sigs": [dict(r) for r in con.execute(
                "SELECT sid, MAX(sig) AS sig, SUM(hits) AS hits FROM daily_sig WHERE day >= ? "
                "GROUP BY sid ORDER BY hits DESC LIMIT 10", (start,))],
            "devices": [dict(r) for r in con.execute(
                "SELECT local, remote, dport, SUM(n) AS n, MAX(minute) AS last FROM policy WHERE minute >= ? "
                "GROUP BY local, remote, dport ORDER BY n DESC LIMIT 8", (start_ts,))],
        }

    def aims_on(self, day):
        """What a day's knocks were after (behaviour.aims, as the dashboard's Aims tab), from its events: each
        sender's knocks per service that day. Kept once the day is over and its late lines are in, in memory and in
        daily_aims, so a year's view after a restart doesn't work out 365 days again (reader thread)."""
        if day in self._aims:
            return self._aims[day]
        r = self._db.execute("SELECT aims FROM daily_aims WHERE day = ?", (day,)).fetchone()
        if r is not None:
            self._aims[day] = json.loads(r[0])
            return self._aims[day]
        start, end = day_bounds(day)
        senders = {}
        for remote, svc, n in self._db.execute("SELECT remote, svc, COUNT(*) FROM events WHERE ts >= ? AND ts < ? "
                                               "AND gain & ? > 0 GROUP BY remote, svc", (start, end, ATTEMPT)):
            s = senders.setdefault(remote, {"n": 0, "ports": {}})
            s["n"] += n
            s["ports"][svc] = n
        result = aims(senders.values())
        if time.time() > end + SETTLED:  # today's (or a day just over) is worked out again on the next visit
            self._aims[day] = result
            try:  # stored by the writer's thread, the one that writes
                self.pool.submit(self._keep_aims, day, json.dumps(result, separators=(",", ":")))
            except RuntimeError:  # shutting down: worked out again next time
                pass
        return result

    def _keep_aims(self, day, data):
        with self._db as con:
            con.execute("INSERT OR REPLACE INTO daily_aims VALUES (?, ?)", (day, data))

    def _what(self, ip, org, since=0):
        """What an address was doing (behaviour.py), from what it did since then (epoch seconds): {"key", "text"} or
        None. By ts, so the events_remote index (remote, ts) reads only that stretch of the address's events."""
        con = self._db
        ports = {r[0]: r[1] for r in con.execute(
            "SELECT svc, SUM(gain & ? > 0) FROM events WHERE remote = ? AND ts >= ? AND way = 'in' GROUP BY svc",
            (ATTEMPT, ip, since)) if r[1]}
        r = con.execute("SELECT kind, rule FROM events WHERE remote = ? AND ts >= ? AND gain & ? > 0 ORDER BY ts LIMIT 1",
                        (ip, since, LISTED)).fetchone()
        listed = r and (config.rule_of(r["rule"])[0] or "other" if r["kind"] == "block" else "IDS")
        name = con.execute("SELECT scanner FROM names WHERE ip = ?", (ip,)).fetchone()
        label = what(sum(ports.values()), ports, (name and name[0]) or scanner_of(org), listed)
        return label and {"key": label[0], "text": label[1]}

    def today_events(self, day):
        """Today's threats in the order they came, each with what it added to its knock: to rebuild the live counts
        (the event loop's connection; only at start)."""
        return self._rcon.execute(
            "SELECT ts, kind, action, way, proto, remote, local, sport, dport, svc, rule, sig, sid, cat, gain, app, "
            "target FROM events WHERE ts >= ? AND ts < ? ORDER BY ts, id", day_bounds(day)).fetchall()

    def unlogged_on(self, day):
        r = self._rcon.execute("SELECT unlogged FROM daily WHERE day = ?", (day,)).fetchone()
        return r[0] if r else 0

    def ip_detail(self, ip):
        con = self._db
        row = con.execute("SELECT * FROM ips WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return {"ip": ip, "found": False}
        geo = con.execute("SELECT city, cc, asn, org FROM events WHERE remote = ? ORDER BY ts DESC LIMIT 1",
                          (ip,)).fetchone()
        name = con.execute("SELECT host, scanner FROM names WHERE ip = ?", (ip,)).fetchone()
        org = geo["org"] if geo else row["org"]
        return {
            "ip": ip, "found": True, **dict(row), **(dict(geo) if geo else {}),
            "host": name["host"] if name else None,  # its name in reverse DNS, if it has one
            "scanner": (name and name["scanner"]) or scanner_of(org),  # the scanning company it belongs to, or None
            "what": self._what(ip, org),
            "daily": [dict(r) for r in con.execute(
                "SELECT day, hits, ids FROM daily_ip WHERE ip = ? ORDER BY day", (ip,))],
            "ports": [dict(r) for r in con.execute(
                "SELECT svc, dport, COUNT(*) AS n FROM events WHERE remote = ? GROUP BY svc, dport "
                "ORDER BY n DESC LIMIT 10", (ip,))],
            "sigs": [dict(r) for r in con.execute(
                "SELECT sig, COUNT(*) AS n FROM events WHERE remote = ? AND kind = 'ids' GROUP BY sig "
                "ORDER BY n DESC LIMIT 10", (ip,))],
            "events": [dict(r) for r in con.execute(
                "SELECT ts, kind, action, way, proto, dport, svc, sig, cat, gain, app, target FROM events "
                "WHERE remote = ? ORDER BY ts DESC LIMIT 60", (ip,))],
        }

    def close(self):
        def close_worker():
            con = getattr(self._local, "con", None)
            if con is not None:
                con.close()
        for pool in (self.rpool, self.pool):
            pool.submit(close_worker)
            pool.shutdown(wait=True)
        self._rcon.close()
