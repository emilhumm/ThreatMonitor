# ThreatMonitor

A live wall dashboard for OPNsense, in the style of GitHub's activity globe. OPNsense sends its firewall log
(and Suricata IDS alerts, if the IDS is on) over syslog. Each blocked or alerted internet address is geolocated
and drawn on a 3D globe you can drag and zoom, with a running threat stream on the right.

```
OPNsense ──syslog udp/tcp 5514──▶ threatmonitor (Python, aiohttp) ──WebSocket──▶ browser (globe.gl)
                                   └ DB-IP Lite GeoIP + ASN, today's counters in data/state.json
```

## What is on the screen

| Where | What |
|---|---|
| Centre | Globe ("beams on glass": a dark sphere with glowing coastlines, land a shade lighter than the sea; Natural Earth 1:50m, so small island countries are on it too). A beam of light per source location: height = hits today, cyan = mostly firewall blocks, pink = mostly IDS alerts, flashing white when hit, rising out of a pool of light on the ground (size = hits), so seen from above it stands somewhere; and the six busiest places are labelled. Everything lit glows softly into the dark (a glow pass after each frame). Each threat flies in as a comet and breaks on a see-through shield over home, which flashes in its colour, with a "BLOCKED · SSH" / "IDS" tag; your own network going out keeps a plain amber arc and never touches the shield. Once a minute (the cinematic tour: off, or every 30 s to 5 min, in the settings) the camera visits something that just happened (a port scan, an IDS alert, an address back from an earlier day, else a top attacker) with a TV-style caption, then pulls back to where it was and the globe turns on from there; touching the globe stops it for a minute, and so does the pause button. Drag to rotate, scroll to zoom, click a spike to fly to it. The globe spins on its own and resumes 8 s after you let go; ⏸ stops it, ⌂ goes back to home. On a wide screen the globe has the whole page: it sits in the middle (5% of the page lower, `GLOBE_DROP`) but reaches under the see-through cards (dimmed towards the edges, so their text stays readable), and a fly-in is never cut off. Behind it, with Fancy graphics, a sky in the globe's own 3D scene: the stars wheel past when the globe turns or the camera flies, the Milky Way lies where it really is right now, and the edge of the atmosphere is lit by the real sun (where it stands overhead, to ~0.01°). The sky warms towards pink and red when knocks come faster than normal (the last 5 minutes against today's average or the hour before, whichever is higher: calm up to normal, fully warm at three times normal), and an attack the IDS recognised sends a ripple out through the stars when it breaks on the shield (at most one every 20 s). Each of those four can be switched off under Fancy in the settings; the 3D starfield stays. Simple graphics is the flat starfield painted once behind the page. |
| Left (full height) | Threats detected today, each knock counted once (see "What counts as a threat"), from how many different addresses in how many countries, and how that compares with yesterday by the same time of day (▼ teal when quieter, ▲ pink when busier; shown once the history covers all of yesterday). Under it the breakdown, "of today's N threats": blocked by the firewall (teal), from a threat list (white: the sender is on one, by a firewall rule for a list, CrowdSec or Spamhaus DROP, or an IDS list rule), flagged by the IDS (pink), and the knocks from hostile senders, with how many senders that was ("from 292 hostile senders": one sweeper alone can make hundreds of knocks) (red: senders that behaved like attackers, by what they did all day, a port sweep, only the ports IoT botnets want, password guessing, or caught by the IDS, a scan, an exploit, a protocol abused rather than a sender that is merely on a threat list; a research scanner doesn't count; each knock once, `State._attacks`. Knocks, not intentions: a sweeper knocks once per port, and all of it was blocked at the first packet. On 5 Nov ~2,500 knocks came from ~290 hostile senders: 108 sweepers, 93 botnet devices, 87 the IDS caught; the hover gives that split. The IDS alone would have said ~100). Hovering over a number explains it, with today's breakdown: the blocked knocks by kind (connection attempts, UDP probes, pings), the IDS ones by why, the most common attacks. Red means that everywhere: the comet and the tag over home ("ATTACK · SSH"), the stream row, a tour stop. Your own network going out isn't on the card (it isn't a threat); it stays an amber arc, and the History page lists the devices. Then, at the foot of the column, the top 8 sources (the addresses with the most knocks) / most targeted ports / top countries / what they were after (fewer if a short screen has no room). *Aims*, what they were after: the firewall drops a knock at its first packet, so the port is the one clue to intent, and most knocks aim at nothing in particular (on 5 Nov: 75% mapping what's open, 18% aimed at a service, 7% the same unnamed port again and again). It is a ranked list like the other tabs: mapping what's open, each kind of service aimed at with its busiest one beside it (logins, web, IoT & routers, databases, VPN & VoIP, Windows & shares, DDoS amplifiers, mail, factory control), and an unnamed port a few senders keep hitting, with how many senders; the shares and details are in each row's hover (`behaviour.aims`). Mapping is every knock from a sender that tried 6 or more services (`sweep`), a knock on a port no known service uses, and pings. An attacker carries a tag for what it was doing: `scanner` (a company that scans the whole internet), `sweep` (6 or more services tried), `botnet` (only the ports IoT botnets go for: Telnet, ADB, TR-069…), `brute` (20 or more knocks on one login service); the hover text says more (`behaviour.py`). Cycles every 15 s; a click holds a tab for a minute. |
| Right | Threat stream, newest first. Repeated hits from one address within a minute fold into one row (×N), and a packet both the firewall and the IDS logged is one row with a two-coloured dot and the IDS rule under it. A row only shows once it fits whole: none is cut off at the foot. `IDSListed` (pink) is an alert because the sender is on a threat list, `IDSAlert` (red) one for what the traffic did. Hovering over it pauses it so you can read. Only threats: your own network's routine (a device blocked on its way out, an outbound IDS alert outside the threat families) counts as outbound and draws an amber arc, but stays out of the stream; an outbound alert from a threat family (a device calling malware's controller, scanning others, reaching a known-bad host) shows, in amber. |
| Bottom (under globe and stream) | Lined up with the columns above. Activity for the last hour, exactly under the globe (one bar per minute: firewall blocks in teal, IDS alerts in pink on top) · who's knocking, exactly under the stream, as two shares of the day's threats, each with a thin bar: how many came from companies that scan the whole internet for a living (Censys, ONYPHE, Shodan, NETSCOUT and the like; real, but not aimed at you; the biggest named), and how many from returning addresses, already seen on an earlier day (the ↻ ones). A scanner is known by its network's name (`SCANNERS` in `geo.py`) or, for the servers they rent in someone else's cloud, by the server's own name in reverse DNS (`SCANNER_HOSTS`), looked up once a day for each new address and only trusted when the name points back to the address. Scanners that don't name their servers count as unknown, so the share is still a floor. The hover text has the numbers behind them. |
| Settings (the gear by the globe's buttons) | One small popup: Fancy, Simple or Simplest graphics (Simplest to start with, until another is picked in that browser; Simplest is Simple drawn lighter, for a tablet or a phone, see "On a tablet or a weak screen"; under Fancy, a switch each for the Milky Way, the sun, the warming and the ripple, all on to start with), place names on or off, how fast the globe turns by itself (slow, normal or fast), the cinematic tour on or off and how often (30 s, 1 min, 2 min or 5 min; 1 min to start with), and a tick for each of the six cards. Remembered in that browser, so the wall and a laptop can differ; all cards show until you untick one. Activity widens into the bottom-left corner a hidden Top Sources leaves. With Activity or Who's Knocking hidden, the threat stream runs down to the foot of the page and the other one takes the rest of the bottom row (with the stream hidden as well, Activity takes the whole row). With every card on one side hidden, the dimming along that edge goes too. |
| By the globe | Bottom right, its buttons: History (opens the History page), the settings, back to the home view, and pause the turning. Top right, a status pill, only when something needs attention: `WAITING FOR SYSLOG`, `DISCONNECTED`, `DEMO DATA` or a refused sender. |

On a narrow screen (a phone; up to 1100 px wide) it is one column: Threats Detected and Blocks · Alerts first, then the globe, which takes the rest of the screen under them (at least 260 px; the screen's height is measured, as `100svh` came out too tall in an iPhone Home Screen web app) from edge to edge and starts far enough out to show whole with room round it, then the stream, Top Sources and the bottom row. A hidden card leaves no gap, and the globe grows into the space.

`?inset=<px>` (0-400) starts the cards that much further in from the left, for a page shown with something laid over its left edge, such as a Home Assistant dashboard that shows the wall full screen with a navigation rail floating over it. To keep the cards 8 px clear of the rail, use the rail's width plus 8, less the wall's own 14 px padding (`?inset=42` for a 48 px rail). The starfield and the globe still fill the whole screen, the globe keeps to the middle of its (narrower) column and starts 15% further out (that column is narrower by the inset; the ⌂ button and the tour come back to the same view), and the dark fade behind the left column moves in with it. Without it the page is as before.

"Outbound" means a device on your LAN tried to reach an internet address that a block rule or the IDS caught.
Those arcs go from home outward, in amber.

## Run it

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Windows; bin/ on Linux
.venv/Scripts/python -m threatmonitor --demo     # synthetic OPNsense traffic, nothing else needed
.venv/Scripts/python -m threatmonitor            # real: listen for syslog on 5514
```

Open http://localhost:5116/. On the first start it downloads the DB-IP Lite databases (≈70 MB) into `data/`, and
refreshes them monthly. Demo mode keeps its counts in `data/state-demo.json`, apart from the real ones.

Settings are environment variables (`.env.example`): `TM_SYSLOG_ALLOW` (only accept syslog from these
addresses), `TM_HOME_LAT`/`TM_HOME_LON` (where arcs land; default: the WAN address from the firewall log,
geolocated, saved in `data/home.json`), `TM_HTTP_PORT`, `TM_SYSLOG_PORT`, `TM_BIND`, `TM_RULES` (the firewall's
rules by the id it logs, `<rid>=<name>[:list],...`: a name for the dashboard, and `:list` for a rule that blocks a
threat list; find a rule's id in **Firewall › Log Files › Live View**, a line's ⓘ, `rid`. Unset, only OPNsense's
built-in default deny rule has a name), `TM_DASHBOARD_URL` (the link in a push). In Docker also `TZ` (the day's
counts start again at its midnight; default UTC) and `TM_DNS` (a resolver for the container to ask first).

Diagnostics: `/api/debug` shows which senders were heard, line counts per program, the reverse DNS lookups
(`names`: done with and without a name, and still waiting), and samples of lines that were not understood. `/api/stats` is today's numbers as JSON.
It also shows the `version` deployed (written by `deploy.sh`) and `errors`: where something failed, and how often
(a line that trips an error is skipped and counted; a background job that keeps failing logs its traceback once,
then a line every 10 minutes). `/healthz`, Docker's health check, answers 503 when the server's main loop (events,
stats, history writes) hasn't got round for 30 s, or 30 history writes in a row failed, so the container shows as
unhealthy. A write that fails for a passing reason (the disk full, the database locked) is kept and tried again with
the next, up to 50,000 events; `errors` then shows `history write` (and `history lost` if any had to go).

A dashboard that stops taking messages for 5 s (a laptop asleep with the page open) is cut off, so it can't hold up
the others; the dashboard in turn reconnects when it has heard nothing for 10 s. At midnight the counts start again,
but the activity chart and the stream keep their last hour and last events.

The dashboard looks after itself on a wall nobody watches:
- **After a deploy** it reloads by itself: `hello` carries a hash of the web files (`build`), and a reconnect that
  brings a different one loads the new page. The files are served with `Cache-Control: no-cache` (the browser asks,
  and gets a 304 if nothing changed), so the URLs carry no version tokens.
- **When the graphics driver is reset** and WebGL doesn't come back within 15 s (the white globe with a sad face),
  it reloads in Simple graphics, at most 3 times an hour.
- **A panel that fails** to update leaves the others updating.
- **The globe's places** come in full with `hello` (and again at midnight); after that, every 5 s, only the ones
  that changed (a few KB instead of ~190 KB per screen). A place hit in the last minute is never dropped to make room.

## Keep it on your network

The dashboard, its API and the syslog port have no login, and `/api/debug` shows your WAN address. Run it on your
LAN only: don't forward 5116 or 5514 from the internet. To see it from outside, reach it over a VPN or put it
behind a reverse proxy that asks for a login. Set `TM_SYSLOG_ALLOW` to your firewall's address, so nothing else on
the network can feed it lines.

## Point OPNsense at it

1. **System › Settings › Logging › Remote**, add a destination:
   - Transport `TCP(4)`, Hostname: the address of the machine ThreatMonitor runs on, Port `5514`. `UDP(4)` works too, but what it
     sends while the dashboard restarts is lost; over TCP, OPNsense holds those lines and sends them when it
     reconnects (within about a minute)
   - Applications: the firewall log (`filter`/`filterlog`) and, if you use the IDS, `suricata`. Leaving it empty
     sends everything; other programs are counted and ignored.
   - Levels and Facilities: leave empty. RFC5424 on or off: both work.
2. Inbound blocks from the internet are logged by the default deny rule out of the box. Your own block rules
   only show up if "Log packets that are handled by this rule" is ticked on them.
3. Optional IDS: **Services › Intrusion Detection › Administration**, enable it on WAN, and enable
   "eve syslog output" (better than "syslog alerts", whose one-line format is deprecated in Suricata 8; not both:
   each alert would come twice). eve also says which application protocol it was and which site (HTTP host, TLS
   name), shown in the History page's address lookup. Then download/enable rule sets (ET open, Abuse.ch…).
4. **With the IDS on WAN, add the WAN address to Home networks** (Settings, advanced mode), as
   `<WAN address>/32` next to the private ranges. On WAN, Suricata sees traffic after NAT, so everything is
   addressed to the public IP. The ET rules are written as `… -> $HOME_NET`, so without this they never match:
   on 2026-11-02 Suricata had inspected 81,498 WAN packets and raised zero alerts, and within seconds of the
   change it was alerting. Update the entry if the PPPoE address changes (`/api/debug` → `home_ips`).

The status pill turns green (`LIVE`) within seconds of the first line arriving.

## What counts as a threat

**Each knock once.** A packet the firewall blocks and the IDS flags is logged by both (sometimes by two IDS rules),
so counting log lines counted it two or three times: on 4 Nov, 68% of IDS alerts were the IDS's look at a packet
the firewall had blocked. The server pairs them (`knocks.py`): a firewall block and the IDS alerts for the same
source and port within 3 seconds are one knock. Every number on the dashboard and the History page counts knocks;
the events themselves are all kept, each marked with what it added to its knock (`events.gain`). The first start
after this change marks the stored history the same way and rebuilds the day's counts from it (once).

**Why the IDS flagged it.** About 95% of IDS alerts fire on who is sending, not what: the source is on a threat list
(ET CINS, ET DROP/DShield, Spamhaus DROP). Those count as *listed*; ET INFO/POLICY rules are notices; the rest
(ET SCAN, ET EXPLOIT, GPL…) count as *attacks* the IDS recognised.

**On a threat list.** A knock is *listed* when its sender is on a threat list, whoever says so: an IDS list rule, or
a block by a firewall rule for a list (`TM_RULES`, `:list`: here CrowdSec's blocklist and the Spamhaus DROP alias).
It counts once however many lists name it, for whichever named it first; Blocks · Alerts has it as its own row, with
the split in its hover text, and the blocked row's hover splits the blocks by rule. Until 5 Nov only the IDS's
lists counted: that day, 3,612 of 7,439 knocks were listed by the IDS, and the firewall's lists added 1,037 more
(63% in all). The first start after this change marked the stored blocks the same way (database version 3).

**Not in the firewall log.** An inbound knock the IDS flagged with no firewall line for it within the 3 seconds:
no block, no "late" block (a packet that opens nothing, set aside as `filterlog_late`) and no pass (the firewall
letting it in). Until 4 Nov 17:10 that was about a quarter of the IDS's inbound knocks: CrowdSec (os-crowdsec) drops
the addresses on its blocklist (the `crowdsec_blocklists` alias) with rules of its own that didn't log. With
**Services › CrowdSec › Settings › Enable log for rules** ticked, its drops are ordinary firewall blocks (rule label
`855c2284…`) and this count stays near zero; anything that shows up there now is worth a look. `/api/debug` counts
the IDS knocks that did meet a late block or a pass (`late_flagged`, `pass_flagged`, with examples) and shows the
last IDS lines as they came (`ids_lines`).

**Answers to our own traffic.** Until 5 Nov, video calls showed up as attacks: a call's STUN replies (from the
call service's relays at port 3478, rule *ET INFO STUN Binding Response*) were 1,573 of that day's 8,855 threats,
the four biggest "attackers", and nearly all of the knocks not in the firewall log (the firewall rightly lets a
call's answers through). The IDS's eve output says who opened each connection
(`flow.src_ip`): an alert on a packet answering a connection our side opened now reads as the traffic it answers,
outbound (`parse.answers_us`), and is judged as outbound alerts are (below): a threat family there stays a threat,
in amber, as one of our devices reaching a bad host. `/api/debug` counts them as `ids_replies`. The first
start after this change moved the stored ones (inbound informational alerts from a port that answers) out of the
threats in the history (database version 2) and rebuilt the day's counts.

- **Counted:** an inbound packet that tries to open something (a TCP SYN, a UDP packet to a service port, a
  ping), blocked by the firewall; any inbound Suricata alert; an outbound one only from the families that say
  something is wrong with a device of ours (`parse.OUTBOUND_THREAT_RULES`): malware and its controllers (ET MALWARE,
  CNC, COINMINER, abuse.ch's sets ...), a device scanning or attacking others (ET SCAN, EXPLOIT, DOS, WEB_SERVER
  ...), exploits or phishing served to it (WEB_CLIENT, PHISHING, CURRENT_EVENTS), ET HUNTING, and a host on a
  threat list (not Tor relays).
- **Not counted, only shown in the stream (amber):** your own device going out and hitting a block rule, e.g. a
  phone trying DNS-over-TLS to 1.1.1.1 past a local DNS filter. The internet side there isn't an attacker.
- **Not counted, our own network:** every other outbound IDS alert: ET INFO and POLICY notices, file sharing (ET
  P2P), games, chat, Tor. Until 6 Nov it was the other way round, the harmless families were listed and all other
  outbound alerts counted, so each new kind counted as attacks until it was found: on 5 Nov a file-sharing client ran
  for two minutes and its 34 alerts made its peers attackers. A family missing from the threat list now
  shows as our own network (an amber arc, and on the History page under your devices), not as an attack. The first
  start with this (database version 5) moved the stored ones out of the threats and rebuilt the counts from that
  day on. The same goes for an outbound alert on a device's TLS fingerprint (the JA3 / JA3S rules,
  `parse.FINGERPRINT_RULES`), whatever its family. A fingerprint names the encryption library a program uses, which many unrelated
  programs share, not what it does or whom it talks to: on 5 Nov a smart TV's streaming app matched abuse.ch's
  "Possible Adware" 54 times, and the streaming service's servers at Akamai counted as attackers. The History page lists them under your
  devices. An inbound sender with such a fingerprint stays a threat. The first start with this (database version 4,
  the first migration done with `rebuild_rollups`) moved the 56 stored ones out of the threats and rebuilt the
  day's counts.
- **Ignored, counted in `/api/debug` as `filterlog_late`:** the tail of your own traffic that pf blocks once its
  state is gone: mid-connection TCP (ACK/FIN/RST), late UDP replies from service ports (QUIC from a CDN, DNS),
  and ICMP replies and errors where the router logs the ICMP type (pfSense does; OPNsense writes only `datalength=N`,
  so there every blocked ICMP packet counts as a ping). Every filter reload or IDS restart produces a burst of these.
- Home addresses are learned only from inbound firewall blocks (kept in `data/home_ips.json`). An IDS alert can
  run from the WAN address to an outside server, such as an external-IP lookup, so it can't be used to learn them.

## On a tablet or a weak screen

Country borders, beams and their pools of light are each drawn as one merged object: a built-in graphics chip struggles with the number of separate objects per frame far more than with pixels. That took an Intel HD 530 laptop from 14-20 to ~60 frames a second, glow included.

The glow and the Fancy sky each cost the graphics chip a little on every frame. The sky's Milky Way is painted once, a strip a frame, when Fancy first comes on; after that it is one picture lookup per pixel, ~16,500 small star squares and two thin shells around the globe. (Painted in one go it kept an Intel HD 530 busy for up to half a second, and Windows resets the graphics driver when one job runs past 2 s; Chrome then shows a white page with a sad face in the corner.) If the graphics driver is reset while Fancy is on, that browser tab stays on Simple, reloads included, until Fancy is picked again. If the page runs below about 24 frames a second for 10 seconds, it drops to Simple graphics for that visit (the settings popup and the browser console say so; the saved choice stays Fancy), and if it is still that slow, it switches the glow off too. `?lite` starts with Simple graphics and no glow (Fancy and Simplest can't be picked), and `?glow` keeps both on regardless.

globe.gl's own pointer checks are off: once the globe had been touched (or a mouse had been over it) they tested everything drawn against the pointer 20 times a second, over 130,000 triangles and 82,000 line segments, about 7 ms each time, which on a recent iPhone made the spin stutter every third frame until the page was reloaded. Hovering over a place and tapping it (to fly there) are worked out by the page itself, with one ray from the camera to the sphere.

Simplest, the third choice in the settings, is Simple drawn lighter, for a tablet or a phone: the globe at no more than 1.5 device pixels per CSS pixel (on a 2x screen 44% fewer pixels a frame), without edge smoothing, each frame's picture before the glow in 8-bit sRGB instead of half floats (half the memory to write and read back; the same to the eye), and the cards' letters with a crisp outline instead of the blurred haze, which had to be blurred again whenever a card changed. Text, numbers and place names stay as sharp as ever; the globe's lines are a little softer. On a mid-range Android wall tablet (measured 2026-11-07) Simple ran at 35 frames a second with a stutter about once a second, Simplest at 57-60 and smooth. Edge smoothing is set when the page starts, so picking Simplest, or leaving it, reloads the page. With Simplest the slow-page check above first steps down to 1 pixel per CSS pixel, then switches the glow off, and it keeps watching for the whole visit. A browser starts on Simplest; picking Fancy or Simple in the settings is remembered in that browser from then on.

## History

Every threat (firewall block or IDS alert) is stored in `data/history.db` (SQLite, WAL), with its time, address,
port, service, rule, country, city and network. It's kept for `TM_KEEP_DAYS` days (default 365) and pruned every 6 hours.
Daily roll-ups (per day, per address, port, country and IDS rule) keep the range views fast. Your own devices
hitting outbound block rules are counted per minute (`policy` table), not stored one by one. The database grows
by about 5–6 MB a day (a full day is some 20,000 events), so a year is roughly 2–2.5 GB. The History page's
questions run on their own thread and connection, so even a year-long view never holds up the live dashboard's
writes; its queries read only the period asked for (a test checks their query plans).

- **`/history`** (the clock button on the dashboard): 7 days / 30 days / 90 days / 1 year. It has totals (in knocks,
  with the share from a threat list and the attacks the IDS recognised), a daily chart (the knocks the IDS flagged on
  top), what they were after per day (the Aims tab day by day, `History.aims_on`: a row each for the threat-list
  share, mapping what's open, each kind of service and the same unnamed port, with a small line per day on its own
  scale and yesterday against the whole days before it; a day only partly recorded, today and the first, is a hollow
  dot left out of the comparison; a day is worked out once it is over and its late lines are in, 11 minutes past
  midnight, and kept in the `daily_aims` table, so a year's view after a restart doesn't work out 365 days again;
  the page gets them as columns, a value per day, `history.aims_columns`), top sources
  (with what each was doing and the number of days each was seen), ports, countries, IDS rules, your devices hitting
  block rules, and an address lookup (`/history#<address>`) showing everything one address did, with its name in
  reverse DNS and the scanning company it belongs to, if any (the names table keeps the confirmed names).
- **On the live page**, an address that was also seen on earlier days gets a ↻ tag (`↻ 5d`) in the stream and in
  Top Sources.
- `GET /api/history?days=N` and `GET /api/ip/<address>` return the same data as JSON (gzip-compressed when the
  client accepts it). The page refreshes while it is in view only: every minute for 7 and 30 days, every 5 minutes
  for 90 days and a year.
- A future change to how events are counted: correct the events, then `History.rebuild_rollups(con, since)` works
  the per-day roll-ups out again in SQL (a test checks it gives what the writes gave). The migrations so far read
  rows into memory, which a year of events (millions) would not survive.
- On its first start, an empty database is seeded with that day's counts from `state.json`. Those are counts
  only, so the address lookup has no individual events from before history started.
- Backed up every night to the router's share (see [Backup](#backup)). The file is in `/srv/threatmonitor/data/` on
  the box.
- Syslog over UDP that arrives while the container restarts is lost (seen: up to about half a minute after a
  `deploy.sh`). Over TCP (on the box since 2026-11-04), OPNsense holds those lines and sends them once it has
  reconnected, about a minute after a restart. In a test restart, the lines logged during the downtime and the
  reconnect all came in afterwards, with their real times.
- A line that arrives more than 5 s after it was logged (held back, or waiting while the server starts) keeps the
  time in its own header, up to 10 minutes back; beyond that the clocks disagree and it keeps its arrival time.
  The firewall's "late" and "pass" lines do the same, so after a restart they still pair with the IDS alert for
  the same packet. `/api/debug` counts these as `delayed` (and lines with no readable time as `no_time`).

## Health warnings

Two ways the IDS can go blind without anyone noticing get a red banner on the dashboard (and `warnings` in
`/api/debug`), and optionally a push:

- **WAN address changed.** A PPPoE reconnect can hand out a new address, and Suricata's Home networks still hold
  the old one. The change is detected from the address inbound blocks are aimed at, after 5 hits in a row; that
  address is kept in `data/health.json`. The banner names the new address. It clears by itself at the first IDS
  alert aimed at the new address, which proves Home networks were updated.
- **IDS quiet.** No IDS alert for `TM_IDS_SILENT_MIN` minutes (default 60) while the firewall blocked at least 50
  probes. It only applies once the IDS has alerted at least once.

Push: set `TM_NOTIFY_URL` in `.env` to a Home Assistant webhook (`http://<ha>:8123/api/webhook/<id>`, which gets
JSON `{title, message, severity, url}`) or an ntfy topic URL. It sends one message
when a warning appears and one when it clears. In Home Assistant, an automation triggered by that webhook can
send the message to your phone. Set `TM_DASHBOARD_URL` to the dashboard's address as your phone reaches it, for the
link in the push. Test it with:

```bash
ssh <user>@<host> 'docker exec threatmonitor python3 -c "import asyncio; from threatmonitor.health import notify; asyncio.run(notify(\"ThreatMonitor: test\", \"If you can read this, warnings reach your phone.\", \"info\"))"'
```

## On a Docker host

A Linux box with Docker and the compose plugin: code bind-mounted from `/srv/threatmonitor/code` (read-only), data
in `/srv/threatmonitor/data`, settings in `/srv/threatmonitor/.env` (from `.env.example`), ports 5116/tcp
(dashboard) and 5514/udp+tcp (syslog). The container runs as uid 1000:1000, not root, since it reads text written by
attackers; its data folder must be owned by 1000:1000 (`sudo chown -R 1000:1000 /srv/threatmonitor/data`). Docker
keeps at most 3 × 10 MB of its log. The Python packages are pinned in `requirements.txt` to what the image has.

`deploy.sh` runs on your own machine (bash; Git Bash on Windows) and copies the code over ssh. Tell it where, once,
in `.deploy.env` (not in git), or set `REMOTE_HOST` in the environment:

```bash
echo 'REMOTE_HOST=<user>@<host>' > .deploy.env
bash deploy.sh --no-restart                                   # first time
ssh -t <user>@<host> 'cd ~/projects/threatmonitor && sudo bash install/install.sh && sudo bash install/install.sh enable'
bash deploy.sh                                                # later code changes
bash deploy.sh --build                                        # after Dockerfile / requirements.txt changes
bash deploy.sh --no-test                                      # the same without running the tests first
```

`deploy.sh` runs the tests first and deploys nothing if one fails. It writes the commit it deploys (`git describe
--always --dirty`, so `-dirty` when there are uncommitted changes) and the time into `VERSION` next to the code. It
starts the new code exactly once: compose recreates the container by itself when the image or the compose file
changed, otherwise the container is restarted. Then it waits up to 90 s for `/healthz` to answer OK (a start can first
upgrade the database). If it doesn't, it prints the container's last 40 log lines and exits with an error.

### Backup

`sudo bash install/install.sh backup` (on the box) mounts an SMB share, for example a folder on the router's USB
disk (`//SMB_HOST/SMB_SHARE` from `.env`, with `SMB_USER` and `SMB_PASSWORD`; at `/mnt/threatmonitor-backup`), installs
`threatmonitor-backup.timer` (04:00 every night) and makes one backup straight away. Each run:

- takes one consistent snapshot of `history.db` with SQLite's `VACUUM INTO`, checks it with `quick_check`, and packs
  it into one `.tar.gz` with `state.json`, `health.json`, `home.json` and `home_ips.json`. (Not `.backup`: an online
  backup starts over whenever another connection writes, and the monitor writes every second, so on a large database
  it never finishes.)
- works in `/var/tmp`, on disk. `/tmp` on the box is in memory, and a year's copy is a few GB.
- removes old copies before writing the new one, keeping the newest 7 nightly copies and the copies made on the 1st
  of the month for about 6 months. It then checks the share has room for the new copy (plus 10 % and 64 MB) and
  stops with an error if not. The copy is written as `.part` and renamed when complete, so a half-written file is
  never taken for a backup.
- runs as uid 1000 (the container's user, which owns the data and the share), at low CPU and disk priority, and is
  stopped after an hour.

Logs: `sudo journalctl -u threatmonitor-backup`. The script and the units are installed copies
(`/usr/local/bin/threatmonitor-backup-db.sh`, `/etc/systemd/system/threatmonitor-backup.*`), so after changing
`backup/`, deploy and then re-run `sudo bash /srv/threatmonitor/code/install/install.sh backup` on the box.

To see that a backup can be restored, without touching the live data (no sudo):

```bash
bash /srv/threatmonitor/code/install/install.sh check-backup              # the newest copy on the share
bash /srv/threatmonitor/code/install/install.sh check-backup <archive>    # a path, or just its name on the share
```

It unpacks the archive's `history.db` into `/var/tmp`, runs SQLite's `quick_check` and shows what the copy holds: the
days (first and last), the number of events, the newest event's time and the schema version (`user_version`). It
fails if the check isn't ok, and removes what it unpacked.

To restore one: `sudo bash /srv/threatmonitor/code/install/install.sh restore <archive>`. It checks the archive the
same way first and changes nothing if that fails. Then it stops the container and moves the current `history.db`,
`history.db-wal` and `history.db-shm` aside together as `history.db.pre-restore.<date-time>` (`-wal`, `-shm`):
kept, never deleted, and none of them left next to the restored file, where SQLite would replay the old write log
into it. It puts the checked `history.db` in place (owned 1000:1000, the container's user), starts the container and
waits up to 90 s for `/healthz`. `state.json` (today's live counts) is left as it is. The output says how to undo:
stop the container, move the restored set away and the `pre-restore` set back under the old names, start it.

## The code

- `threatmonitor/`, the server (Python, aiohttp): lines come in through `syslog.py` and are read by `parse.py`;
  `knocks.py` pairs a block with its IDS alerts; `state.py` keeps today and `history.py` the history (SQLite);
  `behaviour.py` says what a sender was doing; `geo.py` places and names addresses; `health.py` watches for an IDS
  gone blind; `server.py` has the HTTP and WebSocket side and the background loops.
- `web/`, no build step: the browser loads the ES modules as they are (served no-cache, see above). `index.html`
  starts `js/main.js` (background stars, start-up, the data coming in, the WebSocket), which uses `js/globe.js`
  (globe, places, beams and pools, arcs, glow, shield), `js/sky.js` (Fancy graphics, a lost GPU), `js/shaders.js`,
  `js/tour.js`, `js/panels.js` (cards, stream, status, clock), `js/prefs.js` (settings) and `js/shared.js` (the
  state and helpers they share). `history.html` starts `history.js`. `common.js` holds what both pages use.
  `vendor/`: globe.gl, topojson-client, the country shapes, and the fonts (Mona Sans and JetBrains Mono, as Google
  Fonts serves them, kept here so a page never waits for Google).
- Both pages are served with a Content-Security-Policy: scripts, fonts and connections only from the server itself.

## Tests

```bash
.venv/Scripts/python -m pytest -q
```

The container runs Python 3.13, the laptop 3.14, so `deploy.sh` runs the tests on both. The 3.13 environment
(`.venv313`, not in git) was made with the Python install manager:

```bash
py install 3.13
py -V:3.13 -m venv .venv313
.venv313/Scripts/python -m pip install -r requirements.txt pytest
```

## Credits

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0; both pages link to it). Globe by [globe.gl](https://globe.gl), country shapes
from [world-atlas](https://github.com/topojson/world-atlas) (Natural Earth); both vendored in `web/vendor/`. Fonts
[Mona Sans](https://github.com/github/mona-sans) and [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono),
both under the SIL Open Font License 1.1, in `web/vendor/fonts/`. The copyright notices and licenses of these, and
of the libraries bundled inside globe.gl, are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

MIT, see [LICENSE](LICENSE). The vendored files in `web/vendor/` keep their own licenses, listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
