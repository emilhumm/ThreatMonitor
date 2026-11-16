"""Settings, all from environment variables (TM_*). Defaults suit running on the laptop."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
DATA_DIR = Path(os.environ.get("TM_DATA_DIR", ROOT / "data"))

BIND = os.environ.get("TM_BIND", "0.0.0.0")  # 127.0.0.1 keeps both listeners off the network (demo on the laptop)
HTTP_PORT = int(os.environ.get("TM_HTTP_PORT", "5116"))
SYSLOG_PORT = int(os.environ.get("TM_SYSLOG_PORT", "5514"))  # UDP and TCP

# Comma-separated sender IPs allowed to send syslog (your OPNsense's LAN address, e.g. "192.168.1.1"). Empty = accept
# any sender.
SYSLOG_ALLOW = {s.strip() for s in os.environ.get("TM_SYSLOG_ALLOW", "").split(",") if s.strip()}


def _float(name):
    v = os.environ.get(name, "").strip()
    return float(v) if v else None


# Where the arcs land. Unset = geolocate the WAN address seen in inbound blocks (0, 0 until the first one).
HOME_LAT = _float("TM_HOME_LAT")
HOME_LON = _float("TM_HOME_LON")
HOME_LABEL = os.environ.get("TM_HOME_LABEL", "Home")
DEFAULT_HOME = (0.0, 0.0)

DEMO = os.environ.get("TM_DEMO", "").lower() in ("1", "true", "yes")


def _rules(spec):
    out = {}
    for item in spec.split(","):
        rid, _, name = item.strip().partition("=")
        name, _, flag = name.partition(":")
        if rid and name.strip():
            out[rid] = (name.strip(), flag.strip() == "list")
    return out


# Firewall rules by the id OPNsense logs for them (Firewall › Log Files › Live View, a line's ⓘ: "rid"): the name to
# show, and ":list" for a rule that blocks a threat list, whose knocks then count as "on a threat list" like an IDS
# list rule's. TM_RULES="<rid>=<name>[:list],...". The default names OPNsense's built-in default deny rule only; an
# unnamed rule shows as "other".
RULES = _rules(os.environ.get("TM_RULES", "").strip() or "02f4bab031b57d1e30553ce08e0ec131=Default deny")


def rule_of(rid):
    """(name or None, blocks a threat list) for a firewall rule id."""
    return RULES.get(rid, (None, False))

KEEP_DAYS = int(os.environ.get("TM_KEEP_DAYS", "365"))  # history in data/history.db; older events are deleted

# Push for health warnings (WAN address changed, IDS gone quiet). A Home Assistant webhook URL
# (http://<ha>:8123/api/webhook/<id>, gets JSON {title, message}) or an ntfy topic URL (https://ntfy.sh/<topic>).
NOTIFY_URL = os.environ.get("TM_NOTIFY_URL", "").strip()
DASHBOARD_URL = os.environ.get("TM_DASHBOARD_URL", "").strip() or f"http://localhost:{HTTP_PORT}/"  # the link in a push
IDS_SILENT_MIN = int(os.environ.get("TM_IDS_SILENT_MIN", "60"))  # warn after this long without an IDS alert...
IDS_SILENT_BLOCKS = 50                                            # ...while the firewall blocked at least this many
