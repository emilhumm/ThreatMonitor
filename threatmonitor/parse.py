"""Turn OPNsense syslog lines into threat events.

Two programs matter:
  filterlog  the pf firewall log, one CSV line per logged packet (only block/reject lines are kept)
  suricata   IDS/IPS alerts, either the classic one-line alert or eve JSON ("Enable eve syslog output")

Both RFC 3164 (OPNsense's default for remote logging) and RFC 5424 headers are accepted.
"""
import ipaddress
import json
import re
import time
from datetime import datetime

_HDR_5424 = re.compile(
    r"^(?:\d+ )?<\d{1,3}>1 (?P<iso>\S+) \S+ (?P<prog>\S+) \S+ \S+ (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$",
    re.S)
_HDR_3164 = re.compile(
    r"^(?:\d+ )?<\d{1,3}>(?:(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)|(?P<iso>\S+T\S+)) (?:(?P<host>\S+) )?"
    r"(?P<prog>[\w./-]+)(?:\[\d+\])?: ?(?P<msg>.*)$", re.S)

_SURICATA = re.compile(
    r"(?P<drop>\[w?Drop\] )?(?:\[\*\*\] )?\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<sig>.*?)(?: \[\*\*\])?"
    r"(?: \[Classification: (?P<cls>[^\]]*)\])? \[Priority: (?P<prio>\d+)\]"
    r" \{(?P<proto>[^}]+)\} (?P<src>\S+) -> (?P<dst>\S+)\s*$")

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP", 81: "HTTP",
    88: "Kerberos", 102: "S7comm", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    502: "Modbus", 500: "IKE", 554: "RTSP", 587: "SMTP", 623: "IPMI", 631: "IPP", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 1900: "SSDP", 2000: "Cisco", 2049: "NFS", 2222: "SSH-alt", 2323: "Telnet-alt", 2375: "Docker",
    2376: "Docker", 3128: "Proxy", 3306: "MySQL", 3389: "RDP", 3478: "STUN", 4443: "HTTPS-alt", 4500: "IPsec",
    4567: "HTTP-alt", 5000: "UPnP", 5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5353: "mDNS", 5432: "Postgres",
    5555: "ADB", 5672: "AMQP", 5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis",
    6443: "Kubernetes", 6667: "IRC", 7547: "TR-069", 8000: "HTTP-alt", 8008: "HTTP-alt", 8080: "HTTP-proxy",
    8081: "HTTP-alt", 8088: "HTTP-alt", 8291: "Winbox", 8443: "HTTPS-alt", 8545: "Ethereum", 8728: "MikroTik",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt", 9100: "Printer", 9200: "Elastic", 10000: "Webmin",
    11211: "Memcached", 20000: "DNP3", 27017: "MongoDB", 34567: "DVR", 34568: "DVR", 37215: "Huawei", 37777: "DVR",
    44818: "EtherNet/IP", 47808: "BACnet",
    49152: "UPnP", 51820: "WireGuard", 52869: "UPnP", 60001: "HTTP-alt",
}


def service(proto, port):
    if proto in ("icmp", "ipv6-icmp", "icmpv6"):
        return "ICMP"
    if port is None:
        return proto.upper() if proto else "?"
    return PORT_NAMES.get(port, f"{proto}/{port}" if proto else str(port))


def is_global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _header(line):
    line = line.lstrip("\ufeff").rstrip("\r\n\x00")
    return _HDR_5424.match(line) or _HDR_3164.match(line)


def split_header(line):
    """Return (program, message) for a syslog line, or (None, None) if the header is not recognised."""
    m = _header(line)
    if m is None:
        return None, None
    return m.group("prog"), m.group("msg").lstrip("\ufeff")


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _logged(m, now):
    """When the sender logged the line (epoch seconds), from its header; None if it has no time we can read.

    An RFC 3164 time has no year or zone: it is read as local time, in the year that doesn't put it in the future
    (a line logged on 31 December and read on 1 January is from last year).
    """
    try:
        if m.groupdict().get("bsd"):
            mon, day, hms = m.group("bsd").split()
            h, mi, s = (int(x) for x in hms.split(":"))
            year = time.localtime(now).tm_year

            def at(y):
                return time.mktime((y, _MONTHS.index(mon) + 1, int(day), h, mi, s, 0, 0, -1))
            t = at(year)
            return at(year - 1) if t - now > 86400 else t
        iso = m.group("iso")
        return datetime.fromisoformat(iso).timestamp() if iso and iso != "-" else None
    except (ValueError, OverflowError):
        return None


def parse_filterlog(msg, actions=("block", "reject")):
    """One pf log CSV line -> event dict, or None if it is not a block/reject or not parseable.

    Field layout (OPNsense scripts/filter/read_log.py): rulenr,subrulenr,anchor,label,interface,reason,action,dir,
    ipversion, then for IPv4 tos,ecn,ttl,id,offset,flags,protonum,protoname,length,src,dst and for IPv6
    class,flowlabel,hoplimit,protoname,protonum,length,src,dst, then for tcp/udp srcport,dstport,datalen,...
    """
    f = msg.split(",")
    if len(f) < 9:
        return None
    action = f[6]
    if action not in actions:
        return None
    ipver = f[8]
    if ipver == "4" and len(f) >= 20:
        proto, src, dst, rest = f[16].lower(), f[18], f[19], f[20:]
    elif ipver == "6" and len(f) >= 17:
        proto, src, dst, rest = f[12].lower(), f[15], f[16], f[17:]
    else:
        return None
    sport = dport = None
    flags = icmp = None
    if proto in ("tcp", "udp") and len(rest) >= 2:
        sport, dport = _int(rest[0]), _int(rest[1])
        if proto == "tcp" and len(rest) >= 4:
            flags = rest[3] or None
    elif proto == "icmp" and rest:
        # the ICMP type (request, reply, unreachport, timexceed, ...) where the router logs it, as pfSense does.
        # OPNsense writes only "datalength=N" there (9,999 of its lines checked, 2026-11-09): no type, so every
        # blocked ICMP packet counts as a ping (opens_connection)
        icmp = rest[0] if rest[0] and not rest[0].startswith("datalength=") else None
    return {
        "kind": "block", "action": action, "iface": f[4], "dir": f[7], "rule": f[3] or f[0],
        "proto": proto, "src": src, "sport": sport, "dst": dst, "dport": dport, "flags": flags, "icmp": icmp,
    }


def _hostport(s):
    """'1.2.3.4:80' / '2001:0db8:...:0001:80' / '[2001:db8::1]:80' / bare address -> (ip, port).

    Suricata's syslog alert prints a port even for ICMP (':0'), so the split does not depend on the protocol.
    """
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        return host, _int(port.lstrip(":"))
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, _int(port)
    if s.count(":") == 8:  # Suricata prints IPv6 fully expanded, then :port
        host, _, port = s.rpartition(":")
        return host, _int(port)
    return s, None


def parse_suricata(msg):
    msg = msg.strip()
    if msg.startswith("{"):
        return _parse_eve(msg)
    m = _SURICATA.search(msg)
    if m is None:
        return None
    proto = m.group("proto").lower()
    src, sport = _hostport(m.group("src"))
    dst, dport = _hostport(m.group("dst"))
    if proto not in ("tcp", "udp", "sctp"):
        sport = dport = None
    cls = m.group("cls")
    sig = m.group("sig").strip()
    return {
        "kind": "ids", "action": "drop" if m.group("drop") else "alert", "proto": proto,
        "src": src, "sport": sport, "dst": dst, "dport": dport,
        "sig": sig, "sid": int(m.group("sid")), "prio": int(m.group("prio")),
        "cls": None if cls in (None, "(null)") else cls, "cat": ids_category(sig),
    }


def _parse_eve(msg):
    try:
        d = json.loads(msg)
    except ValueError:
        return None
    if d.get("event_type") != "alert" or "alert" not in d:
        return None
    a = d["alert"]
    http, tls = d.get("http") or {}, d.get("tls") or {}
    return {
        "kind": "ids", "action": "drop" if a.get("action") == "blocked" else "alert",
        "proto": str(d.get("proto", "")).lower(), "src": d.get("src_ip"), "sport": d.get("src_port"),
        "dst": d.get("dest_ip"), "dport": d.get("dest_port"), "iface": d.get("in_iface"),
        "sig": a.get("signature"), "sid": a.get("signature_id"), "prio": a.get("severity"),
        "cls": a.get("category"), "cat": ids_category(a.get("signature")),
        # what only eve tells: the application protocol, and the site the traffic was for (HTTP host, TLS name)
        "app": d.get("app_proto") if d.get("app_proto") not in (None, "failed") else None,
        "target": http.get("hostname") or tls.get("sni"),
        # who started the connection the packet belongs to (the flow's first sender), and which way the packet went
        "started_by": (d.get("flow") or {}).get("src_ip"), "dir": d.get("direction"),
    }


def parse_pass(line, now=None):
    """A firewall line for a packet it let through, as an event with action "pass" (or None): no threat, but if the
    IDS flagged that packet, it got through. It carries "logged" as parse_line's events do."""
    m = _header(line)
    if m is None or m.group("prog") != "filterlog":
        return None
    ev = parse_filterlog(m.group("msg").lstrip("\ufeff"), actions=("pass",))
    ev = ev and classify(ev)
    if ev:
        ev["logged"] = _logged(m, now or time.time())
    return ev


def parse_line(line, now=None):
    """Syslog line -> (program, event or None). program is None when the header is unrecognised.

    The event carries "logged": when the sender logged it, from the line's header (None if it can't be read).
    """
    m = _header(line)
    if m is None:
        return None, None
    prog, msg = m.group("prog"), m.group("msg").lstrip("\ufeff")
    if prog == "filterlog":
        ev = parse_filterlog(msg)
    elif prog == "suricata":
        ev = parse_suricata(msg)
    else:
        return prog, None
    if ev is None:
        return prog, None
    ev = classify(ev)
    if ev is not None:
        ev["logged"] = _logged(m, now or time.time())
    return prog, ev


# UDP source ports that answer rather than ask: DNS, NTP, QUIC/HTTP3, IKE, STUN/TURN (incl. Google's)
REPLY_PORTS = {53, 123, 443, 500, 3478, 3479, 3480, 3481, 5349, *range(19302, 19310)}
# ICMP types that are answers or errors about earlier traffic; an echo request (ping) is the one that probes. Only
# where the router logs the type (not OPNsense; parse_filterlog)
ICMP_REPLIES = {"reply", "unreach", "unreachnet", "unreachhost", "unreachproto", "unreachport", "needfrag",
                "timexceed", "paramprob", "redirect", "srcquench", "tstampreply", "inforeply", "maskreply"}


INFO_RULES = ("ET INFO ", "ET POLICY ", "GPL INFO ", "GPL POLICY ")
# rules that fire on who is sending, not on what: the source is on a threat list (CINS, DShield, Spamhaus DROP...)
LIST_RULES = ("ET DROP ", "ET CINS ", "ET COMPROMISED ", "ET TOR ", "ET 3CORESec ")
# the rule families that, on our own side's traffic, say something is wrong with a device of ours: it calls a malware
# controller, attacks or scans others, is served an exploit or a phishing page, or reaches a host on a threat list.
# Any other outbound alert is our own network's routine (file sharing, games, chat, a policy notice), whatever its family
# is called. Listing those instead let each new kind count as attacks until it was found: a TV's TLS fingerprint on
# 5 Nov, a file-sharing client the same evening
OUTBOUND_THREAT_RULES = (
    *(r for r in LIST_RULES if r != "ET TOR "),  # a Tor relay is no bad host to reach
    *(f"ET {f} " for f in ("MALWARE", "TROJAN", "CNC", "MOBILE_MALWARE", "COINMINER", "WORM", "ATTACK_RESPONSE",
                           "EXPLOIT", "EXPLOIT_KIT", "SHELLCODE", "SCAN", "DOS", "WEB_SERVER", "WEB_SPECIFIC_APPS",
                           "WEB_CLIENT", "PHISHING", "CURRENT_EVENTS", "HUNTING")),
    *(f"GPL {f} " for f in ("ATTACK_RESPONSE", "EXPLOIT", "SHELLCODE", "SCAN", "WEB_SERVER", "WEB_CLIENT")),
    "SSLBL", "URLhaus", "ThreatFox", "Feodo Tracker",  # abuse.ch's own rule sets
)
# rules on the fingerprint of a TLS client (JA3, JA3S): it names the encryption library a program uses, which many
# unrelated programs share, not what it does or whom it talks to. On 5 Nov a smart TV's streaming app matched
# abuse.ch's "Possible Adware" 54 times, and the streaming service's servers counted as attackers. abuse.ch's own set ("SSLBL: Malicious JA3
# SSL-Client Fingerprint ...") is fingerprints too
FINGERPRINT_RULES = re.compile(r"\bJA3S?\b", re.IGNORECASE)


def ids_category(sig):
    """What kind of IDS rule fired: "list" (the source is on a threat list), "info" (a notice, no attack) or "attack"
    (the IDS recognised what the traffic was doing: a scan, an exploit, a protocol abused)."""
    sig = sig or ""
    if sig.startswith(LIST_RULES):
        return "list"
    if sig.startswith(INFO_RULES):
        return "info"
    return "attack"


def is_policy(ev):
    """Our own network doing something a rule notes but that is no attack: shown, not counted as a threat.

    That is an outbound firewall block (a LAN device stopped on its way out, e.g. DNS-over-TLS past a local DNS filter), or an
    outbound IDS alert from any family but OUTBOUND_THREAT_RULES (an external-IP lookup, file sharing, a script's user
    agent), or on a device's TLS fingerprint (FINGERPRINT_RULES). Outbound alerts from those families (ET MALWARE,
    ET SCAN, a listed host, ...) stay threats, as does every inbound alert.
    """
    if ev["way"] != "out":
        return False
    sig = ev.get("sig") or ""
    return (ev["kind"] == "block" or not sig.startswith(OUTBOUND_THREAT_RULES)
            or bool(FINGERPRINT_RULES.search(sig)))


def opens_connection(ev):
    """False for a blocked packet that is the tail of our own traffic rather than someone reaching in.

    pf's default rule logs these whenever state is lost (a filter reload, an IDS restart, a state timeout):
    TCP that is already under way (ACK, FIN, RST, PSH...), UDP answers from a service port to one of our high ports
    (late QUIC from a CDN, a slow DNS reply), and ICMP replies and errors. A scan starts with a bare SYN, a UDP probe
    to a service port, or a ping.
    """
    if ev["kind"] != "block":
        return True
    if ev["proto"] == "tcp" and ev.get("flags"):
        return "S" in ev["flags"] and "A" not in ev["flags"]
    if ev["proto"] == "udp" and ev["sport"] is not None and ev["dport"] is not None:
        return not (ev["sport"] in REPLY_PORTS and ev["dport"] >= 1024)
    if ev["proto"] == "icmp":
        return ev.get("icmp") not in ICMP_REPLIES
    return True


def answers_us(ev):
    """True for an IDS alert on a packet that answers its destination: the destination opened the connection (eve's
    flow.src_ip, its first sender), or, where eve doesn't name it, the packet went "to_client". Before this, the
    STUN replies of video calls (the call service's relays answering from port 3478) counted as 18% of a day's threats."""
    if ev["kind"] != "ids":
        return False
    if ev.get("started_by"):
        return ev["started_by"] == ev["dst"] != ev["src"]
    return ev.get("dir") == "to_client"


def stored_reply(ev):
    """An event stored before answers_us as an inbound threat that was a reply to our own traffic. Stored events don't
    keep who opened the connection; an informational IDS rule on a packet from a port that answers is such a reply."""
    return (ev.get("kind") == "ids" and ev.get("way") == "in" and ev.get("cat") == "info"
            and ev.get("sport") in REPLY_PORTS)


def classify(ev):
    """Pick the remote (internet) side of the event, and which way it goes. Events with no global address on either
    side are dropped. A packet answering a connection our side opened is turned round, so it reads as the traffic it
    answers: outbound, to the remote's port (a STUN reply from 3478 is our call to a STUN server)."""
    if answers_us(ev):
        ev["src"], ev["dst"], ev["sport"], ev["dport"] = ev["dst"], ev["src"], ev["dport"], ev["sport"]
        if not is_global(ev["dst"]):
            return None
        ev["remote"], ev["local"], ev["way"], ev["reply"] = ev["dst"], ev["src"], "out", True
    elif is_global(ev["src"]):
        ev["remote"], ev["local"], ev["way"] = ev["src"], ev["dst"], "in"
    elif is_global(ev["dst"]):
        ev["remote"], ev["local"], ev["way"] = ev["dst"], ev["src"], "out"
    else:
        return None
    ev["svc"] = service(ev["proto"], ev["dport"])
    return ev
