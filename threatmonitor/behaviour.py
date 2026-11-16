"""What an address was doing, judged from what it did: one word for the dashboard, a few for the hover and History.
And what all of today's knocks were after (aims), for the dashboard's Aims tab."""
from collections import Counter, defaultdict

SWEEP = 6     # services tried: a port sweep from here on
ATTACKS = ("sweep", "botnet", "brute")  # what() keys that are attacks in themselves, whatever the IDS saw
BRUTE = 20    # knocks on one login service: someone trying to get in rather than looking around

LOGIN = {"SSH", "SSH-alt", "Telnet", "Telnet-alt", "RDP", "SMB", "FTP", "VNC", "MSSQL", "MySQL", "Postgres", "Oracle",
         "WinRM", "SIP", "Redis", "MongoDB"}
# the services the IoT botnets (Mirai and its offspring) go for: cheap routers, cameras, set-top boxes
IOT = {"Telnet", "Telnet-alt", "ADB", "TR-069", "Huawei", "UPnP", "DVR"}

# What a knock aimed at a service was after, by the service's name (parse.PORT_NAMES). A named service in none of
# these is "Other services".
AIMS = (
    ("Logins", {"SSH", "SSH-alt", "RDP", "VNC", "FTP", "FTP-data", "WinRM", "Webmin", "SOCKS", "Proxy"}),
    ("Web", {"HTTP", "HTTPS", "HTTP-proxy", "HTTP-alt", "HTTPS-alt"}),
    ("IoT & routers", {*IOT, "RTSP", "Winbox", "MikroTik", "Cisco", "Printer", "IPP"}),
    ("Databases", {"MSSQL", "MySQL", "Postgres", "Oracle", "Redis", "MongoDB", "Elastic", "Memcached"}),
    ("VPN & VoIP", {"SIP", "SIP-TLS", "IKE", "IPsec", "OpenVPN", "PPTP", "WireGuard", "STUN", "GRE", "ESP"}),
    ("Windows & shares", {"SMB", "NetBIOS", "MSRPC", "LDAP", "LDAPS", "Kerberos", "NFS", "rsync"}),
    ("DDoS amplifiers", {"DNS", "NTP", "SNMP", "SSDP", "mDNS", "RPC", "TFTP", "IPMI"}),
    ("Mail", {"SMTP", "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS"}),
    ("Factory control", {"Modbus", "S7comm", "DNP3", "EtherNet/IP", "BACnet", "MQTT"}),
)
AIM_OF = {svc: name for name, svcs in AIMS for svc in svcs}
# a port no known service uses, knocked on this often by this few senders: someone wants that very port
REPEAT_KNOCKS, REPEAT_SENDERS = 20, 20


def aims(senders):
    """Today's knocks by what they were after, from each sender's knocks in all ("n") and per service ("ports"):

    - mapping what's open: every knock of a sender that tried SWEEP or more services ("sweeps"), a knock on a port no
      known service uses ("random"), a ping ("pings"). On 5 Nov that was 75% of all knocks;
    - aimed at a service: by group (AIMS), each with its services, busiest first;
    - the same unnamed port again and again: REPEAT_KNOCKS or more knocks on it from REPEAT_SENDERS or fewer senders.

    A sender under SWEEP services has every one of its services in "ports" (the state keeps up to 12).
    """
    mapping, aimed, by_svc, unnamed = Counter(), Counter(), defaultdict(Counter), {}
    for s in senders:
        ports = s["ports"]
        if len(ports) >= SWEEP:
            mapping["sweeps"] += s["n"]
            continue
        for svc, n in ports.items():
            if svc == "ICMP":
                mapping["pings"] += n
            elif svc.startswith(("tcp/", "udp/")):
                u = unnamed.setdefault(svc, [0, 0])
                u[0] += n
                u[1] += 1
            else:
                group = AIM_OF.get(svc, "Other services")
                aimed[group] += n
                by_svc[group][svc] += n
    repeat = sorted(([svc, n, k] for svc, (n, k) in unnamed.items() if n >= REPEAT_KNOCKS and k <= REPEAT_SENDERS),
                    key=lambda r: -r[1])
    mapping["random"] = sum(n for n, _ in unnamed.values()) - sum(r[1] for r in repeat)
    return {"mapping": dict(mapping), "repeat": repeat[:3],
            "aimed": [[g, n, [svc for svc, _ in by_svc[g].most_common(3)]] for g, n in aimed.most_common()]}


def what(hits, ports, scanner=None, listed=False, ports_capped=False):
    """(key, words) for an address, or None when nothing stands out.

    hits: its knocks; ports: service -> knocks (the live state keeps up to 12 services, so ports_capped says there
    may be more); scanner: the scanning company it belongs to; listed: a threat list names it (which one: "IDS" for
    the IDS's list rules, else the firewall rule's name).
    """
    if scanner:
        return "scanner", f"{scanner}: scans the whole internet for a living"
    if len(ports) >= SWEEP:
        return "sweep", f"port sweep: {len(ports)}{'+' if ports_capped else ''} services tried"
    if ports and set(ports) <= IOT:
        return "botnet", f"IoT botnet pattern: {', '.join(sorted(ports))}"
    top, n = max(ports.items(), key=lambda kv: kv[1]) if ports else (None, 0)
    if top in LOGIN and n >= BRUTE:
        return "brute", f"keeps knocking on {top}: {n} times"
    if listed:
        return "listed", "on the IDS threat lists" if listed in (True, "IDS") else f"on a threat list ({listed})"
    if hits == 1:
        return "once", "one knock"
    return None
