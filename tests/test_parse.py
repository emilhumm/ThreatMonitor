import time
from datetime import datetime, timezone

from threatmonitor.parse import is_policy, opens_connection, parse_line, split_header
from threatmonitor.syslog import split_frames

V4_TCP = ("82,,,02f4bab031b57d1e30553ce08e0ec131,igb0,match,block,in,4,0x0,,244,54321,0,none,6,tcp,40,"
          "185.220.101.1,203.0.113.77,51234,22,0,S,1234567,,1024,,")
V4_UDP = "82,,,02f4bab031b57d1e30553ce08e0ec131,igb0,match,block,in,4,0x0,,52,0,0,DF,17,udp,76,45.1.2.3,203.0.113.77,40000,5060,56"
V6_TCP = ("97,,,abcd,igb0,match,block,in,6,0x00,0x00000,57,tcp,6,40,2a06:4880::1,2001:db8:1::5,"
          "51111,3389,0,S,1,,1024,,")
V4_PASS = V4_TCP.replace(",block,", ",pass,")


def test_rfc3164_filterlog():
    prog, ev = parse_line(f"<134>Nov  2 19:05:01 OPNsense.home.arpa filterlog[64123]: {V4_TCP}")
    assert prog == "filterlog"
    assert ev["kind"] == "block" and ev["way"] == "in"
    assert (ev["remote"], ev["dport"], ev["svc"], ev["proto"]) == ("185.220.101.1", 22, "SSH", "tcp")
    assert ev["iface"] == "igb0" and ev["flags"] == "S"


def test_rfc5424_filterlog_and_udp():
    prog, ev = parse_line(
        f'<134>1 2026-11-02T19:05:01+01:00 OPNsense.home.arpa filterlog 64123 - [meta sequenceId="7"] {V4_UDP}')
    assert prog == "filterlog"
    assert (ev["remote"], ev["dport"], ev["svc"]) == ("45.1.2.3", 5060, "SIP")


def test_ipv6_filterlog():
    _, ev = parse_line(f"<134>Nov 12 01:02:03 fw filterlog[1]: {V6_TCP}")
    assert (ev["remote"], ev["dport"], ev["svc"]) == ("2a06:4880::1", 3389, "RDP")


def test_pass_and_private_are_ignored():
    assert parse_line(f"<134>Nov  2 19:05:01 fw filterlog[1]: {V4_PASS}") == ("filterlog", None)
    private = V4_TCP.replace("185.220.101.1", "192.168.1.5").replace("203.0.113.77", "192.168.1.1")
    assert parse_line(f"<134>Nov  2 19:05:01 fw filterlog[1]: {private}") == ("filterlog", None)


def test_outbound_block_from_lan():
    out = V4_TCP.replace("185.220.101.1", "192.168.1.23").replace("203.0.113.77", "94.130.1.1")
    _, ev = parse_line(f"<134>Nov  2 19:05:01 fw filterlog[1]: {out}")
    assert ev["way"] == "out" and ev["remote"] == "94.130.1.1" and ev["local"] == "192.168.1.23"


def test_suricata_classic():
    line = ("<33>Nov  2 19:05:01 OPNsense.home.arpa suricata[7642]: [1:2010935:3] ET SCAN Suspicious inbound to "
            "MSSQL port 1433 [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 45.1.2.3:51234 -> "
            "203.0.113.77:1433")
    prog, ev = parse_line(line)
    assert prog == "suricata" and ev["kind"] == "ids" and ev["action"] == "alert"
    assert ev["sig"] == "ET SCAN Suspicious inbound to MSSQL port 1433"
    assert (ev["sid"], ev["prio"], ev["cls"]) == (2010935, 2, "Potentially Bad Traffic")
    assert (ev["remote"], ev["dport"], ev["svc"]) == ("45.1.2.3", 1433, "MSSQL")


def test_suricata_drop_ipv6_and_icmp():
    v6 = ("<33>Nov  2 19:05:01 fw suricata[1]: [Drop] [1:2001219:20] ET SCAN Potential SSH Scan "
          "[Classification: Attempted Information Leak] [Priority: 2] {TCP} "
          "2a06:4880:0000:0000:0000:0000:0000:0001:4444 -> 2001:0db8:0000:0000:0000:0000:0000:0005:22")
    _, ev = parse_line(v6)
    assert ev["action"] == "drop" and ev["dport"] == 22
    assert ev["remote"] == "2a06:4880:0000:0000:0000:0000:0000:0001"
    icmp = ("<33>Nov  2 19:05:01 fw suricata[1]: [1:2100366:8] GPL ICMP_INFO PING *NIX [Classification: Misc "
            "activity] [Priority: 3] {ICMP} 45.1.2.3 -> 203.0.113.77")
    _, ev = parse_line(icmp)
    assert ev["svc"] == "ICMP" and ev["remote"] == "45.1.2.3" and ev["dport"] is None


def test_midstream_tcp_is_not_a_new_connection():
    def fl(flags, proto_tail="6,tcp"):
        line = V4_TCP.replace(",0,S,1234567,", f",0,{flags},1234567,").replace("6,tcp", proto_tail)
        return parse_line(f"<134>Nov  2 19:44:55 fw filterlog[1]: {line}")[1]
    assert opens_connection(fl("S")) and opens_connection(fl("SEC"))
    for flags in ("FPA", "FA", "PA", "RA", "A", "R", "SA"):
        assert not opens_connection(fl(flags)), flags
    _, udp = parse_line(f"<134>Nov  2 19:05:01 fw filterlog[1]: {V4_UDP}")
    assert opens_connection(udp)  # 40000 -> 5060: a SIP probe


def test_late_udp_and_icmp_replies():
    quic = V4_UDP.replace("45.1.2.3,203.0.113.77,40000,5060", "157.240.200.35,203.0.113.77,443,40463")
    _, ev = parse_line(f"<134>Nov  2 20:05:01 fw filterlog[1]: {quic}")
    assert ev["remote"] == "157.240.200.35" and not opens_connection(ev)
    dns_probe = V4_UDP.replace("40000,5060", "53,53")  # to a service port: still counts
    assert opens_connection(parse_line(f"<134>Nov  2 20:05:01 fw filterlog[1]: {dns_probe}")[1])
    icmp = "82,,,x,igb0,match,block,in,4,0x0,,52,0,0,none,1,icmp,84,45.1.2.3,203.0.113.77,{t},1234,1"
    ping = parse_line(f"<134>Nov  2 20:05:01 fw filterlog[1]: {icmp.format(t='request')}")[1]
    reply = parse_line(f"<134>Nov  2 20:05:01 fw filterlog[1]: {icmp.format(t='reply')}")[1]
    assert ping["icmp"] == "request" and opens_connection(ping) and not opens_connection(reply)


def test_opnsense_icmp_has_no_type():
    # OPNsense logs an ICMP packet's data length where pfSense logs its type: no type, and it counts as a ping
    line = "82,,,x,igb0,match,block,in,4,0x0,,52,0,0,none,1,icmp,40,45.1.2.3,203.0.113.77,datalength=20"
    _, ev = parse_line(f"<134>Nov  9 12:05:01 fw filterlog[1]: {line}")
    assert ev["proto"] == "icmp" and ev["icmp"] is None and opens_connection(ev)


def test_suricata_syslog_icmp_prints_port_zero():
    line = ("<33>Nov  2 19:05:01 fw suricata[1]: [wDrop] [1:2100366:8] GPL ICMP_INFO PING *NIX [Classification: "
            "(null)] [Priority: 3] {ICMP} 45.1.2.3:0 -> 203.0.113.77:0")
    _, ev = parse_line(line)
    assert ev["remote"] == "45.1.2.3" and ev["dport"] is None and ev["svc"] == "ICMP"
    assert ev["action"] == "drop" and ev["cls"] is None
    assert opens_connection(ev)


def test_suricata_eve_json():
    eve = ('{"timestamp":"2026-11-02T19:05:01.1+0100","event_type":"alert","src_ip":"45.1.2.3","src_port":5555,'
           '"dest_ip":"203.0.113.77","dest_port":23,"proto":"TCP","in_iface":"igb0","alert":{"action":"blocked",'
           '"signature_id":2027973,"signature":"ET SCAN Mirai Variant Telnet Brute Force","category":"Attempted '
           'Administrator Privilege Gain","severity":1}}')
    _, ev = parse_line(f"<33>1 2026-11-02T19:05:01+01:00 fw suricata 7642 - - {eve}")
    assert ev["action"] == "drop" and ev["svc"] == "Telnet" and ev["prio"] == 1
    assert parse_line('<33>Nov  2 19:05:01 fw suricata[1]: {"event_type":"flow"}') == ("suricata", None)


def test_other_programs_and_garbage():
    assert parse_line("<38>Nov  2 19:05:01 fw sshd[123]: Accepted publickey for root") == ("sshd", None)
    assert parse_line("hello world") == (None, None)
    assert split_header("<134>Nov  2 19:05:01 fw filterlog[1]: x")[0] == "filterlog"


def test_time_logged():
    t = time.time() - 90  # a line held back for a minute and a half
    lt = time.localtime(t)
    bsd = f"{time.strftime('%b', lt)} {lt.tm_mday:>2} {time.strftime('%H:%M:%S', lt)}"
    _, ev = parse_line(f"<134>{bsd} fw filterlog[1]: {V4_TCP}")
    assert ev["logged"] == int(t)
    _, ev = parse_line(f"<134>2026-11-02T19:05:01+01:00 fw filterlog[1]: {V4_TCP}")
    assert ev["logged"] == datetime(2026, 11, 2, 18, 5, 1, tzinfo=timezone.utc).timestamp()
    eve = '{"event_type":"alert","src_ip":"45.1.2.3","dest_ip":"203.0.113.77","proto":"TCP","alert":{"signature_id":1}}'
    _, ev = parse_line(f"<33>1 2026-11-02T19:05:01.250+01:00 fw suricata 7642 - - {eve}")
    assert ev["logged"] == datetime(2026, 11, 2, 18, 5, 1, 250000, tzinfo=timezone.utc).timestamp()
    _, ev = parse_line(f"<33>1 - fw suricata 7642 - - {eve}")
    assert ev["logged"] is None
    # logged in the last second of the year and read just after midnight: last year's
    new_year = time.mktime((2027, 1, 1, 0, 0, 5, 0, 0, -1))
    _, ev = parse_line(f"<134>Dec 31 23:59:59 fw filterlog[1]: {V4_TCP}", now=new_year)
    assert ev["logged"] == new_year - 6


def test_tcp_framing():
    a = b"<134>Nov  2 19:05:01 fw filterlog[1]: one"
    frames, rest = split_frames(b"%d %s%d %s" % (len(a), a, len(a), a[:10]))
    assert frames == [a] and rest == b"%d %s" % (len(a), a[:10])
    frames, rest = split_frames(b"<134>x one\n<134>x two\n<134>x th")
    assert frames == [b"<134>x one", b"<134>x two"] and rest == b"<134>x th"


def test_reply_on_our_own_connection_reads_as_outbound():
    # a call relay's STUN reply to a call our side set up: eve names our WAN address as the flow's first sender
    stun = ('{"event_type":"alert","src_ip":"52.114.233.29","src_port":3478,"dest_ip":"203.0.113.77","dest_port":39705,'
            '"proto":"UDP","direction":"to_client","alert":{"action":"allowed","signature_id":2016149,'
            '"signature":"ET INFO Session Traversal Utilities for NAT (STUN Binding Response)","severity":3},'
            '"flow":{"src_ip":"203.0.113.77","dest_ip":"52.114.233.29","src_port":39705,"dest_port":3478}}')
    _, ev = parse_line(f"<174>Nov  5 11:32:23 fw suricata[1]: {stun}")
    assert (ev["way"], ev["remote"], ev["local"], ev["dport"], ev["sport"]) == ("out", "52.114.233.29", "203.0.113.77",
                                                                              3478, 39705)
    assert is_policy(ev)  # our own traffic, noted by an informational rule: no threat
    # without the flow object, the packet's direction tells the same
    no_flow = stun.split(',"flow"')[0] + "}"
    _, ev = parse_line("<174>Nov  5 11:32:23 fw suricata[1]: " + no_flow)
    assert ev["way"] == "out" and ev["remote"] == "52.114.233.29"
    # a listed sender that opened the connection itself stays an inbound knock
    cins = ('{"event_type":"alert","src_ip":"118.194.238.196","src_port":55798,"dest_ip":"203.0.113.77",'
            '"dest_port":8291,"proto":"TCP","direction":"to_server","alert":{"signature_id":2403490,'
            '"signature":"ET CINS Active Threat Intelligence Poor Reputation IP group 191"},'
            '"flow":{"src_ip":"118.194.238.196","dest_ip":"203.0.113.77"}}')
    _, ev = parse_line(f"<174>Nov  5 11:32:23 fw suricata[1]: {cins}")
    assert (ev["way"], ev["remote"], ev["svc"]) == ("in", "118.194.238.196", "Winbox")
    # ... but a listed host answering a connection we opened is ours going out, and stays a threat
    ours = cins.replace('"flow":{"src_ip":"118.194.238.196"', '"flow":{"src_ip":"203.0.113.77"')
    _, ev = parse_line("<174>Nov  5 11:32:23 fw suricata[1]: " + ours)
    assert ev["way"] == "out" and ev["remote"] == "118.194.238.196" and not is_policy(ev)


def test_policy_is_outbound_blocks_and_outbound_alerts_outside_the_threat_families():
    base = {"way": "out", "kind": "ids"}
    assert is_policy({**base, "sig": "ET INFO External IP Lookup ip-api.com"})
    assert is_policy({**base, "sig": "ET POLICY curl User-Agent Outbound"})
    assert is_policy({**base, "sig": "GPL P2P BitTorrent announce request"})  # a torrent client: its peers attack no one
    assert is_policy({**base, "sig": "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 4"})
    assert is_policy({**base, "sig": None})
    assert not is_policy({**base, "sig": "ET MALWARE Possible Win32/Agent Tesla C2 Checkin"})
    assert not is_policy({**base, "sig": "ET SCAN Suspicious inbound to mySQL port 3306"})  # a device of ours scanning
    assert not is_policy({**base, "sig": "ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response"})
    assert not is_policy({**base, "sig": "ET DROP Spamhaus DROP Listed Traffic Inbound group 12"})  # reaching a listed host
    assert not is_policy({**base, "sig": "ThreatFox Cobalt Strike botnet C2 traffic (ip:port - confidence level: 80%)"})
    assert is_policy({**base, "sig": "SSLBL: Malicious JA3 SSL-Client Fingerprint detected (Tofsee)"})
    assert is_policy({"way": "out", "kind": "block"})
    assert not is_policy({"way": "in", "kind": "ids", "sig": "ET INFO Inbound something"})
    assert not is_policy({"way": "in", "kind": "ids", "sig": "ET P2P BitTorrent peer sync"})


def test_an_alert_on_our_own_devices_tls_fingerprint_is_our_network():
    # a smart TV's streaming app, whose TLS fingerprint (JA3) abuse.ch has seen in adware: our device going out, no attack
    tv = ('{"event_type":"alert","src_ip":"203.0.113.77","src_port":51000,"dest_ip":"2.18.244.217","dest_port":443,'
          '"proto":"TCP","direction":"to_server","app_proto":"tls","tls":{"sni":"drod20p.akamaized.net"},'
          '"alert":{"signature_id":2028371,"signature":"ET JA3 Hash - [Abuse.ch] Possible Adware"},'
          '"flow":{"src_ip":"203.0.113.77","dest_ip":"2.18.244.217"}}')
    _, ev = parse_line(f"<174>Nov  5 20:05:52 fw suricata[1]: {tv}")
    assert ev["way"] == "out" and ev["remote"] == "2.18.244.217" and is_policy(ev)
    # someone reaching in with such a fingerprint is still a threat; other families going out stay threats too
    assert not is_policy(dict(ev, way="in"))
    assert not is_policy(dict(ev, sig="ET MALWARE Win32/Lumma Stealer Related CnC Domain in TLS SNI"))
