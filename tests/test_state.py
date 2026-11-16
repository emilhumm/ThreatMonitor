import time

from threatmonitor.parse import parse_line
from threatmonitor.state import State

GEO = {"lat": 52.52, "lon": 13.405, "cc": "DE", "country": "Germany", "city": "Berlin", "asn": 1, "org": "Org"}
LINE = ("<134>Nov  2 19:05:01 fw filterlog[1]: 82,,,x,igb0,match,block,in,4,0x0,,244,1,0,none,6,tcp,40,"
        "185.220.101.1,203.0.113.77,51234,{port},0,S,1,,1024,,")


def event(port=22, geo=GEO):
    _, ev = parse_line(LINE.format(port=port))
    ev["ts"] = time.time()
    ev["geo"] = geo
    return ev


def test_counts_and_views(tmp_path):
    st = State(tmp_path)
    for port in (22, 22, 23, 8888, 8000):
        st.add(event(port))
    st.add(event(22, geo=None))
    s = st.stats()
    assert {k: s["totals"][k] for k in ("block", "ids", "out", "attempts", "blocked")} == {
        "block": 6, "ids": 0, "out": 0, "attempts": 6, "blocked": 6}
    assert s["unique"] == 1 and s["countries"] == 1
    assert s["top_ips"][0]["n"] == 6 and s["top_ips"][0]["ports"][0] == "SSH"
    assert s["top_ports"][0] == {"port": "22", "svc": "SSH", "n": 3}
    assert {p["port"]: p["svc"] for p in s["top_ports"]}["8888"] == "HTTP-alt"
    assert sum(c[0] for c in s["activity"]["cells"]) == 6
    assert len(st.globe_points()) == 1 and st.globe_points()[0]["n"] == 5


def test_outbound_policy_blocks_are_not_threats(tmp_path):
    st = State(tmp_path)
    st.add(event())
    dot = LINE.replace("185.220.101.1,203.0.113.77", "192.168.1.187,1.1.1.1").replace("igb0", "igc0")
    for _ in range(50):
        _, ev = parse_line(dot.format(port=853))
        ev["ts"], ev["geo"] = time.time(), dict(GEO, cc="AU")
        st.add(ev)
    s = st.stats()
    assert (s["totals"]["block"], s["totals"]["ids"], s["totals"]["out"], s["totals"]["attempts"]) == (1, 0, 50, 1)
    assert s["unique"] == 1 and [c["cc"] for c in s["top_countries"]] == ["DE"]
    assert [p["port"] for p in s["top_ports"]] == ["22"]
    assert sum(c[0] for c in s["activity"]["cells"]) == 1
    assert len(st.recent) == 1  # nor in the threat stream


def test_returning_addresses(tmp_path):
    st = State(tmp_path)
    back = event()
    back["seen"] = {"first": time.time() - 86400, "days": 1}  # the history knew it from an earlier day
    st.add(back)
    st.add(event())  # its second knock today: the address carries "seen"
    new = event()
    new["remote"] = "45.1.2.3"
    st.add(new)
    assert st.stats()["returning"] == 2


def test_networks_and_scanners(tmp_path):
    st = State(tmp_path)
    st.add(event())
    censys = dict(GEO, asn=398324, org="Censys, Inc.")
    for ip in ("167.94.138.1", "167.94.138.2", "167.94.138.2"):
        ev = event(geo=censys)
        ev["remote"] = ip
        st.add(ev)
    s = st.stats()
    nets = {asn: (n["org"], n["n"], n["ips"], n["scanner"]) for asn, n in st.networks.items()}
    assert nets[398324] == ("Censys, Inc.", 3, 2, "Censys") and len(nets) == 2
    assert [n["scanner"] for asn, n in st.networks.items() if asn != 398324] == [None]
    assert s["scanners"] == {"n": 3, "names": ["Censys"]}
    other = dict(censys, asn=398705)  # the same company on another of its networks counts once by name
    ev = event(geo=other)
    ev["remote"] = "206.168.34.1"
    st.add(ev)
    # a server of Shodan's in someone else's network, known by its name in reverse DNS (the server sets "scanner")
    cloud = dict(GEO, asn=15169, org="Google LLC")
    for _ in range(5):
        ev = event(geo=cloud)
        ev["remote"] = "34.1.2.3"
        st.add(ev)
    st.ips["34.1.2.3"].update(host="red2.census.shodan.io", scanner="Shodan")
    s = st.stats()
    assert s["scanners"] == {"n": 9, "names": ["Shodan", "Censys"]}
    # Google's network isn't a scanner's for one server in it: only that address counts
    assert (st.networks[15169]["org"], st.networks[15169]["scanner"]) == ("Google LLC", None)
    st.save()
    again = State(tmp_path)
    again.load()  # the per-network totals come back from the saved addresses, and so do the names
    assert again.networks == st.networks
    assert again.stats()["scanners"] == s["scanners"]


def test_snapshot_round_trip(tmp_path):
    st = State(tmp_path)
    st.add(event())
    st.save()
    again = State(tmp_path)
    again.load()
    assert again.stats()["totals"] == st.stats()["totals"]
    assert again.seq == 1 and len(again.recent) == 1
