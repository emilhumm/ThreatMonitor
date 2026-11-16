import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor

from threatmonitor import geo
from threatmonitor.geo import reverse_name, scanner_host, scanner_of


def test_scanner_by_network_and_by_name():
    assert scanner_of("Censys, Inc.") == "Censys" and scanner_of("Arbor Networks, Inc.") == "NETSCOUT"
    assert scanner_of("Google LLC") is None and scanner_of(None) is None
    assert scanner_host("red2.census.shodan.io") == "Shodan"
    assert scanner_host("crawler176.deepfield.net.") == "NETSCOUT"
    assert scanner_host("shodan.io") == "Shodan"
    assert scanner_host("notshodan.io") is None             # only the domain itself, or a name under it
    assert scanner_host("154-16-44-11.infrawat.ch") == "Infrawatch"
    assert scanner_host("shodan.io.example.com") is None
    assert scanner_host("www.rapid7.com") is None           # Rapid7's scanners only, not its web site
    assert scanner_host("") is None and scanner_host(None) is None


def test_reverse_name_must_point_back(monkeypatch):
    names = {"34.1.2.3": "red2.census.shodan.io", "6.6.6.6": "scanner.shodan.io"}
    forward = {"red2.census.shodan.io": ["34.1.2.3"], "scanner.shodan.io": ["34.9.9.9"]}

    def getnameinfo(sa, flags):
        if sa[0] not in names:
            raise socket.herror("no name")
        return names[sa[0]], "0"

    def getaddrinfo(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in forward.get(host, [])]

    monkeypatch.setattr(geo.socket, "getnameinfo", getnameinfo)
    monkeypatch.setattr(geo.socket, "getaddrinfo", getaddrinfo)
    with ThreadPoolExecutor(2) as pool:
        def look(ip):
            return asyncio.run(reverse_name(ip, pool))
        assert look("34.1.2.3") == "red2.census.shodan.io"
        assert look("6.6.6.6") == ""        # names itself after Shodan, but Shodan's name doesn't point back to it
        assert look("1.2.3.4") == ""        # no name at all
