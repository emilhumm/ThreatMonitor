import asyncio

from threatmonitor import config, health
from threatmonitor.health import Health


def ids_to(local, way="in"):
    return {"kind": "ids", "way": way, "local": local}


BLOCK = {"kind": "block", "way": "in", "local": "81.0.0.1"}


def test_wan_change_needs_confirming_hits_and_clears_on_ids(tmp_path):
    h = Health(tmp_path)
    h.seen_wan("81.0.0.1", 100)
    assert h.wan["ip"] == "81.0.0.1" and not h.warnings(200)
    for t in range(4):
        h.seen_wan("81.0.0.2", 200 + t)
    h.seen_wan("81.0.0.1", 205)        # the old one again: not a change (several addresses, or noise)
    h.seen_wan("81.0.0.2", 206)
    assert h.wan["ip"] == "81.0.0.1"
    for t in range(5):
        h.seen_wan("81.0.0.2", 300 + t)
    assert h.wan["ip"] == "81.0.0.2" and h.wan["previous"] == "81.0.0.1"
    assert "81.0.0.2/32" in h.warnings(400)["wan"]
    h.event(ids_to("81.0.0.1"), 410)   # an alert at the old address proves nothing
    assert "wan" in h.warnings(420)
    h.event(ids_to("81.0.0.2"), 430)
    assert "wan" not in h.warnings(440)
    assert Health(tmp_path).wan["confirmed"]  # kept across a restart


def test_ids_silence(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "IDS_SILENT_MIN", 60)
    h = Health(tmp_path)
    for _ in range(100):
        h.event(BLOCK, 0)
    assert not h.warnings(10_000)      # never seen an alert: IDS may simply not be in use
    h.event(ids_to("81.0.0.1"), 1000)
    for _ in range(49):
        h.event(BLOCK, 1000)
    assert not h.warnings(1000 + 3700)  # quiet, but too little traffic to call it
    h.event(BLOCK, 1000)
    assert "No IDS alert for 61 min" in h.warnings(1000 + 3700)["ids"]
    h.event(ids_to("81.0.0.1"), 5000)
    assert not h.warnings(5001)


def test_notify_on_appear_and_clear(tmp_path, monkeypatch):
    sent = []

    async def fake_notify(title, message, severity="alert"):
        sent.append(title)
    monkeypatch.setattr(health, "notify", fake_notify)
    h = Health(tmp_path)
    h.seen_wan("81.0.0.1", 1)
    for t in range(5):
        h.seen_wan("81.0.0.2", 2 + t)
    asyncio.run(h.check())
    asyncio.run(h.check())             # still active: no second message
    h.event(ids_to("81.0.0.2"), 10)
    asyncio.run(h.check())
    assert sent == ["ThreatMonitor: attention", "ThreatMonitor: OK again"]
