"""One knock, counted once.

A packet that the firewall blocks and that matches an IDS rule is logged twice: once by the firewall, once by the
IDS (sometimes by two IDS rules). Counted as events, every such knock was two or three threats. Here the events for
the same source and port within PAIR seconds of the first one join its knock: one firewall block, and IDS alerts for
rules not already on it. A second block for the same port starts a new knock: that's another packet.
"""
from collections import deque

PAIR = 3  # seconds

# What an event adds to its knock, as bits (kept in the history as events.gain): it starts the knock (ATTEMPT), or
# the knock gets its firewall block (BLOCKED), its first IDS alert (FLAGGED), its first sign that the sender is on a
# threat list (LISTED: an IDS list rule's alert, or a block by a firewall rule for a list, ev["list_rule"]) or its
# first alert for an attack the IDS recognised (ATTACK)
ATTEMPT, BLOCKED, FLAGGED, LISTED, ATTACK = 1, 2, 4, 8, 16
GAINS = ((ATTEMPT, "attempts"), (BLOCKED, "blocked"), (FLAGGED, "flagged"), (LISTED, "listed"), (ATTACK, "attack"))


def packet_kind(proto):
    """What a blocked knock was, by its protocol: "tcp" (someone opening a connection), "udp" (a probe of a UDP
    service), "ping" or "other"."""
    return {"tcp": "tcp", "udp": "udp", "icmp": "ping", "ipv6-icmp": "ping", "icmpv6": "ping"}.get(proto or "", "other")


def alone(ev):
    """What an event adds when it is a knock of its own (no pairing): everything it is."""
    if ev["kind"] != "ids":
        return ATTEMPT | BLOCKED | (LISTED if ev.get("list_rule") else 0)
    return ATTEMPT | FLAGGED | {"list": LISTED, "attack": ATTACK}.get(ev.get("cat"), 0)


def describe(ev):
    """A firewall line in a few words, for /api/debug: who, which port (none for a ping), what the packet was."""
    port = f':{ev["dport"]}' if ev.get("dport") is not None else None
    what = " ".join(x for x in (ev["remote"], "->", port, ev["proto"], ev.get("flags") or ev.get("icmp")) if x)
    return f'{what} ({ev["action"]}, rule {ev.get("rule")})' if ev.get("action") == "pass" else what


class Knocks:
    def __init__(self):
        self.open = {}          # (remote, dport) -> the latest knock: {"t", "block", "sids", "cats", "way"}
        self.order = deque()    # (key, knock), oldest first, to close them
        self.other = {}         # (remote, dport) -> (when, how, what): a firewall line waiting for its IDS alert

    def add(self, ev):
        """Join ev to its knock or start one; the bits it adds (above). Sets ev["dup"] (it joined a knock already
        counted) and ev["knock_ts"] (when the knock started)."""
        key = (ev["remote"], ev["dport"])
        k = self.open.get(key)
        ids = ev["kind"] == "ids"
        if k is None or abs(ev["ts"] - k["t"]) > PAIR or (ev.get("sid") in k["sids"] if ids else k["block"]):
            k = self.open[key] = {"t": ev["ts"], "block": False, "sids": set(), "cats": set(), "way": ev["way"]}
            self.order.append((key, k))
            o = self.other.pop(key, None)
            if o is not None and abs(ev["ts"] - o[0]) <= PAIR:
                k[o[1]] = o[2]
                ev["other"] = o[1:]
            gain = ATTEMPT
        else:
            gain = 0
        if ids:
            cat = ev.get("cat")
            gain |= (FLAGGED if not k["sids"] else 0) | (LISTED if cat == "list" and cat not in k["cats"] else 0) | (
                ATTACK if cat == "attack" and cat not in k["cats"] else 0)
            k["sids"].add(ev.get("sid"))
            k["cats"].add(cat)
        else:
            gain |= BLOCKED | (LISTED if ev.get("list_rule") and "list" not in k["cats"] else 0)
            k["block"] = True
            if ev.get("list_rule"):
                k["cats"].add("list")  # an IDS list alert for the same packet adds no second LISTED
        ev["dup"] = not gain & ATTEMPT
        ev["knock_ts"] = k["t"]
        return gain

    def other_line(self, ev, how):
        """A firewall line that is no threat of its own: "late", a block for a packet that opens nothing (no TCP SYN:
        see parse.opens_connection), or "pass", the firewall let the packet through. Either way, if the IDS flagged
        that packet, the firewall did log it, so the knock isn't "unlogged"; a pass means it got through. True when it
        meets a knock already open; else it waits PAIR seconds for one (and that IDS alert gets ev["other"])."""
        key = (ev["remote"], ev["dport"])
        k = self.open.get(key)
        if k is not None and k["sids"] and abs(ev["ts"] - k["t"]) <= PAIR:
            k[how] = describe(ev)
            return True
        self.other[key] = (ev["ts"], how, describe(ev))
        return False

    def close(self, now):
        """Close the knocks over (a second past PAIR, for lines still on their way). Returns the inbound ones the IDS
        flagged but the firewall log has no block for."""
        out = []
        while self.order and now - self.order[0][1]["t"] > PAIR + 1:
            key, k = self.order.popleft()
            if self.open.get(key) is k:
                del self.open[key]
            if k["sids"] and not k["block"] and not k.get("late") and not k.get("pass") and k["way"] == "in":
                out.append(k)
        if len(self.other) > 1000 or (self.other and not self.order):
            self.other = {key: x for key, x in self.other.items() if now - x[0] <= PAIR + 1}
        return out
