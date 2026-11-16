"""Syslog receiver: UDP and TCP on the same port. Each received line goes to a callback(line, sender_ip)."""
import asyncio
import logging
import re

log = logging.getLogger("syslog")

_OCTETS = re.compile(rb"(\d{1,6}) <")
MAX_BUF = 1 << 20


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, handle, allow, reject):
        self.handle, self.allow, self.reject = handle, allow, reject

    def datagram_received(self, data, addr):
        if self.allow and addr[0] not in self.allow:
            self.reject(addr[0])
            return
        for line in data.decode("utf-8", "replace").splitlines():
            if line:
                self.handle(line, addr[0])


def split_frames(buf):
    """Take complete messages off a TCP buffer -> (messages, rest).

    Handles both RFC 6587 framings: octet counting ("<len> <msg>") and newline-terminated.
    """
    out = []
    while True:
        buf = buf.lstrip(b"\r\n")
        m = _OCTETS.match(buf)
        if m:
            start = m.end() - 1
            end = start + int(m.group(1))
            if len(buf) < end:
                break
            out.append(buf[start:end])
            buf = buf[end:]
            continue
        i = buf.find(b"\n")
        if i < 0:
            break
        out.append(buf[:i])
        buf = buf[i + 1:]
    return out, buf


async def _tcp_client(reader, writer, handle, allow, reject):
    peer = writer.get_extra_info("peername")[0]
    try:
        if allow and peer not in allow:
            reject(peer)
            return
        buf = b""
        while chunk := await reader.read(65536):
            frames, buf = split_frames(buf + chunk)
            for f in frames:
                line = f.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    handle(line, peer)
            if len(buf) > MAX_BUF:
                buf = b""
    except ConnectionError:
        pass
    finally:
        writer.close()


async def start(host, port, handle, allow, reject):
    """reject(sender_ip) is called for traffic from senders outside `allow`, so it can be shown, not just lost."""
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: _Udp(handle, allow, reject), local_addr=(host, port))
    tcp = await asyncio.start_server(lambda r, w: _tcp_client(r, w, handle, allow, reject), host, port)
    log.info("listening for syslog on %s udp/tcp %d%s", host, port,
             f" from {', '.join(sorted(allow))}" if allow else "")
    return udp, tcp
