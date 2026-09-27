#!/usr/bin/env python3
"""Local smoke client for boltapi_quic_interop_server (aioquic).

Mirrors the interop runner's server-facing cases without docker:
  handshake / transfer / multiplexing / retry: hq-interop GETs, byte-exact
  resumption: two connections, the second resumes with a session ticket
  zerortt:    the second connection sends its GETs as 0-RTT
  http3:      h3 GETs (aioquic's H3 client)

  local_client.py --port P --www DIR --case CASE [--files a,b,...]
Exit 0 on success; prints the reason and exits 1 on any mismatch.
"""
import argparse
import asyncio
import os
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, StreamReset


class HqClient(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._waiters = {}
        self._bufs = {}
        self._h3 = None

    def use_h3(self):
        self._h3 = H3Connection(self._quic)

    def get(self, path):
        loop = asyncio.get_event_loop()
        if self._h3 is not None:
            sid = self._quic.get_next_available_stream_id()
            self._h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"),
                                        (b":authority", b"server"), (b":path", path.encode())],
                                  end_stream=True)
        else:
            sid = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(sid, b"GET " + path.encode() + b"\r\n", end_stream=True)
        fut = loop.create_future()
        self._waiters[sid] = fut
        self._bufs[sid] = bytearray()
        self.transmit()
        return fut

    def quic_event_received(self, event):
        if self._h3 is not None:
            for ev in self._h3.handle_event(event):
                if isinstance(ev, DataReceived):
                    self._bufs[ev.stream_id] += ev.data
                    if ev.stream_ended:
                        self._done(ev.stream_id)
                elif isinstance(ev, HeadersReceived) and ev.stream_ended:
                    self._done(ev.stream_id)
            return
        if isinstance(event, StreamDataReceived) and event.stream_id in self._bufs:
            self._bufs[event.stream_id] += event.data
            if event.end_stream:
                self._done(event.stream_id)
        elif isinstance(event, StreamReset) and event.stream_id in self._waiters:
            fut = self._waiters.pop(event.stream_id)
            if not fut.done():
                fut.set_exception(RuntimeError(f"stream {event.stream_id} reset"))

    def _done(self, sid):
        fut = self._waiters.pop(sid, None)
        if fut is not None and not fut.done():
            fut.set_result(bytes(self._bufs.pop(sid)))


def config(alpn, tickets, ticket=None):
    c = QuicConfiguration(is_client=True, alpn_protocols=alpn,
                          verify_mode=ssl.CERT_NONE, server_name="server")
    c.session_ticket = ticket
    return c


async def fetch(args, alpn, files, ticket=None, early=False, tickets=None, parallel=0):
    conf = config(alpn, tickets, ticket)

    def on_ticket(t):
        if tickets is not None:
            tickets.append(t)

    async with connect(args.host, args.port, configuration=conf,
                       create_protocol=HqClient, session_ticket_handler=on_ticket,
                       wait_connected=not early) as client:
        if alpn == H3_ALPN:
            client.use_h3()
        out = {}
        step = parallel or len(files)
        for i in range(0, len(files), step):
            batch = files[i:i + step]
            futs = [client.get("/" + f) for f in batch]
            for f, fut in zip(batch, futs):
                out[f] = await asyncio.wait_for(fut, timeout=args.timeout)
        resumed = client._quic.tls.session_resumed
        early_ok = client._quic.tls.early_data_accepted
        await asyncio.sleep(0.3)  # let the ticket / final ACKs arrive
        return out, resumed, early_ok


def check(args, got):
    for name, body in got.items():
        want = open(os.path.join(args.www, name), "rb").read()
        if body != want:
            sys.exit(f"FAIL {name}: got {len(body)} bytes, want {len(want)}")


def make_files(args, sizes):
    names = []
    for i, n in enumerate(sizes):
        name = f"f{i}_{n}"
        path = os.path.join(args.www, name)
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(os.urandom(n))
        names.append(name)
    return names


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--www", required=True)
    ap.add_argument("--case", required=True)
    ap.add_argument("--timeout", type=float, default=60)
    args = ap.parse_args()
    hq = ["hq-interop"]
    c = args.case
    if c in ("handshake", "retry"):
        got, _, _ = await fetch(args, hq, make_files(args, [1024, 10240]))
    elif c == "transfer":
        got, _, _ = await fetch(args, hq, make_files(args, [2 << 20, 3 << 20, 5 << 20]))
    elif c == "multiplexing":
        got, _, _ = await fetch(args, hq, make_files(args, [32] * 300))
    elif c == "http3":
        got, _, _ = await fetch(args, H3_ALPN, make_files(args, [5120, 10240, 512000]))
    elif c in ("resumption", "zerortt"):
        tickets = []
        files = make_files(args, [5120, 10240, 32, 33, 34])
        got, _, _ = await fetch(args, hq, files[:1], tickets=tickets)
        if not tickets:
            sys.exit("FAIL no session ticket received")
        got2, resumed, early = await fetch(args, hq, files[1:], ticket=tickets[-1],
                                           early=(c == "zerortt"))
        if not resumed:
            sys.exit("FAIL second connection did not resume")
        if c == "zerortt" and not early:
            sys.exit("FAIL 0-RTT not accepted")
        got.update(got2)
    else:
        sys.exit(f"unknown case {c}")
    check(args, got)
    print(f"OK {c}: {len(got)} files")


if __name__ == "__main__":
    asyncio.run(main())
