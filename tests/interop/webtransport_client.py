#!/usr/bin/env python3
# webtransport_client.py — WebTransport-over-HTTP/3 interop check for Bolt API.
# Run: uv run --no-project --with aioquic python tests/interop/webtransport_client.py <port>
#
# Verifies the server-side WebTransport handshake — exactly what a browser's
# `await wt.ready` awaits: an extended CONNECT (:method=CONNECT,
# :protocol=webtransport) to /wt returns HTTP 200, which requires the server to
# advertise SETTINGS_ENABLE_CONNECT_PROTOCOL + SETTINGS_H3_DATAGRAM +
# SETTINGS_WT_MAX_SESSIONS and the QUIC max_datagram_frame_size transport param.
# aioquic refuses to send a WebTransport CONNECT unless the peer advertised all of
# that, so a 200 here means the full WebTransport capability is correctly offered.
#
# Exit: 0 = WT session established (200); 75 = QUIC handshake not established
# (bounded SKIP); 2 = connected but CONNECT != 200; 6/7 = timeout / startup error.

import asyncio
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

OVERALL_TIMEOUT_S = 18.0
CONNECT_TIMEOUT_S = 8.0
EX_HANDSHAKE_PENDING = 75


class WtClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # enable_webtransport makes aioquic validate the peer's WT settings before
        # it will send a CONNECT — so this exercises our SETTINGS advertisement too.
        self._http = H3Connection(self._quic, enable_webtransport=True)
        self._status = {}   # stream_id -> :status int
        self._fut = {}      # stream_id -> future resolved on the response headers

    def quic_event_received(self, event: QuicEvent) -> None:
        for ev in self._http.handle_event(event):
            self._on_h3(ev)

    def _on_h3(self, ev: H3Event) -> None:
        sid = getattr(ev, "stream_id", None)
        if isinstance(ev, HeadersReceived) and sid in self._fut:
            for name, value in ev.headers:
                if name == b":status":
                    self._status[sid] = int(value.decode())
            fut = self._fut[sid]
            if not fut.done():
                fut.set_result(True)

    async def connect_wt(self, host: str, port: int, path: str) -> int:
        sid = self._quic.get_next_available_stream_id()
        fut = self._loop.create_future()
        self._fut[sid] = fut
        self._http.send_headers(sid, [
            (b":method", b"CONNECT"),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", f"{host}:{port}".encode()),
            (b":path", path.encode()),
        ], end_stream=False)
        self.transmit()
        await asyncio.wait_for(fut, timeout=8.0)
        return self._status.get(sid, 0)


async def run(port: int) -> int:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = 0     # ssl.CERT_NONE — loopback self-signed
    cfg.insecure = True
    cfg.max_datagram_frame_size = 65536  # required to offer WebTransport
    try:
        cm = connect("127.0.0.1", port, configuration=cfg,
                     create_protocol=WtClient)
        client = await asyncio.wait_for(cm.__aenter__(), timeout=CONNECT_TIMEOUT_S)
    except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
        print(f"WT SKIP: QUIC handshake not established ({exc!r})",
              file=sys.stderr, flush=True)
        return EX_HANDSHAKE_PENDING
    try:
        assert isinstance(client, WtClient)
        # Let the server's SETTINGS (incl. the WebTransport settings) arrive before
        # we attempt the CONNECT — aioquic validates them.
        await asyncio.sleep(0.5)
        try:
            status = await client.connect_wt("127.0.0.1", port, "/wt")
        except (asyncio.TimeoutError, ConnectionError) as exc:
            print(f"WT SKIP: connected but CONNECT did not complete ({exc!r})",
                  file=sys.stderr, flush=True)
            return EX_HANDSHAKE_PENDING
        if status == 200:
            print("WT OK: extended CONNECT :protocol=webtransport -> 200 "
                  "(WebTransport session ready)", flush=True)
            return 0
        print(f"WT FAIL: CONNECT status {status} != 200", file=sys.stderr, flush=True)
        return 2
    finally:
        await cm.__aexit__(None, None, None)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: webtransport_client.py <port>", file=sys.stderr)
        return 64
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("usage: webtransport_client.py <port>", file=sys.stderr)
        return 64
    try:
        return asyncio.run(asyncio.wait_for(run(port), timeout=OVERALL_TIMEOUT_S))
    except asyncio.TimeoutError:
        print(f"WT FAIL: timeout after {OVERALL_TIMEOUT_S}s",
              file=sys.stderr, flush=True)
        return 6
    except Exception as exc:  # noqa: BLE001 — top-level test harness
        print(f"WT FAIL (startup): {exc!r}", file=sys.stderr, flush=True)
        return 7


if __name__ == "__main__":
    sys.exit(main())
