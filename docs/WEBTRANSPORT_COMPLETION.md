# WebTransport — completion punch-card

Full WebTransport-over-HTTP/3: browser `wt.ready` → datagrams + bidi/uni streams,
multiple sessions. Builds on QUIC (`docs/QUIC_COMPLETION.md`) and the cert work
(`docs/WEBTRANSPORT_CERT_PLAN.md`). Tiger Style; verify with aioquic, Pion
(webtransport-go), and Chrome via the **chrome-devtools MCP**.

Status: `[x]` done · `[~]` partial · `[ ]` todo.

## Where we are (done, committed)
- [x] Extended CONNECT (`:method=CONNECT`, `:protocol=webtransport`) handled in
      `h3_connection.h`: HEADERS-without-FIN detected, answered **200**, the bidi
      stream kept open as the session. **aioquic-proven** (`WT OK → 200`).
- [x] H3 SETTINGS advertise `ENABLE_CONNECT_PROTOCOL` (RFC 9220) + `H3_DATAGRAM`
      (RFC 9297) + `WT_MAX_SESSIONS`; QUIC `max_datagram_frame_size` (RFC 9221).
- [x] `serverCertificateHashes`: stable ≤14-day ECDSA P-256 cert + `/wt/cert-hash`;
      page pins it (must pass a **Uint8Array** — ArrayBuffer is silently ignored).
      Verified via the MCP: Chrome **honors the pin** (no cert reject).

## P0 — Browser session establishment  (blocked on QUIC P0)
- [ ] Depends on `QUIC_COMPLETION` P0 (Chrome handshake completion: ACK + coalesce).
      Once Chrome reaches `Established`, `wt.ready` should resolve (cert pin already
      works). **This turns the test-page WebTransport pill green.**
- [ ] Depends on `QUIC_COMPLETION` P0 multi-connection demux (#42) so Chrome's retries
      don't wedge the endpoint.
- [ ] Gate: chrome-devtools MCP — `new WebTransport(url,{serverCertificateHashes})` →
      `READY`.

## P1 — Datagrams  (needs QUIC DATAGRAM, RFC 9221 + H3 DATAGRAM, RFC 9297)
- [ ] H3 datagram framing: quarter-stream-id prefix mapping a QUIC DATAGRAM to the WT
      session's CONNECT stream (RFC 9297 §2.1 / WT-over-H3 draft).
- [ ] App API: `session.send_datagram(bytes)` / `on_datagram(cb)`; bounded queues.
- [ ] Gate: aioquic + Chrome (MCP) datagram echo round-trip.

## P2 — Streams (session-associated bidi/uni)
- [ ] Uni-stream type `0x54` (WT uni) + bidi signal value `0x41` with the session id
      prefix (WebTransport-over-HTTP/3 draft); route stream data to the right session.
- [ ] App API: `session.open_bidi()/open_uni()`, `on_stream(cb)`, stream read/write
      over the existing QUIC stream layer with flow control.
- [ ] Gate: aioquic + Chrome echo on a WT bidi stream (text + large binary).

## P3 — Session lifecycle + multiplexing
- [ ] Capsule protocol (RFC 9297): `CLOSE_WEBTRANSPORT_SESSION` / `DRAIN_WEBTRANSPORT_SESSION`.
- [ ] Multiple concurrent sessions per connection (route by CONNECT stream id);
      `WT_MAX_SESSIONS` accounting; clean teardown.
- [ ] `App::on_webtransport(path, handler)` mirroring `on_data_channel`; per-session
      object exposing datagrams + streams.
- [ ] GOAWAY / graceful shutdown.

## P4 — Interop + examples
- [ ] Pion `webtransport-go` peer (bounded, skip-if-absent via `bounded_proc.h`).
- [ ] aiortc/aioquic WebTransport client scripts in `tests/interop/` (extend
      `webtransport_client.py` to datagrams + streams).
- [ ] Browser demo: `testing/web/` WebTransport echo + datagram + stream page (MCP-tested).
- [ ] CI WITH_HTTP3 leg runs the WT gates (skip-if-absent).

## Notes
- WebTransport rides the SAME QUIC + H3 stack; nearly all remaining work is QUIC P0/P1
  (handshake completion + DATAGRAM + multi-connection) plus the thin WT framing layers.
- Later: WebTransport can carry **media** (WebCodecs + WT) as an alternative to WebRTC
  for some relay shapes — but the classic browser-relay path is WebRTC (see
  `docs/WEBRTC_RELAY_PLAN.md`).

**Order:** QUIC P0 (handshake) → P0 browser ready (pill green) → P1 datagrams →
P2 streams → P3 sessions/multiplexing → P4 interop. The pill goes green at "P0 browser
ready"; everything after makes WebTransport *useful*.
