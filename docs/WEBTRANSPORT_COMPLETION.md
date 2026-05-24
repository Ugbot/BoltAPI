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

## P0 — Browser session establishment  ✅ DONE — Chrome wt.ready RESOLVES
- [x] QUIC_COMPLETION P0 done: Chrome completes the QUIC+TLS handshake to
      **Established** (coalesce #45 + out-of-order CRYPTO reassembly + WT-compliant
      leaf cert; cert pin verified). #42 multi-connection done.
- [x] **The missing setting**: Chrome 148 needs the draft-02
      `SETTINGS_ENABLE_WEBTRANSPORT` (0x2b603742)=1 IN ADDITION to the draft-07+
      `SETTINGS_WT_MAX_SESSIONS` (0x14e9cd29). With only the latter, Chrome returned
      `ERR_METHOD_NOT_SUPPORTED` and never sent CONNECT. Emitting BOTH (cross-draft)
      makes Chrome open the WebTransport session. (enable_connect_protocol 0x08 +
      h3_datagram 0x33 + QUIC max_datagram_frame_size were already correct.)
- [x] Gate MET: chrome-devtools MCP — `new WebTransport(url,{serverCertificateHashes})`
      → **READY**. Server trace: `WT-CONNECT? decode=1 method='CONNECT'
      protocol='webtransport' path='/wt'` → 200; page logs "READY — WebTransport
      session open". The full path works end-to-end with real Chrome:
      QUIC+TLS handshake → H3 SETTINGS → Extended CONNECT → 200 → wt.ready.

## P1 — Datagrams  ✅ DONE (committed c37baf2) — Chrome datagram echo round-trips
- [x] QUIC DATAGRAM frames (RFC 9221): parse 0x30/0x31 + `send_datagram()` honoring
      the peer's `max_datagram_frame_size` (quic/connection.h; frame types were declared
      but unimplemented).
- [x] H3 datagram framing (RFC 9297): quarter-stream-id prefix (= session CONNECT
      stream id / 4) maps a QUIC DATAGRAM to the WT session; server echoes it back to
      that session (demo shape).
- [~] App API: not yet exposed — the demo echoes inside h3_connection.h. A proper
      `session.send_datagram`/`on_datagram` App callback is the follow-up.
- [x] Gate: loopback `QuicDatagram.RoundTripEcho` (deterministic) + **Chrome (MCP)
      datagram echo round-trip** (webtransport.html sends 'bolt-wt-ping' → echo received).

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
