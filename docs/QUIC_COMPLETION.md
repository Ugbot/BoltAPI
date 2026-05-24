# QUIC — completion punch-card

What's left to make our QUIC stack a *complete, browser- and relay-grade* transport.
Foundation for HTTP/3 **and** WebTransport. Tiger Style throughout (bounded, noexcept,
≥2 asserts/fn, no exceptions, zero warnings). Verify with aioquic (have) + Chrome via
the **chrome-devtools MCP** + the QUIC Interop Runner.

Status: `[x]` done · `[~]` partial · `[ ]` todo.

## Where we are (done, committed)
- [x] RFC 9000 primitives: varint, packet headers, frames, PN spaces, ACK ranges.
- [x] RFC 9001 packet protection: HKDF + AEAD (AES-128/256-GCM, ChaCha20) + header
      protection; cipher-suite-aware key schedule (SHA-256/384). App. A byte-exact.
- [x] TLS 1.3 QUIC handshake over OpenSSL 3.6 native QUIC-TLS callbacks; transport
      params (incl. ISCID/ODCID §7.3, max_datagram_frame_size §RFC9221).
- [x] RFC 9002 loss recovery + NewReno; streams (send/recv state machines, ordered
      reassembly, RESET/STOP_SENDING); per-stream + connection flow control.
- [x] Robustness: Version Negotiation, Retry + token + 3× anti-amplification,
      CONNECTION_CLOSE/Closing/Draining, idle timeout, stateless reset, key update,
      GREASE tolerance, seeded packet fuzz.
- [x] **Interop proven vs aioquic** (independent stack): full handshake + HTTP/3
      GET/POST + WebTransport CONNECT→200.
- [x] Cert: process-stable ECDSA P-256, ≤14-day server identity (`shared_server_identity`),
      `server_cert_sha256()` for WebTransport pinning.

## P0 — Chrome handshake completion  (THE current blocker; #45)
Diagnosed via the chrome-devtools MCP + QUIC trace: with a fresh connection + the
Uint8Array cert pin, TLS advances cleanly (`failed=0`, cert accepted), but **Chrome
stays at the Initial level** — it re-sends Initials and never processes the server's
ServerHello, so 1-RTT is never reached. aioquic advances on the same flight; Chrome
does not.
- [ ] **ACK the peer's Initial/Handshake packets in the server's own first flight.**
      The server's ServerHello Initial (99 B) currently has no room for an ACK frame.
      Emit ACK frames per PN space so Chrome stops retransmitting and advances. Audit
      `flush()`/ACK-eliciting logic: an ACK must ride the Initial that carries the
      ServerHello (and the Handshake packet that carries Cert/Finished).
- [ ] **Coalesce** Initial(ServerHello) + Handshake(Cert/CertVerify/Finished) (+ 1-RTT
      when ready) into a single UDP datagram (RFC 9000 §12.2). The server currently
      sends them as separate datagrams; Chrome prefers/▸expects coalescing.
- [ ] Re-check anti-amplification (3×) and PN spaces don't stall the first flight.
- [ ] Gate: Chrome (chrome-devtools MCP) completes the QUIC handshake to `Established`
      and `wt.ready` resolves; aioquic stays green.

## P0 — Multi-connection server demux  (#42; blocks ANY multi-client / relay use)
Today the H3/WebTransport endpoint drives ONE `QuicConnection` with a reset-on-Initial
heuristic; it wedges under a real browser's retransmits and can't serve >1 peer.
- [ ] Per-DCID **connection table** (bounded, `bolt::SwissTable` DCID→slot; fixed pool).
- [ ] On inbound: parse DCID, route to the owning connection; an Initial with an unknown
      DCID + valid form **creates** a new connection (subject to Retry/anti-amp).
- [ ] Retire connections on close/idle; bounded count; per-connection peer address.
- [ ] Remove the single-peer reset hack in `App::start_http3` / `http3_new_connection_`.
- [ ] Gate: 2+ concurrent QUIC clients (aioquic ×N) served simultaneously; Chrome retries
      don't wedge; sequential + concurrent both clean.

## P1 — QUIC DATAGRAM frames (RFC 9221)  (enables WebTransport datagrams)
- [ ] Parse + emit DATAGRAM frames (0x30 no-length / 0x31 length-prefixed); deliver to
      the app; respect `max_datagram_frame_size` both ways; bounded recv queue.
- [ ] App/connection API: `send_datagram()` / `on_datagram()`. No per-packet malloc.
- [ ] Gate: aioquic + Chrome datagram echo round-trip.

## P2 — Advanced transport
- [ ] 0-RTT / session resumption (RFC 9001 §4.6): session tickets, early data, remembered
      transport params. (Big throughput win for relays/reconnects.)
- [ ] Connection migration + path validation (PATH_CHALLENGE/RESPONSE, §9).
- [ ] Multiple connection IDs (NEW/RETIRE_CONNECTION_ID), preferred address; full
      stateless-reset emission.
- [ ] ECN; GREASE versions/params emission (not just tolerance).

## P3 — Performance (correctness-gated; measure-or-revert)
- [~] Inline I/O-thread datagram processing (done for the UDP path).
- [ ] Batched UDP recv/send (recvmmsg/sendmmsg/WSARecvMsg; GSO/GRO) — measure under a
      *multi-connection* bench (single-conn showed no win).
- [ ] Zero-copy framing via `bolt::wire`; per-connection `bolt::SwissTable`; per-packet
      `bolt::Arena`; pacing (token bucket). No malloc on the data path.
- [ ] `benchmarks/quic_throughput_bench.cpp` exists; extend to many-connection.

## P4 — Interop + CI
- [ ] **QUIC Interop Runner** matrix rows vs quiche / ngtcp2 / picoquic / msquic
      (handshake, transfer, retry, resumption, multiplexing).
- [ ] Browser (Chrome + Firefox) H3 via the chrome-devtools MCP; curl --http3 smoke.
- [ ] CI leg (WITH_HTTP3=ON) runs unit + loopback + bounded interop (skip-if-absent).

**Order:** P0 handshake-ACK/coalesce → P0 multi-connection demux → P1 DATAGRAM →
P4 browser/interop gates → P2 advanced → P3 perf. P0 unblocks Chrome HTTP/3 **and**
WebTransport; multi-connection unblocks the relay/SFU use cases.
