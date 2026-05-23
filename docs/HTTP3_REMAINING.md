# HTTP/3 — Remaining Work (ordered punch-card)

> Execute top-to-bottom. Each wave: correctness-gated, default `ctest` stays green,
> committed + pushed. Tiger Style, prefer Bolt, OpenSSL for crypto only.
> Detailed design + decision log: `docs/HTTP3_PLAN.md`.

## Done (waves 1–4, committed)
- [x] **W1** QUIC primitives — varint, packet headers, frames, PN spaces, ACK (RFC 9000 vectors).
- [x] **W2** Packet protection — HKDF + AEAD + header protection (RFC 9001 Appendix A byte-exact).
- [x] **W3** TLS 1.3 QUIC handshake — OpenSSL 3.6 QUIC-TLS callbacks + transport params (in-proc handshake, matching secrets).
- [x] **W4** QUIC connection — real handshake to Established over UDP loopback, both roles, ALPN h3, 1-RTT round-trip.

## W5a — QUIC transport completion  *(in progress)*
- [~] RFC 9002 loss recovery (RTT/PTO, ACK + time/packet-threshold loss detection, retransmit CRYPTO+STREAM).
- [~] NewReno congestion control (cwnd/ssthresh, slow start/avoidance/recovery; in-flight gating).
- [~] QUIC streams — bidi/uni, STREAM frames, ordered reassembly, RESET_STREAM/STOP_SENDING, MAX_STREAMS.
- [~] Flow control — per-stream + connection (MAX_DATA/MAX_STREAM_DATA/*_BLOCKED), window updates.
- [~] Gate: loopback stream echo (multi-KB, byte-exact, FIN) + lossy-link completes via retransmit + flow-control no-deadlock.

## W5b — QPACK + HTTP/3 frames + App bridge  *(the "serves requests" wave)*
- [x] **QPACK** (RFC 9204): static table, Huffman, encoder + decoder, encoder/decoder streams, dynamic table (static + literal; bounded dynamic table). PORTED FasterAPI `qpack/*` → `boltapi/http3/{qpack,qpack_static_table,qpack_huffman}.h`.
- [x] **HTTP/3 frame layer** (RFC 9114): `boltapi/http3/frame.h` — control stream + SETTINGS (QPACK_MAX_TABLE_CAPACITY / MAX_FIELD_SECTION_SIZE / QPACK_BLOCKED_STREAMS), HEADERS, DATA, GOAWAY/CANCEL_PUSH/MAX_PUSH_ID types; uni-stream type prefixes (control, push, QPACK enc/dec); bounded frame reader/writer over `quic/varint.h`. Header-only, compiles unconditionally.
- [x] **Bridge**: `boltapi/http3/h3_connection.h` — a client-initiated bidi stream's HEADERS(+DATA) → QPACK-decode pseudo-headers (:method/:path/:scheme/:authority) + regular headers + accumulate DATA body → `H3Request` → App `dispatch_http3()` (the SAME router + middleware + handler the H1/H2 path uses, factored into `App::dispatch_coro_`) → QPACK-encode :status + headers as HEADERS + body as DATA back on the stream, then FIN. Bounded fixed-capacity per-stream pool (no unbounded growth).
- [x] App/seam wiring: `App::enable_http3()` + `App::start_http3()` bring a real QUIC server endpoint up on a UDP port (sharing `net::UdpTransport`) and bridge decoded requests through the shared dispatch path; `register_http3` keeps the `ProtocolRegistry` path exercised (the registry stub stays NotImplemented at the *seam* level by design — the real serving is App-direct, mirroring the WebRTC wiring). Gated by `BOLTAPI_WITH_HTTP3`; the frame/h3 headers + `dispatch_http3` stay unconditional so the gate runs in the default suite.
- [x] Gate: loopback our-client ↔ our-server (`tests/http3_app_test.cpp`, default suite) — `app.get("/ping")`→200 "pong", `app.post("/echo")`→byte-exact echo of an 8 KB randomized body, and a 404 for an unrouted path, all answered over real HTTP/3 (QPACK HEADERS + DATA over QUIC) status + body byte-exact. Bounded by wall-clock deadlines (no hang).

## W5c — Real interop
- [ ] **curl --http3** smoke against the demo server (curl built with HTTP/3, or via uv-run a client).
- [ ] **quiche** and/or **nghttp3** client interop (independent stacks — the real gate, like aiortc for WebRTC).
- [ ] **Chrome/Firefox** HTTP/3 (needs valid cert + **Alt-Svc** advertised from the H1/H2 server: `alt-svc: h3=":443"`).
- [ ] Wire H3 into `examples/demo_server.cpp` + a `testing/` page/script; GTEST_SKIP gating when clients absent.
- [ ] Add to the QUIC Interop Runner test matrix (handshake, transfer, retry, resumption rows).

## W5d — Protocol robustness
- [ ] Version Negotiation packet (server) + handling (client).
- [ ] Retry packet + token validation (anti-amplification address validation, RFC 9000 §8).
- [ ] Stateless reset; idle timeout; CONNECTION_CLOSE (app + transport) + draining; key update (RFC 9001 §6).
- [ ] Anti-amplification limit (3×) before address validation; ECN (optional); GREASE tolerance.
- [ ] Packet-parser fuzzing + malformed-input hardening (bounded, never UB).

## W5e — Advanced (optional / later)
- [ ] 0-RTT + session resumption (early data; transport-params remembered).
- [ ] Connection migration + path validation (PATH_CHALLENGE/RESPONSE).
- [ ] QUIC DATAGRAM frames (RFC 9221) — enables WebTransport later.
- [ ] Multiple connection IDs (NEW/RETIRE_CONNECTION_ID); preferred address.

## W5f — Performance
- [ ] Process QUIC packets **inline on the I/O thread** (no per-packet worker hop — same fix as UDP/STUN); decrypt + demux inline, hand only app work to workers.
- [ ] Batched UDP recv/send (recvmmsg/sendmmsg; WSARecvMsg; GSO/GRO/ECN).
- [ ] Zero-copy packet framing via `bolt::wire`; per-conn/stream `bolt::SwissTable`; per-packet `bolt::Arena`; no malloc on the data path; pacing.
- [ ] Bench vs quiche/nghttp3 (handshake/s, 1-RTT throughput, CPU/byte); compare to our H1/H2 numbers.

## W5g — Consolidation
- [ ] CI: H3 build leg (BOLTAPI_WITH_HTTP3=ON) runs the QUIC unit + loopback + interop(skip-if-absent) tests on the matrix.
- [ ] Docs: README HTTP/3 section; fold this punch-card's done items back into PROJECT_MAP + HTTP3_PLAN; remove HTTP3_REMAINING when complete.

---
**Order:** W5a → W5b (HTTP/3 serves requests) → W5c (interop proof) → W5d (robustness) → W5f (perf) → W5e (advanced, as needed) → W5g (consolidate). W5b is the milestone that makes HTTP/3 *real*; W5c proves it against the world.
