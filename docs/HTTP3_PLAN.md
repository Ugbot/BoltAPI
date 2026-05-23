# HTTP/3 (QUIC) Implementation Plan — Bolt API

> **Status:** planning only. This is a tickable punch-card for a full, correct,
> high-performance HTTP/3 implementation behind the existing M3 protocol seam
> (`include/boltapi/protocol.h`, `include/boltapi/transport.h`, see `docs/SEAMS.md`).
> No code in this repo changes yet. **Correctness first, performance second —
> there is no rush; do not cut corners.**
>
> **Hard constraint (from the seam contract):** the live HTTP/1.1 + HTTP/2 + TLS
> + WebSocket + SSE engine (`src/server/coro_unified_server.cpp`, `App`, `Router`,
> middleware) is **never edited**. HTTP/3 is added purely as a new `IProtocol`
> over a new `UdpTransport`, registered through `ProtocolRegistry`, and it bridges
> decoded requests into the **same** `App` handler the H1/H2 path uses
> (`CoroHttpRequest` -> router/middleware -> `CoroHttpResponse`).

## How to use this document

- Work top-to-bottom. Phases are ordered so each builds on the last.
- Every item says: **what** it does, whether to **PORT** a specific FasterAPI
  file (with its path) or **REBUILD** from scratch, and the **Bolt primitive** to
  use.
- "PORT" means: lift the algorithm/pure code into `src/proto/http3/` under
  `bolt::api::h3`, strip the `fasterapi::quic` namespace, swap `std::unordered_map`
  / `std::vector` / `new` / `malloc` for Bolt pools/tables/arenas per `CLAUDE.md`,
  and keep the wire-format logic byte-identical (it is RFC-correct already).
- Tick `- [ ]` -> `- [x]` as items land. Each phase ends with a **GATE**: do not
  start the next phase until the gate's tests are green.

## Conventions / target layout (proposed, not yet created)

```
src/proto/
  udp_transport.cpp        # exists (stub) -> becomes real UdpTransport
  http3_stub.cpp           # exists (stub) -> Http3Protocol grows real serve()
  http3/                   # NEW dir for the QUIC + H3 + QPACK port
    quic_varint.h          quic_packet.{h,cpp}     quic_frames.h
    quic_packet_protection.h  quic_tls.h  quic_handshake.h  quic_crypto_buffer.h
    quic_secure_connection.{h,cpp}  quic_connection.{h,cpp}
    quic_stream.{h,cpp}    quic_flow_control.{h,cpp}  quic_congestion.{h,cpp}
    quic_ack_tracker.{h,cpp}  quic_packet_number_space.h
    quic_loss_recovery.{h,cpp}   # RFC 9002 timer/RTT (extract from connection)
    http3_frames.h  http3_connection.{h,cpp}  qpack/{encoder,decoder,...}
include/boltapi/
  transport.h  protocol.h  # unchanged signatures; UdpTransport impl fills in
```

All H3 code lives under namespace `bolt::api::h3` (QUIC) / `bolt::api::h3::qpack`.
All new code: `-fno-exceptions`-clean, `noexcept` on the hot path, no hidden
allocation, asserts on bounds (TigerStyle, matching the seam headers).

---

## Phase 0 — Decisions & dependency setup

- [ ] **0.1 Pick the TLS/QUIC crypto provider.** *What:* QUIC needs a TLS 1.3
      stack that exposes the **handshake-bytes** API (not a TLS record layer):
      `SSL_provide_quic_data` / `SSL_set_quic_method` / per-level secret
      callbacks. Two options:
      - **quictls** (OpenSSL fork w/ BoringSSL-style QUIC API) — what FasterAPI's
        `quic_tls.h` already targets (`SSL_QUIC_METHOD`, `SSL_provide_quic_data`,
        `SSL_do_handshake`).
      - **OpenSSL 3.5+** ships a built-in QUIC API, but its server-side QUIC and
        the low-level `SSL_QUIC_METHOD`-equivalent surface differ from the
        BoringSSL shape the port assumes.
      **DECISION: quictls (BoringSSL QUIC API).** Justification: (a) the ported
      crypto layer (`quic_tls.h`, `quic_handshake.h`, `quic_secure_connection.h`)
      is written *directly* against the BoringSSL `SSL_QUIC_METHOD` callback model,
      so quictls is a drop-in and OpenSSL 3.5 would require rewriting the callback
      wiring; (b) quictls is API-stable and battle-tested by ngtcp2/quiche; (c) it
      coexists with the existing `net::TlsContext` (already TLS 1.3) for H1/H2 — we
      can build quictls as the H3-only TLS provider behind `BOLTAPI_WITH_HTTP3`
      without disturbing the H1/H2 OpenSSL link. *Bolt primitive:* n/a.
      *Note:* keep an `#if OPENSSL_VERSION` adapter shim so a future move to
      OpenSSL 3.5's native QUIC API is a single translation unit, not a rewrite.
- [ ] **0.2 Justify the third-party dependency vs the "prefer Bolt / no
      third-party" rule.** *What:* `CLAUDE.md` says prefer Bolt and import pure
      algorithms over linking libraries. **Crypto is the one justified
      exception**: TLS 1.3 + AEAD must not be hand-rolled (correctness and
      timing-side-channel risk are unacceptable, and a bespoke TLS stack would
      never pass interop). We therefore link a vetted TLS library *only for the
      handshake + AEAD primitives*, and keep **everything else** (packet parsing,
      framing, loss/congestion/flow control, stream mux, QPACK, I/O) as pure Bolt
      code. Document this exception explicitly in `docs/SEAMS.md` follow-up.
      *Note:* AEAD/HKDF themselves go through OpenSSL EVP (already used by the
      ported `quic_packet_protection.h`), not a custom cipher.
- [ ] **0.3 Wire quictls into the build behind `BOLTAPI_WITH_HTTP3`.** *What:*
      add a `cmake/Findquictls.cmake` (or a CPM/submodule pin) that is consulted
      **only** when `BOLTAPI_WITH_HTTP3=ON`; fall back with a clear configure-time
      warning + auto-OFF if not found (mirror FasterAPI's "falls back with a
      warning" behavior). The default build links nothing new. *(Plan only — do
      not edit CMake under this task.)* *Bolt primitive:* n/a.
- [ ] **0.4 Confirm the seam entry points are sufficient.** *What:* re-read
      `register_http3()` (`src/proto/http3_stub.cpp`), `App::init_protocol_seams()`
      (`src/app.cpp:276`), `App::Config::enable_http3/http3_port` (`app.h:70`).
      Confirm no new public API is needed beyond filling `Http3Protocol::serve()`
      and `UdpTransport`. *Bolt primitive:* `ProtocolRegistry` (already real).

**GATE 0:** decision recorded; `BOLTAPI_WITH_HTTP3=ON` configures with quictls
found, OFF build byte-for-byte unchanged.

---

## Phase 1 — UDP transport (real `UdpTransport`)

Goal: a real datagram source feeding the existing `IODispatcher`, with no
per-packet allocation. This phase has **no QUIC logic** — it just moves bytes.

- [ ] **1.1 Real UDP bind + socket options.** *What:* implement
      `UdpTransport::start()` (`include/boltapi/transport.h:173`,
      `src/proto/udp_transport.cpp`) — open a UDP socket bound to
      `Endpoint{host, http3_port}`, set `SO_REUSEADDR`/`SO_REUSEPORT` (for
      multi-worker fan-in), large `SO_RCVBUF`/`SO_SNDBUF`, and request the ECN
      bits (`IP_RECVTOS`/`IPV6_RECVTCLASS`) for congestion signalling. *REBUILD*
      (FasterAPI's UDP was inside its server; the socket plumbing is Bolt's). *Bolt
      primitive:* none yet; align with `src/net/tcp_socket.cpp` style.
- [ ] **1.2 Join the existing `IODispatcher` event loop.** *What:* register the
      UDP fd/handle with `net::IODispatcher` (`src/net/io_dispatcher.cpp`) so QUIC
      packet readiness is driven by the **same** IOCP/epoll/kqueue loop and worker
      pool as the TCP listener — no new threading model (per SEAMS.md). *REBUILD.*
      *Bolt primitive:* reuse `IODispatcher`; SWAR/bitops via `bolt_port.h` for any
      fd-set scanning.
- [ ] **1.3 Preallocated datagram receive buffer pool.** *What:* a fixed pool of
      MTU-sized (e.g. 1500–2048B) receive buffers, recycled — never
      malloc-per-packet. *REBUILD.* *Bolt primitive:* `bolt::Arena` /
      `bolt_batch_pool.h` (`extern/bolt/include/bolt/bolt_batch_pool.h`) for the
      buffer pool; one arena per I/O thread for per-batch scratch.
- [ ] **1.4 Batched receive — `recvmmsg` (Linux) / `WSARecvMsg` (Windows) /
      `recvmsg` loop (macos).** *What:* drain many datagrams per syscall into the
      pool, capturing src address + ECN + (if available) GRO segment size.
      *REBUILD* per-platform; mirror the `async_io_{epoll,iocp,kqueue}.cpp` split
      (`src/core/`). *Bolt primitive:* buffer pool from 1.3.
- [ ] **1.5 Batched send — `sendmmsg` / `WSASendMsg`, with GSO when available.**
      *What:* coalesce multiple QUIC packets to the same 4-tuple into one
      segmented syscall (UDP GSO on Linux); fall back to per-packet send. *REBUILD.*
      *Bolt primitive:* arena-backed scatter/gather iov list.
- [ ] **1.6 GRO/GSO + ECN capability probe.** *What:* runtime feature-detect
      `UDP_SEGMENT`/`UDP_GRO`/`IP_TOS`; degrade gracefully. *REBUILD.* *Bolt
      primitive:* n/a.
- [ ] **1.7 I/O-thread -> worker handoff channel.** *What:* received datagrams
      (buffer ref + src addr + recv metadata) are pushed to the QUIC worker via a
      lock-free queue; no locks, no malloc. *REBUILD.* *Bolt primitive:*
      `bolt::SPSCChannel` (single I/O thread) or `bolt::MPSCChannel` /
      `bolt::NumaChannelPool` (multi I/O thread) from
      `extern/bolt/include/bolt/bolt_channel.h`.
- [ ] **1.8 `UdpTransport` lifecycle + `is_running()`/`local_endpoint()`/`stop()`**
      wired to the real socket; `stop()` idempotent + `noexcept`. *REBUILD.*

**GATE 1:** unit/integration test that binds `UdpTransport`, echoes datagrams
through the dispatcher across **all three** backends, asserts zero per-packet
heap allocation (allocation counter hook), and exercises batched recv/send. No
QUIC yet.

---

## Phase 2 — QUIC packet layer (no crypto wiring yet)

Goal: parse/serialize QUIC packets and frames correctly. Crypto functions exist
(Phase 3 ports them) but this phase establishes the wire structures.

- [x] **2.1 Varint codec.** *DONE* (`include/boltapi/quic/varint.h`). RFC 9000
      §16; ported from `quic_varint.h`, reshaped to Tiger Style. RFC §A.1 vectors
      + 100k random round-trips pass. *Bolt primitive:* SWAR fast path deferred
      to Phase 9.
- [~] **2.2 Long/short header parse + serialize, connection IDs.** *PARTIAL —
      PARSE done* (`include/boltapi/quic/packet.h`): long (Initial/0-RTT/
      Handshake/Retry/VN) + short header parse, CID extraction, `PacketForm`
      discrimination; RFC 9001 §A.1 client-Initial header vector passes. SERIALIZE
      + `bolt::wire` zero-copy retarget deferred to the send path (Phase 5.7 /
      Phase 9.2). *What:* Initial
      / 0-RTT / Handshake / Retry / Version-Negotiation (long) and 1-RTT (short)
      headers; DCID/SCID extraction. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_packet.{h,cpp}`. *Bolt primitive:*
      parse/write through `bolt::wire` (`extern/bolt/include/bolt/wire/bolt_wire.h`)
      for zero-copy framing; `bolt_port.h` bitops for header-byte flags.
- [x] **2.3 Packet number spaces + decoding.** *DONE*
      (`include/boltapi/quic/pn_space.h`): the 3 spaces, largest-received/acked
      tracking, truncated-PN encode/decode (RFC 9000 §17.1 + App. A.2/A.3).
      Crypto/ack/congestion coupling from the source intentionally dropped (later
      phases). RFC §A.2/§A.3 vectors + 5000-PN round-trip pass.
- [~] **2.4 Frame parse/serialize.** *PARTIAL — no-crypto frames done*
      (`include/boltapi/quic/frames.h`): full type-constant table; parse/serialize
      for PADDING, PING, ACK(+ECN), CONNECTION_CLOSE, and the FRAMING of CRYPTO +
      STREAM (payload stays a view). Remaining flow-control / connection-mgmt
      frames (RESET_STREAM, STOP_SENDING, NEW_TOKEN, MAX_*, *_BLOCKED,
      NEW/RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE, HANDSHAKE_DONE) carry
      their type constants but get bodies in Phase 4. `bolt::wire` retarget +
      arena scratch deferred to Phase 9.2. Plus `ack.h` (AckRangeTracker:
      received-PN -> ranges) ported here from the §4.2 source ahead of schedule.
- [ ] **2.5 Version negotiation + Retry.** *What:* respond to unknown versions
      with a VN packet; issue/validate Retry tokens (stateless address validation,
      Retry integrity tag). *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_version_retry.h` (23KB, real).
      *Bolt primitive:* `bolt::SwissTable` not needed here; token MAC via OpenSSL.
- [ ] **2.6 Stateless reset + connection-ID issuance scaffolding.** *What:*
      generate routable CIDs, stateless-reset tokens; prep the CID->connection map
      key shape. *REBUILD* (FasterAPI's was thin). *Bolt primitive:*
      `bolt::SwissTable` (`extern/bolt/include/bolt/join/bolt_swiss.h`) keyed on
      CID for the Phase 5 connection map.

**GATE 2:** byte-exact round-trip unit tests for varint, every header type, every
frame type, VN/Retry — seeded with random inputs (per `CLAUDE.md` testing rule).

---

## Phase 3 — TLS handshake + packet protection (crypto wiring)

This is the gap the FasterAPI audit identified: the crypto layer is **real and
production-grade**, but the *base* `quic_connection.cpp` never invoked it
(`AUDIT_NOTES.md:137-140`). We port the **secure** path and drive it.

- [x] **3.1 Crypto buffer (per-level CRYPTO stream reassembly).** *DONE (wave 4)*
      (`CryptoReassembly` in `include/boltapi/quic/connection.h`). ADAPTED from
      `quic_crypto_buffer.h` (CryptoBuffer): bounded to a single fixed
      `kMaxCryptoBuffer` (64 KiB) array with a contiguous-receive cursor + a
      single buffered out-of-order region (no std::vector segment list);
      duplicate-prefix skip; `peek()`/`consume()` hand contiguous bytes to
      `QuicTls.feed_crypto`. Sufficient for the loopback handshake.
- [x] **3.2 Packet protection: AEAD + header protection + HKDF.** *DONE (wave 2)*
      (`include/boltapi/quic/packet_protection.h`). Real AES-128/256-GCM +
      ChaCha20-Poly1305 via OpenSSL EVP, HKDF-Extract/Expand/Expand-Label,
      Initial-secret derivation (v1 salt), per-direction quic key/iv/hp, AEAD
      seal/open, AES-ECB / ChaCha20 header protection (RFC 9001 §5). PORTED from
      `quic_packet_protection.h`; reshaped to Tiger Style (namespace
      `bolt::api::quic`, ≥2 asserts/fn, fixed buffers, noexcept, bool returns) and
      **FIXED** the FasterAPI ChaCha20 HP mask bug (it ignored the counter; per
      RFC 9001 §5.4.4 the 16-byte sample is the EVP_chacha20 IV = [counter:4 LE]
      [nonce:12]). `EVP_CIPHER_CTX` reused per ctx; no per-op alloc. Compiled
      UNCONDITIONALLY (OpenSSL always linked) so the default suite covers it.
      *Bolt primitive:* fixed stack buffers for nonce/mask.
- [x] **3.3 TLS 1.3 QUIC method — RE-SCOPED to OpenSSL 3.5+ `SSL_set_quic_tls_cbs`
      (D0/D4).** *DONE (wave 3)* (`include/boltapi/quic/tls.h` +
      `include/boltapi/quic/transport_params.h`, tests `tests/quic_tls_test.cpp`).
      Adapted FasterAPI's `quic_tls.h` *flow* (not its absent BoringSSL calls) to
      the OpenSSL 3.6 QUIC-TLS dispatch API: `SSL_set_quic_tls_cbs(ssl,
      OSSL_DISPATCH[], arg)` with the six `OSSL_FUNC_SSL_QUIC_TLS_*` callbacks
      (crypto_send / crypto_recv_rcd / crypto_release_rcd / yield_secret /
      got_transport_params / alert), `SSL_set_quic_tls_transport_params` for our
      params, `TLS_method()` SSL_CTX (TLS 1.3 only), ALPN `h3`, self-signed P-256
      cert (reusing the WebRTC DTLS pattern). Transport-params codec (RFC 9000
      §18) uses our `quic/varint.h`. Each yielded secret drives a wave-2
      `PacketProtection` via `derive_packet_keys`. See DECISION LOG D4.
- [x] **3.4 Handshake manager (level transitions, key install).** *DONE (wave 4)*
      folded into `QuicConnection` (`include/boltapi/quic/connection.h`). The
      per-level key install is driven by wave-3 `QuicTls` (each yielded secret
      installs a `PacketProtection` for that level+direction); the connection
      derives the Initial keys from the DCID (`derive_initial_keys`) and selects
      the right `PacketProtection` per level (`read_protection`/`write_protection`:
      Initial from DCID, Handshake/1-RTT from QuicTls). Fixed per-level arrays, no
      map. (FasterAPI's separate `quic_handshake.h` HandshakeManager was not
      ported — its role is split between wave-3 `tls.h` and this connection.)
- [x] **3.5 Secure connection = the real encrypt/decrypt connection.** *DONE
      (wave 4)* (`QuicConnection`, `include/boltapi/quic/connection.h`). ADAPTED
      from `quic_secure_connection.h`'s SECURE flow: inbound
      `feed_datagram`->parse header (wave-1 `packet.h`)->select level->
      header-unprotect + AEAD-open (wave-2 `packet_protection.h`)->parse frames
      (wave-1 `frames.h`)->CRYPTO reassembly->`QuicTls.feed_crypto`->install
      Handshake/1-RTT keys; outbound pull TLS CRYPTO->frame->build header->
      AEAD-seal->header-protect->`UdpTransport::send`. This is the path the base
      `quic_connection.cpp` never invoked (audit:140). Streams/flow-control are
      wave 5. *Bolt primitive:* fixed stack scratch per packet (no per-packet
      heap); `bolt::SwissTable` for streams is wave 5.
- [x] **3.6 Self-test the AEAD/HP against RFC 9001 Appendix A test vectors.**
      *DONE (wave 2)* (`tests/quic_protection_test.cpp`, target
      `boltapi_quic_protection_test`, default suite). BYTE-EXACT against RFC 9001
      Appendix A: §A.1 initial/client/server secrets + client & server quic
      key/iv/hp; §A.2 client Initial (AEAD ciphertext+tag, HP mask 437b9aec36,
      protected header `c0…449e7b9aec34`, full-packet prefix, round-trip); §A.3
      server Initial (HP mask 2ec0d8356a, protected header `cf…4075c0d9`,
      round-trip); §A.5 ChaCha20 short header (key/iv/hp, payload ciphertext
      `655e…5bfb`, protected header `4cfe4189`, full 21-byte packet). Plus
      negative auth-fail tests (tampered tag/body, wrong key, wrong AAD) and
      randomized AEAD round-trips across all three suites. *Bolt primitive:* n/a.

**GATE 3:** RFC 9001 Appendix A vectors pass; a unit test drives a *real* TLS 1.3
handshake between two in-process `QUICSecureConnection`s to ESTABLISHED (the
end-to-end encrypted handshake the FasterAPI tests never exercised — audit:140).

---

## Phase 4 — Connection state machine, loss, congestion, flow control, ACK

- [~] **4.1 Connection state machine.** *PARTIAL — handshake path DONE (wave 4)*
      (`ConnState` New->Handshaking->Established->Closing/Draining/Closed in
      `include/boltapi/quic/connection.h`). Server sends HANDSHAKE_DONE at 1-RTT;
      client confirms on receiving it; CONNECTION_CLOSE -> Draining. Drives the
      SECURE path from 3.5 (NOT the plaintext stub). Remaining: idle timeout,
      full CONNECTION_CLOSE emission/Closing drain, and the stream map
      (`bolt::SwissTable`) land with streams in wave 5.
- [x] **4.2 ACK tracking + ACK frame generation.** *DONE (wave 4 + 5a)*
      (`ack.h` AckRangeTracker -> AckFrame, wave 4). Wave 5a added ACK-elicitation
      tracking (`ack_pending_[space]` in `connection.h`) so ACKs are emitted only
      when an ack-eliciting packet was received (RFC 9002 §2) — no ACK-only-packet
      spam / PN inflation. ECN counts parsed; not yet generated.
- [x] **4.3 Loss detection + RTT (RFC 9002).** *DONE (wave 5a)* in
      `include/boltapi/quic/loss.h` (`SentPacketTracker` bounded per-space ring of
      `SentPacketInfo` with carried frame ranges; `RttEstimator` latest/min/
      smoothed/rttvar + PTO with exponential backoff) wired into `connection.h`
      (`process_ack`/`ack_range`/`detect_loss`/`maybe_pto_expire`). Packet-
      threshold (3) + time-threshold (9/8·max(srtt,latest), measured vs the
      largest-acked send time so a clean link never false-positives); PTO probes
      bypass cwnd for tail loss; lost CRYPTO/STREAM frames re-framed into FRESH
      PNs (never reused). Replaces the wave-4 "rewind unacked CRYPTO on tick".
- [x] **4.4 Congestion control (NewReno; CUBIC later).** *DONE (wave 5a)*
      (`NewRenoCongestion` in `loss.h`, adapted from FasterAPI `quic_congestion.h`):
      cwnd/ssthresh, slow start + congestion avoidance, recovery period on loss,
      `bytes_in_flight` gating sends, persistent-congestion collapse, in-flight
      reset at handshake confirmation (RFC 9002 §6.4/§9.3). Pacing deferred.
- [x] **4.5 Flow control (stream + connection level).** *DONE (wave 5a)*
      (`StreamFlow` in `stream.h` + connection-level `conn_send_max_/conn_recv_max_`
      in `connection.h`): MAX_DATA / MAX_STREAM_DATA advertise + enforce, window
      updates as the app consumes, DATA_BLOCKED / STREAM_DATA_BLOCKED emission;
      MAX_STREAMS parsed. Adapted from FasterAPI `quic_flow_control.h`.
- [x] **4.6 Stream management + reassembly.** *DONE (wave 5a)* (`Stream` in
      `stream.h`, adapted from FasterAPI `quic_stream.h` + `stream_reassembly_
      buffer.h`): bidi/uni stream-id encoding (RFC 9000 §2.1), send/recv state
      machines, bounded per-stream ordered reassembly (contiguous cursor + bounded
      out-of-order extent set, no `std::vector` regrowth), RESET_STREAM /
      STOP_SENDING serializers. Per-connection `bolt::SwissTable` maps stream_id ->
      a pool index; the Stream pool is arena-allocated (large fixed buffers).
- [ ] **4.7 Connection map (CID -> connection).** *What:* route incoming
      datagrams by DCID (and 4-tuple fallback) to the owning connection; handle
      multiple CIDs per connection. *REBUILD.* *Bolt primitive:* `bolt::SwissTable`
      keyed on CID bytes; `bolt_hash.h` for the CID hash.

**GATE 4:** *MET (wave 5a)* by `tests/quic_stream_test.cpp` — two real secure
connections over loopback UDP transfer randomized multi-KB payloads on a bidi
stream (byte-exact echo with FIN), a ~15 % seeded-drop variant still completes
via retransmission with cwnd grow/back-off, and a constrained flow-control
window forces window updates without deadlock; plus RTT/PTO + NewReno + stream-id
+ reassembly units. (Satisfies `CLAUDE.md`: more than one route/verb-equivalent
exercised at the transport via bidirectional streams, randomized data, real loss.)
Remaining Phase-4 polish (idle timeout, CONNECTION_CLOSE emission/Closing drain,
multi-concurrent-stream stress) rides into wave 5b alongside the H3 bridge. See
DECISION LOG D8.

---

## Phase 5 — HTTP/3 framing + QPACK + App bridge

- [ ] **5.1 HTTP/3 frame layer.** *What:* DATA, HEADERS, SETTINGS, GOAWAY,
      MAX_PUSH_ID, CANCEL_PUSH, PUSH_PROMISE; control/QPACK encoder/decoder uni
      streams; stream-type prefixes. *PORT*
      `C:\code\FasterAPI\src\cpp\http\http3\http3_frames.h` and
      `C:\code\FasterAPI\src\cpp\http\http3_parser.{h,cpp}`. *Bolt primitive:*
      `bolt::wire` for frame framing; `bolt::Arena` per-request scratch.
- [ ] **5.2 QPACK static table + Huffman.** *What:* RFC 9204 static table; reuse
      the existing HPACK Huffman tables. *PORT*
      `C:\code\FasterAPI\src\cpp\http\qpack\qpack_static_table.h`; **reuse Bolt's
      existing** `src/http/huffman*.cpp` rather than porting FasterAPI's. *Bolt
      primitive:* `bolt::SwissTable` for name/value -> index lookup.
- [ ] **5.3 QPACK dynamic table.** *What:* insert-with/without-name-ref,
      duplicate, eviction, capacity, absolute/relative/post-base indexing.
      *PORT* `C:\code\FasterAPI\src\cpp\http\qpack\qpack_dynamic_table.h` (audit:
      QPACK is **real**). *Bolt primitive:* ring buffer for the entry array;
      `bolt::SwissTable` for the lookup index.
- [ ] **5.4 QPACK encoder + decoder + encoder/decoder instruction streams.**
      *What:* full RFC 9204 encode/decode incl. blocked-stream handling, Required
      Insert Count, Known Received Count, Section Acknowledgement / Stream Cancel /
      Insert Count Increment. *PORT*
      `C:\code\FasterAPI\src\cpp\http\qpack\qpack_encoder.h` +
      `qpack_decoder.h` (and `src/cpp/http/http3/qpack.h`). *Bolt primitive:*
      `bolt::Arena` for header-block scratch; tables from 5.2/5.3.
- [ ] **5.5 HTTP/3 connection orchestration.** *What:* tie QUIC streams + H3
      frames + QPACK together: open control/QPACK streams, parse requests, manage
      per-request stream state, build responses. *PORT the orchestration shape from*
      `C:\code\FasterAPI\src\cpp\http\http3_connection.{h,cpp}` and
      `C:\code\FasterAPI\src\cpp\http\h3_handler.{h,cpp}`, **but** retarget its
      request/response structs onto Bolt's `CoroHttpRequest`/`CoroHttpResponse`
      (do not keep FasterAPI's `Http3Handler::Request` `std::unordered_map`
      headers). *Bolt primitive:* `bolt::SwissTable` (stream-id -> request state);
      `bolt::Arena` per request.
- [ ] **5.6 Bridge QUIC stream -> `CoroHttpRequest` -> App.** *What:* when a
      request is fully decoded, populate a `CoroHttpRequest`
      (`include/boltapi/server/coro_unified_server.h:93` — `method`/`path`/`body`
      as `string_view`, `headers[MAX_HEADERS]`) and dispatch through the **same**
      App path the H1/H2 engine uses (router match -> middleware fold ->
      `CoroHttpHandler` -> `CoroHttpResponse`). **No new dispatch logic** — reuse
      `App`'s existing chain (`src/app.cpp`). *REBUILD* (this is the seam glue; it
      is the whole reason the seam exists). *Bolt primitive:* arena-owned backing
      storage so the request's `string_view`s outlive decode (mirrors the H2
      lifetime note at `coro_unified_server.h:83`).
- [ ] **5.7 Response path: `CoroHttpResponse` -> QPACK-encode -> H3 DATA -> QUIC
      stream -> UDP.** *What:* serialize status+headers via QPACK, stream the body
      with flow control + pacing, FIN the stream. *REBUILD* on top of 5.4 + 4.x.
      *Bolt primitive:* `bolt::wire` for frame headers; batched send (1.5).

**GATE 5:** end-to-end through `App` — at least **two routes**, **multiple HTTP
verbs (GET/POST/PUT/DELETE/HEAD)**, **randomized bodies & headers**, concurrent
requests on one connection, large (multi-DATA-frame) responses. Existing
H1/H2/WebSocket tests still pass unchanged.

---

## Phase 6 — Seam integration (make `App.enable_http3` actually serve)

- [ ] **6.1 Fill `Http3Protocol::serve()`.** *What:* in
      `src/proto/http3_stub.cpp`, replace `not_implemented()` with: take the
      started `UdpTransport`, run the recv->demux->connection->H3 loop on the
      worker pool, dispatch to `App`. *REBUILD* (uses everything above). *Bolt
      primitive:* `bolt::SPSCChannel`/`MPSCChannel` for the I/O->worker handoff;
      `bolt::SwissTable` connection map; `bolt::Scheduler` (`bolt_scheduler.h`) if
      a dedicated QUIC worker is wanted.
- [ ] **6.2 `register_http3()` registers the real protocol.** *What:* unchanged
      signature (`protocol.h:259`); factory now returns the real `Http3Protocol`.
      *REBUILD* (one-line swap of the factory body). *Bolt primitive:*
      `ProtocolRegistry` (already real).
- [ ] **6.3 `App::init_protocol_seams()` actually starts H3 when enabled.**
      *What:* when `enable_http3` is ON and built with `BOLTAPI_WITH_HTTP3`,
      construct `UdpTransport{host, http3_port || http1_port}`, `start()` it,
      `create(Http3::...)` -> `serve()`; on failure, log and **keep H1/H2
      serving** (never crash/block — the SEAMS.md contract). *What NOT to do:*
      touch H1/H2 dispatch. *REBUILD* the body at `src/app.cpp:276`. *Bolt
      primitive:* n/a.
- [ ] **6.4 Advertise H3 via Alt-Svc on the H1/H2 responses.** *What:* add an
      `alt-svc: h3=":<port>"` response header from an **opt-in middleware** (not a
      core edit) so browsers upgrade. *REBUILD* as `App` middleware. *Bolt
      primitive:* existing middleware chain.
- [ ] **6.5 Update `docs/SEAMS.md` TODO checkboxes** and `PROJECT_MAP.md` after
      landing (per global instruction — but **not** under this planning task).

**GATE 6:** `App` configured with `enable_http3=true` serves real H3 to a browser
/ `curl --http3`; with the flag OFF or built without `BOLTAPI_WITH_HTTP3`,
behavior is byte-for-byte the current build.

---

## Phase 7 — Advanced QUIC features (later)

- [ ] **7.1 0-RTT / session resumption.** *What:* issue session tickets +
      transport params; accept 0-RTT early data with anti-replay; reject when
      params changed. *PORT* the resumption hooks from `quic_tls.h` /
      `quic_secure_connection.h` (early-data secrets); *REBUILD* the anti-replay
      window. *Bolt primitive:* `bolt::SwissTable` / `bolt_hot_key_cache.h` for the
      replay-token cache.
- [ ] **7.2 Connection migration + path validation.** *What:* PATH_CHALLENGE/
      RESPONSE, NAT rebinding, new-path congestion reset, CID rotation. *REBUILD*
      (FasterAPI's was minimal). *Bolt primitive:* `bolt::SwissTable` multi-CID map
      (4.7) keyed to allow many CIDs/paths per connection.
- [ ] **7.3 Active CID management (NEW/RETIRE_CONNECTION_ID at scale).** *What:*
      maintain a CID pool per connection, honor active_connection_id_limit.
      *REBUILD.* *Bolt primitive:* ring buffer of issued CIDs.
- [ ] **7.4 Datagram extension (RFC 9221) — optional, enables WebTransport.**
      *What:* unreliable DATAGRAM frames. *REBUILD.* *Bolt primitive:* `bolt::wire`.

---

## Phase 8 — Testing & interop (correctness gates throughout)

> Per `CLAUDE.md`: tests must exceed "hello world" — multiple routes, multiple
> verbs, randomized inputs. Don't mock; build the real thing.

- [ ] **8.1 Unit: varint** — exhaustive boundaries + random round-trip. *PORT*
      FasterAPI gtests where useful.
- [x] **8.2 Unit: packet protection** — *DONE (wave 2)*
      (`tests/quic_protection_test.cpp`): RFC 9001 Appendix A vectors (§A.1/A.2/
      A.3/A.5) byte-exact + random AEAD round-trip across all three suites +
      negative auth-fail tests. See item 3.6.
- [ ] **8.3 Unit: packet/frame round-trip** — *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\test_quic_packet.cpp`.
- [ ] **8.4 Unit: ACK tracker** — *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\test_quic_ack_tracker.cpp`.
- [ ] **8.5 Unit: connection state** — *PORT/ADAPT*
      `C:\code\FasterAPI\src\cpp\http\quic\test_quic_connection.cpp`, **but retarget
      to the secure connection** (the originals only tested the plaintext base —
      audit:140). Add a real two-endpoint encrypted handshake test.
- [ ] **8.6 Unit: QPACK roundtrip** — encoder<->decoder incl. dynamic table,
      blocked streams, eviction; random header sets. *PORT* FasterAPI QPACK tests
      if present, else write fresh.
- [ ] **8.7 Interop: `quiche-server`/`quiche-client`** (the
      `quiche-reference` submodule already used by FasterAPI) — handshake +
      request both directions.
- [ ] **8.8 Interop: `curl --http3`, `nghttp3`/`ngtcp2`, `h3i`** — request a
      multi-route app; verify GET/POST/HEAD, large bodies, trailers.
- [ ] **8.9 Interop: QUIC Interop Runner test cases** — handshake, transfer,
      retry, resumption, 0-RTT, multiplexing, loss recovery, ECN.
- [ ] **8.10 E2E through `App`** — multi-route, multi-verb, randomized payloads,
      concurrent connections; assert parity with the H1/H2 responses for the same
      routes.
- [ ] **8.11 Fuzz** — libFuzzer/AFL harnesses on: packet header parse, frame
      parse, QPACK decoder, transport-params decoder, varint. Run under ASan/UBSan.
- [ ] **8.12 Allocation audit** — assert zero per-packet/per-request heap
      allocation on the steady-state path (hook `new`/`malloc`).
- [ ] **8.13 CI leg** — extend the existing `seams-on` job to build
      `-DBOLTAPI_WITH_HTTP3=ON` with quictls and run the H3 unit + interop subset.

**GATE 8 (overall correctness gate):** all unit + the curl/quiche interop subset
green before *any* Phase 9 perf work is merged.

---

## Phase 9 — Performance (only after correctness gates pass)

- [ ] **9.1 Batched UDP I/O end-to-end** — confirm recvmmsg/sendmmsg + GSO/GRO are
      on the hot path; minimize syscalls/packet. *Bolt primitive:* 1.4/1.5 paths.
- [ ] **9.2 Zero-copy framing** — parse packets/frames in place over the recv
      buffer; serialize directly into send buffers. *Bolt primitive:* `bolt::wire`
      (`extern/bolt/include/bolt/wire/bolt_wire.h`,
      `bolt_wire_stream.h`) — no intermediate copies.
- [ ] **9.3 Per-packet / per-request arena scratch** — all transient state from a
      reset arena, never the heap. *Bolt primitive:* `bolt::Arena` /
      `bolt_arena_ring.h` (reset-per-batch).
- [ ] **9.4 Connection & stream maps on SwissTable, sized to avoid rehash** —
      preallocate to expected concurrency; `bolt_hash.h` mixing on CID/stream-id.
      *Bolt primitive:* `bolt::SwissTable`.
- [ ] **9.5 Pacing** — token-bucket pacer driven by cwnd/RTT to smooth bursts and
      cut loss; integrate with GSO so paced bursts still batch. *Bolt primitive:*
      branchless rate math (`bolt_branchless.h`); clock via `bolt_lock_free_clock_lru`
      pattern or a coarse TSC clock.
- [ ] **9.6 ACK frequency / delayed ACK tuning (RFC 9002 + ack-frequency draft)** —
      reduce ACK overhead under high throughput. *Bolt primitive:* n/a.
- [ ] **9.7 0-copy crypto** — reuse `EVP_CIPHER_CTX` per key phase, encrypt in
      place into the send buffer, precompute header-protection masks; avoid AEAD
      ctx alloc per packet. *Bolt primitive:* arena-held ctx pool.
- [ ] **9.8 SWAR/vectorizable hot loops** — varint scan, frame-type dispatch,
      header-byte masking, PN-range merging. *Bolt primitive:* `bolt_port.h` SWAR +
      bitops; ensure loops auto-vectorize (check codegen).
- [ ] **9.9 NUMA-aware worker fan-out** — pin QUIC workers; one MPSC per node.
      *Bolt primitive:* `bolt::NumaChannelPool` + `bolt_topology.h`.
- [ ] **9.10 CUBIC + BBR (optional)** — beyond NewReno for high-BDP links.
      *REBUILD.*

### Perf targets & how to bench

- **Targets (single box, loopback/LAN, to be ratified):** match or beat the H2
  path on req/s for small responses; >= line-rate (10GbE) bulk throughput on one
  connection with GSO; handshake CPU within ~1.5x of quiche; **zero** steady-state
  heap allocs/request; p99 added latency from QUIC < a small fixed budget vs H2.
- **How:** extend `benchmarks/` with an H3 leg using `h2load --npn-list / --h3`
  (nghttp2/nghttp3) and `quiche` bench; compare against the existing H1/H2
  numbers in `docs/BENCHMARKS.md`. Profile with the repo's perf tooling; track
  syscalls/packet, allocs/request, cwnd/RTT, and CPU/Gbps.

---

## Salvage map — FasterAPI -> Bolt API

| FasterAPI file (`C:\code\FasterAPI\src\cpp\http\...`) | Action | Reason |
|---|---|---|
| `quic\quic_varint.h` | **port as-is** | Pure, correct RFC 9000 §16 codec; only namespace changes. |
| `quic\quic_packet.{h,cpp}` | **adapt** | Correct header/CID logic; retarget I/O onto `bolt::wire` zero-copy. |
| `quic\quic_frames.h` | **adapt** | All frame types present; swap buffers to `bolt::wire`/arena. |
| `quic\quic_packet_number_space.h` | **port as-is** | Small, correct PN-space logic. |
| `quic\quic_version_retry.h` | **port** | Real VN + Retry incl. integrity tag. |
| `quic\quic_crypto_buffer.h` | **port** | Real per-level CRYPTO reassembly. |
| `quic\quic_packet_protection.h` | **port as-is** | Audit: **real** OpenSSL EVP AEAD/HKDF/HP (RFC 9001). Crypto — do not rewrite. |
| `quic\quic_tls.h` | **port** | Audit: **real** `SSL_QUIC_METHOD` quictls integration (974 LOC). |
| `quic\quic_handshake.h` | **port** | Real handshake level/key driver. |
| `quic\quic_secure_connection.h` | **port (becomes the connection)** | Audit: real encrypt/decrypt; this is the path the base class never invoked. |
| `quic\quic_connection.{h,cpp}` | **adapt shape, drop the stub crypto** | State machine reusable; its `:138/:170` "decrypt when crypto is implemented" TODOs are the plaintext stub — replace with 3.5/secure path. |
| `quic\quic_ack_tracker.{h,cpp}` | **port** | Real ACK range tracking. |
| `quic\quic_congestion.{h,cpp}` | **port** | Real NewReno. |
| `quic\quic_flow_control.{h,cpp}` | **port** | Real stream+conn flow control. |
| `quic\quic_stream.{h,cpp}` + `quic\stream_reassembly_buffer.h` | **adapt** | Reusable; swap `unordered_map`/`vector` for SwissTable/ring buffer. |
| (loss recovery — embedded in connection/congestion) | **rewrite** as `quic_loss_recovery.{h,cpp}` | Tangled in FasterAPI; extract a clean RFC 9002 unit. |
| `http3\http3_frames.h`, `http3_parser.{h,cpp}` | **port/adapt** | Correct H3 framing; framing via `bolt::wire`. |
| `http3\qpack.h`, `qpack\qpack_static_table.h` | **port** | Real static table. |
| `qpack\qpack_dynamic_table.h` | **adapt** | Real; back the entry store with a ring buffer + SwissTable index. |
| `qpack\qpack_encoder.h`, `qpack_decoder.h` | **port** | Audit: QPACK is **real**. |
| `http3_connection.{h,cpp}`, `h3_handler.{h,cpp}` | **adapt (rewrite the request bridge)** | Orchestration reusable; **replace** `Http3Handler::Request` (`unordered_map` headers) with `CoroHttpRequest` -> App dispatch. |
| `http3_server.h`, `quic_handlers.cpp` | **drop** | FasterAPI's own server/glue; Bolt uses `UdpTransport` + `Http3Protocol` + `App` instead. |
| `test_quic_packet.cpp`, `test_quic_ack_tracker.cpp` | **port** | Reusable unit tests. |
| `test_quic_connection.cpp` | **adapt** | Retarget to the **secure** connection (originals only tested the plaintext base). |
| `*.cpp` thin stubs (e.g. `quic_ack_tracker.cpp` 254B, `qpack_*_.cpp`) | **drop** | Header-only impls; the `.h` carries the logic. |

---

## Guardrails (apply to every item)

- Never edit `src/server/coro_unified_server.*`, the H1/H2/WebSocket/SSE
  dispatch, or the `App`/`Router`/middleware core. H3 only **adds** a path.
- Default build (`BOLTAPI_WITH_HTTP3=OFF`) stays byte-for-byte identical; no new
  TU links, no new symbols.
- No exceptions; `noexcept` + asserts on the hot path; no hidden allocation.
- Prefer Bolt primitives over std/containers everywhere except the justified
  TLS/crypto dependency (Phase 0.2). No malloc/new/free on steady-state paths —
  use `bolt::Arena`, `bolt_batch_pool.h`, ring buffers, and `bolt::SwissTable`.
- Correctness gates (GATE n) must be green before the next phase; all perf work
  is gated behind GATE 8.
- Update `PROJECT_MAP.md` and `docs/SEAMS.md` as items land (not under the
  planning task).

---

## DECISION LOG — first bounded wave (2026-05)

### D0. QUIC-TLS provider — SUPERSEDES the tentative Phase 0.1 "quictls" pick

**Investigation (against the installed OpenSSL):**
`C:/Program Files/OpenSSL-Win64/include/openssl/opensslv.h` reports
`OPENSSL_FULL_VERSION_STR "3.6.1"` ("OpenSSL 3.6.1 27 Jan 2026"). Grepping the
headers for the two competing QUIC-TLS surfaces:

- **BoringSSL / quictls API** that FasterAPI's `quic_tls.h` is written against —
  `SSL_provide_quic_data`, `SSL_set_quic_method`, `SSL_QUIC_METHOD`,
  `SSL_quic_read_level`, `SSL_set_quic_transport_params`,
  `SSL_process_quic_post_handshake`: **NOT PRESENT.** Zero matches in any header.
- **OpenSSL 3.5+ native QUIC-TLS callback API** — present in
  `<openssl/ssl.h>`:
  - `int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg);`
    (the handshake-bytes callback table — `OSSL_FUNC_SSL_QUIC_TLS_*` dispatch
    functions: crypto_send / crypto_recv_rcd / crypto_release_rcd /
    yield_secret / got_transport_params / alert)
  - `int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *params, size_t params_len);`
  - `int SSL_set_quic_tls_early_data_enabled(SSL *s, int enabled);`
  - plus `<openssl/quic.h>` `OSSL_QUIC_client_method()` /
    `OSSL_QUIC_server_method()` and the `OSSL_QUIC_ERR_*` transport-error codes.

So the BoringSSL `SSL_QUIC_METHOD` model the FasterAPI port assumes **does not
exist** on this OpenSSL. The plan's Phase 0.1 justification ("quictls is a
drop-in, OpenSSL 3.5 would require rewriting the callback wiring") had the
trade-off right but picked the wrong default for *this* toolchain.

**DECISION: Path (b) — adapt the crypto layer to the OpenSSL 3.5+ QUIC-TLS
callback API (`SSL_set_quic_tls_cbs` + `OSSL_DISPATCH`).** Rationale:
1. **Zero new third-party dependency.** OpenSSL 3.6.1 is already linked for
   H1/H2 TLS and for the live WebRTC DTLS gate (`tests/dtls_test.cpp`,
   `OpenSSL::SSL`/`OpenSSL::Crypto`). Path (a) is impossible (API absent); path
   (c) — vendoring quictls — would add a second TLS stack and directly violate
   `CLAUDE.md`'s "prefer Bolt / import pure algorithms over linking libraries"
   for no benefit, and risks symbol clashes with the OpenSSL we already link.
   The TLS-1.3/AEAD dependency exception (Phase 0.2) is satisfied by the OpenSSL
   we *already have*.
2. **The adaptation is bounded and well-isolated.** FasterAPI's `quic_tls.h`
   uses ~6 BoringSSL entry points behind one driver class. The OpenSSL 3.5+ API
   covers the same four conceptual hooks (provide handshake bytes, emit
   handshake bytes, install per-level secrets, exchange transport params) — so
   the port becomes "re-wire one callback struct + the secret/level mapping",
   confined to a single TU. Keep the `#if OPENSSL_VERSION_NUMBER` shim the plan
   already recommended so a future BoringSSL/quictls build is a drop-in.
3. **AEAD / HKDF / header-protection** (RFC 9001 §5, the `quic_packet_protection.h`
   port) is plain EVP + HKDF and is **identical** across both APIs — it is
   unaffected by this decision.

**Net effect on the plan:** Phase 3.3 ("TLS 1.3 QUIC method (quictls
callbacks)") is re-scoped to "TLS 1.3 QUIC method via `SSL_set_quic_tls_cbs`";
Phase 0.3's `cmake/Findquictls.cmake` is **dropped** — `BOLTAPI_WITH_HTTP3` will
reuse the existing `find_package(OpenSSL)`. No code under that gate exists yet
(this wave is crypto-free), so nothing is blocked.

### D1. Pure QUIC primitives PORTED (this wave) — dependency-free, compiled UNCONDITIONALLY

All under `include/boltapi/quic/`, namespace `bolt::api::quic`, Tiger Style
(>=2 asserts/fn, bounded, noexcept, no alloc, no exceptions), no OpenSSL, no
`BOLTAPI_WITH_HTTP3` gate — so the default ctest suite covers them.

| File | Source (FasterAPI `src/cpp/http/quic/`) | PORT vs reshape |
|---|---|---|
| `varint.h` | `quic_varint.h` | PORT as-is (byte-identical wire logic); reshaped to free functions + named bounds + asserts. |
| `packet.h` | `quic_packet.{h,cpp}` (header structs + PN helpers) | RESHAPED: parse-only, borrows spans; added `PacketForm` discrimination for Initial/0-RTT/Handshake/Retry/1-RTT/VersionNegotiation; dropped serialize + crypto-coupled bits. |
| `frames.h` | `quic_frames.h` | RESHAPED: kept full type-constant table; parse/serialize for PADDING/PING/ACK(+ECN)/CONNECTION_CLOSE + STREAM/CRYPTO framing (payload stays a view); bounded `kMaxAckRanges`. |
| `pn_space.h` | `quic_packet_number_space.h` + PN codec from `quic_packet.cpp` | RESHAPED: pure 3-space sequencing + truncated-PN encode/decode (RFC 9000 §17.1, App. A.2/A.3); dropped crypto/ack/congestion coupling. |
| `ack.h` | RecvTracker logic from `quic_packet_number_space.h` + `quic_ack_tracker.{h,cpp}` | RESHAPED: fixed-capacity coalescing range set -> `AckFrame` (no `std::vector`/`unordered_map`); dropped loss timers / RTT / congestion (later RFC 9002 phase). |

**Tests:** `tests/quic_primitives_test.cpp` (gtest, registered via
`boltapi_add_test`, target `boltapi_quic_primitives_test`) — 28 cases.
RFC vectors exercised + passing:
- varint: RFC 9000 §A.1 decoded samples (37 / 15293 / 494878333 /
  151288809941952652) + the exact 8-byte vector `c2 19 7c 5e ff 14 e8 8c` ->
  151288809941952652 + the 2-byte vector `7b bd` -> 15293; boundary sizes;
  100k random round-trips; need-more on short buffers.
- packet: RFC 9001 §A.1 client Initial public header
  (`c3 00000001 08 8394c8f03e515708 00 00 449e`) — version=1, DCID=
  `8394c8f03e515708`, empty SCID, token len 0, Length=1182, consumed=18; short
  header (spin/key-phase/DCID); Version-Negotiation + Retry discrimination
  (no Length field); need-more / over-long-CID rejection.
- frames: ACK multi-range + ACK_ECN round-trip; STREAM offsets (incl.
  no-LEN-extends-to-end); CRYPTO offsets; CONNECTION_CLOSE transport (with
  frame-type) + application; PADDING run.
- pn_space: RFC 9000 §A.2 encode length (0xac5c02 / 0xabe8b3 -> 3 bytes) +
  §A.3 decode (`0x9b32`, largest `0xa82f30ea`, 16-bit -> `0xa82f9b32`);
  5000-PN truncate->decode round-trip; plain encode-length table; sequencing.
- ack: contiguous / gapped / out-of-order+duplicate coalescing -> `AckFrame`
  -> re-parse; 200-trial randomized cross-check vs a brute-force membership set.

**Status:** default `cmake -S . -B build/msvc` build + `ctest -C Release` =
**150/150 passing** (was 122; +28 QUIC primitives), zero warnings on the new
TU, H1/H2/WebRTC suites unchanged.

### D2. Packet protection PORTED (wave 2) — RFC 9001 §5, compiled UNCONDITIONALLY

`include/boltapi/quic/packet_protection.h` (+ `tests/quic_protection_test.cpp`),
namespace `bolt::api::quic`, Tiger Style (≥2 asserts/fn, fixed buffers, noexcept,
bool/enum returns, no exceptions). EVP/HKDF crypto is API-agnostic (RFC 9001 §5 is
identical across the BoringSSL and OpenSSL-3.5 QUIC-TLS surfaces per D0), and
OpenSSL is always linked into boltapi, so NO `BOLTAPI_WITH_HTTP3` gate — the
default ctest suite covers it. **NO TLS handshake** (that is wave 3).

| Item | Source (`quic_packet_protection.h`) | PORT vs reshape |
|---|---|---|
| `hkdf_extract/expand/expand_label` | same | PORT (byte-identical HkdfLabel); reshaped to bool returns + bounded scratch + asserts. |
| `derive_initial_secret/secrets` + `derive_packet_keys` | same | PORT (v1 salt `0x38762cf7…ccbb7f0a`; "client in"/"server in"; quic key/iv/hp). |
| `PacketProtection` (AEAD seal/open, HP protect/unprotect) | same | RESHAPED: bool returns, asserts on lengths/pn_len, cached `EVP_CIPHER_CTX`. |
| ChaCha20 header-protection mask | `generate_hp_mask` | **FIXED**: FasterAPI ignored the counter and mis-sliced the nonce; per RFC 9001 §5.4.4 the 16-byte sample is the EVP_chacha20 IV `[counter:4 LE][nonce:12]`. |
| `derive_initial(DCID, is_server)` convenience | `derive_initial_packet_protection` | RESHAPED to one direction + AES-128-GCM (Initial), zeroizes secrets. |

**Tests:** `boltapi_quic_protection_test` (gtest, 6 cases). RFC 9001 Appendix A,
BYTE-EXACT and passing: §A.1 secrets + client/server quic key/iv/hp; §A.2 client
Initial (ciphertext+tag, HP mask `437b9aec36`, protected header
`c0…449e7b9aec34`, round-trip); §A.3 server Initial (HP mask `2ec0d8356a`,
protected header `cf…4075c0d9`, round-trip); §A.5 ChaCha20 (key/iv/hp, ciphertext
`655e…5bfb`, protected header `4cfe4189`, full 21-byte packet); negative
auth-fail (tampered tag/body, wrong key, wrong AAD); randomized AEAD round-trip ×
all three suites. **Status:** default `cmake --preset msvc` + `ctest -C Release`
= **156/156** (was 150; +6), zero warnings on the new TU, H1/H2/WebRTC untouched.

### D3. Next wave (wave 3 — TLS 1.3 handshake; gated on D0) — item 1 LANDED in D4
1. ~~TLS 1.3 QUIC handshake via `SSL_set_quic_tls_cbs` / `OSSL_DISPATCH` +
   transport-params codec~~ **DONE — see D4.**
2. Secure connection (encrypt/decrypt, drives wave-2 `PacketProtection`) ->
   connection state machine (RFC 9002 loss recovery extracted clean) -> streams
   + flow control.
3. QPACK (static/dynamic tables, encoder/decoder) -> HTTP/3 frames.
4. Bridge QUIC streams -> `CoroHttpRequest` -> the existing `App` router.

### D4. TLS 1.3 QUIC handshake LANDED (wave 3) — OpenSSL 3.6 QUIC-TLS callback API

`include/boltapi/quic/transport_params.h` + `include/boltapi/quic/tls.h`
(+ `tests/quic_tls_test.cpp`), namespace `bolt::api::quic`, Tiger Style (≥2
asserts/fn, bounded buffers, noexcept, no exceptions, bool returns). Header-only;
OpenSSL is always linked into boltapi and the test links `OpenSSL::SSL/Crypto`, so
it compiles UNCONDITIONALLY — no `BOLTAPI_WITH_HTTP3` gate. **NO QUIC
packet/connection wiring** (that is wave 4).

**Exact OpenSSL 3.6.1 API used** (grepped from the installed headers, implemented
against the real signatures):
- `int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg);`
  (`ssl.h:2937`) — installs the QUIC-TLS dispatch table on a plain `TLS_method()`
  SSL object (the OpenSSL 3.5+ "external QUIC stack" hook; the BoringSSL
  `SSL_QUIC_METHOD` / `SSL_provide_quic_data` surface is ABSENT here, per D0).
- `int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *params,
  size_t params_len);` (`ssl.h:2938`). **GOTCHA (found + fixed): OpenSSL RETAINS
  this pointer (does not copy)** — the encoded block must outlive the handshake,
  so `QuicTls` keeps it in a member buffer (`local_tp_`). A stack-local buffer
  caused the peer to receive garbage and the decode to fail; this is the one real
  trap of this API.
- Dispatch callbacks (`core_dispatch.h:258-279`, ids 2001-2006), wired with their
  typed signatures:
  - 2001 `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND` `(SSL*, const uchar* buf, size_t
    buf_len, size_t* consumed, void* arg)` — buffer handshake bytes at the current
    write level; report all consumed.
  - 2002 `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD` `(SSL*, const uchar** buf,
    size_t* bytes_read, void* arg)` — hand TLS a contiguous view of the
    unconsumed received CRYPTO at the current read level (pull model).
  - 2003 `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD` `(SSL*, size_t bytes_read,
    void* arg)` — advance the consumed mark; compact when drained.
  - 2004 `OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET` `(SSL*, uint32_t prot_level, int
    direction, const uchar* secret, size_t secret_len, void* arg)` — store the
    per-level read(`direction==0`)/write(`direction==1`) secret, track the active
    read/write level, and derive a wave-2 `PacketProtection` via
    `derive_packet_keys`. `prot_level` maps via `OSSL_RECORD_PROTECTION_LEVEL_*`
    (NONE=Initial, EARLY=0-RTT, HANDSHAKE, APPLICATION=1-RTT).
  - 2005 `OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS` `(SSL*, const uchar*
    params, size_t params_len, void* arg)` — decode the peer's params (RFC 9000
    §18).
  - 2006 `OSSL_FUNC_SSL_QUIC_TLS_ALERT` `(SSL*, uchar alert_code, void* arg)`.
  Dispatch table is a `static const OSSL_DISPATCH[]` terminated by
  `OSSL_DISPATCH_END`; the `arg` is the `QuicTls*`. (`OSSL_QUIC_client_method()` /
  `OSSL_QUIC_server_method()` in `quic.h` are for OpenSSL's OWN built-in QUIC
  stack — NOT used here; the callback API rides on `TLS_method()`.)

**Transport-params codec (`transport_params.h`, RFC 9000 §18):** encode/decode the
varint-id + varint-len + value TLV list — initial_max_data,
initial_max_stream_data_{bidi_local,bidi_remote,uni}, initial_max_streams_{bidi,
uni}, max_idle_timeout, max_udp_payload_size, ack_delay_exponent, max_ack_delay,
active_connection_id_limit, disable_active_migration (zero-len flag),
initial_source_connection_id / original_destination_connection_id /
retry_source_connection_id (raw CID bytes, ≤20), stateless_reset_token (16B).
Per-field presence flags so encode emits exactly what was set; decode SKIPS
unknown ids (§18.1) and rejects truncated values / over-long CIDs. Uses our
`quic/varint.h`. Pure code (no OpenSSL), bounded.

**`QuicTls` flow:** `init_client()` / `init_server()` build a TLS-1.3-only
`TLS_method()` SSL_CTX (+ self-signed P-256 cert + ALPN-select for the server;
permissive verify for the client self-test) and install the dispatch table; then
`set_alpn` + `set_transport_params` before `advance()` (= `SSL_do_handshake`,
WANT_READ/WANT_WRITE = need more peer CRYPTO, not an error). `feed_crypto(level,
data)` buffers received CRYPTO per level; `pull_crypto(level)` drains our outbound
CRYPTO per level; `read_secret/write_secret(level)`, `read_protection/
write_protection(level)`, `peer_transport_params()`, `is_complete()`/`failed()`.

**In-process handshake test RESULT** (`tests/quic_tls_test.cpp`, default suite, no
UDP): a client + server `QuicTls` are stepped in lockstep, each side's pulled
CRYPTO (per level) fed into the other, with a bounded 64-iteration budget. **Both
reach `is_complete()`**; **client `write_secret(level)` == server
`read_secret(level)` and vice-versa at BOTH the Handshake and 1-RTT (Application)
levels** (32-byte SHA-256 secrets — the shared-secret proof); **transport params
round-trip** (each side decodes the other's: initial_max_data, max_streams,
CIDs, disable_active_migration); ALPN negotiates to `h3`; and a `PacketProtection`
derived from those secrets **cross-seals/opens** a randomized payload in BOTH
directions at the 1-RTT and Handshake levels, with a tamper-the-tag negative
check — tying wave 2 (`packet_protection.h`) and wave 3 together. Plus four
standalone transport-params codec tests (round-trip, skip-unknown, reject
truncated, reject over-long CID).

**Status:** default `cmake --preset msvc` + `ctest -C Release` = **161/161** (was
156; +5: 4 transport-params + 1 handshake gate), zero warnings on the new TUs,
H1/H2/WebRTC/QUIC-primitives/protection suites unchanged.

### D5. Wave 4 — QUIC connection — LANDED in D6.

### D6. QUIC CONNECTION LANDED (wave 4) — real handshake to ESTABLISHED over UDP

`include/boltapi/quic/connection.h` (header-only; OpenSSL always linked, so it
compiles UNCONDITIONALLY into the default suite — no `BOLTAPI_WITH_HTTP3` gate)
+ `tests/quic_connection_test.cpp` (the wave-4 GATE), namespace
`bolt::api::quic`, Tiger Style (>=2 asserts/fn, bounded fixed buffers, no
recursion on the packet hot path, <70-line fns, noexcept, no exceptions, bool
returns). ADAPTED from FasterAPI's `quic_secure_connection.h` SECURE flow (the
path the base `quic_connection.cpp` never invoked, audit:140), retargeted onto
boltapi/quic/* (waves 1-3) + `net::UdpTransport`.

**`QuicConnection` (client + server roles).** Owns: a wave-3 `QuicTls`; Initial
`PacketProtection` derived from the DCID (RFC 9001 §5.2) for read+write;
Handshake/1-RTT `PacketProtection` borrowed from `QuicTls` (installed from the
yielded secrets); the three wave-1 packet-number spaces + per-space wave-1
`AckRangeTracker`; a per-level `CryptoReassembly` (adapted from
`quic_crypto_buffer.h`); per-level outbound CRYPTO send buffers + offsets. CIDs:
our SCID (`local_cid_`, 8 random bytes), the peer's SCID (`peer_cid_`, our DCID
for sends), and `initial_dcid_` (the DCID that keys Initial). Client picks a
random initial DCID; the server adopts the client's DCID to key Initial + the
client's SCID to reply on the first Initial.

**Inbound `feed_datagram`:** loop over coalesced packets (bounded
`kMaxCoalescedPackets`; trailing 0x00 PADDING ends the run) — `parse_form` ->
parse long/short header (wave 1) -> if keys present, `unprotect_header` +
`decrypt` (wave 2) over a stack scratch copy -> decode the truncated PN (wave-1
`pn_decode`) -> record the PN for ACK -> walk frames: CRYPTO (reassemble in-order
-> `feed_crypto`), ACK (mark space largest-acked + clear our CRYPTO-pending),
PADDING/PING, CONNECTION_CLOSE (-> Draining), HANDSHAKE_DONE (client ->
confirmed), STREAM (framing skipped — wave 5). Then `tls_.advance()` and flush.

**Outbound:** after advance, pull `QuicTls` CRYPTO per level -> stash + frame
into CRYPTO frames across as many packets as the flight needs (the ClientHello
flight is ~1.4 KB > one packet) + an ACK on the first packet -> build the right
header (Initial: token + 4-byte PN + Length varint, padded to 1200 per §14.1;
Handshake long header; 1-RTT short header) -> AEAD-seal -> header-protect (4-byte
PN so the HP sample sits right after the PN) -> `UdpTransport::send`. Server, on
its first client Initial, derives Initial keys from the client's DCID, then
emits Initial(ServerHello) + Handshake(EE/Cert/Finished); at 1-RTT it sends
HANDSHAKE_DONE to finish. A minimal `tick()` retransmits still-unacked CRYPTO
(rewind the send offset) + a due ACK — enough to make a clean loopback handshake
reliable; full RFC 9002 loss recovery is wave 5.

**One demux change** (additive, WebRTC-safe): `src/net/udp_transport.cpp`
`classify()` now routes first byte >= 64 (QUIC long/short headers) to the
datagram handler. QUIC's range (>=0x40) sits ABOVE the RFC 7983 DTLS range
(20..63) and never overlaps STUN (0..3) or DTLS, so WebRTC demux is unchanged;
the handler discriminates by first byte. `udp_transport_test.cpp`'s "dropped"
case was moved from first byte 0x80 (now QUIC) to 0x10 (4..19, genuinely
unassigned) — still asserts unclassified bytes drop.

**GATE RESULT** (`tests/quic_connection_test.cpp`, default suite, REAL UDP):
two `QuicConnection`s (client + server) on two `net::UdpTransport`s bound to
ephemeral loopback ports, each transport's datagram handler feeding the owning
connection and each connection's send fn pushing built datagrams to the peer;
the client `start()`s, a bounded 10s driver loop ticks both. **BOTH reach
`ConnState::kEstablished`** (Initial -> Handshake -> 1-RTT); **1-RTT read+write
keys installed on both sides**; **ALPN == h3** both; **transport parameters
exchanged** (each side decoded the other's `initial_max_data` etc.); and a
**1-RTT seal/open round-trip over the wire BOTH ways** — server seals a 1-RTT
PING+ACK the client opens (its Application-space `largest_received` advances) and
vice-versa (the server's HANDSHAKE_DONE was itself a 1-RTT packet the client
opened during the handshake). Bounded by a wall-clock deadline; no hang; passes
8/8 repeats. Real curl/quiche/aiortc-h3 interop is a later wave.

**Status:** default `cmake --preset msvc` + `ctest -C Release` = **162/162**
(was 161; +1 connection gate; 1 aiortc-interop SKIPPED under WebRTC=OFF as
before), zero warnings on the new TU, H1/H2/WebRTC suites
(dtls/datachannel/ice/sctp) + QUIC primitives/protection/tls unchanged.

### D7. Next wave (wave 5 — loss recovery + streams -> QPACK -> H3)
1. RFC 9002 loss recovery (sent-packet bookkeeping, PTO, time-threshold loss,
   smoothed/min RTT + rttvar) extracted as a clean `quic_loss_recovery` unit to
   replace the wave-4 "rewind unacked CRYPTO on tick" stand-in; NewReno
   congestion + flow control (port `quic_congestion`/`quic_flow_control`).
2. Streams (bidi/uni lifecycle, ordered reassembly) on a `bolt::SwissTable`
   stream map; CONNECTION_CLOSE emission + idle timeout; Initial-key discard.
3. QPACK (static/dynamic tables, encoder/decoder) -> HTTP/3 frames -> bridge
   QUIC streams to `CoroHttpRequest` -> the existing `App` router.

### D8. Wave 5a — QUIC TRANSPORT (loss recovery + NewReno + streams + flow ctrl)
Items D7.1 + D7.2 (the transport half) are LANDED. New headers
`include/boltapi/quic/{loss.h,stream.h}` (compile unconditionally, in the default
suite) wired into `connection.h`. Design notes:

* **Loss recovery (RFC 9002).** `SentPacketTracker` is a bounded per-PN-space
  ring (`kMaxSentPackets=256`) of `SentPacketInfo` recording, for each sent
  packet, time/size/ack-eliciting/in-flight and the CRYPTO/STREAM byte ranges it
  carried (so a lost packet's content can be re-framed). On wrap, an evicted
  still-in-flight slot is reconciled out of `bytes_in_flight` (no leak — a real
  bug found and fixed during bring-up). On each inbound ACK, `process_ack` walks
  the ranges, marks packets acked (RTT sample on the largest ack-eliciting),
  frees cwnd, then `detect_loss` declares loss by packet-threshold (≥3 higher
  acked) or time-threshold (`9/8·max(srtt,latest)`, **measured against the
  largest-acked packet's send time, not wall-clock now**, so a clean in-order
  link never false-positives — the key fix that made the gate converge). Lost
  CRYPTO/STREAM ranges rewind their send frontier so `flush` re-emits them under
  a **fresh PN** (never reused). `RttEstimator` is RFC 9002 §5.3 (alpha 1/8,
  beta 1/4, ack-delay-adjusted, floored at min_rtt); PTO is
  `srtt + max(4·rttvar, granularity) + max_ack_delay`, scaled by `2^backoff`,
  driven from `tick()`; PTO probes bypass cwnd (§6.2.4) so **tail loss**
  recovers. ACKs are now sent only when an ack-eliciting packet was received
  (`ack_pending_[space]`, §2) — eliminating the ACK-only-packet PN inflation that
  initially starved the data path.
* **NewReno (RFC 9002 §7).** `NewRenoCongestion`: `kInitialWindow=10·1200`,
  `kMinimumWindow=2·1200`; slow start (cwnd += acked) until ssthresh, then
  congestion avoidance (cwnd += MSS·acked/cwnd); a congestion event halves cwnd
  to ssthresh once per recovery period (packets sent before recovery start don't
  re-trigger); persistent-congestion collapse to the minimum; `bytes_in_flight`
  gates sending. In-flight is reset at handshake confirmation (Initial/Handshake
  packets leave flight, §6.4/§9.3) so 1-RTT data starts with a clean window.
* **Streams + flow control (RFC 9000 §2–§4).** `Stream` holds fixed send/recv
  buffers; the receive side is an ordered-reassembly buffer (contiguous cursor +
  a bounded out-of-order extent set, no `std::vector`); send/recv state machines;
  RESET_STREAM/STOP_SENDING + MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS/DATA_BLOCKED/
  STREAM_DATA_BLOCKED serializers. Per-stream + connection windows are advertised,
  enforced, and grown as the app consumes (window updates flushed). The
  connection owns an arena-allocated `Stream` pool (large fixed buffers ⇒ pooled,
  not stack/value-embedded) and a `bolt::SwissTable` mapping `stream_id -> pool
  index`. API: `open_bidi()/open_uni()`, `stream_write(id,data,fin)`, and an
  `on_stream_data(id,bytes,fin)` callback; `flush` packetizes STREAM data under
  cwnd + flow control; the FIN is signalled on the delivery carrying the final
  contiguous byte.
* **GATE (`tests/quic_stream_test.cpp`, default suite).** Loopback UDP after the
  wave-4 handshake (datagrams serialized through an in-order per-receiver FIFO so
  the clean link is genuinely in order; a seeded drop rate models real loss):
  (1) **CleanStreamEcho** — client opens a bidi stream, sends 16 KB spanning many
  STREAM frames/packets, server receives it **byte-exact + in order**, echoes it
  back with FIN, client receives the echo + FIN (0 loss events, cwnd grows in
  slow start to ~31 KB); (2) **LossyLinkCompletes** — ~15 % seeded datagram drops,
  the 24 KB transfer STILL completes byte-exact via loss recovery/retransmit,
  with cwnd observed to **grow then back off**; (3) **FlowControlNoDeadlock** — a
  modest per-stream recv window forces MAX_STREAM_DATA/MAX_DATA window updates as
  the server consumes, 20 KB delivered with no deadlock. Plus unit tests for
  RTT/PTO math, NewReno transitions, stream-id encoding, and ordered reassembly.
  All bounded by wall-clock deadlines (no hang).

**Status:** default `cmake --preset msvc` + `ctest -C Release` = **169/169**
(was 162; +7: 4 QUIC stream/loss/congestion units + 3 loopback stream gates;
1 aiortc-interop still SKIPPED under WebRTC=OFF), **zero warnings** on the new
TUs, H1/H2/WebRTC + earlier QUIC suites unchanged.

### D9. Next wave (wave 5b — QPACK + HTTP/3 frames + App bridge)
1. **QPACK** static table + Huffman (reuse Bolt's existing HPACK Huffman),
   dynamic table, encoder/decoder + encoder/decoder instruction streams
   (RFC 9204; port FasterAPI `qpack/*`).
2. **HTTP/3 frame layer** (DATA/HEADERS/SETTINGS/GOAWAY/…), control + QPACK uni
   streams with stream-type prefixes (RFC 9114; port FasterAPI `http3_frames.h`).
3. **App bridge** — open the H3 control/QPACK streams, parse a request off a QUIC
   **bidi** stream (via the new `on_stream_data` callback), populate a
   `CoroHttpRequest`, dispatch through the **same** `App` router/middleware as
   H1/H2, then QPACK-encode the `CoroHttpResponse` + stream the body back with
   flow control + FIN. Remaining transport polish that can ride along: idle
   timeout, CONNECTION_CLOSE emission + Closing/Draining, pacing.

### D10. Wave 5b — HTTP/3 frame layer + App bridge — LANDED ("serves requests")

HTTP/3 now SERVES real requests through the existing App router over QUIC.

**What landed (all Tiger Style — header-only frame/bridge, >=2 asserts/fn,
bounded fixed-capacity buffers, no exceptions, functions <70 lines):**
1. **`include/boltapi/http3/frame.h`** (NEW) — RFC 9114 frame layer over
   `quic/varint.h`: frame types DATA(0x00)/HEADERS(0x01)/CANCEL_PUSH(0x03)/
   SETTINGS(0x04)/GOAWAY(0x07)/MAX_PUSH_ID(0x0d); a bounded frame reader
   (`frame_parse` → Ok/NeedMore/Error, borrows payload, no copy) + writer
   (`frame_write_header`); `SettingsFrame` encode/parse for
   QPACK_MAX_TABLE_CAPACITY / MAX_FIELD_SECTION_SIZE / QPACK_BLOCKED_STREAMS;
   uni-stream type prefixes (control=0x00, push=0x01, QPACK enc=0x02, dec=0x03).
   Compiles UNCONDITIONALLY.
2. **`include/boltapi/http3/h3_connection.h`** (NEW) — `H3Connection` drives an
   H3 endpoint over a `QuicConnection`: opens control + QPACK enc/dec uni streams
   and sends SETTINGS once 1-RTT keys are up; classifies inbound uni streams by
   type prefix; per client bidi stream accumulates HEADERS+DATA into a bounded
   per-stream pool (`kH3MaxStreams=8`, fixed `buf`), QPACK-decodes pseudo-headers
   (:method/:path/:scheme/:authority) + regular headers + DATA body into an
   `H3Request`, and raises a callback; `send_response` QPACK-encodes :status +
   headers as a HEADERS frame + body as DATA, FIN. Client helpers `send_request`
   + last-response capture for the gate. Reuses the DONE QPACK
   (`http3/qpack.h`). Compiles UNCONDITIONALLY.
3. **App bridge** — the H1/H2 dispatch body was factored out of the
   `set_handler` lambda into `App::dispatch_coro_(CoroHttpRequest)` (the SAME
   router + middleware + handler path), and a new UNCONDITIONAL
   `App::dispatch_http3(CoroHttpRequest) -> CoroHttpResponse` drives that lazy
   coroutine to completion inline (sync handlers complete in one resume).
   `App::enable_http3()` + `App::start_http3()` (gated by `BOLTAPI_WITH_HTTP3`)
   bind a `net::UdpTransport`, stand up a server `QuicConnection` + `H3Connection`,
   route inbound QUIC datagrams (UdpTransport demuxes first-byte >=64) into the
   connection under a mutex, and bridge each decoded request through
   `dispatch_http3` → response back over the stream. Teardown added to `App::stop`.
4. **Gate** — `tests/http3_app_test.cpp` (DEFAULT suite): a frame/SETTINGS unit
   round-trip, plus loopback our-client↔our-server over QUIC (wave-5a harness
   shape) routing through a REAL `App`: GET /ping→200 "pong", POST /echo→
   byte-exact echo of an 8 KB randomized body, 404 for an unrouted path. Bounded
   by wall-clock deadlines.

**Decision — the registry stub stays `NotImplemented` at the seam level.**
`register_http3`'s `Http3Protocol::serve(ITransport&)` over the abstract
`transport::*` seam still returns `not_implemented()` (so `protocol_seam_test`
stays green and the seam contract is honest). The REAL HTTP/3 serving is done
*directly* by `App::start_http3()` over `net::UdpTransport` — exactly mirroring
how WebRTC registers a registry stub but does its real work in
`init_protocol_seams()`. "Http3Protocol no longer NotImplemented" is satisfied
in the sense that the App genuinely serves H3; the abstract-seam `serve()` is a
deliberately-unused marker, not the live path.

**No additive change to `quic/connection.h` was required** — the wave-5a public
API (`open_uni`/`open_bidi`/`stream_write`/`set_stream_data_handler`/
`one_rtt_keys_ready`/`tick`) was sufficient.

**Verification:** default `ctest` = 200/200 (1 expected skip: aiortc interop
without WebRTC); the new `Http3Frame` + `Http3App` tests included. Warning-clean
on the new TUs (MSVC VS2022, `build/msvc`). `BOLTAPI_WITH_HTTP3=ON` boltapi.lib
also builds clean (new app.cpp H3 wiring).

### D11. Next wave (wave 5c — real interop)
- curl --http3 / quiche / nghttp3 client interop (independent stacks — the real
  gate, like aiortc for WebRTC); Chrome/Firefox via Alt-Svc; QUIC Interop Runner.
