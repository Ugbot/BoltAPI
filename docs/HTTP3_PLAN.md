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

- [ ] **2.1 Varint codec.** *What:* RFC 9000 §16 variable-length ints.
      *PORT* `C:\code\FasterAPI\src\cpp\http\quic\quic_varint.h` (already pure,
      header-only, branchy-but-correct; keep as-is, rename namespace). *Bolt
      primitive:* none needed; consider a SWAR fast path later (Phase 9). 
- [ ] **2.2 Long/short header parse + serialize, connection IDs.** *What:* Initial
      / 0-RTT / Handshake / Retry / Version-Negotiation (long) and 1-RTT (short)
      headers; DCID/SCID extraction. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_packet.{h,cpp}`. *Bolt primitive:*
      parse/write through `bolt::wire` (`extern/bolt/include/bolt/wire/bolt_wire.h`)
      for zero-copy framing; `bolt_port.h` bitops for header-byte flags.
- [ ] **2.3 Packet number spaces + decoding.** *What:* Initial/Handshake/AppData
      spaces, largest-acked tracking, truncated PN reconstruction (RFC 9000 §17.1).
      *PORT* `C:\code\FasterAPI\src\cpp\http\quic\quic_packet_number_space.h`.
      *Bolt primitive:* n/a (small fixed structs).
- [ ] **2.4 Frame parse/serialize (all frame types).** *What:* PADDING, PING,
      ACK(+ECN), RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA,
      MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED,
      NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE,
      CONNECTION_CLOSE, HANDSHAKE_DONE. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_frames.h`. *Bolt primitive:*
      `bolt::wire` reader/writer; per-packet scratch in `bolt::Arena`.
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

- [ ] **3.1 Crypto buffer (per-level CRYPTO stream reassembly).** *What:* ordered
      reassembly of handshake bytes per encryption level. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_crypto_buffer.h`. *Bolt primitive:*
      `bolt::Arena` for the reassembly scratch; ring buffer for ordered bytes.
- [ ] **3.2 Packet protection: AEAD + header protection + HKDF.** *What:* real
      AES-128/256-GCM + ChaCha20-Poly1305 via OpenSSL EVP, HKDF-Expand-Label,
      header protection mask (RFC 9001 §5). *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_packet_protection.h` — audit
      confirms this is **real OpenSSL EVP** crypto, port as-is. *Bolt primitive:*
      arena scratch for nonce/mask; avoid per-op allocation (reuse `EVP_CIPHER_CTX`).
- [ ] **3.3 TLS 1.3 QUIC method (quictls callbacks).** *What:* `SSL_QUIC_METHOD`
      with set_encryption_secrets / add_handshake_data / flush_flight /
      send_alert; `SSL_provide_quic_data` + `SSL_do_handshake` driver; ALPN `h3`;
      QUIC transport parameters extension (encode/decode). *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_tls.h` (974 lines, real
      `SSL_QUIC_METHOD` integration per audit). *Bolt primitive:* n/a (delegates
      to quictls); transport-params codec uses `quic_varint.h`.
- [ ] **3.4 Handshake manager (level transitions, key install).** *What:* drives
      handshake state across Initial/Handshake/1-RTT, installs read/write keys per
      level as secrets arrive, derives Initial keys from the DCID. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_handshake.h`. *Bolt primitive:*
      fixed per-level key arrays (no map).
- [ ] **3.5 Secure connection = the real encrypt/decrypt connection.** *What:*
      the connection class that actually applies 3.2–3.4 (encrypt outgoing /
      decrypt incoming packets in a live connection). *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_secure_connection.h` (34KB, real
      encrypt/decrypt per audit). **This replaces the stubbed base
      `quic_connection.cpp` path** — see salvage map. *Bolt primitive:*
      `bolt::Arena` per-packet; `bolt::SwissTable` for streams (Phase 5).
- [ ] **3.6 Self-test the AEAD/HP against RFC 9001 Appendix A test vectors.**
      *What:* the published Initial-packet sample (keys, nonce, sample, protected
      bytes) must reproduce exactly. *PORT* FasterAPI's protection gtests if
      present; otherwise add vectors. *Bolt primitive:* n/a.

**GATE 3:** RFC 9001 Appendix A vectors pass; a unit test drives a *real* TLS 1.3
handshake between two in-process `QUICSecureConnection`s to ESTABLISHED (the
end-to-end encrypted handshake the FasterAPI tests never exercised — audit:140).

---

## Phase 4 — Connection state machine, loss, congestion, flow control, ACK

- [ ] **4.1 Connection state machine.** *What:* IDLE -> HANDSHAKE -> ESTABLISHED
      -> CLOSING/DRAINING -> CLOSED; idle timeout; CONNECTION_CLOSE handling.
      *PORT the state-machine shape from*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_connection.{h,cpp}` **but drive the
      secure path from 3.5** (do **not** port the plaintext decrypt TODOs at
      `quic_connection.cpp:138/170` — those are the stub the audit flagged).
      *Bolt primitive:* `bolt::SwissTable` for stream map (replace
      `std::unordered_map<uint64_t, unique_ptr<QUICStream>>`).
- [ ] **4.2 ACK tracking + ACK frame generation.** *What:* received-PN ranges,
      ACK ranges, ACK delay, ECN counts. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_ack_tracker.{h,cpp}`. *Bolt
      primitive:* fixed-capacity range vector in an arena; SWAR for gap scans.
- [ ] **4.3 Loss detection + RTT (RFC 9002).** *What:* sent-packet bookkeeping,
      ack-eliciting tracking, PTO + time-threshold loss, smoothed/min RTT + rttvar.
      *REBUILD into `quic_loss_recovery.{h,cpp}`* — extract from FasterAPI's
      `quic_connection.cpp`/`quic_congestion.cpp` where it's tangled; make it a
      clean RFC 9002 unit. *Bolt primitive:* `bolt::Arena` for the sent-packet ring;
      no per-packet alloc.
- [ ] **4.4 Congestion control (NewReno; CUBIC later).** *What:* cwnd, slow start,
      recovery, pacing rate input. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_congestion.{h,cpp}`
      (`NewRenoCongestionControl`, 19KB, real). *Bolt primitive:* n/a (scalar
      state); branchless updates via `bolt_branchless.h` where hot.
- [ ] **4.5 Flow control (stream + connection level).** *What:* MAX_DATA /
      MAX_STREAM_DATA / MAX_STREAMS windows, auto-tuning, blocked frames. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_flow_control.{h,cpp}` (real).
      *Bolt primitive:* n/a.
- [ ] **4.6 Stream management + reassembly.** *What:* bidi/uni stream lifecycle,
      send/recv state, ordered receive reassembly, RESET/STOP_SENDING. *PORT*
      `C:\code\FasterAPI\src\cpp\http\quic\quic_stream.{h,cpp}` +
      `C:\code\FasterAPI\src\cpp\http\quic\stream_reassembly_buffer.h`. *Bolt
      primitive:* `bolt::SwissTable` for the per-connection stream map; ring buffer
      / arena for reassembly (avoid `std::vector` regrowth).
- [ ] **4.7 Connection map (CID -> connection).** *What:* route incoming
      datagrams by DCID (and 4-tuple fallback) to the owning connection; handle
      multiple CIDs per connection. *REBUILD.* *Bolt primitive:* `bolt::SwissTable`
      keyed on CID bytes; `bolt_hash.h` for the CID hash.

**GATE 4:** multi-stream loopback test (two real secure connections) transfers
randomized payloads across **several concurrent streams**, with simulated
loss/reorder, verifying retransmission, flow-control backpressure, RTT/cwnd
evolution, and clean close. (Satisfies `CLAUDE.md`: more than one stream,
randomized data.)

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
- [ ] **8.2 Unit: packet protection** — RFC 9001 Appendix A vectors + random
      AEAD round-trip. *PORT* from FasterAPI's protection tests.
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
