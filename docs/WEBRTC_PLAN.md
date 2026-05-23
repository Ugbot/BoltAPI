# Bolt API — WebRTC Implementation Punch-Card

> Ordered, tickable plan to take WebRTC from the M3 **seam stub**
> (`src/proto/webrtc_stub.cpp` → `NotImplemented`) to a real, correctness-first,
> then-performance implementation. **Data-channels first**; media (RTP/SRTP)
> deferred. Correctness gates precede every performance item.
>
> **Hard rule (from the seam):** none of this touches the live HTTP/1.1 + HTTP/2
> + TLS + WebSocket + SSE core (`src/server/coro_unified_server.cpp`, `App`).
> Everything plugs in via `IProtocol` + `ProtocolRegistry` over `UdpTransport`,
> and via ordinary `App` routes for signaling. All new code is compiled only
> under `BOLTAPI_WITH_WEBRTC`.
>
> Status legend: `- [ ]` not started · `- [~]` in progress · `- [x]` done.
> Each item tags: **PORT** (lift a FasterAPI file, cite path) / **ADAPT**
> (reshape it) / **REBUILD** (write fresh) / **DROP**, plus the **Bolt primitive**.

---

## 0. Honest assessment of the FasterAPI WebRTC inheritance

The audit (`FasterAPI/AUDIT_NOTES.md:99-102`, `FASTERAPI_AUDIT.md:35`) rates the
FasterAPI WebRTC at **~40% scaffold: interfaces exist, transport + crypto do
not.** Confirmed by reading the source:

- **`webrtc/sdp_parser.{h,cpp}`** — *the one genuinely reusable piece.* A real
  line-by-line SDP parser/generator (v/o/s/c/t/m/a), zero-copy `string_view`
  views, handles flag vs `name:value` attributes and media format lists. Caveat:
  uses `std::unordered_map`/`std::ostringstream` (allocates) and `std::stoi`
  (throws — violates `-fno-exceptions`). **ADAPT**, don't rewrite.
- **`webrtc/ice.{h,cpp}`** — *stub.* `ICECandidate::from_string` returns a
  hardcoded candidate (`ice.cpp:50-54`); `gather_host_candidates` only adds
  `127.0.0.1` (`:181-201`); `gather_srflx_candidates` is 4 TODOs, no STUN
  (`:203-215`); `STUNMessage::parse/generate` handle only the 20-byte header, no
  attributes (`:63-125`); `start_connectivity_checks` returns 0 doing nothing
  (`:160-164`); `get_selected_pair` returns `candidates[0]` (`:166-179`).
  **REBUILD.** The candidate `to_string` (`:13-39`) is correct and small — keep.
- **`webrtc/data_channel.{h,cpp}`** — *stub above a missing layer.* `send_sctp`
  just `std::cout`s (`data_channel.cpp:145-154`); `close` doesn't send anything
  (`:60-76`). No SCTP exists at all. The PPID enum (RFC 8831) and the
  text/binary dispatch in `receive_data` (`:96-143`) are correct and worth
  keeping. **ADAPT** the message-layer shell; **REBUILD** everything under it.
- **`webrtc/signaling.{h,cpp}`** + `fasterapi/webrtc/signaling.py` — a
  *room/relay SFU-signaling* model (peers, rooms, relay offer/answer/ICE). Real
  logic but `send_to_peer` only `std::cout`s (`signaling.cpp:148-165`) and it
  models browser↔browser relay, not browser↔**our server** answerer. Bolt's v1
  is "WebRTC as transport" (peer = browser, answerer = us). **ADAPT** the
  message shapes; **REBUILD** the wiring against an `App` route.
- **`webrtc/message_parser.{h,cpp}`** — simdjson-based signaling JSON
  parse/generate. `ostringstream` generate + `new`/`delete` parser, and
  ICE-candidate parse is `"{}"` TODO (`message_parser.cpp:71`). **ADAPT** (swap
  generation to manual append; reuse Bolt's existing JSON if present).
- **`webrtc/rtp.{h,cpp}`** — RTP header parse/serialize is real and correct
  (`rtp.cpp:18-115`). **SRTP encrypt/decrypt/derive_session_keys are all TODO**
  (`:147-205`) — they *memcpy and zero a fake tag*, i.e. no crypto. Media is out
  of v1: **DEFER** rtp parse (PORT later), **REBUILD** SRTP later.
- **`http/webtransport_connection.{h,cpp}`** — WebTransport-over-HTTP/3, a
  different stack (CONNECT-UDP / HTTP/3 datagrams). Not on the WebRTC critical
  path. **DROP** for this plan; revisit only if WebTransport is requested (it
  shares the H3 `UdpTransport`).
- **`fasterapi/webrtc/sdp.py`** — Python SDP munging. Bolt is C++-first; **DROP**
  (a thin Python wrapper can come after the C++ path works).

**Net:** salvage SDP parsing (adapt), candidate `to_string`, the PPID enum +
text/binary dispatch, and the RTP header codec (later). **Everything that makes
WebRTC actually connect — ICE/STUN, DTLS, SCTP — must be built.** This matches
the audit's "mostly REBUILD."

### Salvage map

| FasterAPI file | Verdict | One-line reason |
|---|---|---|
| `webrtc/sdp_parser.{h,cpp}` | **ADAPT** | Real SDP parse/gen; strip `unordered_map`/`ostringstream`/`stoi`, make `-fno-exceptions`-safe. |
| `webrtc/ice.cpp` `ICECandidate::to_string` (`:13-39`) | **PORT** | Correct candidate serializer, tiny, no deps. |
| `webrtc/ice.cpp` `from_string` (`:41-57`) | **REBUILD** | Returns hardcoded candidate; no real parse. |
| `webrtc/ice.cpp` `gather_host/srflx` (`:181-215`) | **REBUILD** | Host = only `127.0.0.1`; srflx = 4 TODOs, no STUN. |
| `webrtc/ice.cpp` `STUNMessage::parse/generate` (`:63-125`) | **REBUILD** | Header-only; no attributes, no MAPPED-ADDRESS, no MESSAGE-INTEGRITY/FINGERPRINT. |
| `webrtc/ice.cpp` connectivity/`get_selected_pair` (`:160-179`) | **REBUILD** | No checks; returns `candidates[0]`. |
| `webrtc/data_channel.h` PPID enum + `receive_data` dispatch (`:65-73`, `cpp:96-143`) | **ADAPT** | Correct RFC 8831 PPIDs + text/binary split; reuse over real SCTP. |
| `webrtc/data_channel.cpp` `send_sctp`/`close` (`:60-76`, `:145-154`) | **REBUILD** | `std::cout` placeholder; no SCTP/DTLS underneath. |
| `webrtc/signaling.{h,cpp}` | **ADAPT** | Message shapes useful; rewire from browser-relay to App-route answerer; `send_to_peer` is `cout`. |
| `webrtc/message_parser.{h,cpp}` | **ADAPT** | simdjson parse OK; manual JSON gen; candidate parse is `"{}"` TODO. |
| `webrtc/rtp.cpp` header parse/serialize (`:18-115`) | **PORT (later)** | Correct RTP codec; media is a later phase. |
| `webrtc/rtp.cpp` SRTP (`:147-205`) | **REBUILD (later)** | encrypt/decrypt/derive all TODO; fake auth tag. |
| `http/webtransport_connection.*` | **DROP** | Different stack (WebTransport/H3); not WebRTC critical path. |
| `fasterapi/webrtc/sdp.py`, `signaling.py` | **DROP / later** | Python wrappers; do C++ path first. |

---

## 1. Scope decision (v1 vs later)

- [ ] **Lock v1 scope = data channels only ("WebRTC as transport").** The
      browser is the *offerer*; Bolt is the *answerer*. One `RTCPeerConnection`
      with `createDataChannel(...)`, terminated by Bolt, surfaced to `App` as
      `IDataChannel`. **REBUILD** (decision/doc). No Bolt primitive.
- [ ] **v1 in-scope:** signaling over an `App` route; SDP offer/answer; ICE host
      + server-reflexive (STUN) candidates with full connectivity checks; DTLS
      1.2 (then 1.3) handshake (server role); SCTP association + DCEP +
      ordered/reliable channels; `IDataChannel` send/receive to `App`.
- [ ] **v1 explicitly OUT (later phases):** media (RTP/RTCP/SRTP/jitter/codecs);
      TURN relay candidates; trickle-ICE renegotiation; multi-m-line / BUNDLE of
      media; SFU/room relay; Python binding. Document each as a later phase below.
- [x] **Define the public `App` surface** (sketch, to refine): `App::Config`
      already has `enable_webrtc` (`include/boltapi/app.h:72`). Add
      `App::enable_webrtc(WebRtcConfig)` returning `*this`, and an
      `on_data_channel(label, handler)` registration mirroring `websocket(...)`
      (`app.h:117`). **REBUILD.** No core edits — additive like the WS/SSE regs.
      DONE (Wave 1): added `WebRtcConfig` (`app.h`), `enable_webrtc(WebRtcConfig={})`
      and `on_data_channel(label, handler)` (additive, chainable). Enabling logs
      "WebRTC: signaling/codecs ready, transport not yet implemented" in
      `init_protocol_seams()` (`src/app.cpp`); H1/H2 serving untouched.

---

## 2. Shared UDP transport (prerequisite — co-owned with HTTP/3)

> WebRTC and HTTP/3 share **one** `UdpTransport`. The real socket loop is
> specified in `docs/HTTP3_PLAN.md`; this section lists only what WebRTC needs
> from it and the demux WebRTC adds. Do not duplicate the socket code.

- [x] **Depend on the real `UdpTransport`**. DONE (Wave 2):
      `include/boltapi/net/udp_transport.h` + `src/net/udp_transport.cpp` — a
      standalone, protocol-agnostic UDP transport. ARCHITECTURE DECISION
      (correctness-first, isolation): the engine's `IODispatcher` has no UDP
      path and `async_io` must NOT be touched, so `UdpTransport` owns its OWN
      UDP socket + a dedicated receive thread (non-blocking socket + a 50ms
      `select()` poll loop + atomic stop flag → clean, hang-free shutdown on
      winsock and POSIX). `bind(host,port)` (IPv4; ephemeral via port 0, IPv6 a
      TODO hook), `start()/stop()` lifecycle, `send(peer,len)` → `sendto`,
      `recvfrom` into a PREALLOCATED 2KB buffer capturing the source `sockaddr`,
      cache-line-padded atomic rx/tx/drop counters. Compiled UNCONDITIONALLY
      into `boltapi`. Batched recv (`recvmmsg`/IOCP) is a LATER perf phase (§11).
- [x] **First-byte packet demultiplexer on the UDP socket** (RFC 7983). DONE
      (Wave 2): in the receive loop, classify by first byte — `0..3` → STUN
      (routed to the registered `StunHandler`/IceAgent), `20..63` → DTLS (routed
      to the registered datagram handler; none yet → dropped with a counter),
      else → dropped with a counter. RTP/RTCP (`128..191`, media) is a later
      phase. Per-peer SwissTable keyed by 4-tuple is deferred to the DTLS/SCTP
      wave (ICE-lite handles STUN inline in the rx path — cheap + correct).
- [ ] **I/O→worker handoff for WebRTC packets.** Inbound classified datagrams
      cross from the I/O thread to the peer's worker via a lock-free SPSC. One
      SPSC per peer connection. **REBUILD.** Bolt primitive: `bolt_channel.h`
      SPSC (fall back to `bolt_disruptor.h` if multi-producer needed).
- [ ] **Per-packet arena.** Each inbound datagram processed in a thread-local
      `bolt::Arena` reset per packet — STUN parse, DTLS record, SCTP chunk parse
      all allocate from it, zero `malloc` in the hot path. **REBUILD.** Bolt
      primitive: `bolt_arena.h`.

---

## 3. Signaling (offer/answer over App routes)

> Reuses the existing routing + WS engine. No new core. Two transports offered:
> HTTP POST (simplest) and WebSocket (for trickle ICE).

- [ ] **`ISignaling` concrete impl** wired to a real `App` endpoint. Implement
      `protocol.h`'s `ISignaling::on_offer` / `on_ice_candidate`
      (`include/boltapi/protocol.h:216-230`) backed by the peer-connection
      factory. **REBUILD** (the sketch is declaration-only).
- [x] **HTTP signaling route:** `App.post("/webrtc/offer", ...)` accepts the
      browser's SDP offer (JSON `{type:"offer", sdp:"..."}`), drives ICE gather +
      SDP answer generation, returns the answer JSON. Reuses `Router`/`Request`/
      `Response` unchanged. **REBUILD** wiring; **ADAPT** JSON shapes from
      `webrtc/message_parser.cpp:91-132`.
      DONE (Signaling/interop wave): under `BOLTAPI_WITH_WEBRTC` + `enable_webrtc`,
      `build_dispatch()` registers a POST route at `WebRtcConfig.signaling_path`
      (default `/webrtc/offer`) backed by `App::handle_webrtc_offer(body, answer)`
      (`src/app.cpp`): accepts the OFFER as raw SDP **or** a JSON `{"sdp":...}`
      envelope (both), parses it with our SDP codec, extracts the peer
      ice-ufrag/ice-pwd (pinned on the `IceAgent` via `set_expected_remote` for
      STUN USERNAME validation) and the sha-256 DTLS fingerprint (pinned on the
      `DtlsSessionManager` for peer-cert verification), and returns OUR ANSWER
      (`build_answer`: ice-lite, setup:passive, our ufrag/pwd, our
      fingerprint:sha-256, our host `a=candidate` lines, the application m-line,
      sctp-port + max-message-size, group:BUNDLE/mid/msid-semantic). The route is
      an ordinary `App` POST — H1/H2 serving is untouched. V1 = single active peer
      (a new offer re-pins the stack); multi-peer keyed by ufrag is §13. Unit
      test: `tests/signaling_test.cpp`. Validated end-to-end against aiortc (§10).
- [ ] **WebSocket signaling route** (for trickle ICE / renegotiation):
      `App.websocket("/webrtc/signal", ...)` (mirrors `app.h:117`). Messages:
      `offer`/`answer`/`ice-candidate` — shapes **ADAPT** from
      `fasterapi/webrtc/signaling.py:225-240` and `webrtc/signaling.cpp:68-117`.
      Drop the room/SFU relay logic (out of v1 scope §1). **ADAPT/REBUILD.**
- [x] **SDP parser/generator (ADAPT `webrtc/sdp_parser.{h,cpp}`).** Lift the
      line parser; replace `std::unordered_map` attribute store with a small
      fixed-capacity vector of `{key,val}` `string_view`s, replace
      `std::ostringstream generate` with manual buffer append into a
      `bolt::Arena`, and replace `std::stoi` (`sdp_parser.cpp:124`) with a
      noexcept `from_chars`. **ADAPT.** Bolt primitive: `bolt_arena.h` +
      `bolt::wire` byte append.
      DONE (Wave 1): `include/boltapi/webrtc/sdp.h` + `src/webrtc/sdp.cpp`.
      Fixed-capacity `SdpAttribute[]`/`SdpMedia[]` (no unordered_map), zero-copy
      `string_view` fields, `std::from_chars` (no stoi), manual `std::string`
      append (no ostringstream), all noexcept. Compiled unconditionally into
      `boltapi`. (Used plain `std::string` append rather than `bolt::Arena` —
      generate is not a per-packet hot path; parse is zero-alloc.)
- [x] **SDP answer builder for the data-channel m-line.** Emit
      `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`, plus
      `a=setup:passive`, `a=fingerprint:sha-256 <cert fp>`, `a=ice-ufrag`,
      `a=ice-pwd`, `a=sctp-port:5000`, `a=mid:0`, and our host/srflx
      `a=candidate:` lines. **REBUILD** (FasterAPI never produced a real answer).
      Bolt primitive: `bolt_arena.h`.
      DONE (Wave 1): `webrtc::build_answer(AnswerParams, std::string&)` emits the
      full passive answer (BUNDLE, ice-ufrag/pwd, fingerprint:sha-256, setup,
      mid, sctp-port, max-message-size, optional a=ice-lite). Wave 2:
      `AnswerParams.candidates[]` now emits the IceAgent's `a=candidate:` host
      lines + `a=end-of-candidates`; DTLS fingerprint stays a placeholder hook.
- [x] **Parse the offer's required fields:** remote `ice-ufrag`/`ice-pwd`, remote
      DTLS `fingerprint` + `setup` role, `mid`, `sctp-port`, and the offerer's
      `candidate:` lines (trickle or in-SDP). **REBUILD** the field extraction on
      top of the adapted parser.
      DONE (Wave 1): `SdpMedia` accessors `ice_ufrag()/ice_pwd()/fingerprint()/
      setup()/mid()/sctp_port()/max_message_size()` + generic `attr("candidate")`;
      `SdpSession::application_media()`.
- [x] **Correctness gate:** unit test parses real Chrome + Firefox offers (fixed
      fixtures) and round-trips an answer that those browsers accept (validated
      in the interop test §10). No Bolt primitive.
      DONE (Wave 1): `tests/sdp_test.cpp` — parses a real Chrome + Firefox
      data-channel offer, asserts the extracted fields, round-trips a built
      answer, and rejects malformed/empty/overflow input without throwing.
      Browser-acceptance interop validation still pending (needs the transport).

---

## 4. STUN client + message codec

> RFC 5389/8489. Needed for connectivity checks (mandatory) and srflx gathering.

- [x] **Full STUN message codec (REBUILD `STUNMessage`, `ice.cpp:63-125`).**
      Parse/generate header **and attributes**: `MAPPED-ADDRESS`,
      `XOR-MAPPED-ADDRESS`, `USERNAME`, `MESSAGE-INTEGRITY` (HMAC-SHA1),
      `FINGERPRINT` (CRC-32), `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLING/
      CONTROLLED`, `ERROR-CODE`. Keep the existing magic-cookie check
      (`ice.cpp:79`). **REBUILD.** Bolt primitive: `bolt::wire` for fixed-layout
      attribute TLV framing; `bolt_arena.h` for the message buffer.
      DONE (Wave 1): `include/boltapi/webrtc/stun.h` + `src/webrtc/stun.cpp`.
      Header (class/method bit-encode, magic cookie, 96-bit TID) + TLV with
      4-byte padding; all listed attributes; zero-copy parse into a bounded
      fixed `Attribute[]` (no heap), `Builder` writes into a caller buffer (no
      heap). Compiled unconditionally into `boltapi`. (Hand-rolled big-endian
      read/write helpers rather than `bolt::wire`; codec is self-contained.)
- [ ] **Transaction-ID generation + matching table.** 96-bit random TID per
      request, matched on response. **REBUILD.** Bolt primitive:
      `join/bolt_swiss.h` keyed by TID.
- [x] **MESSAGE-INTEGRITY (HMAC-SHA1) + FINGERPRINT (CRC-32).** Compute/verify
      over the message with the ICE password as key. **REBUILD.** Crypto: prefer
      a Bolt/own SHA1+HMAC; OpenSSL `HMAC` acceptable as the same justified
      stopgap as DTLS (§6). CRC-32 — Bolt likely has one (`bolt_hash.h`); else own.
      DONE (Wave 1): `Builder::add_message_integrity` (OpenSSL `HMAC`/`EVP_sha1`,
      with the RFC 5389 §15.4 header-length fixup) + `add_fingerprint` (own
      CRC-32, XOR 0x5354554e, §15.5); `verify_message_integrity`/
      `verify_fingerprint` recompute and compare. Validated byte-exact against
      RFC 5769 vectors (short-term + long-term MD5 credential).
- [ ] **STUN binding request → server-reflexive candidate.** Send binding
      request to configured STUN server(s), parse `XOR-MAPPED-ADDRESS`, emit an
      `srflx` candidate (fills the `gather_srflx_candidates` TODOs at
      `ice.cpp:203-215`). **REBUILD.** Bolt primitive: SPSC for the async
      response; `bolt_arena.h`.
- [~] **Correctness gate:** unit tests vs canned STUN vectors (RFC 5769 test
      vectors) for parse/generate + MESSAGE-INTEGRITY + FINGERPRINT; live binding
      request against a public STUN server (e.g. Google) returns our public IP.
      DONE (Wave 1): `tests/stun_test.cpp` — RFC 5769 §2.1 request, §2.2 IPv4
      response, §2.4 long-term-credential request decode + MESSAGE-INTEGRITY +
      FINGERPRINT verified byte-exact; XOR-MAPPED-ADDRESS decode to 192.0.2.1:
      32853; builder round-trips for ICE connectivity-check attributes; malformed
      input rejected without crash. PENDING: live binding request (needs UDP
      transport, next wave).

---

## 5. ICE agent (RFC 8445)

> Bolt is always the **controlled** answerer in v1, which simplifies nomination.

- [x] **Candidate model (ADAPT `ICECandidate`).** DONE (Wave 2):
      `include/boltapi/webrtc/ice.h` `IceCandidate`. PORTED `to_string`
      (FasterAPI `ice.cpp:13-39`) to manual `std::string` append (no `<sstream>`,
      `-fno-exceptions`). REBUILT `from_string` as a real tokenizer
      (foundation/component/proto/priority/addr/port/typ + optional raddr/rport),
      returns false on malformed input (no crash). Round-trip unit-tested.
- [x] **Host candidate gathering (REBUILD `gather_host_candidates`).** DONE
      (Wave 2): `IceAgent::gather_host_candidates(port)` enumerates real
      interfaces — `GetAdaptersAddresses` on Windows (`#ifdef _WIN32`, links
      iphlpapi) / `getifaddrs` on POSIX — collects usable IPv4 host candidates,
      skips loopback unless no other usable IPv4 exists, and assigns RFC 8445
      §5.1.2.1 host priority + foundation + type=host. Fixed-capacity candidate
      array (`kIceMaxCandidates`), no heap per candidate beyond the owned strings.
- [ ] **Server-reflexive gathering** — consume §4's STUN srflx output into the
      candidate list. **REBUILD.**
- [ ] **Candidate pairing + priority ordering** (RFC 8445 §6.1.2): form
      local×remote pairs, compute pair priority, sort, prune redundant.
      **REBUILD** (FasterAPI had none). Bolt primitive: fixed array +
      `bolt_branchless.h`-friendly priority compute.
- [ ] **Connectivity checks (REBUILD `start_connectivity_checks`,
      `ice.cpp:160-164`).** Triggered + ordinary checks: STUN binding requests
      with `PRIORITY` + `ICE-CONTROLLED`, role-conflict handling, retransmit with
      RTO backoff, mark pairs succeeded/failed, learn peer-reflexive candidates.
      **REBUILD.** Bolt primitive: SPSC for check responses; `bolt_arena.h`;
      a timer wheel for RTO (own or `bolt_scheduler.h` if it fits).
- [x] **Nomination + selected pair (REBUILD `get_selected_pair`).** DONE
      (Wave 2): as the controlled ICE-lite agent,
      `IceAgent::handle_stun(...)` validates the inbound Binding Request
      (USERNAME == "ourUfrag:..." + MESSAGE-INTEGRITY with OUR pwd), sends a
      Binding Success Response (XOR-MAPPED-ADDRESS(peer) + MESSAGE-INTEGRITY +
      FINGERPRINT), and on `USE-CANDIDATE` records the peer 4-tuple as the
      SELECTED pair (`selected_peer()` / `has_selected_peer()`), exposed for the
      DTLS wave. Bad username → 401, missing/garbled USERNAME → 400, bad
      integrity → 401; malformed input is dropped without crashing. SwissTable
      4-tuple→peer is deferred to multi-peer (DTLS/SCTP) wave.
- [x] **ICE-lite option.** DONE (Wave 2): decision taken — Bolt is the
      ICE-LITE controlled answerer. We advertise `a=ice-lite` (SDP
      `AnswerParams.ice_lite`) and implement the RESPONDER-ONLY path: we never
      initiate connectivity checks; we only answer Binding Requests. This is the
      `IceAgent` above.
- [ ] **Correctness gate:** unit test pairing/priority math vs RFC 8445 examples;
      integration test completes ICE with a browser (host + srflx) end to end.

---

## 6. DTLS (over the ICE-selected path)

> **Bolt-vs-third-party tension:** the project prefers Bolt-native / no
> third-party libs. **DTLS crypto is the justified stopgap to use OpenSSL.**
> Reimplementing the X.509/ECDHE/AEAD record stack is out of scope and a
> security footgun. We treat OpenSSL as a vendored crypto provider behind a thin
> Bolt-style wrapper; the *transport, demux, framing* around it stay Bolt-native.

- [x] **Self-signed cert + key generation at startup** (ECDSA P-256). Compute the
      **SHA-256 fingerprint** for the SDP `a=fingerprint` line (§3). **REBUILD**
      (wrapper over OpenSSL `EVP`/`X509`). Bolt primitive: none (one-time setup).
      DONE (DTLS wave): `include/boltapi/webrtc/dtls.h` + `src/webrtc/dtls.cpp`
      `DtlsContext::create()` builds an `SSL_CTX(DTLS_server_method())` with a
      fresh self-signed ECDSA P-256 cert (RSA-2048 fallback), and computes our
      cert's SHA-256 DER fingerprint as "AA:BB:.." via `x509_sha256_fingerprint`
      / `X509_digest`. One-time at App startup. Compiled UNCONDITIONALLY.
- [x] **DTLS server endpoint over UDP-via-ICE.** Drive OpenSSL DTLS with a
      **memory BIO** so we feed it datagrams from the UDP demux (§2) and pull out
      records to send — never letting OpenSSL own the socket (it must go through
      the ICE-selected 4-tuple). DTLS **1.2 first**, then enable **1.3**.
      **REBUILD.** Bolt primitive: `bolt_arena.h` for the per-record scratch;
      SPSC for the handshake datagram flow.
      DONE (DTLS wave): `DtlsSession` wraps a server-role `SSL` over a read BIO +
      write BIO (`BIO_s_mem`). `feed(datagram)` → `BIO_write(rbio)` →
      `SSL_do_handshake()` (handles WANT_READ/WANT_WRITE) → drain `wbio` with
      `BIO_read` → `UdpTransport::send(peer,…)` each record. `DtlsSessionManager`
      keys sessions by peer sockaddr (bounded fixed table; SwissTable is the §11
      perf upgrade) and is wired as `UdpTransport`'s datagram handler (first byte
      20..63). DTLS 1.2 floor (`set_min_proto_version`); 1.3 negotiates up. State:
      New → Handshaking → Established / Failed. (Per-record arena/SPSC is the §11
      perf phase; the wbio drain uses a fixed `kDtlsDrainBuf` stack scratch.)
- [x] **Server/client role from SDP `a=setup`.** Browser offers `actpass`; Bolt
      answers `setup:passive` → Bolt is DTLS **server**. Honor an offer that
      forces us active if it ever occurs. **REBUILD.**
      DONE (DTLS wave): `DtlsContext::new_ssl()` calls `SSL_set_accept_state`
      (server role); the SDP answer emits `a=setup:passive` (§3). The server is
      purely reactive — the manager creates a session on the first ClientHello
      and never speaks first. (An offer forcing us active is a later edge case.)
- [x] **Fingerprint verification.** After handshake, verify the peer cert's
      SHA-256 matches the `a=fingerprint` from the offer (§3). Reject on
      mismatch. **REBUILD** (this is the actual security check). Bolt primitive:
      none.
      DONE (DTLS wave): `SSL_VERIFY_PEER` + a permissive verify callback (WebRTC
      binds identity by fingerprint, not CA chain). On handshake completion,
      `verify_peer()` pulls the peer cert (`SSL_get1_peer_certificate`), computes
      its SHA-256, and compares to the offer's `a=fingerprint`
      (`fingerprints_equal`, tolerant of the "sha-256 " algo prefix + case).
      Mismatch → `State::Failed` (rejected). Validated by a NEGATIVE test.
- [x] **Export keying material** (`SCTP` needs none; **DTLS-SRTP export is media
      only**, deferred to §8). For v1 just confirm the handshake completes and
      the secure record layer is up. **REBUILD.**
      DONE (DTLS wave): handshake completion → `Established`; `send_app`/`read_app`
      (SSL_write/SSL_read over the BIOs) expose the secure record layer — the
      byte channel SCTP runs on next. DTLS-SRTP keying export is a documented
      TODO (media phase §12), not needed for data channels.
- [x] **Correctness gate:** standalone test does a full DTLS 1.2 then 1.3
      handshake against OpenSSL's `openssl s_client -dtls` and against a browser;
      assert fingerprint match enforced (negative test: wrong fp → rejected).
      DONE (DTLS wave): `tests/dtls_test.cpp` (gtest, UNCONDITIONAL) stands up our
      `UdpTransport`+`DtlsContext`+`DtlsSessionManager` (server) and runs a REAL
      OpenSSL DTLS CLIENT over a connected loopback UDP socket
      (`BIO_new_dgram`+`DTLS_client_method`, `SSL_connect`). Asserts BOTH sides
      reach handshake-complete, the server session is `Established`, the server
      reads the client cert and fingerprint verification PASSES (client cert
      SHA-256 fed in as the offer fp), a fingerprint MISMATCH is REJECTED
      (session `Failed`), and a DTLS app-data round-trip (client SSL_write →
      server read_app echoes → client SSL_read) works. Bounded by a 10s deadline.
      Browser + `s_client -dtls` interop is a later live-interop gate (§10).

---

## 7. SCTP over DTLS — the hard part (FasterAPI had none)

> **Bolt-vs-third-party tension (sharpest here).** Browsers speak SCTP-over-DTLS
> (RFC 8261) for data channels. Two paths:
>
> - **Option A — `usrsctp`** (the de-facto third-party userland SCTP). Fast to
>   correctness, but it's a large C dependency with its own allocator/threading,
>   directly contradicting the "Bolt-native, no third-party, preallocated"
>   ethos. If chosen, sandbox it behind a Bolt wrapper and a compile flag.
> - **Option B — focused Bolt-native minimal SCTP.** Implement *only* the subset
>   WebRTC data channels need: single stream-multiplexed association, DATA/SACK/
>   INIT/INIT-ACK/COOKIE/HEARTBEAT/FORWARD-TSN, ordered + unordered, reliable +
>   partial-reliability (RFC 3758), DCEP. This is real work but bounded, fully
>   pool-allocated, and aligns with the project's "use our own stack" mandate.
>
> **Recommendation: build Option B** (matches `CLAUDE.md`: "use our server here
> to back the python not whatever libraries you can find"). Keep Option A behind
> `BOLTAPI_WEBRTC_USRSCTP` as a bring-up/interop oracle only. Items below assume B.

- [x] **SCTP common header + chunk framing** (RFC 4960 §3) over the DTLS record
      layer (RFC 8261: each SCTP packet is one DTLS application record).
      Parse/serialize common header (ports, verification tag, CRC-32c) + TLV
      chunks. DONE (SCTP wave): `include/boltapi/webrtc/sctp.h` +
      `src/webrtc/sctp.cpp`. Big-endian common header (src/dst port, verification
      tag, CRC-32c) + 4-byte-aligned chunk TLV iteration. **CRC-32c uses
      `bolt::io::crc32c`** (RFC 3309 / Castagnoli, hardware path on MSVC x64);
      `sctp_crc32c` zeroes the checksum field and stores the result little-endian.
      Unit-tested against known vectors (`crc32c("123456789")==0xE3069283`, the
      RFC 3720 zero/0xFF vectors). Compiled UNCONDITIONALLY.
- [x] **Association setup: 4-way handshake.** INIT → INIT-ACK (with state
      cookie) → COOKIE-ECHO → COOKIE-ACK. DONE (SCTP wave): `SctpAssociation`
      works as BOTH Passive (answerer/responder, default) and Active (initiator,
      for the test client). Stateless responder: the INIT-ACK carries a
      deterministic state cookie (our tag + peer tag + init TSNs); COOKIE-ECHO
      validates it carries our tag and restores peer state. Verification tags
      generated + cross-checked. Loopback unit test drives INIT..COOKIE-ACK
      between two in-process endpoints. (SwissTable vtag→assoc is the multi-peer
      §11 perf upgrade; v1 is one association per DTLS session.)
- [x] **DATA chunk + TSN/stream sequencing.** DONE (SCTP wave): DATA chunk with
      TSN assignment, per-stream SSN, U/B/E flags, PPID. Reliable + ordered
      delivery: in-sequence SSN delivered immediately, future SSN buffered in a
      bounded per-association reorder ring and flushed when the gap fills.
      Preallocated send ring + reorder buffers (no per-message malloc).
      HARDENING WAVE: **message fragmentation/reassembly** now implemented
      (RFC 4960 §6.9). Outbound messages > `kSctpMaxChunkData` (1100 B) split
      into consecutive-TSN DATA chunks with B/M/E flags (same SSN ordered, U-bit
      unordered); inbound DATA buffered in a bounded per-assoc fragment store
      (`kSctpMaxFrags`, ABORT on overflow) and reassembled per (stream, SSN/U)
      into the full message before delivery — handles browser messages up to
      256 KiB (`kSctpMaxMessage`). **Unordered delivery** is fully wired end to
      end (U-bit on send + reassemble-and-deliver-immediately, no head-of-line
      block). Tested: 64K/256K both directions ordered+unordered, byte-exact
      (`tests/sctp_robust_test.cpp`).
- [x] **SACK + retransmission.** DONE (SCTP wave): cumulative TSN ack SACK on
      every received DATA; the SEND side parses gap-ack blocks too.
      HARDENING WAVE: replaced the threshold retransmit with a real **RTO timer**
      (RFC 6298: SRTT/RTTVAR, RTO min/max, exponential backoff on T3 timeout,
      Karn's algorithm — RTT sampled only on never-retransmitted chunks) and
      **congestion control** (RFC 4960 §7: cwnd/ssthresh, slow start +
      congestion avoidance via partial_bytes_acked, cwnd cut on loss; flight_size
      tracked; cwnd/rwnd-gated `flush_send`). **Fast retransmit** on 3 dup gap
      reports, and we now **emit our OWN gap-ack blocks** in SACK so the peer can
      fast-retransmit. Driven by `tick(now_ms)` (was `tick_retransmit`), pumpable
      on a timer or per-IO; deterministic via an injectable clock. Tested under
      seeded packet loss: a large reliable transfer completes via RTO without
      stall/busy-loop, cwnd grows then backs off (`tests/sctp_robust_test.cpp`).
- [x] **Partial reliability (RFC 3758) + FORWARD-TSN** for
      `maxRetransmits`/`maxPacketLifetime` (unreliable data channels).
      DONE (HARDENING WAVE): `SctpReliability` carries the per-message policy
      (unordered / rexmit-limited(max_retransmits) / time-limited(max_lifetime_ms)),
      plumbed from `DATA_CHANNEL_OPEN`'s channel-type byte (reliable / partial-
      rexmit / partial-timed, ordered+unordered — RFC 8832) through DCEP into the
      SCTP send path. The sender abandons a message that exceeds its retransmit
      budget (incl. max_retransmits==0 → abandon on first loss) or lifetime, emits
      a **FORWARD-TSN** chunk (send + receive) advancing the cumulative TSN past
      the abandoned fragments + per-stream ordered-SSN skip; the receiver advances
      and drops orphaned buffered fragments. Tested: a partial-reliable channel
      under loss abandons a message and later messages still arrive past it
      (`tests/sctp_robust_test.cpp`). FORWARD-TSN-Supported advertised in
      INIT/INIT-ACK.
- [x] **DCEP — Data Channel Establishment Protocol (RFC 8832).** DONE (SCTP
      wave): `src/webrtc/data_channel.cpp` parses `DATA_CHANNEL_OPEN` (PPID 50,
      type/channelType/priority/reliability/labelLen/protocolLen/label/protocol),
      replies `DATA_CHANNEL_ACK`, and extracts label + protocol + stream id. The
      WebRTC PPID enum (DCEP=50, string=51, binary=53, empty-string=56,
      empty-binary=57) lives in `sctp.h`. The active side emits its own OPEN
      (mirrors browser `createDataChannel`). (Reliability/ordering options parsed
      but mapped to reliable+ordered in v1.)
- [x] **Wire SCTP send/recv to the DTLS record layer (§6) and the UDP demux
      (§2).** DONE (SCTP wave): `include/boltapi/webrtc/peer_hub.h` +
      `src/webrtc/peer_hub.cpp` (`WebRtcPeerHub`) is the UdpTransport datagram
      handler: it feeds DTLS, and once a session is Established lazily creates a
      per-peer `DataChannelStack` whose SCTP packet sink is `DtlsSession::send_app`
      (SCTP rides as DTLS application records), then drains `DtlsSession::read_app`
      (decrypted SCTP packets) into the association. Outbound DATA → SCTP packet →
      `send_app` → DTLS encrypt → UDP. (SPSC layer + batched send buffers are the
      §11 perf phase; v1 is the correct inline path.)
- [x] **Correctness gate:** loopback test does INIT→data→SACK and DCEP
      open/ack/echo. DONE (SCTP wave): `tests/datachannel_test.cpp` (gtest,
      UNCONDITIONAL) — (1) CRC-32c known vectors; (2) the 4-way handshake +
      reliable/ordered DATA+SACK round-trip between two in-process
      `SctpAssociation` endpoints over two streams, both directions; (3) the e2e
      loopback below (§8/§10), now incl. a **64 KiB binary message** fragmented +
      reassembled byte-exact over the real DTLS+UDP path.
      HARDENING WAVE: added `tests/sctp_robust_test.cpp` (gtest, UNCONDITIONAL) —
      a cross-wired two-endpoint harness with a VIRTUAL CLOCK + seeded packet-loss
      relay (deterministic, bounded, no hang): 64K/256K fragmentation/reassembly
      both directions ordered+unordered (byte-exact); unordered-not-HOL-blocked;
      partial-reliability-abandons-under-loss (FORWARD-TSN, later msgs arrive);
      lossy-link-completes-via-RTO (cwnd grows then backs off); multi-stream mixed
      randomised round-trip. **DEFERRED:** `aiortc`/browser interop (later live
      validation wave).

---

## 8. Data channel surface to App (`IDataChannel`)

- [x] **Concrete `IDataChannel`** implementing `protocol.h` (`label()`/`send()`/
      `close()`), backed by an SCTP stream + DCEP state. DONE (SCTP wave):
      `webrtc::DataChannel` in `include/boltapi/webrtc/data_channel.h` +
      `src/webrtc/data_channel.cpp` derives `proto::IDataChannel`; `send()` emits a
      real SCTP DATA chunk (PPID 53 binary), plus typed `send_text`/`send_binary`
      with the right PPID (51/53, empty → 56/57). Text/binary PPID dispatch on
      receive routes to `on_message(data,len,is_binary)`. `close()` flips state +
      fires `on_close` (SCTP stream-reset is a later refinement).
- [x] **App-facing registration + callbacks.** DONE (SCTP wave):
      `App::on_data_channel(label, handler)` (already declared, app.h) is now
      wired: under `BOLTAPI_WITH_WEBRTC`, `init_protocol_seams()` builds a
      `WebRtcPeerHub` whose channel-ready callback matches the established
      channel's label to a registered handler (exact label, else "" wildcard) and
      attaches an `on_message` that invokes the App `DataChannelHandler(label,
      data, len)`. Per-channel `on_open`/`on_message`/`on_close` exist on
      `DataChannel`. (Inbound currently runs inline on the I/O thread; the SPSC
      worker handoff is the §11 perf phase. No handler change needed to move it.)
- [ ] **Backpressure.** Surface SCTP send-window state as a `bufferedAmount`-like
      signal so `App` handlers can throttle; bound the per-channel send ring.
      DEFERRED (later): the send ring IS bounded (`kSctpSendQueue`, `send()`
      returns false when full) but a `bufferedAmount` signal is not yet surfaced.
- [x] **Correctness gate:** e2e — `RTCDataChannel`-shaped flow ↔ `App`
      `on_data_channel` echo. DONE (SCTP wave): `tests/datachannel_test.cpp`
      `DataChannel.EndToEndLoopbackEcho` stands up the full server stack
      (UdpTransport + DTLS server + DtlsSessionManager + WebRtcPeerHub with an
      App-shaped `on_data_channel("chat")` echo handler) and a CLIENT using our
      own stack as the ACTIVE side (UDP → OpenSSL DTLS client → our SCTP active →
      DCEP OPEN → send). Asserts the handler fires with label "chat", receives a
      string message, echoes it, and the client gets the echo — plus a second
      string + a binary message round-trip. Bounded by a deadline (no hang).
      **DEFERRED:** empty-message + >1KB fragmentation cases and ordered-vs-
      unordered channels; live browser `RTCDataChannel` interop.

---

## 9. WebRtcProtocol integration into the seam

- [ ] **Replace the `WebRtcProtocol` stub** (`src/proto/webrtc_stub.cpp:36-51`):
      implement `serve(ITransport&)` to (1) confirm `kind()==Datagram`, (2) start
      the UDP demux (§2), (3) accept peers driven by signaling (§3). Keep
      `transport_kind()==Datagram`. **REBUILD.** Bolt primitive: as composed
      above.
- [ ] **Keep `register_webrtc(ProtocolRegistry&)`** (`webrtc_stub.cpp:55-61`) —
      now registering the real factory. No registry change
      (`protocol.h:141-196`). **ADAPT** (factory body only).
- [ ] **`App::enable_webrtc` real path.** `init_protocol_seams()` (`app.h:195`)
      currently logs "not yet implemented" for the stub; switch the ON+compiled
      path to: build cert (§6), register signaling routes (§3), create
      `UdpTransport`, `create(ProtocolId::WebRtc)->serve(...)` on the worker pool.
      Still **never touches H1/H2** and is a no-op when the flag/compile-option is
      off (per `docs/SEAMS.md` App-hook table). **REBUILD** (additive).
- [ ] **Lifecycle/teardown.** `WebRtcProtocol::stop()` (was no-op,
      `webrtc_stub.cpp:50`) closes all peers/channels, drains SPSCs, frees arenas,
      releases the UDP socket share. Idempotent, `noexcept`. **REBUILD.**
- [ ] **Correctness gate:** `App` with `enable_webrtc=true` serves H1/H2 *and* a
      data-channel echo simultaneously; flag OFF build is byte-for-byte unchanged
      (existing `tests/protocol_seam_test.cpp` still green).

---

## 10. Testing (correctness gates before any perf work)

> Per `CLAUDE.md`: tests are more than hello-world — multiple channels, multiple
> message types, randomized payloads. **Don't mock — build the real path.**

- [x] **STUN unit tests** — RFC 5769 vectors: parse/generate, XOR-MAPPED-ADDRESS,
      MESSAGE-INTEGRITY, FINGERPRINT. **REBUILD.**
      DONE (Wave 1): `tests/stun_test.cpp` (14 cases), registered as
      `boltapi_stun_test`. All RFC 5769 vectors pass byte-exact.
- [~] **ICE unit tests** — DONE (Wave 2): `tests/ice_test.cpp` — candidate
      `to_string`/`from_string` round-trip (host + srflx + malformed), host
      gathering returns >= 1 candidate, deterministic credential generation, and
      THE LIVE STUN GATE: a real Binding Request (USERNAME/PRIORITY/ICE-
      CONTROLLING/USE-CANDIDATE/MESSAGE-INTEGRITY/FINGERPRINT) sent over the wire
      to a `UdpTransport`+`IceAgent`, asserting a Binding Success with
      XOR-MAPPED-ADDRESS == client addr + valid MI + FINGERPRINT + nomination;
      wrong-integrity rejected (error, no nomination); garbage survives without
      crash. Also `tests/udp_transport_test.cpp` covers bind/round-trip/demux/
      shutdown. PENDING: full pairing/priority math vs RFC 8445 examples +
      role-conflict (not needed for the ICE-lite responder; revisit if we add a
      controlling path).
- [~] **DTLS handshake test** — vs `openssl s_client -dtls` and a browser; DTLS
      1.2 and 1.3; negative fingerprint-mismatch rejection.
      DONE (DTLS wave): `tests/dtls_test.cpp` — a LIVE DTLS handshake over
      loopback UDP between our `DtlsContext`/`DtlsSession`/manager (server) and a
      real OpenSSL `DTLS_client_method` client; both sides complete, server
      session `Established`, peer-cert fingerprint verify PASSES, fingerprint
      MISMATCH REJECTED, and an app-data round-trip echoes. Plus context-level
      fingerprint generation + `fingerprints_equal` unit cases. PENDING: live
      `openssl s_client -dtls` CLI + browser interop (live-interop gate).
- [~] **SCTP/DCEP roundtrip** — Bolt↔Bolt loopback (INIT/SACK/retransmit) and
      DCEP open/ack/echo. DONE (SCTP wave): `tests/datachannel_test.cpp` — CRC-32c
      vectors, the 4-way handshake + reliable/ordered DATA+SACK round-trip between
      two in-process endpoints, and the e2e DCEP open/ack/echo over real DTLS +
      our SCTP (loopback, our stack on both ends). PENDING: injected loss/reorder
      fuzz + `aiortc` interop (later validation wave).
- [ ] **Browser interop** — automated Chrome + Firefox `RTCPeerConnection` +
      `createDataChannel` against a live `App` (headless via Playwright/Puppeteer):
      full offer → answer → ICE → DTLS → SCTP → echo. Both browsers, multiple
      channels, multiple verbs of signaling route (HTTP POST and WS).
- [x] **libwebrtc / aiortc interop** — a non-browser native peer (`aiortc`
      easiest) as a second oracle independent of browser quirks.
      DONE (Signaling/interop wave): `tests/interop/aiortc_datachannel.py` (run via
      `uv run --no-project --with aiortc python ...` — ephemeral env, no global
      install) is a REAL aiortc `RTCPeerConnection`: `createDataChannel("chat")`,
      createOffer, POST the offer to the Bolt signaling route, setRemoteDescription
      on the answer, then on "open" send a text + a 64 KiB binary message and
      assert both echoes return byte-exact (bounded ~20s, exit 0/nonzero).
      `tests/aiortc_interop_test.cpp` (gtest, guarded by `BOLTAPI_WITH_WEBRTC`)
      starts the full App (UDP ICE/DTLS/SCTP + signaling route + on_data_channel
      echo) on a free port and shells out to the script; SKIPs (never fails) if
      uv/aiortc can't bootstrap. **RESULT: PASSED here** (uv 0.8.17, aiortc 1.14.0)
      — first proof of the Bolt stack vs an independent WebRTC implementation:
      aiortc ICE ↔ our ICE-lite, aiortc DTLS client ↔ our DTLS server, aiortc SCTP
      ↔ our Bolt-native SCTP, DCEP both ways. INTEROP BUGS FOUND + FIXED for this
      gate: (1) **DTLS-SRTP** — aiortc's DTLS client aborts with "no SRTP profile"
      unless the server echoes a `use_srtp` profile, so `DtlsContext::create` now
      advertises `SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80` (data channels
      never use the keys, but the extension must be negotiated); (2) **same-host
      ICE** — always advertise a `127.0.0.1` host candidate (in addition to NIC
      candidates) with the UDP socket bound to `0.0.0.0` so a same-host peer is
      reachable; (3) **SCTP peer MTU** — accept inbound DATA chunks up to
      `kSctpMaxRecvChunkData` (aiortc frames ~1200 B payloads, larger than our
      conservative 1100 B send chunk) in `handle_data`/`ingest_fragment`;
      (4) **ICE USERNAME** — validate the request's peer-side ufrag token against
      the offer's ice-ufrag (`set_expected_remote`).
- [~] **e2e through `App`** — data-channel echo handler registered via
      `on_data_channel`; randomized text/binary/empty/large payloads; assert
      ordered vs unordered semantics.
      DONE (Signaling/interop wave): the aiortc interop gate above runs a real
      `App` with `on_data_channel("chat")` echo end-to-end over the signaling route
      + UDP ICE/DTLS/SCTP, proving a text message AND a 64 KiB binary message
      (fragmented/reassembled) round-trip byte-exact through the live App surface.
      PENDING: empty-payload + unordered-channel assertions and randomized payload
      fuzz over the interop path (the loopback `sctp_robust_test` already covers
      empty/unordered/randomised against our own stack).
- [ ] **Concurrency/soak** — N simultaneous peer connections, each multiple
      channels, sustained for minutes; assert zero leaks (arena/pool accounting)
      and stable memory. **REBUILD.**
- [ ] **Negative/fuzz** — malformed STUN/SDP/SCTP/DTLS records must be rejected
      without crash (feed random bytes into each parser via the per-packet arena).

---

## 11. Performance (only after §10 gates pass)

> Targets are starting points; measure, don't assume (the audit flagged
> FasterAPI's numbers as arithmetic, not measured — we won't repeat that).

- [ ] **Batched UDP I/O** — `recvmmsg`/`sendmmsg` (IOCP overlapped batches on
      Windows) for STUN/DTLS/SCTP datagrams. Shared with H3 (`docs/HTTP3_PLAN.md`).
      Bolt primitive: `bolt_batch_pool.h`.
- [ ] **Per-packet arena, zero hot-path malloc** — every inbound packet parsed in
      a reset-per-packet `bolt::Arena`; assert no `new`/`malloc` on the data path
      (the `CLAUDE.md` mandate). Bolt primitive: `bolt_arena.h`.
- [ ] **Zero-copy framing** — STUN attributes, SCTP chunks, DCEP, RTP later, all
      framed/parsed via `bolt::wire` over the receive buffer with no intermediate
      copies. Bolt primitive: `bolt/wire/bolt_wire.h`, `bolt_wire_stream.h`.
- [ ] **Lock-free packet→worker** — one SPSC per peer; no locks on the data path;
      handler runs only on the worker. Bolt primitive: `bolt_channel.h`
      (SPSC) / `bolt_disruptor.h` (if MP fan-in to a worker is needed).
- [ ] **SwissTable maps** — 4-tuple→peer, TID→transaction, vtag→association, and
      (media, later) SSRC→stream — all `bolt::SwissTable`, not `std::unordered_map`.
      Bolt primitive: `join/bolt_swiss.h`.
- [ ] **Preallocated send/reassembly rings** — SCTP send queue, retransmit queue,
      and per-stream reorder buffer are bounded rings sized at association setup.
      Bolt primitive: `bolt_arena_ring.h`.
- [ ] **Branchless / vectorizable hot paths** — STUN/SCTP header field extraction
      and CRC written to vectorize; use `bolt_branchless.h` helpers; verify with
      the build's existing bench harness. Bolt primitive: `bolt_branchless.h`.
- [ ] **Benchmarks + targets** (record in `docs/BENCHMARKS.md`):
      - data-channel echo RTT p50/p99 vs `aiortc` and vs a browser baseline;
      - max simultaneous peers / channels at fixed CPU;
      - sustained data-channel throughput (large ordered transfer);
      - DTLS handshakes/sec; SCTP packets/sec/core.
      Gate perf changes on no correctness regression (re-run §10).

---

## 12. Media phase (LATER — explicitly out of v1)

> Only the *transport*; codecs (Opus/VP8/H264/AV1) stay out of scope.

- [ ] **RTP/RTCP parse/serialize — PORT `webrtc/rtp.cpp:18-115`** (header codec is
      correct). Add RTCP (SR/RR/feedback). **PORT + REBUILD (RTCP).** Bolt
      primitive: `bolt::wire`, `bolt_arena.h`.
- [ ] **SRTP — REBUILD `webrtc/rtp.cpp:147-205`** (encrypt/decrypt/derive are all
      TODO; fake auth tag today). DTLS-SRTP keying via the §6 export step
      (`use_srtp` extension). Crypto via OpenSSL (same justified stopgap as DTLS).
      **REBUILD.**
- [ ] **Jitter buffer** for inbound media. **REBUILD.** Bolt primitive:
      `bolt_arena_ring.h`.
- [ ] **a=msid/SSRC mapping** — `SwissTable` SSRC→stream. **REBUILD.**
- [ ] **Codecs explicitly OUT** — Bolt forwards/echoes media; encode/decode is the
      application's job.

---

## 13. Later / optional (post-v1)

- [ ] **TURN relay candidates** (RFC 8656) for symmetric-NAT peers — allocate,
      permissions, channel-bind. **REBUILD.**
- [ ] **Trickle ICE renegotiation** beyond initial gather (WS signaling path §3).
- [ ] **BUNDLE / multiple m-lines** (needed once media + data coexist).
- [ ] **SFU / room relay** — re-introduce the `webrtc/signaling.{h,cpp}` room
      model (**ADAPT**) for multi-peer broadcast.
- [ ] **Python binding** (`fasterapi/webrtc/*.py` — **DROP & rewrite** via Cython
      per `CLAUDE.md`) once the C++ path is solid.
- [ ] **WebTransport** (`http/webtransport_connection.*`) — shares H3's
      `UdpTransport`; pursue only if requested.

---

## Dependency order (build sequence)

```
§2 UdpTransport+demux ─┬─► §4 STUN ─► §5 ICE ─┐
                       │                       ├─► §6 DTLS ─► §7 SCTP/DCEP ─► §8 IDataChannel ─► §9 seam
§3 Signaling/SDP ──────┘                       │
                                               └─ (§5 selected pair feeds §6)
§10 tests gate each box · §11 perf after §10 · §12/§13 later
```

**One-line summary:** salvage SDP parsing + candidate serialization + the PPID
enum + (later) the RTP header codec from FasterAPI; **build everything that
makes a connection** — STUN, ICE, DTLS (OpenSSL stopgap), and a Bolt-native
minimal SCTP/DCEP — on the shared `UdpTransport`, surfaced to `App` as
`IDataChannel`, correctness-gated against browsers + `aiortc` before any
performance tuning, and never touching the HTTP/1.1+HTTP/2 core.
