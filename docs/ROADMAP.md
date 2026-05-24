# Bolt API — Roadmap, Known Issues & Things Not Yet Fully Tried

The core is feature-complete (HTTP/1.1–3, WebSocket, SSE, WebRTC data + audio +
video), interop-proven (aioquic for HTTP/3, aiortc for WebRTC), 239/239 tests
green on MSVC. This file tracks what's **known-imperfect, deferred, or unverified**
so nothing gets lost — plus the infrastructure we're adding next (Docker, real
long-running integration tests).

Legend: 🔴 bug · 🟡 incomplete/plumbed-not-negotiated · ⚪ untried/unverified · 🟢 planned infra.
Task numbers (`#NN`) refer to the in-repo task tracker.

---

## 1. Performance issues (measured)

- 🔴 **SRTP `protect` ~25× slower than `unprotect`** (`#38`). `media_throughput_bench`
  measured `protect_rtp` ≈ **9.3 µs/pkt** vs `unprotect_rtp` ≈ **0.35 µs/pkt**
  (AES-CM-128-HMAC-SHA1-80, 1100 B). Almost certainly per-call EVP key/IV setup or
  HMAC re-init on the protect path. Fix: cache/reuse `EVP_CIPHER_CTX` / `EVP_MAC_CTX`
  and precompute session key schedule; re-bench to confirm parity. **Highest-value
  perf fix.**
- ⚪ **Batched UDP recv/send not implemented** (deferred in W5f/WP). `recvmmsg` /
  `WSARecvMsg` / GSO/GRO would help many-source high-PPS (many QUIC conns, dense
  media), but showed **no measurable win on single-connection loopback**, so it was
  not added speculatively. Needs a *realistic multi-connection* bench to justify.
- ⚪ **No load/soak baseline.** Current numbers are micro/loopback only
  (`benchmarks/quic_throughput_bench.cpp`, `media_throughput_bench.cpp`): QUIC
  ≈ 62 handshakes/s, ≈ 1.7 MB/s, ≈ 5.4–6.0 µs/byte (AEAD-dominated) on this box.
  No sustained-throughput, many-connection, or HTTP/1.1+2 vs peers numbers under
  real load. (See §4 integration tests.)
- 🟡 **Middleware per-request `std::function` allocation** (TODO in `middleware.h`).
  The chain allocates per request; an arena-backed continuation is a known perf pass
  not yet done.
- ℹ️ **Measured-neutral, deliberately reverted** (kept for the record so we don't
  re-chase): `bolt::Arena` per-packet scratch vs fixed stack scratch (both QUIC and
  media) — neutral-to-worse, reverted. Per-SSRC linear scan (≤16) beats a
  `bolt::SwissTable` probe at that size — kept; revisit only if the bound grows.

## 2. Correctness — plumbed but not fully negotiated/wired

- 🟡 **SDP answer doesn't emit `a=rtx` / `a=rtcp-fb` / `a=ulpfec` / `a=extmap`** (`#37`).
  RTX/FEC/TWCC/abs-send-time are *wired into* `WebRtcPeerHub` and *read from* the
  offer, but the answer builder (`sdp.cpp`) only echoes existing lines — so a real
  browser/aiortc peer won't actually **negotiate** RTX/FEC/TWCC end-to-end. Extend
  the answer builder to emit them.
- 🟡 **WebRTC key update / DTLS renegotiation** — TODO (noted in WA).
- 🟡 **Query-param URL-decoding** — `Request::query_param()` returns the **raw**
  value (no `%`-decode). Documented follow-up in `request.h`.
- 🟡 **`Request::client_ip()`** — the engine doesn't thread the peer address into
  `CoroHttpRequest`; only `X-Forwarded-For` / `X-Real-IP` are honored. Thread the
  real peer addr through.
- 🟡 **405 vs 404** — a method mismatch on an existing path returns **404** (405 is
  a documented optional, not implemented).
- 🟡 **Compression** — gzip only; brotli/zstd are unwired options.

## 3. Untried / unverified (the big one)

- ⚪ **Linux / macOS not continuously tested.** Everything is developed and gated on
  **Windows/MSVC**. The `epoll`/`io_uring` (Linux) and `kqueue` (macOS) async-I/O
  backends compile but have **no continuous test coverage**. → **Dockerfile + Linux
  CI** (§4) is the top infra priority.
- ⚪ **HTTP/3 browser interop (Chrome/Firefox)** — only **aioquic** is proven. Needs
  a valid (non-self-signed) cert + Alt-Svc to drive a real browser.
- ⚪ **QUIC Interop Runner matrix** — handshake/transfer/retry/resumption rows not run
  against the public interop matrix (quiche, nghttp3, ngtcp2, picoquic, …).
- ⚪ **HTTP/3 advanced (W5e), not implemented**: 0-RTT / session resumption,
  connection migration + path validation, **QUIC DATAGRAM frames (RFC 9221)**,
  multiple connection IDs / preferred address.
- ⚪ **WebTransport** (over HTTP/3, RFC 9297) — not started (depends on H3 DATAGRAM).
- ⚪ **Pion (Go) interop** — peer added (`tests/interop/pion/`); the 64 KiB **binary**
  data-channel path needs Pion-harness `maxMessageSize` tuning (our stack passes
  64 KiB binary against aiortc, so this is a harness-config item, not a Bolt bug).
  Pion **media** interop unverified.
- ⚪ **Browser `getUserMedia` media echo** — `testing/web/media.html` exists as a
  **manual** gate; not automated.
- ⚪ **Simulcast / SVC / RTX / FEC / BWE end-to-end** — codecs are unit-gated; a real
  browser doing simulcast + our negotiation (blocked on `#37`) is unverified.
- ⚪ **Multi-peer WebRTC at scale** — some paths assume a single active peer
  (signaling keyed by ufrag); concurrent-peer lifecycle not load-tested.
- ⚪ **Sanitizers (ASan/UBSan) on the full suite** — `BOLTAPI_SANITIZE` exists but
  isn't run continuously (needs the Linux/Docker lane).
- ⚪ **Continuous fuzzing** — beyond the seeded in-suite fuzz gates (QUIC parser,
  HTTP/1.1), there's no persistent fuzzing.

## 4. Planned infrastructure 🟢

### 4.1 Dockerfile — reproducible Linux build + test (`#NEW`)
- Multi-stage image: builder (cmake + ninja + a C++20 toolchain + OpenSSL 3.x +
  the Bolt submodule) → runtime/test. Builds with `WITH_HTTP3=ON` + `WITH_WEBRTC=ON`.
- Runs the full `ctest` suite on **Linux** (exercises the epoll/io_uring backend the
  Windows box never touches) and, separately, an **ASan/UBSan** configured build.
- A `docker-compose` (or compose-like) bringing up the demo server + the interop
  peers (aioquic / aiortc via `uv`, Pion via Go) in containers so interop runs
  hermetically — no dependence on a dev box having uv/Go/curl-http3.
- Wire into CI: a Linux job (default + sanitizers) and the interop job, each under a
  job timeout, alongside the existing MSVC build.

### 4.2 Real integration tests — long-running, no skip-on-timeout (`#NEW`)
The current interop tests are deliberately **bounded + skip-if-absent** so the PR
suite can never hang (hard ctest TIMEOUT ceiling + `tests/interop/bounded_proc.h`
process-tree kill). That's right for the **fast** lane, but we also want a separate
**nightly / "run-all-night"** lane that actually exercises the stack hard and is
*allowed* to take hours:
- **Soak / load**: sustained traffic over H1/H2/H3 (many concurrent connections,
  large transfers, long keep-alive), watching throughput, latency, and **resource
  drift** (memory, FD/handle leaks, thread counts) over time.
- **Real-client interop without skip**: aioquic + aiortc + Pion + (where possible)
  headless Chrome/Firefox, run to completion in containers — failures are real
  failures, not skips.
- **QUIC Interop Runner** rows against multiple independent stacks.
- **WebRTC media soak**: continuous audio+video echo for N minutes, verifying no
  RTP/SRTP drift, no leak, NACK/RTX/TWCC behaving under induced loss.
- These live in a separate target/lane (e.g. `BOLTAPI_BUILD_INTEGRATION` / a nightly
  CI workflow) so they never gate fast PR feedback.

## 5. Smaller follow-ups
- WX leftovers (`#36`): CI workflow legs (WEBRTC=ON / HTTP3=ON), browser manual-gate
  docs, Pion harness `maxMessageSize` tuning.
- Close out M4 (`#18`): fold done punch-card items back into `PROJECT_MAP.md`, README
  benchmark section.
- `LICENSE` is still TBD.

---
*Keep this file honest: when something here gets fixed/verified, move it to
`PROJECT_MAP.md` as done and delete it here. When a new gap is found, add it here
with a task number.*
