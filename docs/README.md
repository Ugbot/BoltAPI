# Bolt API documentation

Start with the top-level [`README.md`](../README.md) (overview, build, quickstart)
and [`examples/`](../examples/README.md) (runnable code). This folder holds the
deeper references and the living design/decision logs.

## Guides
- [`JSON.md`](JSON.md) — the `req.json()` / `res.json()` facility (Bolt `fionn`)
- [`COMPRESSION.md`](COMPRESSION.md) — gzip response compression middleware
- [`BENCHMARKS.md`](BENCHMARKS.md) — router + throughput numbers (how we measure)
- [`PERF_TARGETS.md`](PERF_TARGETS.md) — Floor/Good/Great targets per surface (what to aim for) + CI regression gates
- [`SEAMS.md`](SEAMS.md) — the `ProtocolRegistry` extension model for H3/WebRTC

## Protocol design + decision logs
- HTTP/3: [`HTTP3_PLAN.md`](HTTP3_PLAN.md) (design + decision log D1…) · [`HTTP3_REMAINING.md`](HTTP3_REMAINING.md) (checklist)
- WebRTC: [`WEBRTC_PLAN.md`](WEBRTC_PLAN.md) (data) · [`WEBRTC_MEDIA_PLAN.md`](WEBRTC_MEDIA_PLAN.md) (audio/video) · [`WEBRTC_REMAINING.md`](WEBRTC_REMAINING.md) (checklist)

## Gateway (design suite — early milestone)
A Kong/Gravitee-class API gateway on the BoltAPI engine. Phase 0 — the outbound
HTTP client (`bolt::api::http::Client`) that the gateway needs — has landed and is
gated in CI; everything past that is **design only** so far. The documents below
are the blueprints for the remaining phases.
- [`gateway/GATEWAY_VISION.md`](gateway/GATEWAY_VISION.md) — positioning, thesis, non-goals, success criteria
- [`gateway/GATEWAY_COMPETITIVE_RESEARCH.md`](gateway/GATEWAY_COMPETITIVE_RESEARCH.md) — Kong · Gravitee · Envoy · APISIX · Tyk · nginx (borrow vs differ)
- [`gateway/GATEWAY_ARCHITECTURE.md`](gateway/GATEWAY_ARCHITECTURE.md) — how it lands on the engine (plugins=middleware, upstream client, host routing, Bolt primitives, control-plane open decision)
- [`gateway/GATEWAY_FEATURES.md`](gateway/GATEWAY_FEATURES.md) — per-capability specs + the FasterAPI→BoltAPI port ledger
- [`gateway/GATEWAY_ROADMAP.md`](gateway/GATEWAY_ROADMAP.md) — phased checklist (Phase 0 upstream client → … → control plane → observability)

## Status, issues, and what's next
- [`../PROJECT_MAP.md`](../PROJECT_MAP.md) — what exists and its status (the index of record)
- [`ROADMAP.md`](ROADMAP.md) — **known bugs, limitations, untried/unverified items, and planned work.** Read this before adopting Bolt API.

## Completion roadmaps (ordered checklists)
- [`QUIC_COMPLETION.md`](QUIC_COMPLETION.md) — finish QUIC to browser/relay grade
  (Chrome handshake ACK/coalesce, multi-connection demux, DATAGRAM, 0-RTT/migration, perf)
- [`WEBTRANSPORT_COMPLETION.md`](WEBTRANSPORT_COMPLETION.md) — full WebTransport
  (browser `wt.ready`, datagrams, streams, sessions) — mostly rides QUIC completion
- [`WEBRTC_RELAY_PLAN.md`](WEBRTC_RELAY_PLAN.md) — two-way browser media → Pion parity →
  **SFU/relay** (rooms, selective forwarding, simulcast selection) + fun examples
- [`WEBTRANSPORT_CERT_PLAN.md`](WEBTRANSPORT_CERT_PLAN.md) — serverCertificateHashes (done) +
  the precise remaining QUIC↔Chrome handshake blocker

## Conventions
- **Tiger Style** throughout (assert ≥2/fn, bounded/static allocation, no hidden
  control flow, functions < 70 lines, zero warnings, no exceptions).
- Windows = MSVC / clang-cl, **never MinGW**. Linux = LLVM/Clang + lld, never GCC.
  Crypto via OpenSSL only.
- All Python via `uv` (`uv run --with …`).

The full engineering standard, toolchain policy, and testing bar live in
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## Reading these documents

Several files here are **living design and decision logs** written as work was
planned and landed — they record alternatives considered, measurements taken
(including experiments that came out neutral and were reverted), and what remains.
They are kept deliberately, so decisions are traceable rather than folklore. Where
a design doc and the code disagree, the code and [`../PROJECT_MAP.md`](../PROJECT_MAP.md)
are current; the plan documents are historical from the point they were written.
