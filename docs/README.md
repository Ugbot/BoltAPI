# Bolt API documentation

Start with the top-level [`README.md`](../README.md) (overview, build, quickstart)
and [`examples/`](../examples/README.md) (runnable code). This folder holds the
deeper references and the living design/decision logs.

## Guides
- [`JSON.md`](JSON.md) — the `req.json()` / `res.json()` facility (Bolt `fionn`)
- [`COMPRESSION.md`](COMPRESSION.md) — gzip response compression middleware
- [`BENCHMARKS.md`](BENCHMARKS.md) — router + throughput numbers
- [`SEAMS.md`](SEAMS.md) — the `ProtocolRegistry` extension model for H3/WebRTC

## Protocol design + decision logs
- HTTP/3: [`HTTP3_PLAN.md`](HTTP3_PLAN.md) (design + decision log D1…) · [`HTTP3_REMAINING.md`](HTTP3_REMAINING.md) (punch-card)
- WebRTC: [`WEBRTC_PLAN.md`](WEBRTC_PLAN.md) (data) · [`WEBRTC_MEDIA_PLAN.md`](WEBRTC_MEDIA_PLAN.md) (audio/video) · [`WEBRTC_REMAINING.md`](WEBRTC_REMAINING.md) (punch-card)

## Status, issues, and what's next
- [`../PROJECT_MAP.md`](../PROJECT_MAP.md) — what exists and its status (the index of record)
- [`ROADMAP.md`](ROADMAP.md) — **known performance bugs, untried/unverified items, and planned infrastructure (Docker, long-running integration tests)**

## Conventions
- **Tiger Style** throughout (assert ≥2/fn, bounded/static allocation, no hidden
  control flow, functions < 70 lines, zero warnings, no exceptions). See `CLAUDE.md`.
- Windows = MSVC / clang-cl, **never MinGW**. Crypto via OpenSSL only.
- All Python via `uv` (`uv run --with …`).
