# Bolt API — Performance Targets

What "good" and "great" mean for Bolt API, per surface, so a number is judged
against an explicit bar instead of a vibe. Companion to `docs/BENCHMARKS.md` (how
we measure) — this file says **what to aim for**.

## The three tiers

| Tier | Meaning | Use |
|---|---|---|
| 🟥 **Floor** | The regression gate. We must **never** drop below this on the reference box. | Wire into a CI perf check; a drop is a bug to fix or justify. |
| 🟦 **Good** | Competitive — on par with a solid, tuned C++ framework. Shippable, no asterisk. | The bar a feature must clear before we call it "done, fast". |
| 🟩 **Great** | Best-in-class — Envoy / nginx / TechEmpower-top class. The headline. | The optimization north star. |

Rules of the road:
- **Every target names the benchmark that measures it** (reproducible, not a claim).
- **Measured = a real run on the reference box; Target = aspirational** until a run
  fills it in. We never publish a fabricated number (see `docs/BENCHMARKS.md`).
- Targets are **per stated configuration** (cores / connections / payload). A req/s
  number with no config is meaningless.
- Loopback numbers are a *ceiling probe*, not real-network throughput — targets are
  tagged `[loopback]` or `[real-net]`.

## Reference environment

| | |
|---|---|
| Reference box | Intel Core i9-9980HK (8C/16T), Windows 11, MSVC Release |
| Linux parity box | Ubuntu 24.04, Clang/lld, Release (Docker — virtualized loopback is slower; see note) |
| Measurement | `benchmarks/` (router/throughput micro), `benchmarks/loadgen` + `bench_server` (real-socket), `quic_throughput_bench`, `media_throughput_bench` |

> Numbers are machine-dependent — treat tiers as **ratios + intent**, re-baseline on
> new hardware. Server-class CPUs (more cores, AVX-512, faster mem) move "great"
> up; the Docker-on-Windows Linux loopback is ~5–10× slower than native and is for
> *correctness* parity, not perf numbers.

---

## 1. Router — `match()` (CPU, no I/O)  ·  `router_bench`

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Measured now |
|---|---:|---:|---:|---|
| Static hit | < 100 ns/op | < 70 ns/op | < 50 ns/op | **~58–64 ns** (🟦 Good) |
| Param hit | < 350 ns/op | < 220 ns/op | < 150 ns/op | ~195–201 ns (🟦) |
| Miss | < 200 ns/op | < 130 ns/op | < 90 ns/op | ~108–113 ns (🟦) |

Already at **Good**. "Great" on static hit means matching/beating a tuned
`std::unordered_map` (~27 ns) while keeping param/wildcard on the same allocation-
free path — a stretch. Hard invariant (non-negotiable): param-hit and miss stay
**allocation-free** (`no_alloc_test`) and bounded.

## 2. HTTP/1.1 throughput  ·  `loadgen` + `bench_server`, `/plaintext` `[loopback]`

Throughput scales with I/O threads (thread-per-core). State the config.

| Config | 🟥 Floor | 🟦 Good | 🟩 Great | Measured now |
|---|---:|---:|---:|---|
| 1 I/O thread, 32 conns | 45 k req/s | 90 k | 150 k | **~63–69 k** (between 🟥 and 🟦) |
| All cores (thread-per-core), 256 conns | 200 k | 500 k | **1 M+** (TechEmpower-top class) | _not yet measured_ |

`/json` (serialization) should track within ~10% of `/plaintext`. The all-core row
is the headline target and is **aspirational** — it needs the multi-I/O-thread path
exercised + measured. The single-thread row is the regression gate today.

## 3. HTTP/1.1 latency  ·  same harness, at 64 conns sustained `[loopback]`

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Measured now (32 conns) |
|---|---:|---:|---:|---|
| p50 | < 1 ms | < 200 µs | < 100 µs | ~430 µs (needs work) |
| p99 | < 5 ms | < 1 ms | < 400 µs | ~1.1–1.5 ms (≈🟥) |
| p99.9 | < 20 ms | < 5 ms | < 2 ms | ~3.2–3.9 ms (🟦) |

Tail latency under load is the **weakest current area** — driven by the per-request
`std::function` middleware alloc + per-request coroutine frame + worker-hop
scheduling (`docs/ROADMAP.md` §1). The arena-backed-continuation perf pass is the
main lever to move p50/p99 toward Good/Great.

## 4. HTTP/2  ·  `[loopback]` (target — harness TODO)

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Status |
|---|---:|---:|---:|---|
| Multiplexed req/s (1 conn, 100 streams) | 30 k | 80 k | 150 k | _no h2 bench yet_ |

Add an h2 leg to `loadgen` (HPACK + stream mux) before filling this in.

## 5. HTTP/3 / QUIC  ·  `quic_throughput_bench` `[loopback]`

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Measured now |
|---|---:|---:|---:|---|
| Bulk stream throughput (1 stream) | 100 MB/s | 500 MB/s | > 1 GB/s | ~1.7 MB/s — **big headroom** |
| Handshakes/s (concurrent) | 1 k | 10 k | 50 k | ~62 (sequential, latency-bound) |
| CPU per byte (1-RTT bulk) | < 50 ns | < 10 ns | < 3 ns | AEAD-dominated, unprofiled |

QUIC is the **largest perf gap vs its ceiling** — AEAD on modern cores does GB/s,
so today's ~1.7 MB/s loopback says the bench (and likely the path) is setup/copy-
bound, not crypto-bound. Targets are aspirational pending a real profiling pass; the
handshakes/s figure must be re-measured **concurrently** (the current ~62 is one
sequential handshake at a time, i.e. handshake *latency*, not throughput).

## 6. WebRTC media — SRTP  ·  `media_throughput_bench`

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Measured now |
|---|---:|---:|---:|---|
| `unprotect` (AES-CM-128, 1100 B) | < 1 µs/pkt | < 0.5 µs/pkt | < 0.3 µs/pkt | **~0.35 µs** (🟩 Great) |
| `protect` (same) | < 1 µs/pkt | < 0.5 µs/pkt | < 0.3 µs/pkt | **~9.3 µs** 🔴 (25× slower — bug #38) |
| Throughput (per direction) | 500 MB/s | 1.5 GB/s | > 3 GB/s | unprotect ~3 GB/s; protect ~0.12 GB/s 🔴 |

`unprotect` is already **Great**. The `protect` path is the single highest-value
perf fix on the board (#38): cache `EVP_CIPHER_CTX`/`EVP_MAC_CTX` + precompute the
key schedule → bring protect to parity (~0.35 µs). That alone moves protect from
🔴 to 🟩.

## 7. JSON (fionn) — `req.json()` parse  ·  (target — micro-bench TODO)

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Status |
|---|---:|---:|---:|---|
| Parse throughput (typical API body) | 200 MB/s | 1 GB/s | > 2 GB/s | _no parse micro-bench yet_ |

## 8. Footprint & scaling

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Status |
|---|---:|---:|---:|---|
| RSS at idle (server, no conns) | < 50 MB | < 20 MB | < 8 MB | _measure_ |
| Bytes of state per idle keep-alive conn | < 64 KB | < 16 KB | < 4 KB | _measure_ |
| Concurrent connections (1 box) | 10 k | 100 k | 1 M | _measure (soak)_ |
| Resource drift over a 1 h soak | any leak = fail | flat | flat | _soak harness TODO (ROADMAP §4)_ |

Footprint is a core differentiator vs JVM/Go gateways (VISION) — a single static
binary with a tiny resident set. These need the soak/load lane in `docs/ROADMAP.md`
§4 to measure honestly.

## 9. Gateway (Phase 1+)  ·  `loadgen` through the proxy vs direct origin

The gateway's own overhead is the number that matters — measured as **added** cost
over hitting the origin directly.

| Metric | 🟥 Floor | 🟦 Good | 🟩 Great | Status |
|---|---:|---:|---:|---|
| Added p99 latency (proxy vs direct) | < 1 ms | < 300 µs | < 100 µs | _Phase 1_ |
| Proxy req/s vs bare framework | ≥ 50% | ≥ 70% | ≥ 85% | _Phase 1_ |
| vs Kong / Tyk (same box, same load) | match | beat | **1–2 orders faster** | _measure_ |
| vs Envoy / APISIX (same class) | within 3× | within 1.5× | match | _measure_ |

This operationalizes the VISION success criteria: **beat Kong/Tyk; hold Envoy/APISIX
class**. Filled in once Phase 1 (reverse-proxy MVP) lands and is benchmarked.

---

## Regression gates (CI)

The 🟥 Floor rows that have a current measurement become **CI perf gates** (a run
that drops below Floor fails). Initial gate set (to wire into a perf CI leg /
`scripts/`):

- Router static hit < 100 ns/op (`router_bench`).
- HTTP/1.1 `/plaintext`, 1 I/O thread / 32 conns ≥ 45 k req/s; `failed == 0`
  (`loadgen` + `bench_server`).
- HTTP/1.1 p99 < 5 ms at that load.
- SRTP `unprotect` < 1 µs/pkt (`media_throughput_bench`).
- (After #38) SRTP `protect` < 1 µs/pkt.

Gates run on the reference box only (machine-dependent); the Linux/Clang lanes gate
**correctness** (`failed==0`), not these throughput thresholds (virtualized loopback).

## How to read progress

- A surface at 🟦/🟩 with a **Measured** value = done, leave it (don't re-chase
  measured-neutral micro-opts — see ROADMAP §1 for the ones already ruled out).
- A surface at 🟥 or "needs work" = an open optimization with a named lever.
- Today's headline gaps, in priority order: **SRTP protect (#38)** → **HTTP/1.1 tail
  latency (middleware alloc)** → **QUIC throughput (profiling pass)** → **multi-core
  HTTP/1.1 scaling (measure the thread-per-core path)**.

*Keep this honest: when a run fills a cell, write the measured value + tier and date
it; when a target is hit, the next tier becomes the goal.*
