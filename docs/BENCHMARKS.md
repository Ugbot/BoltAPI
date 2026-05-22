# Bolt API — Benchmarks

Hand-rolled `std::chrono` micro/throughput benchmarks. No third-party benchmark
dependency (no google-benchmark): warmup + a large fixed iteration count, with a
`volatile` sink to defeat dead-code elimination.

Build + run (NOT part of `ctest`):

```
cmake -S . -B build/bench -G "Visual Studio 17 2022" -A x64 -DBOLTAPI_BUILD_BENCHMARKS=ON
cmake --build build/bench --config Release
build/bench/benchmarks/Release/boltapi_router_bench.exe
build/bench/benchmarks/Release/boltapi_throughput_bench.exe
```

The benchmark targets are gated by the existing `BOLTAPI_BUILD_BENCHMARKS`
option and live in `benchmarks/`.

## Environment (reference run)

| | |
|---|---|
| CPU | Intel Core i9-9980HK @ 2.40 GHz |
| OS | Windows 11 |
| Toolchain | MSVC (VS 2022), Release |

Numbers are machine-dependent; treat them as ratios, not absolutes.

## Router micro-benchmark (`router_bench`)

Route table: 100 static routes + 30 parametric (`/res/{id}/sub/{sid}`) + 1
wildcard. `match()` measured for a static hit, a param hit, and a miss. The
static-hit number is compared head-to-head against two baselines a hand-rolled
router commonly uses: a linear scan over registered patterns, and a
`std::unordered_map<std::string, id>` keyed on `"METHOD path"`.

| Workload | ns/op | ops/s |
|---|---:|---:|
| Bolt `match()` — static hit | ~58–64 | ~16–17 M |
| Bolt `match()` — param hit | ~195–201 | ~5.0 M |
| Bolt `match()` — miss | ~108–113 | ~9.1 M |
| Baseline — linear scan (static) | ~87–89 | ~11.3 M |
| Baseline — `unordered_map` (static) | ~27–28 | ~36 M |

**Speedup (Bolt static-hit vs baseline):**

- vs linear scan: **~1.4–1.5x faster** — this is the "dictionary routing beats a
  naive hand-rolled router" headline. A linear scan is what most from-scratch
  C++ routers do; Bolt's SwissTable resolves a static route in one FNV hash + one
  probe regardless of table size, so the gap widens as the table grows.
- vs `std::unordered_map`: **~0.45x (i.e. unordered_map ~2x faster)** for this
  small static-only set. Reported honestly: for pure exact-match static lookup on
  a hot, small key set, a tuned `unordered_map` wins. Bolt's value is (a) it also
  resolves **parametric/wildcard** routes (which a flat map cannot) through the
  same allocation-free path, and (b) its cost is independent of registration
  order and of the number of routes, unlike the linear scan.

Notably, **param-hit and miss are still allocation-free** (see `no_alloc_test`)
and bounded — no recursion, an explicit backtracking stack capped at
`kMaxSegments`.

## Throughput benchmark (`throughput_bench`)

A real `bolt::api::App` on loopback cleartext HTTP/1.1 (1 I/O thread, default
worker pool), driven by 4 client threads each firing 20,000 keep-alive requests
over a persistent connection (80,000 total) against a static `/bench` route.

| Metric | Value (reference run) |
|---|---:|
| Completed | 80,000 ok / 0 failed |
| Wall time | ~1.34–1.36 s |
| Throughput | **~59,000–60,000 req/s** |
| Mean latency | **~65–66 µs/req** |

This is a loopback ceiling probe (no network), single I/O thread. It is bounded
and best-effort: it prints results and exits 0 even on partial completion, so it
is safe to wire into a CI bench leg but is deliberately **not** registered with
`ctest`.

## Notes / TODOs

- The router's per-node literal fan-out is bounded by an internal
  `kMaxChildren = 16`. The benchmark's param routes share a small set of
  top-level resource segments so the trie stays within that bound (also the
  realistic shape of an API). Registering >16 distinct literal children at a
  single trie node currently relies on a debug `assert` that is compiled out in
  Release — see "Findings" in the hardening report. Not exercised here.
- The App middleware chain (`std::function`) and the per-request coroutine frame
  allocate per request today; the throughput number includes that cost. The
  zero-alloc guarantee (and `no_alloc_test`) is scoped to `Router::match()` and
  the HTTP/1 parser hot paths.
