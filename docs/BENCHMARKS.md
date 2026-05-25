# Bolt API — Benchmarks

Hand-rolled `std::chrono` micro/throughput benchmarks. No third-party benchmark
dependency (no google-benchmark): warmup + a large fixed iteration count, with a
`volatile` sink to defeat dead-code elimination.

> This file is **how we measure**. For **what to aim for** — the Floor/Good/Great
> targets per surface and the CI regression gates — see
> [`PERF_TARGETS.md`](PERF_TARGETS.md).

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

## Body-path throughput — slot-pool vs `bolt::Arena` (`body_throughput_bench`)

The request-body buffer can use either the default fixed-tier **slot-pool** or
**`bolt::Arena`** (opt-in `-DBOLTAPI_USE_BOLT_ARENA=ON`). This bench POSTs a
32 KiB body to `/echo` (large enough to bypass the connection stack buffer and
force a `RequestBodyBuffer::acquire()` every request), 4 client threads ×
5,000 keep-alive requests.

| Body buffer | req/s | body bandwidth (in+out) | mean latency |
|---|---:|---:|---:|
| slot-pool (default) | ~32.4–32.9 k | ~2.0 GiB/s | ~119 µs |
| `bolt::Arena` (opt-in) | ~32.3–32.5 k | ~2.0 GiB/s | ~120 µs |

**Conclusion: perf-neutral (within noise).** The body buffer is one allocation
per request and is not the bottleneck — the time goes to loopback syscalls, the
`std::string` body/response copies, and coroutine/worker scheduling. Bolt's
~3 ns bump-allocation is real in isolation but invisible here, and the Arena
path needs an atomic `live_views_` self-guard (coroutines migrate worker threads
across `co_await`), which offsets the tiny win. The Arena path is kept as a
**validated, default-OFF opt-in**; the real lever for the body path is a
zero-copy `req.body()` view + zero-copy response (eliminating the string copies)
— a separate, larger change.

## Load generator + endpoint suite (real sockets)

The micro/throughput benches above run the client *in-process*. To measure under
a real socket load driver — and to produce headline req/s + tail-latency numbers
the way TechEmpower/1MRC do — there is a standardized pair:

- **`bench_server`** (`benchmarks/bench_server.cpp`) — a long-lived server over the
  real `App` facade with TechEmpower-aligned routes: `/plaintext`, `/json`,
  `/db`, `/queries?n=K`, `/route/{id}`. **Honest deviation:** BoltAPI dropped the
  PostgreSQL dependency, so `/db` and `/queries` are a **synthetic CPU proxy** (a
  bounded xorshift row generator), *not* a real database round-trip — the numbers
  measure framework + serialization cost, not DB throughput.
- **`boltapi_loadgen`** (`benchmarks/loadgen/`) — an **in-tree async HTTP/1.1 load
  generator with ZERO third-party deps**, built on BoltAPI's own outbound
  primitives (`IODispatcher` `async_connect`/`async_read`/`async_write` +
  `WorkerThreadPool`). N keep-alive connections each run a serial request/response
  loop as a coroutine until a wall-clock deadline; per-request latency goes into a
  per-connection log-linear histogram (no cross-connection sharing → no atomics on
  the hot path), merged at the end for p50/p90/p99/p99.9.
  - **Why in-tree:** it needs no `wrk`/`aiohttp` (portable Windows IOCP + Linux
    epoll, no Python), and — by design — its `http_client.{h,cpp}` core (request
    serializer + incremental response parser + pooled keep-alive connection) is
    **the seed of the future API-gateway's upstream HTTP client**, the one
    outbound-HTTP piece BoltAPI doesn't yet have. See `docs/gateway/`.
  - **v1 limits:** cleartext only (a documented TLS extension point — OpenSSL is
    already linked); responses must be `Content-Length`-framed (a chunked or
    oversized response is reported as a parse error, never a crash); bounded at
    `kMaxConnections = 1024`.

### Reproduce

```
# Windows (MSVC, primary)
cmake -S . -B build/bench -DBOLTAPI_BUILD_BENCHMARKS=ON
cmake --build build/bench --config Release --target boltapi_bench_server boltapi_loadgen
powershell -File scripts\run_benchmarks.ps1 -Duration 10 -Connections 64

# Linux/Docker (Clang/lld, never GCC)
cmake -S . -B build/bench -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld -DBOLTAPI_BUILD_BENCHMARKS=ON
cmake --build build/bench -j --target boltapi_bench_server boltapi_loadgen
scripts/run_benchmarks.sh --duration 10 --connections 64
docker build -f Dockerfile.linux-bench -t boltapi-linux-bench .   # build + smoke gate
```

The orchestration scripts start `bench_server`, drive `boltapi_loadgen` against
each endpoint, scrape the machine-readable `RESULT …` line, and print a table.
They **always** stop the server (`finally` / `trap EXIT`) — no orphan, no hang.
`scripts/wrk_crosscheck.sh` optionally cross-checks against `wrk` (Linux only,
skip-if-absent — never a dependency).

### Endpoint suite (reference run — loopback, conns=32)

Single I/O thread, default worker pool, loopback (no network), this i9-9980HK box.
Loopback is a *ceiling probe* — real-network numbers will differ.

| Endpoint | req/s | p50 µs | p99 µs | notes |
|---|---:|---:|---:|---|
| `/plaintext` | ~63–69 k | ~430–455 | ~1.1–1.5 k | fixed text body |
| `/json` | ~58–67 k | ~400–442 | ~1.1–4.9 k | hand-built JSON object |
| `/db` | ~62 k | ~434–442 | ~1.6–2.2 k | **synthetic** (no real DB) |
| `/queries?n=20` | ~61–65 k | ~442–450 | ~1.1–2.2 k | **synthetic** ×20 rows |
| `/route/{id}` | ~62–65 k | ~426–455 | ~1.2–1.9 k | parametric-routing echo |

### Methodology

- **Closed-loop, keep-alive, serial per connection** (send one request, read the
  full response, repeat). This is the keep-alive pattern; it does *not* pipeline.
- **Coordinated-omission caveat:** latency is measured per request from send →
  full response on a fixed connection pool. Under pure open-loop max throughput
  this under-counts the tail vs an open-loop arrival model; the percentiles here
  are connection-latency, not offered-load-latency. Treat tail numbers as
  indicative, not SLA-grade.
- **Histogram:** log-linear (64 sub-buckets/octave, ~1.5% error), fixed static
  storage, no allocation; `min ≤ p50 ≤ p90 ≤ p99 ≤ p99.9 ≤ max` is asserted by
  construction.
- **Acceptance** (used by `Dockerfile.linux-bench` as a gate): every endpoint
  reports `failed=0` and `ok>0`; the tool always terminates within
  `duration + margin`, even if the server is killed mid-run.

### Comparison framing vs peers (template — measured later, NOT fabricated)

> **No competitor numbers are published here yet.** To compare fairly, run each
> framework's `/plaintext` + `/json` on the **same box** with the **same**
> `boltapi_loadgen` invocation (`--connections 64 --duration 10`), then fill in:

| Framework | /plaintext req/s | /json req/s | p99 µs | notes |
|---|---:|---:|---:|---|
| BoltAPI | _measure_ | _measure_ | _measure_ | this suite |
| nginx (static/proxy) | _measure_ | — | _measure_ | raw-perf baseline |
| Drogon | _measure_ | _measure_ | _measure_ | C++ async peer |

Anything published in this table must come from a real run with the command and
box recorded — never an estimate.

## Notes / TODOs

- The router's literal trie edges live in a shared `bolt::SwissTable` keyed by
  `(parent_node, segment_id)` — fan-out is unbounded and nodes are 16 bytes
  regardless (see `router_fanout_test`). (This replaced an earlier fixed
  `[16]` per-node array that could OOB in Release.)
- The App middleware chain (`std::function`) and the per-request coroutine frame
  allocate per request today; the throughput number includes that cost. The
  zero-alloc guarantee (and `no_alloc_test`) is scoped to `Router::match()` and
  the HTTP/1 parser hot paths.
