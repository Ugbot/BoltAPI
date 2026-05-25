# TFB-style comparison harness — BoltAPI vs Drogon (and friends)

A TechEmpower-style head-to-head: each framework runs in its **own container**, and
the **same `wrk` container** drives both over a shared Docker network — the way
[TechEmpower Framework Benchmarks](https://www.techempower.com/benchmarks/) isolates
frameworks. Neutral tool, identical load, apples-to-apples.

## What's measured

The two **pure-framework** TFB test types (routing + serialization + I/O, no DB):

| Endpoint | TFB test | Response |
|---|---|---|
| `GET /plaintext` | Plaintext | `Hello, World!` (text/plain) |
| `GET /json` | JSON serialization | `{"message":"Hello, World!"}` |

DB-backed tests (single/multiple query, fortunes, updates) are **out of scope**:
BoltAPI dropped PostgreSQL, so this is a fair *framework* comparison. (BoltAPI's
`/db` + `/queries` synthetic endpoints exist for self-benchmarking but aren't part
of this head-to-head.)

## Run it

```bash
# from the repo root (Git-bash on Windows, or any Linux shell with Docker):
benchmarks/tfb/run_compare.sh                       # build images + run
benchmarks/tfb/run_compare.sh --skip-build          # reuse built images
benchmarks/tfb/run_compare.sh --duration 30 --conns 512 --threads 8
```

Output (example shape):

```
== TFB-style comparison (wrk -t4 -c256 -d15s) ==
boltapi  /plaintext   req/s=...   p99=...
boltapi  /json        req/s=...   p99=...
drogon   /plaintext   req/s=...   p99=...
drogon   /json        req/s=...   p99=...
```

## Pieces

- `Dockerfile.boltapi` — builds `boltapi_bench_server` (Clang/lld, system OpenSSL,
  epoll); binds `0.0.0.0:8080`, thread-per-core (`-e IO_THREADS=…`).
- `drogon_app.cpp` + `drogon_CMakeLists.txt` + `Dockerfile.drogon` — the Drogon
  equivalent on the official `drogonframework/drogon` image (same two endpoints,
  `0.0.0.0:8080`, one thread per core).
- `Dockerfile.wrk` — the neutral load tool (`wrk`, the TFB standard).
- `run_compare.sh` — builds the images, runs each server + `wrk` on a shared
  network, prints a req/s + p99 table. Always cleans up the containers + network.

## First measured result (2026-05-25, a LOADED 16-core dev box — ratio only)

Docker-on-Windows/WSL2, server + wrk sharing the host CPU, box busy + warm (so
absolutes are depressed — `router_bench` read ~2× its baseline at the time). Read
the **ratio**, not the absolutes:

| | /plaintext | /json |
|---|---:|---:|
| **BoltAPI** (io-threads 8) | ~22 k req/s | ~22.6 k req/s |
| **Drogon** (thread-per-core) | ~42 k req/s | ~36 k req/s |

**Drogon is currently ~1.9× faster on plaintext, ~1.6× on JSON, with much lower
tail** (p99 ~23–28 ms vs BoltAPI ~66–95 ms). This is honest and expected — it
confirms the documented gaps in `docs/PERF_TARGETS.md`: HTTP/1.1 throughput is
between Floor and Good, multi-core scaling was unmeasured, and tail latency (the
dispatch coroutine frame + worker-hop scheduling) is the weakest area. **This
harness is the tool to drive those down.**

BoltAPI **IO-thread scaling** (measured here): 4→~16 k, **8→~22 k**, 16→~15 k —
more IO threads than ~half the cores oversubscribes (IO threads + the worker pool
+ wrk exceed the core count). Hence the harness pins BoltAPI to ~cores/2 IO threads.

## Reading the numbers (important)

On a **single dev box** the server container and the `wrk` container **share the
host CPU** (TFB runs the load generator on a *separate* machine). So:

- **Absolute** req/s will be lower than a dedicated rig, and noisy if the box is
  busy or thermally throttled. Probe with `boltapi_router_bench` (pure CPU) — when
  its static-hit reads its ~60 ns/op baseline, the box is cool enough to trust.
- The **ratio** BoltAPI:Drogon is the meaningful result — both face identical
  conditions in the same run.

## Adding another framework

Add `Dockerfile.<fw>` building a server with the same two endpoints on
`0.0.0.0:8080`, then add a `run_fw <name> tfb-<fw>` line to `run_compare.sh`.
Candidates: nginx (static `/plaintext`), a raw `epoll`/`io_uring` baseline, etc.
