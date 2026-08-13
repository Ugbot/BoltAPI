# Contributing to Bolt API

Thanks for your interest in Bolt API. This document is the canonical statement of
the project's engineering standard, toolchain policy, and review expectations.

## Getting set up

Bolt API needs CMake ≥ 3.21, a C++20 compiler, OpenSSL 3.x, and the
[Bolt](https://github.com/Ugbot/bolt) submodule.

```sh
git clone --recursive https://github.com/Ugbot/BoltAPI.git
cd BoltAPI
# already cloned without --recursive?
git submodule update --init --recursive
```

**Linux / macOS**
```sh
cmake --preset release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
```

**Windows (MSVC — never MinGW)**
```sh
cmake --preset msvc
cmake --build build/msvc --config Release
ctest --test-dir build/msvc -C Release
```

Optional protocol lanes are off by default; the QUIC/WebRTC *codecs* always
compile and are unit-tested, while the flags gate the parts of `App` that bind
UDP sockets and serve:

```sh
cmake --preset msvc -DBOLTAPI_WITH_HTTP3=ON -DBOLTAPI_WITH_WEBRTC=ON
```

Container lanes matching CI are in the repo root (`Dockerfile.linux-test`,
`Dockerfile.linux-h3-test`, `Dockerfile.linux-bench`, `Dockerfile.linux-gateway`);
each one runs its `ctest` gate as a build step, so a green `docker build` is a
green test run.

## Toolchain policy

- **C++20.** No compiler extensions.
- **Windows = MSVC (Visual Studio 2022) or clang-cl. Never MinGW.**
- **Linux = LLVM/Clang + lld. Never GCC** — Clang is the closest parity to the
  MSVC primary; GCC diverges on C++20 corners.
- Hardening flags match Bolt and are applied `PRIVATE`
  (`cmake/BoltApiCompileOptions.cmake`): `/EHsc /GR-` on MSVC,
  `-fno-exceptions -fno-rtti` on GCC/Clang. Code is `noexcept`.

## Engineering standard — Tiger Style + HFT

Bolt API follows [Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
(safety → performance → developer experience), with high-frequency-trading
threading discipline on top.

**Tiger Style**
- Assert everywhere: at least two assertions per non-trivial function, covering
  both positive and negative space.
- Bounded, static allocation: fixed-capacity structures sized at startup. **No
  dynamic allocation on the steady-state request path.**
- Every limit is an explicit named constant in config — no magic numbers.
- Bounded control flow: no recursion on hot paths; functions stay around 70 lines
  or fewer.
- Deterministic behaviour, and explicit error handling via `result` / error codes.
  No exceptions — programmer error fails fast via assert.

**HFT threading**
- Thread-per-core / shared-nothing; IO and worker threads are pinned via Bolt's
  topology and affinity helpers.
- Lock-free bounded SPSC/MPSC channels with explicit backpressure — shed load,
  never grow unbounded.
- Cache-line-pad shared atomics to avoid false sharing.
- Spin, don't sleep, on hot loops; minimize syscalls and wakeups.
- Mechanical sympathy: compact cache-resident state, prefetching, arena buffers.

## Prefer Bolt over third-party

The goal is **zero vendored dependencies except Bolt**. Before importing or
vendoring anything, check whether Bolt already provides it and use Bolt's version:

| Need | Use |
|---|---|
| JSON | Bolt **fionn** (`bolt::parse`) — not simdjson |
| Hashing | `swiss_mix` |
| Hash maps | `bolt::SwissTable` |
| Allocation | `bolt::Arena` |
| Queues / channels | Bolt SPSC / MPSC channels |
| Topology / affinity | `bolt_topology`, `bolt_port` |

Anything not yet in Bolt (OpenSSL for TLS/crypto, gzip/brotli/zstd) is treated as
a **stopgap** to be recreated in or moved into Bolt later. Do not add new
third-party dependencies casually. No CPM, no coroio, no Python in the build, no
simdjson. Crypto via OpenSSL is the one accepted runtime dependency.

Hot paths in particular are the point of the fork and should stay Bolt-native:
routing (dictionary-interned segments + `bolt::SwissTable` + segment trie),
per-request memory (`bolt::Arena`), cross-thread handoff (`bolt::SPSCChannel`).

## Testing

Tests must exceed hello-world. Concretely:

- Multiple routes and multiple HTTP verbs, with randomized input data.
- Integration tests spin up a real server on an ephemeral port.
- Protocol work is gated on RFC test vectors where the RFC provides them, and on
  interop against an independent stack where one exists (aioquic for HTTP/3,
  aiortc for WebRTC).
- Tiger Style / HFT gates are themselves tests: assertions-on builds,
  no-allocation-on-hot-path, bounded-resource, and backpressure checks.
- Every test carries a hard `ctest` TIMEOUT ceiling so no test can hang the
  suite. External-client interop legs run through the bounded process runner
  (`tests/interop/bounded_proc.h`), which kills the whole process tree.

Python-based interop helpers run through `uv` (`uv run --with …`), never bare
`pip`/`python`.

## Submitting changes

1. Open an issue first for anything substantial, so the design can be agreed
   before you write it.
2. Keep changes focused, and keep the suite green — run `ctest` locally for the
   configuration you touched.
3. Add or extend tests alongside the change. A performance change needs a
   measurement; a protocol change needs a vector or an interop leg.
4. Performance claims should state the machine and method. See
   [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for the reference machine and
   methodology, and record neutral-or-worse results too — the docs deliberately
   keep a record of measured-neutral experiments so they are not re-chased.
5. Update [`PROJECT_MAP.md`](PROJECT_MAP.md) when you add or change a component,
   and the relevant doc under [`docs/`](docs/README.md).

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), consistent with the project.

## Where things live

- [`README.md`](README.md) — overview, quickstart, build
- [`PROJECT_MAP.md`](PROJECT_MAP.md) — what exists and its status
- [`docs/README.md`](docs/README.md) — documentation index
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — known gaps, limitations, and planned work
- [`examples/`](examples/) — runnable examples
- [`testing/README.md`](testing/README.md) — manual / interop harness
