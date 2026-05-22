# Bolt API

High-performance C++20 HTTP framework — a clean fork of FasterAPI's proven
coroutine HTTP core, re-homed onto [Bolt](https://github.com/Ugbot/bolt) (a
zero-allocation, branch-free compute library) for every hot path.

**Status:** early (M0 — build skeleton). See `PROJECT_MAP.md`.

## Why
FasterAPI has a solid coroutine HTTP engine wrapped in a lot of dead/broken
extras. Bolt API keeps only the engine (HTTP/1.1 + HTTP/2 over TLS/ALPN +
WebSocket + coroutine SSE + chained middleware) and makes its hot paths
Bolt-native — most notably a **dictionary-based router** (interned segments +
SwissTable lookup) for ultra-fast matching.

## Principles
TigerStyle (assert everywhere, bounded/static allocation, no recursion on hot
paths) + HFT threading (thread-per-core, CPU pinning, lock-free bounded channels
with backpressure, no false sharing, spin-don't-sleep). See `CLAUDE.md`.

## Build
Requires CMake ≥3.21, a C++20 compiler, and the Bolt submodule.

```
git clone --recursive <repo>            # or: git submodule update --init --recursive
```

**Windows (MSVC — never MinGW):**
```
cmake --preset msvc
cmake --build build/msvc --config Release
ctest --preset msvc
```

**Linux / macOS:**
```
cmake --preset release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
```

## Layout
`include/boltapi` (public headers) · `src` · `tests` · `examples` · `extern/bolt`
(submodule). License: see `LICENSE` (TBD).
