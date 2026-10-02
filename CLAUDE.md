# Bolt API — working agreement

- Use the @PROJECT_MAP.md to find what we have, and update it as we go.
- Bolt API is a high-performance C++20 HTTP framework: a hard fork of FasterAPI's
  proven coroutine HTTP core (`CoroUnifiedServer`), re-homed onto **Bolt**
  (`extern/bolt`, a git submodule) for all hot-path primitives. We deliberately
  left behind FasterAPI's fat (Python bridge, PostgreSQL, MCP, WebRTC, HTTP/3,
  dead duplicate servers).

## Engineering standard — TigerStyle + HFT
- **TigerStyle (safety → performance → DX):** assert everywhere (≥2 per non-trivial
  fn, positive + negative space); bounded/static allocation (fixed-capacity, sized
  at startup, NO dynamic allocation on the steady-state request path); every limit
  is an explicit named constant in config; bounded control flow (no recursion on
  hot paths; functions ≤~70 lines); deterministic; explicit error handling via
  `result`/error codes (no exceptions — fail fast via assert on programmer error).
- **HFT threading:** thread-per-core / shared-nothing; pin IO + worker threads
  (bolt topology/affinity); lock-free bounded SPSC/MPSC channels with explicit
  backpressure (shed, never unbounded); cache-line pad shared atomics (no false
  sharing); spin-don't-sleep on hot loops; minimize syscalls/wakeups; mechanical
  sympathy (compact cache-resident state, prefetch, arena buffers).

## Scale is tunable (1 thread to 200 cores)
Reactor count, accept sockets, handler workers and connection caps come from
one run-time scale profile (Gestalt2 `docs/ENGINEERING.md` §5a), reported in
`boltapi_limits.h`; no hardcoded thread counts. **One reactor** (embedded, a
sidecar, a test) handles accept, IO and dispatch on one thread with no
cross-thread handoff and no idle threads. **Many cores, many NICs:** one
pinned reactor per core with its own `SO_REUSEPORT` listener (no shared accept
queue), one RSS/RX queue per reactor per NIC with IRQ affinity matched to the
reactor's core, per-reactor arenas on the local NUMA node, listeners bindable
per NIC/address. Perf claims report single-reactor req/s and p99 plus the
reactor-scaling curve. Today the default is one IO thread and wire-protocol
servers start a thread per connection up front: G2CHK-449.

## Hot paths use Bolt (the point of the fork)
- Router: dictionary-interned segments + `bolt::SwissTable` static lookup + segment
  trie with interned ids (flagship — see docs/FASTPATHS.md).
- Per-request memory: `bolt::Arena`. Cross-thread handoff: `bolt::SPSCChannel`.
  Hashing: `swiss_mix`. Affinity/topology: `bolt::CpuTopology` / `bolt_port.h`.

## Build / toolchain
- C++20. Targets: `boltapi` (static) + `boltapi::boltapi`, `boltapi::headers`.
- **Windows = MSVC (Visual Studio 2022) or clang-cl. NEVER MinGW.**
  Configure: `cmake --preset msvc` then `cmake --build build/msvc --config Release`.
  Linux/macOS: `cmake --preset release && cmake --build build/release`.
- Match Bolt's hardening: noexcept code; `/EHsc /GR-` (MSVC), `-fno-exceptions
  -fno-rtti` (GCC/Clang), applied PRIVATE (see cmake/BoltApiCompileOptions.cmake).
- **Prefer Bolt over third-party. Goal: zero vendored deps except Bolt.** Before
  importing/vendoring anything, check if Bolt provides it and use Bolt's version:
  JSON → Bolt **fionn** (`bolt::parse`), NOT simdjson; hashing → `swiss_mix`;
  maps → `bolt::SwissTable`; alloc → `bolt::Arena`; queues → bolt channels;
  topology → `bolt_topology`/`bolt_port`. Anything not yet in Bolt (OpenSSL TLS,
  gzip/brotli/zstd) is a stopgap to be recreated in/moved into Bolt later — don't
  add new third-party deps casually. No CPM, no coroio, no Python, no simdjson.

## Testing
- Tests must exceed hello-world: multiple routes, multiple HTTP verbs, randomized
  input data. Integration tests spin a real server. Plus TigerStyle/HFT gates:
  assertions-on, no-allocation-on-hot-path, bounded-resource, backpressure.
