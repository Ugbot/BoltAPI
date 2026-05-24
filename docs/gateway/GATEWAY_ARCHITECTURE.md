# Gateway Architecture — how it lands on BoltAPI

> Suite: [VISION](GATEWAY_VISION.md) ·
> [COMPETITIVE_RESEARCH](GATEWAY_COMPETITIVE_RESEARCH.md) · **ARCHITECTURE** (this) ·
> [FEATURES](GATEWAY_FEATURES.md) · [ROADMAP](GATEWAY_ROADMAP.md).

How the gateway maps onto BoltAPI's *existing, verified* engine. The headline:
**most of it is additive** — the router, the middleware onion, and the dispatch
bridge need no changes; the one genuinely missing primitive is an **outbound HTTP
client**, and the one routing extension is **host/header matching**.

References are to real files in this repo (verified during planning).

---

## 1. Request lifecycle today (what we build on)

`src/app.cpp` → `App::dispatch_coro_()` is the single gate every request passes
through, regardless of protocol (H1/H2/H3):

```
socket → engine parser → CoroHttpRequest (zero-copy views)
      → App::dispatch_coro_()
          ├─ method_from(creq.method)            → Method enum
          ├─ router_.match(method, path)         → MatchResult{route_id, params[]}
          ├─ Request(creq, params) + Response(cresp)   (thin facades)
          ├─ run_chain(route_index, req, res)    → middleware fold → handler
          └─ co_return CoroHttpResponse
      → engine writes status + headers + body back to the socket
```

A gateway is: **the matched "handler" is an upstream-forwarding coroutine, and the
middleware chain carries the policy plugins.** No new dispatch path.

## 2. Plugins = the middleware onion (no engine change)

`include/boltapi/middleware.h`:
`AsyncMiddleware = coro_task<void>(Request&, Response&, Next)`, folded right-to-left,
terminal = the matched handler. This is *already* the gateway plugin model:

- **Short-circuit** (auth/rate-limit deny): don't call `next()`, write
  `res.unauthorized()` / `res.status(429)` and return. (CORS preflight already does
  exactly this in `app.cpp`.)
- **Transform request:** mutate `Request`/headers before `co_await next()`.
- **Transform response:** edit `Response` after `co_await next()` returns.
- **Forward:** the terminal handler is the upstream proxy coroutine (§3).

A "gateway plugin" is therefore a factory that produces an `AsyncMiddleware`
configured for a route. **Ordering** follows registration; we adopt Envoy/APISIX's
explicit-priority idea by ordering the chain deterministically (auth → rate-limit →
transform → cache → proxy).

> **Known cost (documented in `docs/ROADMAP.md`):** each middleware link is a
> `std::function`, allocating per request when captures exceed SBO. A 6–10 plugin
> chain is acceptable for v1; the arena-backed-continuation perf pass (already a
> tracked TODO) becomes more valuable here and is folded into ROADMAP Phase 2.

## 3. The upstream HTTP client (THE missing piece)

Today BoltAPI has **no outbound HTTP client** — no request serializer, no response
parser, no connection pool. But it *does* have fully-implemented async outbound I/O
primitives (verified): `include/boltapi/net/io_dispatcher.h` —
`async_connect`/`async_read`/`async_write` (`ConnectAwaitable`/`ReadAwaitable`/
`WriteAwaitable`), implemented on IOCP (`ConnectEx`) and epoll (`EPOLLOUT`+`SO_ERROR`).

**We are already building the client core for the benchmark load generator**
(`benchmarks/loadgen/http_client.{h,cpp}`): a transport-agnostic request
serializer + an incremental response parser + a pooled keep-alive connection,
deliberately dependency-free so it can be **promoted** into a real
`boltapi::http::Client`. That promotion is gateway **Phase 0** (ROADMAP).

The upstream layer the gateway needs on top of that core:

```
struct Upstream {                  // an LB pool ("cluster" in Envoy terms)
    bolt::SwissTable name → pool;  // pools keyed by upstream name
    Target targets[];              // host:port + health state, bounded
    LbPolicy policy;               // round-robin / least-conn / hash
};

// forward(): pick a healthy target, get/borrow a keep-alive connection from the
// pool, serialize_request(req → wire), co_await write, co_await read until the
// ResponseParser completes, relay status/headers/body into `Response`.
coro_task<void> proxy_to(Upstream&, Request&, Response&);
```

Connection pooling reuses `http_client.h`'s `ClientConn` (keep-alive, stable
buffers across `co_await`). TLS-to-upstream (HTTPS origins) is the documented
extension point in `http_client.h` (OpenSSL already linked) — a later phase.

## 4. Routing for a gateway

`include/boltapi/router.h` + `src/router.cpp`: SwissTable for static routes
(`swiss_mix(method, fnv1a(path))`, O(1)) + a flat segment trie for `{param}` /
`*` wildcard, all interned via `bolt::DictionaryPool`. **Path + method routing is
done.**

What a gateway adds — **host-based and header-based routing** — does **not** need
changes to the SwissTable/trie core. Two clean options:

- **Pre-router layer:** a small front matcher that selects a *virtual host* /
  routing table by `Host` (and optionally a header), then defers to the existing
  per-host `Router`. (This mirrors nginx `server`-blocks / Envoy virtual hosts.)
- **Key composition:** fold the host into the static key (`swiss_mix(host, method,
  path)`) for exact host+path routes, with the pre-router handling wildcard hosts.

Recommended: a **pre-router virtual-host map** (`bolt::SwissTable` host → Router*),
falling back to a default router — it keeps the hot path one extra hash and reuses
the existing router unchanged. Header-based routing rides as a middleware that can
re-target (or 404) based on header predicates.

## 5. Bolt primitives mapping

| Gateway need | Bolt primitive | Why |
|---|---|---|
| Upstream pool lookup (by name) | `bolt::SwissTable` | O(1), same hash family as the router |
| Virtual-host → router map | `bolt::SwissTable` | host-based routing pre-layer |
| Rate-limit quota map (per key) | `bolt::SwissTable` (sharded) | in-process counters, no Redis hop |
| Per-request plugin scratch | `bolt::Arena` | bump-alloc, reset per request |
| Interned upstream/plugin/route names | `bolt::DictionaryPool` | dedup config strings |
| Quota/LB hash keys | `swiss_mix` | consistent with router keying |
| Cross-thread handoff (if any) | `bolt::SPSC/MPSC` | bounded, lock-free, backpressure |
| Worker/IO affinity | `bolt::CpuTopology` | thread-per-core pinning (already in engine) |

Per CLAUDE.md: **prefer Bolt over third-party** — `SwissTable` not
`std::unordered_map`, `Arena` not `malloc`, bolt channels not `std::queue`. The
FasterAPI rate limiter we port (FEATURES) uses `std::unordered_map`+`shared_mutex`
today; re-homing it onto sharded `SwissTable` is part of that port.

## 6. Config / control-plane model — **OPEN DECISION (decide before Phase 4)**

This is the biggest architectural fork. Four options, with trade-offs:

| Option | What | Pros | Cons |
|---|---|---|---|
| **(a) Code-first** | Configure routes/upstreams/plugins in C++ via the App facade (like `app.get`/`use` today) | Zero new machinery; type-safe; matches current style; fastest to ship | Recompile to change config; not ops-friendly |
| **(b) Declarative YAML + hot reload** | A config file (routes→upstreams, per-route plugin chains) parsed at start + on change (watch/SIGHUP) | GitOps-friendly; Kong-decK/APISIX UX; no recompile | Needs a YAML parser (a vendored dep — or a minimal in-tree one) + a safe atomic swap of the live config |
| **(c) Admin REST API + store** | A running control plane mutating a backing store; data planes pull/watch | Kong-classic; dynamic; multi-node | Most machinery; an admin listener + authz + a store; biggest surface |
| **(d) DB-backed** | Routes/plugins in a database | Familiar to Kong/Tyk users | Heaviest dep; against the "no mandatory datastore" stance |

**Recommended path (not yet committed):** **(a) → (b) → (c)**. Ship the MVP
code-first (a) so the data path is proven without config machinery; add declarative
YAML + hot reload (b) for operability (the decK/xDS-style UX from the research);
consider an admin API (c) only if multi-node/dynamic-fleet demand appears. A YAML
dependency conflicts with "zero vendored deps except Bolt" — so (b) requires either
a minimal in-tree config parser (possibly via Bolt **fionn** if a JSON config is
acceptable instead of YAML) or an explicit, justified exception. **This choice is
deferred to the user before Phase 4** — it is recorded here as a decision, not a
decree.

## 7. Threading & safety notes

- The gateway inherits the engine's **thread-per-core / coroutine-on-worker** model
  (`IODispatcher` + `WorkerThreadPool`). Coroutines migrate worker threads across
  `co_await`, so upstream-connection state (buffers, parser) must live in stable
  storage (the pool record), exactly as `http_client.h` already does for the load
  generator — that lesson transfers directly.
- Rate-limit counters are shared across workers → shard the `SwissTable` and use
  per-shard atomics (the FasterAPI limiter's atomics survive the port); never a
  global lock on the hot path.
- TigerStyle everywhere: bounded pools (max upstreams, max targets/upstream, max
  plugins/route as named constants), explicit error paths (502/503/504 on upstream
  failure/overload/timeout), assertions on invariants.
