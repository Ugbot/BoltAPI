# Bolt API Gateway — Vision & Positioning

> Part of the gateway design suite: **VISION** (this) ·
> [COMPETITIVE_RESEARCH](GATEWAY_COMPETITIVE_RESEARCH.md) ·
> [ARCHITECTURE](GATEWAY_ARCHITECTURE.md) · [FEATURES](GATEWAY_FEATURES.md) ·
> [ROADMAP](GATEWAY_ROADMAP.md).
>
> Status: **design only.** Nothing in this suite is built yet. These are the
> executable blueprints — the gateway is a planned milestone, sequenced behind the
> upstream HTTP client (Phase 0, see ROADMAP). The thinking here was seeded by the
> gateway work explored in this project's predecessor, **FasterAPI** (mostly inside
> its now-dropped MCP subsystem), plus fresh competitive research.

## The thesis

Bolt API is already "the fastest *complete* implementation of the web protocols"
(HTTP/1.1–3, WebSocket, SSE, WebRTC). An **API gateway** is the natural next layer:
the same engine, pointed at *upstreams* instead of (only) local handlers, with
policy enforced on the way through.

The bet: **a coroutine + Arena + zero-allocation-hot-path C++ data plane can beat
the mainstream gateways (Kong/Gravitee/Tyk) on latency and footprint by 1–2 orders
of magnitude**, because those carry an interpreter or a GC on the request path:

- **Kong** runs Lua plugins on OpenResty/LuaJIT (fast, but per-request Lua + a
  table-heavy plugin model).
- **Gravitee** and most API-management planes are JVM (GC pauses, heap churn).
- **Tyk** is Go (GC, goroutine scheduling) and reflection-y middleware.
- Only **Envoy** (C++) and **APISIX** (OpenResty) are in the same performance
  class — and they are the references we measure against, not the ones we expect
  to dominate on raw throughput.

BoltAPI's advantage is mechanical: no GC, no per-request `malloc` on the steady
path (`bolt::Arena`), SwissTable routing, inline coroutine I/O, thread-per-core.
The cost we pay for that advantage is that **every feature must be (re)built to
TigerStyle** — bounded, assert-rich, no exceptions — rather than `apt install`-ed
from an ecosystem of plugins. This suite is about making that build tractable.

## What an "API gateway" means here

A reverse proxy that sits in front of one or more upstream services and, per route:

1. **Routes** the request to an upstream (by path, host, header, method).
2. **Enforces policy** on the way in: authn/authz, rate limiting, CORS, request
   validation/transformation, quotas.
3. **Forwards** to a healthy upstream instance (load balancing, connection reuse,
   retries, timeouts, circuit breaking).
4. **Transforms + relays** the response back (headers, compression, caching).
5. **Observes** everything (metrics, structured logs, request IDs, tracing).

The classic Kong/Gravitee feature checklist — expressed in BoltAPI terms in
[FEATURES](GATEWAY_FEATURES.md).

## Target users

- Teams who already run BoltAPI services and want a same-stack edge/proxy with no
  new runtime (no Lua, no JVM, no Go sidecar).
- Latency-sensitive shops (fintech/HFT-adjacent, ad-tech, real-time) where the
  gateway's own overhead is a measurable tax and GC tail latency is unacceptable.
- Anyone who wants a single static binary gateway with a tiny resident set instead
  of a multi-process control/data-plane install.

## Non-goals (initially)

- **Full API-management suite** (developer portal, monetization/billing, API
  catalog, GUI policy studio) — that is Gravitee/Apigee territory; we start as a
  *data plane*, not a management product.
- **Distributed control plane** (multi-node config store, push-based config to a
  fleet) — Phase 4 at the earliest; the MVP is single-binary, code-first config.
- **A plugin marketplace / third-party plugin ABI** — plugins are first-class
  middleware compiled in, not a dynamic plugin runtime, until there's demand.
- **Service mesh / sidecar (xDS, mTLS-everywhere)** — Envoy owns that; we may
  borrow xDS *ideas* for dynamic config but not the mesh role.

## Success criteria

1. **Feature parity** with the core gateway checklist in
   [FEATURES](GATEWAY_FEATURES.md) (proxy, LB, rate-limit, auth, health/circuit
   breaker, cache, transform, observability), each TigerStyle + tested.
2. **Performance:** measured (with the benchmark tooling in `docs/BENCHMARKS.md`)
   to add **minimal overhead** over direct origin — target: gateway p99 added
   latency in the low-hundreds-of-µs on loopback, and req/s within a small
   constant factor of the bare framework — and to **beat Kong/Tyk** head-to-head
   on the same box. Envoy/APISIX are the "same class" yardsticks.
3. **Operability:** a single binary, declarative config (Phase 4) with hot
   reload, and Prometheus-scrapable metrics — no external dependency to run.

The performance criterion is gated on real numbers from the load generator
(`benchmarks/loadgen/`) against `bench_server` configured as a proxy — not on
estimates.
