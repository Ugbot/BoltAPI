# Gateway Roadmap — phased plan + punch-card

> Suite: [VISION](GATEWAY_VISION.md) ·
> [COMPETITIVE_RESEARCH](GATEWAY_COMPETITIVE_RESEARCH.md) ·
> [ARCHITECTURE](GATEWAY_ARCHITECTURE.md) · [FEATURES](GATEWAY_FEATURES.md) ·
> **ROADMAP** (this).

Phased, correctness-gated increments (the same green-increment discipline used for
HTTP/3 and WebRTC). Each phase lists deliverables, the gate that proves it, and the
FasterAPI reference to study. Legend: `[ ]` todo · `[~]` partial · `[x]` done.
**Everything below is `[ ]`** — this is a plan; nothing is built yet.

The enabling insight (see ARCHITECTURE §3): the **upstream HTTP client** is the
one missing primitive, and we are *already* building its core as the benchmark
load generator (`benchmarks/loadgen/http_client.{h,cpp}`). Phase 0 promotes it.

---

## Phase 0 — Upstream HTTP client (the enabling primitive)
- [ ] Promote `benchmarks/loadgen/http_client.{h,cpp}` → `include/boltapi/http/client.h`
      + `src/http/client.cpp` (`boltapi::http::Client`): request serializer +
      incremental response parser + pooled keep-alive `ClientConn`, on the engine's
      `IODispatcher` async I/O.
- [ ] Connection pool keyed by upstream (`bolt::SwissTable`), bounded
      `max_conns_per_upstream`, keep-alive reuse, idle reaping.
- [ ] `coro_task<ClientResponse> Client::send(target, ClientRequest)`.
- **Gate:** a loopback gtest — Client GETs/POSTs a second in-process `App` and gets
      byte-exact responses; pool reuses connections across N requests; ASan clean.
- **Reference:** `mcp/proxy/{proxy_core,upstream_connection}.h` (shape only).

## Phase 1 — Reverse-proxy MVP (the headline gate)
- [ ] `Upstream`/`Target` model + `App::proxy(route, upstream)` (code-first config).
- [ ] `proxy_to(Upstream&, Request&, Response&)` terminal handler: forward method/
      path/query/body, set `X-Forwarded-*`, relay status/headers/body; `502/503/504`
      on failure/overload/timeout.
- [ ] Host-based routing pre-layer (`bolt::SwissTable` host → Router); header-based
      routing as a middleware (ARCHITECTURE §4).
- **Gate:** **BoltAPI forwards to a backend `bench_server` and relays the response
      byte-exact**, driven through the real router+middleware; benchmarked with
      `benchmarks/loadgen` (added-latency + req/s vs direct origin recorded in
      `docs/BENCHMARKS.md`). This is the "it's a gateway now" milestone.

## Phase 2 — Policy plugins (port from FasterAPI)
- [ ] Rate limiting ♻️ (`http/rate_limiter.h` → sharded `bolt::SwissTable`), `429`.
- [ ] JWT + Bearer/Multi/scope auth ♻️ (`http/jwt_auth.h`, `mcp/security/auth.h`), `401/403`.
- [ ] API keys + consumers (`SwissTable` key store), per-key quotas.
- [ ] Response cache ♻️ (`http/response_cache.h`), request/response transformers ♻️.
- [ ] CORS ✅ + compression ✅ reused per route.
- [ ] Fold in the arena-backed-middleware-continuation perf pass (ROADMAP/`middleware.h` TODO).
- **Gate:** per-plugin unit tests + an integration test stacking auth→rate-limit→
      cache→proxy on one route, with deny short-circuits verified; bench the chain cost.

## Phase 3 — Resilience (data-path robustness)
- [ ] Load balancing 🆕 (round-robin / least-conn / consistent-hash), bounded pools.
- [ ] Active + passive health checks 🆕 (FasterAPI stub → real background checker);
      LB skips unhealthy targets; failover.
- [ ] Circuit breaker ♻️🆕 (port the state struct, finish half-open + reset timers);
      bounded retries w/ backoff (idempotent only); per-route/upstream timeouts.
- **Gate:** kill/slow a target mid-run and verify failover + breaker open→half-open→
      close + no error storm; loopback fault-injection test.

## Phase 4 — Control plane (**config-model decision required first**)
- [ ] **Decide** the config model with the user (ARCHITECTURE §6: code-first vs
      declarative-YAML/JSON+hot-reload vs admin-API vs store). Recommended path:
      already shipped code-first (Phase 1) → add declarative file + hot reload here.
- [ ] Declarative config (routes→upstreams, per-route plugin chains) parsed at start
      + on change; atomic swap of the live config (no dropped requests). If JSON is
      acceptable, use Bolt **fionn** (no new dep); YAML would need a justified dep.
- [ ] Graceful reload (SIGHUP-style) and GOAWAY/drain on shutdown.
- **Gate:** change a route's upstream/plugins via config + reload with zero failed
      in-flight requests; config round-trip test.

## Phase 5 — Observability + advanced
- [ ] `/metrics` Prometheus endpoint (req/status/latency/per-route/per-upstream),
      collection ported from `http/metrics.h`.
- [ ] Request-id generation + propagation; structured access logs.
- [ ] Distributed tracing (W3C `traceparent`; OpenTelemetry export).
- [ ] Traffic splitting / canary 🆕 (weighted clusters); blue-green.
- [ ] mTLS to upstreams + client-cert auth; OAuth2 introspection / OIDC.
- **Gate:** scrape `/metrics` under load; trace propagation end-to-end; a 95/5 canary
      split verified by per-target counters.

---

## Cross-cutting gates (every phase)
- TigerStyle: bounded pools (named constants for max upstreams/targets/plugins),
  ≥2 asserts/non-trivial fn, no exceptions, no steady-state allocation on the proxy
  hot path, functions ≤~70 lines.
- Tests exceed hello-world: multiple routes/verbs, randomized input; integration
  tests spin a real server + a real upstream; hard ctest TIMEOUT ceiling.
- Both platforms: MSVC (primary) + Linux/Clang (a `Dockerfile.linux-gateway` lane,
  modeled on `Dockerfile.linux-bench`).
- Perf measured, never estimated: `benchmarks/loadgen` against the proxy path,
  numbers + box recorded in `docs/BENCHMARKS.md`; compared head-to-head with
  Kong/Tyk and held to Envoy/APISIX class.

## Dependency order
```
Phase 0 (client) ──> Phase 1 (proxy MVP) ──> Phase 2 (plugins)
                                      └─────> Phase 3 (resilience)
                                              Phase 4 (control plane) ──> Phase 5 (observability/advanced)
```
Phase 0 unblocks everything; Phases 2 and 3 can proceed in parallel after Phase 1;
Phase 4's first task is the config-model decision (do not start 4 before it).
