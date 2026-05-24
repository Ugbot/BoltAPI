# Gateway Features — per-capability specs

> Suite: [VISION](GATEWAY_VISION.md) ·
> [COMPETITIVE_RESEARCH](GATEWAY_COMPETITIVE_RESEARCH.md) ·
> [ARCHITECTURE](GATEWAY_ARCHITECTURE.md) · **FEATURES** (this) ·
> [ROADMAP](GATEWAY_ROADMAP.md).

One spec per capability. Each notes **what FasterAPI already has** (reusable
reference at `C:\code\FasterAPI`, mostly inside the dropped MCP subsystem — so it
is *source to study/port*, not a live dependency) and **what BoltAPI must build
fresh**. Legend: ✅ exists in BoltAPI today · ♻️ port/adapt from FasterAPI ·
🆕 build new.

---

## Reverse proxy / upstream forwarding 🆕

The core. Terminal handler that forwards a matched request to an upstream and
relays the response.

- **Build on:** `benchmarks/loadgen/http_client.{h,cpp}` (serializer + incremental
  response parser + pooled keep-alive `ClientConn`), promoted to `boltapi::http::Client`
  (ROADMAP Phase 0); engine async I/O (`io_dispatcher.h`).
- **FasterAPI reference:** `src/cpp/mcp/proxy/proxy_core.h` declared the *shape*
  (`UpstreamConnection::send_request`, `ConnectionPool::acquire/release`,
  `proxy_request`) but transports were STDIO-only and the HTTP path was never wired
  — study the interfaces, build the HTTP client fresh.
- **Spec:** `proxy_to(Upstream&, Request&, Response&)`; preserve method/path/query/
  body; set `X-Forwarded-For`/`X-Forwarded-Proto`/`Host` per config; map upstream
  failure → `502`, pool exhaustion/overload → `503`, upstream timeout → `504`.
  Streaming bodies are a later phase (v1 buffers, bounded by `max_body_size`).

## Load balancing 🆕

Pick a healthy target within an upstream pool.

- **Policies:** round-robin (default), least-connections, consistent-hash (by
  client IP or a header — `swiss_mix`). Bounded `max_targets` per upstream.
- **FasterAPI reference:** none (MCP proxy was single-upstream-per-route). Build new.
- **Envoy parallel:** "cluster" + LB policy + endpoints; mirror that decomposition.

## Rate limiting ♻️

- **FasterAPI has it, complete:** `src/cpp/http/rate_limiter.h` — three algorithms
  (**token-bucket**, **sliding-window** with sub-window granularity, **fixed-window**),
  `RateLimitMiddleware` with a pluggable **key extractor** (default: X-Forwarded-For
  / X-Real-IP), `X-RateLimit-*` + `Retry-After` headers, `EndpointRateLimiter` for
  per-pattern limits. Atomics-based buckets (token/sliding/fixed windows are atomic).
- **Port work:** re-home onto Bolt — swap the `std::unordered_map<…> + std::shared_mutex`
  state maps for a **sharded `bolt::SwissTable`** (per-shard atomics, no global lock
  on the hot path); keep the algorithms verbatim. Wire as an `AsyncMiddleware` that
  short-circuits with `429` (the engine already has a 429 reason phrase).
- **Distributed (later):** an external store (Redis-style) only as an *option*; MVP
  is in-process (Tyk uses Redis and pays a hop — we don't, by default).

## Authentication / Authorization ♻️

Auth is the #1 gateway use case (Tyk's whole posture).

- **FasterAPI has:** `src/cpp/http/jwt_auth.h` (JWT HS256/384/512 + RS256/384/512,
  claim validation exp/nbf/iss/aud/iat, Bearer extraction) and
  `src/cpp/mcp/security/auth.h` (`Authenticator`/`BearerTokenAuth`/`MultiAuth` +
  scope-based authorize + `WWW-Authenticate`). OpenSSL-only deps — portable.
- **Port work:** bring the HTTP-layer JWT + the Bearer/Multi/scope model across as
  middleware (`401`/`403` short-circuit). API keys → a `SwissTable` key store.
- **Build new (phased):** OAuth2 token introspection (server-to-server), OIDC,
  HMAC request signing, **mTLS** (client-cert verification — the TLS context exists;
  mutual-cert validation must be configured). API-key consumers + per-key quotas
  (Kong "consumer" / Tyk "key" concept).

## Circuit breaker / retries / timeouts ♻️🆕

- **FasterAPI has the config + a state struct:** `UpstreamConfig{max_retries,
  retry_delay_ms, request_timeout_ms}` and `MCPProxy::CircuitBreakerState{failure_count,
  is_open, last_failure_time_ms}` with `is_circuit_open/record_success/record_failure`
  — but the **half-open transition + reset timers are not implemented** and it was
  never wired into a send path.
- **Build:** a proper breaker state machine (closed → open on N failures → half-open
  after a cooldown → closed on a probe success), per-target. Bounded retries with
  backoff on idempotent methods; per-route + per-upstream timeouts. Envoy's outlier-
  detection is the reference for ejecting bad endpoints.

## Health checks & failover ♻️🆕

- **FasterAPI:** declared `enable_health_check` + `health_check_interval_ms` +
  `is_healthy()` per connection + `get_upstream_health()`, but `health_monitor.cpp`
  is an unimplemented stub and there's no background checker.
- **Build:** an **active** health checker (a periodic coroutine pinging a configured
  path, expecting a status, with a timeout) + **passive** health (mark a target
  unhealthy on consecutive proxy failures, recover after a window). Unhealthy
  targets are skipped by the LB; failover to the next healthy target.

## Caching ♻️

- **FasterAPI has:** `src/cpp/http/response_cache.h` — LRU + ETag + `304 Not
  Modified` + Cache-Control parsing (GET/HEAD).
- **Port:** bring across as a response-phase middleware; back the LRU with bounded
  capacity (TigerStyle) and key by `swiss_mix(host, method, path[, vary headers])`.
  Mirror nginx `proxy_cache` semantics for TTL + revalidation.

## Request / response transformation ♻️

- **FasterAPI has:** the `Transformer` interface + `MetadataTransformer` (inject
  proxy headers), `SanitizingTransformer` (redact JSON fields), `CachingTransformer`
  (cache headers) in `proxy_core.h` — interfaces defined, hooks not wired to a live
  flow.
- **Port/build:** re-home as request- and response-phase middleware: add/remove/
  rename headers, rewrite path/host for the upstream, redact response fields
  (`bolt::parse`/fionn for JSON edits), set/strip cookies. Gravitee's policy steps
  are the breadth reference.

## Observability 🆕 (FasterAPI collects, doesn't export)

- **FasterAPI:** `src/cpp/http/metrics.h` collects counters + `ProxyStats`
  (requests/latency/per-upstream/per-route) — but **no export** (no Prometheus/
  StatsD) and request-logging is a stub.
- **Build:** a `/metrics` Prometheus-text endpoint (counters + histograms for req
  count, status classes, upstream latency, per-route); **request-id** generation +
  propagation (`X-Request-ID`); structured access logs; distributed **tracing**
  (W3C `traceparent` propagation; OpenTelemetry export) as a later phase. Keep
  collection in-process (atomics/`SwissTable`), lowest latency.

## Traffic splitting / canary 🆕

- **FasterAPI:** none. Build from scratch.
- **Spec:** weighted routing across upstream pools/targets (e.g. 95%/5%), sticky by
  client/header optional; the basis for canary + blue-green. A weighted LB policy +
  a routing predicate. Envoy weighted-clusters is the reference.

## CORS ✅ and Compression ✅ (already in BoltAPI)

- **CORS:** done (`App` built-in middleware, `enable_cors`). Reuse as-is per route.
- **Compression:** gzip done (`include/boltapi/compression.h`, `enable_compression`);
  brotli/zstd are unwired options (`docs/COMPRESSION.md`). Reuse on the response path.

---

## FasterAPI → BoltAPI port ledger

| Capability | FasterAPI file (reference) | Action |
|---|---|---|
| Rate limiting (3 algos) | `src/cpp/http/rate_limiter.h` | ♻️ port → sharded SwissTable |
| JWT auth | `src/cpp/http/jwt_auth.h` | ♻️ port (OpenSSL only) |
| Bearer/Multi/scope auth | `src/cpp/mcp/security/auth.h` | ♻️ port HTTP parts |
| Response cache (LRU/ETag/304) | `src/cpp/http/response_cache.h` | ♻️ port |
| Transformers (metadata/redact/cache) | `src/cpp/mcp/proxy/proxy_core.h` | ♻️ re-home as middleware |
| Circuit breaker state | `src/cpp/mcp/proxy/proxy_core.h` | ♻️ port struct, 🆕 finish state machine |
| Connection pool shape | `src/cpp/mcp/proxy/{proxy_core,upstream_connection}.h` | study; 🆕 build on `http_client.h` |
| Metrics counters | `src/cpp/http/metrics.h` | ♻️ port collection, 🆕 add export |
| Health checks | `src/cpp/http/health_monitor.{h,cpp}` | 🆕 build (FasterAPI stub) |
| Upstream HTTP client | — (none; STDIO-only) | 🆕 build (Phase 0, from `http_client.h`) |
| Load balancing | — | 🆕 build |
| Traffic split / canary | — | 🆕 build |

The pattern: **policy** capabilities (rate-limit, auth, cache, transform, metrics-
collection) are largely portable from FasterAPI; the **data-path** capabilities
(upstream client, pooling, LB, health, circuit breaker, canary) are new — and all
hang off the one new primitive, the outbound HTTP client.
