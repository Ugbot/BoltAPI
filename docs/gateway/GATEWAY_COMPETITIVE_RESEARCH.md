# API Gateway — Competitive Research

> Suite: [VISION](GATEWAY_VISION.md) · **COMPETITIVE_RESEARCH** (this) ·
> [ARCHITECTURE](GATEWAY_ARCHITECTURE.md) · [FEATURES](GATEWAY_FEATURES.md) ·
> [ROADMAP](GATEWAY_ROADMAP.md).

Studied analysis of the gateways we benchmark against and borrow from. The goal is
not to clone any one of them but to make deliberate, documented choices. Each
section: **architecture · config model · extension mechanism · performance ·
borrow vs differ**. (Descriptions reflect each project's well-known public
architecture; verify version specifics against current docs before relying on a
detail.)

---

## 1. Kong

**Architecture.** A Lua layer on top of **OpenResty** (nginx + LuaJIT). nginx owns
the event loop, connection handling, and proxying; Kong's logic runs as Lua in
nginx's `access`/`header_filter`/`body_filter`/`log` phases. Routing + config are
loaded from a datastore (PostgreSQL, or "DB-less" from a YAML file). "Hybrid mode"
splits a **control plane** (CP, holds config) from **data planes** (DP, proxy
traffic and pull config from the CP over a gRPC/WebSocket channel).

**Config model.** Entities: *Services* (upstreams), *Routes* (match rules → a
service), *Plugins* (attached globally or per service/route/consumer), *Consumers*
(API clients), *Upstreams/Targets* (LB pools with health checks). Managed via an
**Admin REST API**, or declaratively via **decK** (a CLI that syncs a YAML file to
the gateway — GitOps-friendly), or fully DB-less from a `kong.yaml`.

**Extension.** Plugins are Lua modules implementing phase handlers
(`access(conf)`, `header_filter(conf)`, …) + a config schema. A rich bundled set
(auth: key-auth, jwt, oauth2, ldap; traffic: rate-limiting, proxy-cache,
request/response-transformer; observability: prometheus, zipkin). Also a Go and a
JS plugin runner (external process via PDK) for non-Lua plugins.

**Performance.** Very good for an "everything" gateway (nginx + LuaJIT is fast),
but each request pays per-phase Lua dispatch + table allocation; rate-limiting and
some plugins hit the datastore or a shared dict. p99 is sensitive to plugin count.

**Borrow vs differ.** *Borrow:* the **Service / Route / Plugin / Consumer / Upstream
entity model** is the clearest mental model in the space — adopt its vocabulary.
The **decK declarative-YAML + sync** workflow is the config UX to emulate (our
Phase 4). *Differ:* no Lua/interpreter on the request path — plugins are compiled
TigerStyle middleware; no mandatory datastore (start DB-less/code-first).

---

## 2. Gravitee

**Architecture.** A full **API-management** platform (JVM/Java). Components: a
**Gateway** (data plane, reactive Netty-based), a **Management API** + **Console**
(admin UI), a **Developer Portal**, and a backing store (MongoDB/JDBC + Elasticsearch
for analytics). Strongly oriented toward *managing* APIs, not just proxying them.

**Config model.** APIs are defined in the console/management API with a **flow**
engine: each API has flows (matched by path/method/condition) containing ordered
**policies**. Plans/subscriptions gate consumer access (API keys, JWT, OAuth2);
analytics + monetization are first-class.

**Extension.** **Policies** (Java classes, or expression-language steps) applied on
request/response phases inside a flow — rate limiting, transformation, auth, quota,
JSON-to-XML, etc. A "policy studio" GUI composes them visually.

**Performance.** JVM data plane: throughput is decent but carries GC and heap
overhead; tuned for *manageability and breadth* over raw edge latency.

**Borrow vs differ.** *Borrow:* the **flow model** (ordered policies matched by a
condition) is a clean way to express per-route plugin chains with conditions — a
richer version of our middleware fold; and the **plan/subscription/quota** concept
is the right framing for API-product features later. *Differ:* we are a data plane
first — the console/portal/monetization stack is explicitly a non-goal initially
(VISION). No JVM.

---

## 3. Envoy

**Architecture.** A CNCF C++ L4/L7 proxy — the de-facto **data-plane standard**
(the engine inside Istio, Consul, many API gateways). Thread-per-core
(non-blocking, run-to-completion workers), a **filter chain** architecture:
listeners → network filters → HTTP connection manager → an ordered chain of
**HTTP filters** → a **router filter** that forwards to a **cluster** (upstream
pool) via configurable **load balancing**, with health checking, circuit breaking,
outlier detection, retries, and timeouts as core features.

**Config model.** Static bootstrap YAML/JSON **or** dynamic via the **xDS** APIs
(LDS/RDS/CDS/EDS — listeners/routes/clusters/endpoints discovery) served by a
control plane over gRPC. This dynamic, push-based config is Envoy's signature: a
control plane streams updates; data planes apply them without restart.

**Extension.** Native C++ filters; **WASM** filters (proxy-wasm) for sandboxed
extension in multiple languages; Lua filter for small logic; ext_authz / ext_proc
to call out to an external authz/processing service.

**Performance.** The benchmark to match — C++, no GC, highly optimized. Its
overhead is small and predictable; it is explicitly a "same class" yardstick, not
a target to dominate.

**Borrow vs differ.** *Borrow:* the **filter-chain + router-filter + cluster +
LB/health/circuit-breaker/outlier-detection** decomposition is the cleanest
data-plane architecture — map it onto our middleware + upstream client + pool
(ARCHITECTURE). The **xDS dynamic-config** idea (push config without restart) is
the gold standard for Phase 4+ hot reload. *Differ:* we won't implement the full
xDS protocol or the mesh/sidecar role initially; WASM filters are a possible far-
future extension, not the v1 plugin model (compiled middleware is simpler + faster).

---

## 4. Apache APISIX

**Architecture.** Also OpenResty (nginx + LuaJIT), but config lives in **etcd** and
is **watched** for changes — so route/plugin updates propagate to all nodes in
milliseconds with no reload (its headline differentiator vs classic Kong). A radix-
tree router; a plugin runner for non-Lua plugins (Go/Python/Java via an external
process, and proxy-wasm).

**Config model.** Routes, Services, Upstreams, Consumers, Plugins, *Plugin Configs*
(reusable plugin bundles) — stored in etcd, edited via an Admin API or a dashboard.
The etcd-watch model means **declarative, dynamic, hot** by construction.

**Extension.** ~100 bundled Lua plugins (auth, traffic, observability, transform,
serverless), the external plugin runner, and wasm. Plugin order is explicit
(priority numbers).

**Performance.** One of the fastest OpenResty gateways; the radix router + etcd-
watch keep the hot path lean. Another "same class" reference.

**Borrow vs differ.** *Borrow:* the **watch-based dynamic config** (a store whose
changes stream to the data plane) is the model for our hot reload; **explicit
plugin priority/ordering** is a good ergonomic; reusable **plugin-config bundles**
map to named middleware stacks. *Differ:* no etcd dependency for the MVP (etcd is a
heavyweight external dep); we keep config in-process (code-first → file → optional
store) per ARCHITECTURE's open decision.

---

## 5. Tyk

**Architecture.** A Go gateway. Config per-API in JSON ("API definitions"), stored
in a file, or in Redis/MongoDB via a **dashboard** + a separate **gateway**
process. Redis backs rate limiting, quotas, and analytics.

**Config model.** "API definitions" (JSON) describe listen path, upstream
("target_url"), auth method, version, and a middleware list. Strong built-in
**auth** focus: API keys, JWT, OAuth2, OIDC, HMAC, mTLS, plus per-key quotas and
rate limits managed centrally in Redis.

**Extension.** Middleware via Go plugins (compiled `.so`), gRPC plugins (external
process, any language), JSVM (otto) for small JS, and a rich set of built-in
middleware. Per-API middleware ordering (pre/post/auth phases).

**Performance.** Good (Go, compiled), but carries Go GC + reflection in places;
Redis round-trips for distributed rate-limit/quota add latency vs an in-process
counter.

**Borrow vs differ.** *Borrow:* the **auth-first** posture (JWT/OAuth/OIDC/HMAC/
mTLS + per-key quotas as core, not afterthoughts) — auth is the #1 gateway use
case; and the clean **pre/auth/post middleware phases** per API. *Differ:* no Go/GC;
distributed rate-limit via Redis is a later option — the MVP counts in-process with
`bolt::SwissTable` (no network hop). No `.so`/JSVM plugin runtime initially.

---

## 6. nginx / OpenResty

**Architecture.** The raw-performance **baseline** the whole category is measured
against. nginx: an event-driven, multi-worker C reverse proxy/load balancer with
mature upstream handling (keepalive pools, `proxy_pass`, health checks in the
commercial Plus), caching (`proxy_cache`), and rate limiting (`limit_req`/`limit_conn`).
OpenResty embeds LuaJIT to make nginx programmable (what Kong/APISIX build on).

**Config model.** Static `nginx.conf` (directives, `location` blocks, `upstream`
blocks), reloaded on `SIGHUP` (graceful). No dynamic API in open-source nginx
(hence Kong/APISIX adding one on top).

**Extension.** C modules; Lua via OpenResty. Not an "API gateway" out of the box —
no consumer/plugin/auth entity model — but it is the proxy core everyone respects.

**Performance.** The yardstick for `/plaintext` and proxy throughput. Our
benchmark comparison table (`docs/BENCHMARKS.md`) lists nginx as the baseline to
measure against on the same box.

**Borrow vs differ.** *Borrow:* nginx's **upstream/keepalive connection-pool +
proxy_cache + limit_req** semantics are battle-tested defaults to mirror; its
graceful-reload (`SIGHUP`) is the simplest hot-reload model. *Differ:* we provide
the gateway entity model (routes/plugins/consumers/upstreams) nginx lacks, with a
programmable-but-compiled extension path instead of config-directives or Lua.

---

## Synthesis — what BoltAPI takes from each

| Source | The one thing we take |
|---|---|
| **Kong** | Entity vocabulary (Service/Route/Plugin/Consumer/Upstream) + decK-style declarative YAML sync |
| **Gravitee** | The *flow* model (ordered, condition-matched policies) + plan/quota framing for later |
| **Envoy** | Filter-chain + cluster + LB/health/circuit-breaker/outlier decomposition; xDS-style dynamic config as the hot-reload ideal |
| **APISIX** | Watch-based dynamic/hot config; explicit plugin priority + reusable plugin bundles |
| **Tyk** | Auth-first posture (JWT/OAuth/OIDC/HMAC/mTLS + per-key quotas) + pre/auth/post phases |
| **nginx** | Upstream keepalive pools, proxy_cache, limit_req semantics; SIGHUP graceful reload |

**What we deliberately do differently from all of them:** no interpreter (Lua) or
managed runtime (JVM/Go) on the request path — plugins are compiled, TigerStyle
middleware; no mandatory external datastore (etcd/Redis/Mongo/Postgres) for the
MVP — config and counters live in-process (`bolt::SwissTable`/`bolt::Arena`), with
external stores as an *option* for distributed deployments, not a requirement. The
result should be Envoy-class latency with a far smaller operational surface.

See [ARCHITECTURE](GATEWAY_ARCHITECTURE.md) for how these choices land on BoltAPI's
engine, and [FEATURES](GATEWAY_FEATURES.md) for the per-capability specs.
