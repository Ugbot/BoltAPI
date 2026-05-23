# Bolt API — Protocol Extensibility Seams (M3)

> HTTP/3 + WebRTC are scaffolded as a clean extension seam so they can be
> implemented later **without touching the working HTTP/1.1 + HTTP/2 + TLS +
> WebSocket + SSE core**. This document is the integration contract.

Status: **architecture + stubs only.** Both seams compile to inert stubs that
return `NotImplemented`. The default build (`BOLTAPI_WITH_HTTP3=OFF`,
`BOLTAPI_WITH_WEBRTC=OFF`) is byte-for-byte unchanged in behavior; the existing
test suite passes unmodified, plus one new flag-aware seam test.

---

## The contract in one picture

```
   ┌──────────────────────────────────────────────────────────────┐
   │  App  /  Router  /  middleware  (UNCHANGED — shared by all)    │
   └──────────────────────────────────────────────────────────────┘
            ▲                                   ▲
   built-in │ direct dispatch          extension│ via registry
            │                                   │
   ┌────────┴─────────┐              ┌──────────┴───────────────────┐
   │ HTTP/1.1, HTTP/2 │              │ IProtocol  (protocol.h)       │
   │ (CoroUnified-    │              │  Http3Protocol / WebRtcProtocol│
   │  Server engine)  │              └──────────┬───────────────────┘
   └────────┬─────────┘                         │ runs over
            │ runs over                         │
   ┌────────┴─────────┐              ┌──────────┴───────────────────┐
   │ TCP + TLS stream │              │ ITransport (transport.h)      │
   │ (CoroTcpListener │              │  UdpTransport (Datagram)      │
   │  + TlsContext)   │              └───────────────────────────────┘
   └──────────────────┘
        Stream form                         Datagram form
```

Two interfaces + one registry:

| Piece | File | Role |
|---|---|---|
| `ITransport` | `include/boltapi/transport.h` | the byte/datagram **source** a protocol runs over |
| `UdpTransport` | `include/boltapi/transport.h` (impl gated) | datagram transport for H3/WebRTC |
| `IProtocol` | `include/boltapi/protocol.h` | drives one protocol's **connection handling** over an `ITransport` |
| `ProtocolRegistry` | `include/boltapi/protocol.h` | the **extension point**: `register_protocol` / `has` / `create` |
| `ISignaling`, `IDataChannel` | `include/boltapi/protocol.h` | WebRTC-specific sketches (declarations) |
| `Status` / NotImplemented | reuses `core::result<void>` | exception-free result vocabulary |

---

## `ITransport` — the byte/datagram source

```cpp
enum class TransportKind { Stream, Datagram };

class ITransport {
  virtual Status start() = 0;                 // bind/listen; ok or NotImplemented
  virtual void   stop() noexcept = 0;         // idempotent teardown
  virtual TransportKind kind() const noexcept = 0;   // Stream vs Datagram
  virtual const Endpoint& local_endpoint() const noexcept = 0;
  virtual bool   is_running() const noexcept = 0;
};
```

* **Stream** = TCP(+TLS). **Datagram** = UDP.
* `Status` is `core::result<void>`; the seam's `not_implemented()` /
  `is_not_implemented()` helpers wrap the `not_ready` error code so call sites
  read intent-fully. No exceptions anywhere in the contract.

`UdpTransport` is **declared always** (so headers, the registry, and tests can
name the type and the build surface is stable) but its **implementation is
compiled only under** `BOLTAPI_WITH_HTTP3 || BOLTAPI_WITH_WEBRTC`
(`src/proto/udp_transport.cpp`). Even then it is a stub: `start()` returns
`NotImplemented`; no socket is opened.

### How the live H1/H2 stack maps onto the stream form (documentation only)

We did **not** refactor the live listener. The mapping below is descriptive — it
shows the shape the seam was modelled on:

| `ITransport` (stream) | Live engine equivalent |
|---|---|
| `start()` / `stop()` | `CoroTcpListener::start()` / `stop()` |
| "accept a connection" | `CoroTcpListener` accept loop → client fd → `CoroConnectionHandler` coroutine |
| `kind() == Stream` | a connected TCP byte stream |
| TLS wrapping | `net::TlsContext` (ALPN `h2`/`http/1.1`) wraps the fd; ALPN is the "which protocol?" decision for the stream family today |

---

## `IProtocol` + why H1/H2 stay built-in

```cpp
enum class ProtocolId { Http11, Http2, Http3, WebRtc };

class IProtocol {
  virtual ProtocolId            id() const noexcept = 0;
  virtual TransportKind         transport_kind() const noexcept = 0;
  virtual Status                serve(ITransport& source) = 0;  // stub: NotImplemented
  virtual void                  stop() noexcept = 0;
};
```

* **HTTP/1.1 and HTTP/2 are the built-in protocols.** They keep their current
  **direct dispatch** inside `CoroUnifiedServer` (TCP+TLS stream, ALPN choosing
  `h2` vs `http/1.1`). They are **deliberately not retrofitted** onto
  `IProtocol`, because doing so would mean editing the working core — which M3
  forbids. `ProtocolRegistry::is_builtin()` reports them as built-in;
  `has(Http11)` / `has(Http2)` are `false` because the registry tracks
  **extension** protocols, not the built-ins.
* **HTTP/3 and WebRTC are the extension protocols.** Adding one is "write a real
  `IProtocol` + register its factory" — nothing in the core changes.

This split is the whole point: the registry is real and usable, so filling in
H3 later is purely additive, while H1/H2 keep their faster, direct path for now.

---

## `ProtocolRegistry` — the extension point

```cpp
class ProtocolRegistry {
  Status register_protocol(ProtocolId, ProtocolFactory);  // factory = () -> unique_ptr<IProtocol>
  bool   has(ProtocolId) const noexcept;
  std::unique_ptr<IProtocol> create(ProtocolId) const;    // nullptr if unregistered
  std::size_t size() const noexcept;
  static constexpr bool is_builtin(ProtocolId) noexcept;
};
```

TigerStyle: a **bounded, fixed-capacity** structure — an array indexed by
`ProtocolId` (`kProtocolIdCount` slots), **not** a `std::map`. O(1) lookup, no
hashing, no per-entry heap node. The only allocations are whatever the user's
`std::function`/`unique_ptr` does, and only at register/create time (never in a
hot path). Asserts guard the bounds.

---

## Compile gating / layout

| Artifact | Compiled when | Behavior |
|---|---|---|
| `include/boltapi/transport.h`, `protocol.h` | always (header-only) | inert until a factory registers |
| `src/proto/udp_transport.cpp` | `BOLTAPI_WITH_HTTP3 OR BOLTAPI_WITH_WEBRTC` | `UdpTransport` stub → NotImplemented |
| `src/proto/http3_stub.cpp` | `BOLTAPI_WITH_HTTP3` | `Http3Protocol` stub + `register_http3()` |
| `src/proto/webrtc_stub.cpp` | `BOLTAPI_WITH_WEBRTC` | `WebRtcProtocol` stub + `register_webrtc()` |

When both flags are OFF, **no seam TU is added to the library** and the
`BOLTAPI_WITH_*` defines are absent, so `protocol.h`'s `register_http3` /
`register_webrtc` declarations and the App seam hook bodies are `#if`-compiled
out. The stubs **never** include any FasterAPI `quic/` or `webrtc/` source.

---

## App hook (additive, safe)

`App::Config` gained additive flags (default OFF):

```cpp
bool     enable_http3  = false;
uint16_t http3_port    = 0;   // 0 = reuse http1_port number over UDP
bool     enable_webrtc = false;
```

On `run()` / `start_background()`, after the dispatch is built,
`App::init_protocol_seams()` runs. Its behavior:

| runtime flag | compile option | result |
|---|---|---|
| OFF | — | nothing (fast exit; common path) |
| ON | OFF | one-time `stderr` warning ("ignored: built without …"); **no-op** |
| ON | ON | register stub factory → `create()` → `serve(UdpTransport)` returns NotImplemented → log "HTTP/3 not yet implemented; continuing with HTTP/1.1+HTTP/2" |

On **every** path it **never crashes, never blocks**, and the H1/H2 server keeps
serving. `App`'s public API is purely additive — no breaking changes.

---

## Tests & CI

* `tests/protocol_seam_test.cpp` (gtest via `boltapi_add_test`): registry
  `register`/`has`/`create`, multiple independent protocols, re-register
  replacement, built-in classification, a dummy `IProtocol` returning
  NotImplemented, and `ITransport` kind reporting. **Flag-aware** — the H3/WebRTC
  stub-factory cases are `#if`-guarded, so the file passes in the default
  flags-OFF build using an in-test dummy protocol. The flags are **not** required.
* CI: a `seams-on` leg (`.github/workflows/ci.yml`) configures + builds with
  `-DBOLTAPI_WITH_HTTP3=ON -DBOLTAPI_WITH_WEBRTC=ON` (MSVC/VS2022, never MinGW)
  and runs the seam test, so the ON path can't rot.

---

## Filling in the real implementations (future dev)

Neither requires editing the H1/H2 core.

### HTTP/3

1. **Transport** — run over `UdpTransport` (`Datagram`). Bind the UDP socket via
   the existing `net::IODispatcher` (IOCP/epoll/kqueue) so QUIC packet I/O shares
   the engine's worker pool — no new threading model.
2. **QUIC** — terminate QUIC (connection IDs, streams, loss recovery, TLS 1.3
   handshake via the existing OpenSSL stack; `TlsContext` already speaks TLS 1.3).
   Map each QUIC bidi stream to one HTTP/3 request/response.
3. **QPACK** — header compression (HTTP/3's HPACK analogue); a new codec beside
   the existing `hpack.*`.
4. **Dispatch** — decode the request, then call **the same App request handler**
   the H1/H2 path uses (`CoroHttpRequest` → `set_handler` coroutine →
   `CoroHttpResponse`). Router + middleware are reused unchanged.
5. **Register** — `register_http3(registry)` (already wired); `App::Config`
   `enable_http3` is the runtime switch.

### WebRTC

1. **Signaling** (`ISignaling`) — SDP offer/answer + trickle ICE over the
   **existing** H1/H2/WebSocket App routes (e.g. `POST /webrtc/offer`). No new
   core: signaling is an App handler that forwards into `WebRtcProtocol`.
2. **Transport** — media/data path over `UdpTransport` (`Datagram`).
3. **Connectivity** — ICE → DTLS handshake (reuse OpenSSL) → SCTP association.
4. **Data channels** (`IDataChannel`) — SCTP-over-DTLS-over-UDP; each channel a
   labelled bidirectional message stream surfaced to the App.

### Bolt pieces earmarked for packet handling (comments only today)

* **`bolt::wire`** (`extern/bolt/include/bolt/wire/bolt_wire.h`) — zero-copy
  packet header framing/parsing for QUIC/HTTP3 and DTLS/SCTP/data-channel frames.
* **Bolt SPSC** (`bolt_channel.h` / `bolt_disruptor.h`) — lock-free
  I/O-thread → protocol-worker datagram handoff (TigerStyle: preallocated, no
  per-packet malloc).

---

## TODOs for the real implementation

- [ ] `UdpTransport`: real UDP bind + `IODispatcher` integration + batched
      receive into a preallocated buffer pool (currently NotImplemented stub).
- [ ] HTTP/3: QUIC stack, QPACK codec, QUIC-stream → `CoroHttpRequest` bridge.
- [ ] WebRTC: ICE / DTLS / SCTP, `ISignaling` wired to an App route,
      `IDataChannel` implementation.
- [ ] Decide whether `IProtocol::serve` should expose a coroutine-shaped surface
      once the real impls spawn on the worker pool (kept synchronous-shaped in
      the scaffold to avoid leaking engine internals into the contract).
- [ ] Wire the Bolt `wire`/SPSC pieces (earmarked above) into the datagram path.
