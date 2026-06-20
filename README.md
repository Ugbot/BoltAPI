# Bolt API

[![ci](https://github.com/Ugbot/BoltAPI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Ugbot/BoltAPI/actions/workflows/ci.yml)
[![linux-docker](https://github.com/Ugbot/BoltAPI/actions/workflows/linux-docker.yml/badge.svg?branch=main)](https://github.com/Ugbot/BoltAPI/actions/workflows/linux-docker.yml)

A high-performance, **complete** C++20 web framework — HTTP/1.1, HTTP/2, **HTTP/3
(QUIC)**, WebSocket, Server-Sent Events, and **WebRTC (data + audio + video)** —
behind one ergonomic, FastAPI-style facade.

Bolt API hard-forks FasterAPI's proven coroutine HTTP engine and re-homes its hot
paths onto [Bolt](https://github.com/Ugbot/bolt), a zero-allocation, branch-free
compute library (Swiss-table routing, arenas, ring buffers, `fionn` JSON). The
goal is the *fastest complete* implementation of the web protocols, engineered in
[Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md):
assert everywhere, bounded/static allocation, no hidden control flow.

```cpp
#include <boltapi/app.h>

int main() {
    bolt::api::App app;

    app.get("/health", [](auto& req, auto& res) { res.ok().text("up"); })
       .get("/users/:id", [](auto& req, auto& res) {
            res.ok().json("{\"id\":\"" + req.path_param("id") + "\"}");
       })
       .post("/echo", [](auto& req, auto& res) {
            auto doc = req.json();                       // Bolt fionn parser
            if (!doc.ok()) { res.bad_request().text("bad json"); return; }
            res.created().json(req.body());
       });

    return app.run("0.0.0.0", 8080);   // blocking
}
```

## Protocols & features

| Capability | Status | Notes |
|---|---|---|
| HTTP/1.1 | ✅ | keep-alive, chunked, zero-copy request views |
| HTTP/2 | ✅ | over TLS/ALPN; own HPACK + frame/stream layer (no nghttp2) |
| **HTTP/3 / QUIC** | ✅ | RFC 9000/9001/9002/9114, QPACK; **interop-proven vs aioquic** |
| WebSocket | ✅ | RFC 6455 upgrade + framing, through the same `App` |
| Server-Sent Events | ✅ | coroutine `SSEWriter` |
| **WebRTC — data** | ✅ | ICE-lite + **full ICE/TURN/trickle**, DTLS, Bolt-native SCTP/DCEP; **aiortc-proven** (incl. 64 KiB binary) |
| **WebRTC — audio/video** | ✅ | SRTP, RTP/RTCP, media SDP, interceptors (NACK/RTX/TWCC/FEC), echo/relay; **aiortc media-proven** |
| Dictionary router | ✅ | interned segments + `bolt::SwissTable` static lookup + param/wildcard trie |
| Middleware | ✅ | chained onion, sync + `co_await` async |
| JSON | ✅ | Bolt **fionn** (`req.json()` / `res.json()`); no simdjson |
| TLS | ✅ | OpenSSL 3.x; ALPN negotiation |
| gzip / CORS | ✅ | opt-in middleware |
| Static files | ✅ | dev/demo helper with traversal guard |

Crypto (OpenSSL) is the only non-Bolt runtime dependency.

## Build

Requires CMake ≥ 3.21, a C++20 compiler, OpenSSL 3.x, and the Bolt submodule.
**Windows uses MSVC / clang-cl — never MinGW.**

```sh
git clone --recursive <repo>     # or: git submodule update --init --recursive
```

**Windows (MSVC):**
```sh
cmake --preset msvc
cmake --build build/msvc --config Release
ctest --test-dir build/msvc -C Release
```

**Linux / macOS:**
```sh
cmake --preset release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
```

### Build options
| Option | Default | Effect |
|---|---|---|
| `BOLTAPI_WITH_HTTP3` | OFF | compile + serve HTTP/3 (`App::enable_http3`) |
| `BOLTAPI_WITH_WEBRTC` | OFF | compile + serve WebRTC (`App::enable_webrtc`) |
| `BOLTAPI_BUILD_EXAMPLES` | ON (top-level) | build `examples/` |
| `BOLTAPI_BUILD_BENCHMARKS` | OFF | build `benchmarks/` (not in ctest) |

The QUIC/WebRTC *codecs* always compile (and are unit-tested in the default
suite); the flags gate the parts of `App` that bind UDP sockets and serve.

```sh
# everything on:
cmake --preset msvc -DBOLTAPI_WITH_HTTP3=ON -DBOLTAPI_WITH_WEBRTC=ON
```

## Use it in your project

Header root is `<boltapi/...>`; link the `boltapi::boltapi` target.

```cmake
add_subdirectory(extern/BoltAPI)
target_link_libraries(your_app PRIVATE boltapi::boltapi)
```

## API at a glance

```cpp
bolt::api::App app;

// Routing — every verb, sync or async (co_await):
app.get ("/p/:id", handler);                 // path param  -> req.path_param("id")
app.post_async("/x", [](auto& q, auto& s) -> bolt::api::core::coro_task<void> {
    co_await something();  s.ok();  co_return;
});

// Request:   req.method() req.path() req.query_param("q") req.body() req.json()
//            req.header("X") req.path_param("id")
// Response:  res.status(201).content_type("...").header("k","v")
//            .json(s) / .text(s) / .html(s) / .send(s)
//            shortcuts: res.ok() created() bad_request() not_found() ...

app.use([](auto& req, auto& res, auto next){ next(); });   // middleware (onion)
app.websocket("/ws", [](auto& ws){ ws.on_text_message = [&](auto& m){ ws.send_text(m);} ; });
app.sse_coro("/events", sse_handler);
app.static_files("/", "public");

app.enable_http3(8080);                       // needs BOLTAPI_WITH_HTTP3
app.enable_webrtc().enable_media_echo();      // needs BOLTAPI_WITH_WEBRTC
app.on_data_channel("chat", dc_echo);
app.on_track(rtp_handler);

app.run("0.0.0.0", 8080);                     // or start_background(...) / stop()
```

## Examples

In [`examples/`](examples/) (built when `BOLTAPI_BUILD_EXAMPLES=ON`):

| Example | What it shows |
|---|---|
| `rest_api.cpp` | **start here** — routing, path/query params, JSON, middleware, multiple verbs |
| `hello.cpp` | version + Bolt integration smoke |
| `ws_echo.cpp` | WebSocket echo |
| `sse_stream.cpp` | coroutine Server-Sent Events |
| `http3_server.cpp` | HTTP/1.1 + HTTP/2 + HTTP/3 on one app (Alt-Svc upgrade) |
| `webrtc_echo.cpp` | WebRTC data-channel echo |
| `demo_server.cpp` | the works: HTTP + WS + SSE + WebRTC data **and** audio/video echo |

See [`examples/README.md`](examples/README.md) for run/test commands.

## Architecture

```
include/boltapi/
  app.h request.h response.h router.h middleware.h json.h   # facade
  core/  net/  http/  server/    # forked coroutine engine (IODispatcher, workers)
  quic/  http3/                  # QUIC + HTTP/3 (RFC 9000/9001/9002/9114, QPACK)
  webrtc/                        # stun ice dtls sctp srtp rtp rtcp sdp turn ...
extern/bolt/                     # Bolt submodule (Arena, SwissTable, fionn, ...)
```

One `App::run` builds the router once, then a single coroutine dispatches each
request — H1, H2, and H3 all flow through the **same** router + middleware +
handler path.

## Status

Feature-complete across HTTP/1.1–3 and WebRTC (data + audio + video), with
RFC-vector unit gates and live interop gates (aioquic for HTTP/3, aiortc for
WebRTC). Current suite: **238/238** green on MSVC (default build; 1 expected aiortc-interop skip under `BOLTAPI_WITH_WEBRTC=OFF`). Roadmap and decisions live in
[`PROJECT_MAP.md`](PROJECT_MAP.md) and [`docs/`](docs/).

## Documentation
- [`docs/README.md`](docs/README.md) — documentation index
- [`docs/JSON.md`](docs/JSON.md) · [`docs/COMPRESSION.md`](docs/COMPRESSION.md) · [`docs/SEAMS.md`](docs/SEAMS.md) · [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- HTTP/3: [`docs/HTTP3_PLAN.md`](docs/HTTP3_PLAN.md) · WebRTC: [`docs/WEBRTC_PLAN.md`](docs/WEBRTC_PLAN.md) / [`docs/WEBRTC_MEDIA_PLAN.md`](docs/WEBRTC_MEDIA_PLAN.md)

## License
See `LICENSE` (TBD).
