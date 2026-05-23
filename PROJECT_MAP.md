# Bolt API — Project Map

> What exists and its status. Update as we go. Full plan:
> `~/.claude/plans/compiled-booping-pony.md`. Origin audit: `C:\code\FasterAPI\FASTERAPI_AUDIT.md`.

Legend: ✅ done · 🚧 in progress · ⬜ planned

> **Direction (set 2026-05-23):** goal = the **fastest COMPLETE implementation of all web protocols**. The engine is **not sacred** — refactor `coro_unified_server`/`IODispatcher`/`async_io` when it makes the whole faster/cleaner (correctness-gated, green increments). Near-term consequence: the WebRTC/HTTP3 `UdpTransport` runs on its own rx thread for now (correctness-first); the perf phase should integrate UDP into the unified event loop and unify dispatch via `ProtocolRegistry`.

## Milestones
- ✅ **M0** — repo skeleton + Bolt submodule + build
- ✅ **M1** — HTTP/1.1 + TLS + Bolt-native router + chained middleware + Bolt primitives (App facade, Request/Response, middleware onion, dispatch bridge; router fan-out OOB fixed via SwissTable edges; body Arena gated `BOLTAPI_USE_BOLT_ARENA`; dead ring_buffer/coro_resumer removed)
- ✅ **M2** — HTTP/2(ALPN) + compression seam (gzip/zlib-stopgap) + CORS + coroutine SSE + WebSocket (all verified e2e through App)
- ✅ **M3** — HTTP/3 + WebRTC seams scaffolded (ITransport/IProtocol/ProtocolRegistry; stubs gated; H1/H2 untouched; docs/SEAMS.md)
- 🚧 **M4** — hardening, benchmarks, docs (hardening tests + sanitizers + benches + CI legs landed; remote push pending)
- ✅ **JSON** — Bolt **fionn** (`bolt::parse`) wired as the canonical parser; `Request::json()`; no simdjson. docs/JSON.md
- 🚧 **HTTP/3 (full)** — plan in docs/HTTP3_PLAN.md; not started (mostly port: FasterAPI QUIC TLS/packet-protection/QPACK are real)
- 🚧 **WebRTC (full)** — plan in docs/WEBRTC_PLAN.md. Wave 1: SDP + STUN codecs (RFC 5769 gated). Wave 2: UdpTransport + ICE-lite (live STUN binding over the wire ✅). Next: DTLS, then SCTP/DCEP data channels.
- ⬜ later — Gestalt migration

Current suite: **103/103 ctest green on MSVC** (default build).

## Layout (current)
```
CMakeLists.txt              # root build: links bolt::bolt, builds boltapi static lib
CMakePresets.json          # msvc (VS2022) / ninja-msvc / release / debug
cmake/BoltApiCompileOptions.cmake   # boltapi_apply_hardening (TigerStyle flags)
cmake/BoltApiGTest.cmake            # GTest find/FetchContent + boltapi_add_test() helper
cmake/BoltApiSanitizers.cmake       # option(BOLTAPI_SANITIZE) + boltapi_apply_sanitizers()
benchmarks/                # router_bench + throughput_bench (BOLTAPI_BUILD_BENCHMARKS; not ctest)
docs/BENCHMARKS.md         # measured router ns/op + speedup, throughput req/s
extern/bolt/               # git submodule -> github.com/Ugbot/bolt
include/boltapi/
  boltapi.h                # umbrella
  version.h                # version + bolt_integration_ok()
src/version.cpp            # version + Bolt smoke (Arena + popcount)
examples/hello.cpp         # prints version, checks bolt integration
tests/                     # smoke_test; gtest harness staged (see below)
  util/http_fuzz.h         # seeded HTTP/1.1 fuzz request generator (header-only, std-only)
  util_fuzz_test.cpp       # gtest for http_fuzz (determinism/bounds/well-formedness)
tools/fuzz_check/          # throwaway standalone validation of the fuzz util (not in root build)
```

## Components (planned — populated as milestones land)
| Area | Status | Notes |
|---|---|---|
| Build skeleton + Bolt submodule | ✅ | M0 — MSVC build green, smoke test passes |
| `bolt::api::App` facade | ✅ | M1 — `include/boltapi/app.h` + `src/app.cpp`. Sync get/post/put/del/patch/head/options + async *_async incl. head_async; use()/use_async(); websocket()/sse_coro() forward to engine; run()/start_background()/stop()/is_running(). Dispatch bridge: Router.build() once, single set_handler() does method_from->match->Request/Response->middleware chain->handler, 404 on miss. Built-in CORS middleware inserted first when enable_cors. |
| `bolt::api::Request`/`Response` | ✅ | M1 — `include/boltapi/request.h` (zero-copy view: method/path/query/path_param/header CI/client_ip) + `include/boltapi/response.h` (fluent status/content_type/header/send/json/text/html/body + ok()/created()/.../internal_error()). |
| Bolt-native router (dictionary + SwissTable) | ✅ | flagship fast path — `include/boltapi/router.h` + `src/router.cpp`; static via SwissTable (`swiss_mix`), param/wildcard via flat trie w/ DictionaryPool-interned segments; integrated into `boltapi` lib; router test green in suite |
| Test infrastructure (gtest + http fuzz) | ✅ | `cmake/BoltApiGTest.cmake` (`boltapi_add_test`) + `tests/util/http_fuzz.h` seeded request generator. M1 adds `tests/app_integration_test.cpp` (real App on ephemeral port, raw client socket, multi-route/multi-verb + http_fuzz) and `tests/middleware_test.cpp` (chain order, 401 short-circuit, sync+async mix). 24/24 ctest green on MSVC. |
| Coroutine middleware onion | ✅ | M1 — `include/boltapi/middleware.h`. AsyncMiddleware(Request&,Response&,Next) + sync Middleware auto-wrapped via to_async(); App folds right-to-left, terminal = matched handler; not calling next() short-circuits. Per-request std::function alloc TODO noted (arena-backed continuation = M-series perf pass). |
| Engine hard-fork (CoroUnifiedServer + core/net/http/server) | ✅ | forked into include/boltapi/{core,net,http,server} + src/*; builds+links on MSVC; e2e round-trips GET+POST on cleartext HTTP/1.1 (tests/engine_e2e_test.cpp) |
| Zero-copy CoroHttpRequest (M4 perf) | ✅ | `CoroHttpRequest` is now view-based: method/path/body = `std::string_view`, headers = bounded `CoroHttpHeaderView[MAX_HEADERS=64]` + count (no `unordered_map`, no per-field `std::string`). H1 views point into the connection read buffer (alive across the worker-thread handler hop + keep-alive; reset only after response written). H2 keeps an owned `std::deque<std::string>` backing store (stable addrs) and points views at it. `Request::header()` CI lookup = linear scan; added `header_view()`/`header_name()`/`header_value()`/`header_count()`. Measured MSVC Release: GET +13% req/s (51.9k→58.8k), POST 32KiB echo +15% req/s (29.2k→33.6k); 45/45 ctest green. |
| Flat CoroHttpResponse headers (M4 perf) | ✅ | Response side mirrors the request side: `CoroHttpResponse.headers` is now `CoroResponseHeaders` (`include/boltapi/http/response_headers.h`) — a flat, bounded, OWNED `Entry{std::string name,value}[MAX_RESPONSE_HEADERS=16]` + count replacing `std::unordered_map<std::string,std::string>` (no per-entry heap node, no hashing, contiguous CI linear scan). Map-compatible surface kept so `Response`/middleware/tests are unchanged: `operator[]` find-or-create (supports `h[k]=v` and `h[k]+=v`), case-insensitive `find()/end()/set()/append()/size()`, range-for over `Entry`. Writers use `set()` (`response.h`, `app.cpp` CORS/compression, engine defaults); serialization loops (`coro_unified_server.cpp`, `http1_connection.cpp`) and H2 `send_response` (`http2_connection.{h,cpp}`) iterate the flat array. Capacity deliberately small (16≈1 KiB inline; 64≈4 KiB measurably regressed GET since the response is move-built per request on the coro frame). Measured MSVC Release (spaced A/B, this box): GET neutral (base 57.9k vs after 58.8k median), POST neutral; KEPT per neutral-or-better rule. 45/45 ctest green. |
| HTTP/1.1 + parser + connection | ✅ | forked; http1_parser/http1_connection in `boltapi` lib |
| TLS/ALPN | ✅ | OpenSSL 3.6.1 linked (OpenSSL::SSL/Crypto); BOLTAPI_ENABLE_TLS default ON |
| HTTP/2 (frames/hpack/streams) | ✅ | forked custom impl (no nghttp2); frame/hpack/huffman/stream/connection compiled |
| Windows portability shim | ✅ | include/boltapi/net/sys_compat.h: winsock close/recv/send/set_nonblocking, WSAStartup, ssize_t, time/byteorder shims, windows.h macro undefs |
| Compression / CORS | 🚧 | M2 — gzip codec seam `include/boltapi/compression.h` + `src/compression.cpp` (Accept-Encoding parser + `gzip_encode`); zlib STOPGAP gated by `BOLTAPI_HAVE_GZIP` (option `BOLTAPI_WITH_GZIP` ON; identity when zlib absent — current state on this box). App appends compression middleware LAST (innermost) when `Config.enable_compression`: gzip iff Accept-Encoding gzip + body>256B + no existing Content-Encoding; sets Content-Encoding/Content-Length/Vary. Dual-mode test `tests/compression_test.cpp`. Docs: `docs/COMPRESSION.md` (Bolt-native-codec TODO). CORS done (M1). br/zstd options off/unwired. |
| Coroutine SSE / WebSocket | ✅ | M2 — verified end-to-end through App. WebSocket: `app.websocket("/ws",...)` echo; engine handles RFC6455 upgrade (101 + Sec-WebSocket-Accept) by path, on_text_message→send_text echoes unmasked frames. SSE: `app.sse_coro("/events",...)` streams via SSEWriter; engine sends text/event-stream headers before handler. Tests: `tests/ws_echo_test.cpp` (handshake+accept-key, masked echo, multi-message, close) + `tests/sse_test.cpp` (content-type + ordered events, bounded reads). Examples: `examples/ws_echo.cpp`, `examples/sse_stream.cpp`. |
| HTTP/3 + WebRTC seams | ✅ | M3 — `include/boltapi/transport.h` (ITransport + Stream/Datagram kind; UdpTransport declared always, impl gated) + `include/boltapi/protocol.h` (IProtocol; bounded array-indexed ProtocolRegistry register/has/create — NOT std::map; ISignaling/IDataChannel sketches; Status=core::result<void> NotImplemented). Stubs `src/proto/{udp_transport,http3_stub,webrtc_stub}.cpp` compiled ONLY under their flags, return NotImplemented, register via register_http3/register_webrtc; pull in NO FasterAPI quic/webrtc code. H1/H2 stay BUILT-IN (engine direct dispatch, ALPN) — registry is the EXTENSION point for H3/WebRTC. App::Config gained enable_http3/http3_port/enable_webrtc (additive); App::init_protocol_seams(): flag OFF=fast no-op, runtime-ON+compile-OFF=stderr warning no-op, both-ON=stub serve() NotImplemented logged, H1/H2 unaffected (never crashes/blocks). `tests/protocol_seam_test.cpp` flag-aware (dummy protocol when stubs absent). CMake compiles stub TUs per-option + PUBLIC BOLTAPI_WITH_* defines; CI `seams-on` leg builds flags-ON. Verified MSVC: default 52/52, flags-ON 54/54. `docs/SEAMS.md`. |
| Bolt primitives wired (Arena/SPSC/swiss/topology) | 🚧 | swiss=router done. **Request-body Arena**: `include/boltapi/http/body_buffer_arena.h` now dual-impl behind `option(BOLTAPI_USE_BOLT_ARENA)` (default OFF=slot-pool unchanged; ON=thread-local `bolt::Arena` bump alloc, Handle=non-owning view, self-guarding per-request `thread_body_arena_reset()` reclaims only when no view is live — safe under any-worker coroutine resumption). Reset wired in `coro_unified_server.cpp` (HTTP/1.1 keep-alive iter end ×2; HTTP/2 conn teardown). 45/45 ctest in BOTH modes on MSVC; ON also exercised under Linux ASan/UBSan CI. Dead `ring_buffer.h`/`coro_resumer.h` (SPSCRingBuffer/CoroResumer) removed — were unreferenced. TODO: Bolt topology/affinity thread pinning in worker_pool (deferred perf pass). |

## Toolchain
- C++20; Windows = **MSVC / clang-cl, never MinGW**; Linux/macOS = gcc/clang.
- Deps: OpenSSL, zlib (+ optional brotli/zstd) via find_package/vcpkg. No CPM/coroio/Python.
