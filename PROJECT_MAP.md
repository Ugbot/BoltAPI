# Bolt API — Project Map

> What exists and its status. Update as we go. Full plan:
> `~/.claude/plans/compiled-booping-pony.md`. Origin audit: `C:\code\FasterAPI\FASTERAPI_AUDIT.md`.

Legend: ✅ done · 🚧 in progress · ⬜ planned

## Milestones
- ✅ **M0** — repo skeleton + Bolt submodule + build (builds + tests pass on MSVC; CI workflow added)
- 🚧 **M1** — HTTP/1.1 + TLS + Bolt-native router + chained middleware + Bolt primitives (App facade + Request/Response + middleware onion + dispatch bridge DONE, 24/24 ctest green; remaining: Bolt primitives wired Arena/SPSC/swiss/topology)
- 🚧 **M2** — HTTP/2(ALPN) + compression + CORS + coroutine SSE + WebSocket (WebSocket echo + coroutine SSE verified end-to-end through App with tests + examples; gzip compression seam landed [zlib stopgap, identity locally]; 45/45 ctest green. Remaining: HTTP/2 ALPN surface)
- ⬜ **M3** — HTTP/3 + WebRTC seams (scaffolded)
- 🚧 **M4** — hardening, benchmarks, docs (benchmarks + zero-alloc/bounded-resource hardening tests + ASan/UBSan option + asan/assertions CI legs landed; 36/36 ctest green on MSVC)
- ⬜ later — Gestalt migration

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
| HTTP/1.1 + parser + connection | ✅ | forked; http1_parser/http1_connection in `boltapi` lib |
| TLS/ALPN | ✅ | OpenSSL 3.6.1 linked (OpenSSL::SSL/Crypto); BOLTAPI_ENABLE_TLS default ON |
| HTTP/2 (frames/hpack/streams) | ✅ | forked custom impl (no nghttp2); frame/hpack/huffman/stream/connection compiled |
| Windows portability shim | ✅ | include/boltapi/net/sys_compat.h: winsock close/recv/send/set_nonblocking, WSAStartup, ssize_t, time/byteorder shims, windows.h macro undefs |
| Compression / CORS | 🚧 | M2 — gzip codec seam `include/boltapi/compression.h` + `src/compression.cpp` (Accept-Encoding parser + `gzip_encode`); zlib STOPGAP gated by `BOLTAPI_HAVE_GZIP` (option `BOLTAPI_WITH_GZIP` ON; identity when zlib absent — current state on this box). App appends compression middleware LAST (innermost) when `Config.enable_compression`: gzip iff Accept-Encoding gzip + body>256B + no existing Content-Encoding; sets Content-Encoding/Content-Length/Vary. Dual-mode test `tests/compression_test.cpp`. Docs: `docs/COMPRESSION.md` (Bolt-native-codec TODO). CORS done (M1). br/zstd options off/unwired. |
| Coroutine SSE / WebSocket | ✅ | M2 — verified end-to-end through App. WebSocket: `app.websocket("/ws",...)` echo; engine handles RFC6455 upgrade (101 + Sec-WebSocket-Accept) by path, on_text_message→send_text echoes unmasked frames. SSE: `app.sse_coro("/events",...)` streams via SSEWriter; engine sends text/event-stream headers before handler. Tests: `tests/ws_echo_test.cpp` (handshake+accept-key, masked echo, multi-message, close) + `tests/sse_test.cpp` (content-type + ordered events, bounded reads). Examples: `examples/ws_echo.cpp`, `examples/sse_stream.cpp`. |
| HTTP/3 + WebRTC seams | ⬜ | protocol.h/transport.h registry, stubs |
| Bolt primitives wired (Arena/SPSC/swiss/topology) | 🚧 | swiss=router done. **Request-body Arena**: `include/boltapi/http/body_buffer_arena.h` now dual-impl behind `option(BOLTAPI_USE_BOLT_ARENA)` (default OFF=slot-pool unchanged; ON=thread-local `bolt::Arena` bump alloc, Handle=non-owning view, self-guarding per-request `thread_body_arena_reset()` reclaims only when no view is live — safe under any-worker coroutine resumption). Reset wired in `coro_unified_server.cpp` (HTTP/1.1 keep-alive iter end ×2; HTTP/2 conn teardown). 45/45 ctest in BOTH modes on MSVC; ON also exercised under Linux ASan/UBSan CI. Dead `ring_buffer.h`/`coro_resumer.h` (SPSCRingBuffer/CoroResumer) removed — were unreferenced. TODO: Bolt topology/affinity thread pinning in worker_pool (deferred perf pass). |

## Toolchain
- C++20; Windows = **MSVC / clang-cl, never MinGW**; Linux/macOS = gcc/clang.
- Deps: OpenSSL, zlib (+ optional brotli/zstd) via find_package/vcpkg. No CPM/coroio/Python.
