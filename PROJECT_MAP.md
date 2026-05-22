# Bolt API — Project Map

> What exists and its status. Update as we go. Full plan:
> `~/.claude/plans/compiled-booping-pony.md`. Origin audit: `C:\code\FasterAPI\FASTERAPI_AUDIT.md`.

Legend: ✅ done · 🚧 in progress · ⬜ planned

## Milestones
- ✅ **M0** — repo skeleton + Bolt submodule + build (builds + tests pass on MSVC; CI workflow added)
- 🚧 **M1** — HTTP/1.1 + TLS + Bolt-native router + chained middleware + Bolt primitives (App facade + Request/Response + middleware onion + dispatch bridge DONE, 24/24 ctest green; remaining: Bolt primitives wired Arena/SPSC/swiss/topology)
- ⬜ **M2** — HTTP/2(ALPN) + compression + CORS + coroutine SSE + WebSocket
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
| HTTP/1.1 + parser + connection | ✅ | forked; http1_parser/http1_connection in `boltapi` lib |
| TLS/ALPN | ✅ | OpenSSL 3.6.1 linked (OpenSSL::SSL/Crypto); BOLTAPI_ENABLE_TLS default ON |
| HTTP/2 (frames/hpack/streams) | ✅ | forked custom impl (no nghttp2); frame/hpack/huffman/stream/connection compiled |
| Windows portability shim | ✅ | include/boltapi/net/sys_compat.h: winsock close/recv/send/set_nonblocking, WSAStartup, ssize_t, time/byteorder shims, windows.h macro undefs |
| Compression / CORS | ⬜ | gzip + optional br/zstd |
| Coroutine SSE / WebSocket | ⬜ | forked |
| HTTP/3 + WebRTC seams | ⬜ | protocol.h/transport.h registry, stubs |
| Bolt primitives wired (Arena/SPSC/swiss/topology) | ⬜ | from the start in M1 |

## Toolchain
- C++20; Windows = **MSVC / clang-cl, never MinGW**; Linux/macOS = gcc/clang.
- Deps: OpenSSL, zlib (+ optional brotli/zstd) via find_package/vcpkg. No CPM/coroio/Python.
