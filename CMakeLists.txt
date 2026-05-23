cmake_minimum_required(VERSION 3.21)

project(boltapi
    VERSION     0.1.0
    DESCRIPTION "High-performance C++ HTTP framework built on Bolt"
    LANGUAGES   CXX
)

# ---------------------------------------------------------------------------
# Top-level detection + options
# ---------------------------------------------------------------------------
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(BOLTAPI_IS_TOPLEVEL ON)
else()
    set(BOLTAPI_IS_TOPLEVEL OFF)
endif()

option(BOLTAPI_BUILD_TESTS      "Build Bolt API tests"      ${BOLTAPI_IS_TOPLEVEL})
option(BOLTAPI_BUILD_EXAMPLES   "Build Bolt API examples"   ${BOLTAPI_IS_TOPLEVEL})
option(BOLTAPI_BUILD_BENCHMARKS "Build Bolt API benchmarks" OFF)
option(BOLTAPI_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# Feature toggles (wired up in later milestones; declared now so the build
# surface is stable). Defaults keep M0 dependency-light.
option(BOLTAPI_ENABLE_TLS   "Enable TLS/HTTPS (needs OpenSSL)" ON)   # M1: forked engine needs OpenSSL
option(BOLTAPI_WITH_GZIP    "gzip response compression (zlib stopgap)" ON)
option(BOLTAPI_WITH_BROTLI  "Enable Brotli compression"        OFF)
option(BOLTAPI_WITH_ZSTD    "Enable zstd compression"          OFF)
option(BOLTAPI_WITH_JSON    "Enable simdjson JSON parsing"      OFF)
option(BOLTAPI_WITH_HTTP3   "Enable HTTP/3 seam (scaffold)"     OFF)
option(BOLTAPI_WITH_WEBRTC  "Enable WebRTC seam (scaffold)"     OFF)
option(BOLTAPI_USE_BOLT_ARENA "Use bolt::Arena for request buffers" OFF) # risk-gated

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(BoltApiCompileOptions)
include(BoltApiSanitizers)   # option(BOLTAPI_SANITIZE) + boltapi_apply_sanitizers()

# ---------------------------------------------------------------------------
# Bolt submodule (zero-dependency compute core). Build only what we link.
# ---------------------------------------------------------------------------
# Gestalt2: share one top-level bolt across all consumers so a single
# bolt::bolt target is defined. Standalone boltapi builds (target absent)
# still vendor extern/bolt. See Gestalt2/README.md.
if(NOT TARGET bolt::bolt)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/bolt/CMakeLists.txt)
        message(FATAL_ERROR
            "extern/bolt is missing. Run: git submodule update --init --recursive")
    endif()
    set(BOLT_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
    set(BOLT_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
    set(BOLT_BUILD_IO         OFF CACHE BOOL "" FORCE)
    # bolt::parse hosts fionn — Bolt's skip-aware JSON parser. It is the canonical
    # JSON path for Bolt API (include/boltapi/json.h wraps it). See docs/JSON.md.
    set(BOLT_BUILD_PARSE      ON  CACHE BOOL "" FORCE)
    set(BOLT_BUILD_INGEST     OFF CACHE BOOL "" FORCE)
    add_subdirectory(extern/bolt EXCLUDE_FROM_ALL)
endif()

# ---------------------------------------------------------------------------
# OpenSSL — required by the forked coroutine HTTP engine (TLS/ALPN, WebSocket
# accept-key SHA-1). M1 flips BOLTAPI_ENABLE_TLS ON; the engine links OpenSSL
# unconditionally because http2/websocket use libcrypto even on cleartext.
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# gzip response compression (M2). STOPGAP per repo deps policy: Bolt has no
# compression codec yet, so we use zlib when present, gated behind
# BOLTAPI_HAVE_GZIP. When BOLTAPI_WITH_GZIP=ON AND ZLIB is found we link it and
# define BOLTAPI_HAVE_GZIP=1; otherwise the codec degrades to graceful identity
# (BOLTAPI_HAVE_GZIP=0). See include/boltapi/compression.h for the Bolt-native
# TODO. The define is applied below on the boltapi target.
# ---------------------------------------------------------------------------
set(BOLTAPI_HAVE_GZIP 0)
if(BOLTAPI_WITH_GZIP)
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        set(BOLTAPI_HAVE_GZIP 1)
        message(STATUS "Bolt API gzip: ENABLED (zlib ${ZLIB_VERSION_STRING} — stopgap; Bolt-native codec TODO)")
    else()
        message(STATUS "Bolt API gzip: DISABLED (zlib not found; identity passthrough)")
    endif()
else()
    message(STATUS "Bolt API gzip: DISABLED (BOLTAPI_WITH_GZIP=OFF; identity passthrough)")
endif()

# ---------------------------------------------------------------------------
# Forked engine source list (hard fork of FasterAPI's CoroUnifiedServer).
# Platform backends are gated so exactly one async_io_* and one event_loop_*
# compile per OS.
# ---------------------------------------------------------------------------
set(BOLTAPI_ENGINE_SOURCES
    # core
    src/core/async_io.cpp
    src/core/logger.cpp
    src/core/worker_pool.cpp
    # net (portable)
    src/net/coro_tcp_listener.cpp
    src/net/coro_tls_socket.cpp
    src/net/event_loop.cpp
    src/net/io_dispatcher.cpp
    src/net/tcp_listener.cpp
    src/net/tcp_socket.cpp
    src/net/tls_cert_generator.cpp
    src/net/tls_context.cpp
    src/net/tls_socket.cpp
    # http
    src/http/client.cpp     # Gateway Phase 0: outbound HTTP/1.1 client (upstream forwarding)
    src/http/h2_server_push.cpp
    src/http/hpack.cpp
    src/http/http1_connection.cpp
    src/http/http1_parser.cpp
    src/http/http2_connection.cpp
    src/http/http2_frame.cpp
    src/http/http2_stream.cpp
    src/http/huffman.cpp
    src/http/huffman_table.cpp
    src/http/huffman_table_data.cpp
    src/http/middleware.cpp
    src/http/request.cpp
    src/http/response.cpp
    src/http/websocket.cpp
    src/http/websocket_parser.cpp
    # server
    src/server/coro_unified_server.cpp
)

# Per-OS async I/O + event loop backends (exactly one each).
if(WIN32)
    list(APPEND BOLTAPI_ENGINE_SOURCES
        src/core/async_io_iocp.cpp
        src/net/event_loop_iocp.cpp
    )
elseif(APPLE)
    list(APPEND BOLTAPI_ENGINE_SOURCES
        src/core/async_io_kqueue.cpp
        src/net/event_loop_kqueue.cpp
    )
elseif(UNIX)
    list(APPEND BOLTAPI_ENGINE_SOURCES
        src/core/async_io_epoll.cpp
        src/core/async_io_uring.cpp   # io_uring (ring-per-thread); falls back to epoll on old kernel / Docker seccomp
        src/net/event_loop_epoll.cpp
    )
endif()

# ---------------------------------------------------------------------------
# boltapi — the library (STATIC; grows as milestones land)
# ---------------------------------------------------------------------------
add_library(boltapi STATIC
    src/version.cpp
    src/router.cpp          # Bolt-native dictionary/SwissTable router
    src/app.cpp             # M1: App facade + dispatch bridge + middleware fold
    src/compression.cpp     # M2: gzip codec seam (zlib stopgap, BOLTAPI_HAVE_GZIP)
    src/json.cpp            # JSON: thin facade over bolt::parse (fionn)
    # WebRTC pure codecs (SDP, STUN). Compiled UNCONDITIONALLY: they have no
    # engine deps and zero runtime cost unless used, so the default test suite
    # covers them. Only protocol/transport WIRING is gated behind BOLTAPI_WITH_WEBRTC.
    src/webrtc/sdp.cpp      # SDP parse/generate (ADAPTED from FasterAPI)
    src/webrtc/stun.cpp     # STUN message codec (REBUILT, RFC 5389/8489)
    # WebRTC connection machinery — also compiled UNCONDITIONALLY (standalone,
    # no engine deps, zero cost unless started) so the default suite covers it.
    src/net/udp_transport.cpp  # real async UDP transport (own socket + rx thread)
    src/webrtc/ice.cpp         # ICE-lite agent (gather + STUN binding responder)
    src/webrtc/ice_full.cpp    # WI: FULL ICE agent (RFC 8445: pairs/checks/roles/trickle/restart)
    src/webrtc/turn.cpp        # WI: TURN client + minimal TURN server (RFC 5766/8656)
    src/webrtc/dtls.cpp        # DTLS server (answerer) over UDP via OpenSSL memory BIOs
    # SCTP / DCEP / data channels — Bolt-native minimal SCTP over DTLS (RFC 4960
    # subset + RFC 8261 framing), DCEP (RFC 8832), and the App-facing channel
    # surface. Compiled UNCONDITIONALLY (no engine deps beyond OpenSSL/DTLS
    # already linked); only the App start wiring stays under BOLTAPI_WITH_WEBRTC.
    src/webrtc/sctp.cpp         # minimal SCTP association (CRC-32c, handshake, DATA/SACK)
    src/webrtc/data_channel.cpp # DCEP + IDataChannel + channel routing
    src/webrtc/peer_hub.cpp     # DTLS<->SCTP bridge + App channel surfacing
    ${BOLTAPI_ENGINE_SOURCES}
)
add_library(boltapi::boltapi ALIAS boltapi)
target_include_directories(boltapi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(boltapi PUBLIC cxx_std_20)
# bolt::parse hosts fionn (the JSON parser); link it explicitly so the json
# facade's TU resolves bolt::parse::json::* even though bolt::bolt also
# transitively re-exports it when BOLT_BUILD_PARSE=ON.
target_link_libraries(boltapi PUBLIC bolt::bolt bolt::parse OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    # ws2_32/mswsock for sockets; iphlpapi for GetAdaptersAddresses (ICE host
    # candidate enumeration in src/webrtc/ice.cpp).
    target_link_libraries(boltapi PUBLIC ws2_32 mswsock iphlpapi)
endif()

# gzip seam: PUBLIC so app.h/compression.h consumers and tests compile against
# the same BOLTAPI_HAVE_GZIP value the library was built with.
target_compile_definitions(boltapi PUBLIC BOLTAPI_HAVE_GZIP=${BOLTAPI_HAVE_GZIP})
if(BOLTAPI_HAVE_GZIP)
    target_link_libraries(boltapi PUBLIC ZLIB::ZLIB)
endif()

# ---------------------------------------------------------------------------
# M3 HTTP/3 + WebRTC extensibility seams (ARCHITECTURE + STUBS ONLY).
#
# include/boltapi/transport.h + protocol.h are ALWAYS available (header-only,
# inert until a factory registers). The seam STUB TUs compile ONLY under their
# options so the default lib (flags OFF) is byte-for-byte unchanged in behavior:
#
#   src/proto/udp_transport.cpp  -> BOLTAPI_WITH_HTTP3 OR BOLTAPI_WITH_WEBRTC
#   src/proto/http3_stub.cpp     -> BOLTAPI_WITH_HTTP3
#   src/proto/webrtc_stub.cpp    -> BOLTAPI_WITH_WEBRTC
#
# The defines are PUBLIC so app.h / protocol.h consumers and tests see the same
# flag values the library was built with (the App seam hook + seam test are
# flag-aware). When ON the stubs return NotImplemented; they pull in NO FasterAPI
# quic/webrtc source.
# ---------------------------------------------------------------------------
if(BOLTAPI_WITH_HTTP3 OR BOLTAPI_WITH_WEBRTC)
    target_sources(boltapi PRIVATE src/proto/udp_transport.cpp)
endif()
if(BOLTAPI_WITH_HTTP3)
    target_sources(boltapi PRIVATE src/proto/http3_stub.cpp)
    target_compile_definitions(boltapi PUBLIC BOLTAPI_WITH_HTTP3=1)
    message(STATUS "Bolt API HTTP/3 seam: ENABLED (scaffold stub — returns NotImplemented)")
endif()
if(BOLTAPI_WITH_WEBRTC)
    target_sources(boltapi PRIVATE src/proto/webrtc_stub.cpp)
    target_compile_definitions(boltapi PUBLIC BOLTAPI_WITH_WEBRTC=1)
    message(STATUS "Bolt API WebRTC seam: ENABLED (scaffold stub — returns NotImplemented)")
endif()

# ---------------------------------------------------------------------------
# Bolt-native request body arena (risk-gated, opt-in). When ON, the request
# body buffer is backed by a thread-local bolt::Arena (bump allocator, reset
# per request) instead of the default slot-pool. PUBLIC so headers compiled in
# tests/examples see the same flag value the library was built with.
# See include/boltapi/http/body_buffer_arena.h.
# ---------------------------------------------------------------------------
if(BOLTAPI_USE_BOLT_ARENA)
    target_compile_definitions(boltapi PUBLIC BOLTAPI_USE_BOLT_ARENA=1)
    message(STATUS "Bolt API body arena: bolt::Arena (BOLTAPI_USE_BOLT_ARENA=ON, opt-in)")
else()
    target_compile_definitions(boltapi PUBLIC BOLTAPI_USE_BOLT_ARENA=0)
    message(STATUS "Bolt API body arena: slot-pool (default; set -DBOLTAPI_USE_BOLT_ARENA=ON for bolt::Arena)")
endif()
boltapi_apply_hardening(boltapi)
boltapi_apply_sanitizers(boltapi)   # no-op unless BOLTAPI_SANITIZE=ON

# Header-only consumption alias (for pieces that are header-only).
add_library(boltapi_headers INTERFACE)
add_library(boltapi::headers ALIAS boltapi_headers)
target_include_directories(boltapi_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
# bolt::parse so header-only consumers that pull in boltapi/json.h (directly or
# via request.h) resolve fionn's parse symbols.
target_link_libraries(boltapi_headers INTERFACE bolt::bolt bolt::parse)

# ---------------------------------------------------------------------------
# Examples / Tests
# ---------------------------------------------------------------------------
if(BOLTAPI_BUILD_EXAMPLES)
    add_executable(boltapi_hello examples/hello.cpp)
    target_link_libraries(boltapi_hello PRIVATE boltapi::boltapi)
    boltapi_apply_hardening(boltapi_hello)

    # M2: WebSocket echo server through the App facade.
    add_executable(boltapi_ws_echo examples/ws_echo.cpp)
    target_link_libraries(boltapi_ws_echo PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_ws_echo PRIVATE ws2_32 mswsock)
    endif()
    boltapi_apply_hardening(boltapi_ws_echo)

    # M2: coroutine SSE stream through the App facade.
    add_executable(boltapi_sse_stream examples/sse_stream.cpp)
    target_link_libraries(boltapi_sse_stream PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_sse_stream PRIVATE ws2_32 mswsock)
    endif()
    boltapi_apply_hardening(boltapi_sse_stream)

    # START HERE: a small REST API (routing, params, JSON, middleware).
    add_executable(boltapi_rest_api examples/rest_api.cpp)
    target_link_libraries(boltapi_rest_api PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_rest_api PRIVATE ws2_32 mswsock)
    endif()
    boltapi_apply_hardening(boltapi_rest_api)

    # HTTP/1.1 + HTTP/3 on one App (QUIC over UDP; serves H3 under WITH_HTTP3).
    add_executable(boltapi_http3_server examples/http3_server.cpp)
    target_link_libraries(boltapi_http3_server PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_http3_server PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    boltapi_apply_hardening(boltapi_http3_server)

    # All-four-protocols demo for the Docker/browser story (H1 + H2 + H3 + WebRTC).
    add_executable(boltapi_docker_demo examples/docker_demo.cpp)
    target_link_libraries(boltapi_docker_demo PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_docker_demo PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    boltapi_apply_hardening(boltapi_docker_demo)

    # WebRTC data-channel echo server (debug/example; meaningful under WEBRTC=ON).
    add_executable(boltapi_webrtc_echo examples/webrtc_echo.cpp)
    target_link_libraries(boltapi_webrtc_echo PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_webrtc_echo PRIVATE ws2_32 mswsock iphlpapi)
    endif()
    boltapi_apply_hardening(boltapi_webrtc_echo)

    # WebRTC interop DEMO server: enable_webrtc + on_data_channel("chat") echo +
    # static_files("/", "testing/web") serving the browser test page + the
    # POST /webrtc/offer signaling route. The harness (browser + aiortc) points
    # at this on :8080. Guarded under BOLTAPI_WITH_WEBRTC so the default build is
    # unaffected.
    if(BOLTAPI_WITH_WEBRTC)
        add_executable(boltapi_demo_server examples/demo_server.cpp)
        target_link_libraries(boltapi_demo_server PRIVATE boltapi::boltapi)
        if(WIN32)
            target_link_libraries(boltapi_demo_server PRIVATE ws2_32 mswsock iphlpapi)
        endif()
        boltapi_apply_hardening(boltapi_demo_server)
    endif()
endif()

if(BOLTAPI_BUILD_TESTS)
    enable_testing()
    include(BoltApiGTest)   # GTest (find_package -> FetchContent v1.15.2) + boltapi_add_test()

    # Engine end-to-end test (plain main(), no gtest): spins up a real
    # CoroUnifiedServer on a cleartext HTTP/1.1 port and round-trips a request.
    add_executable(boltapi_engine_e2e tests/engine_e2e_test.cpp)
    target_link_libraries(boltapi_engine_e2e PRIVATE boltapi::boltapi)
    if(WIN32)
        target_link_libraries(boltapi_engine_e2e PRIVATE ws2_32 mswsock)
    endif()
    boltapi_apply_hardening(boltapi_engine_e2e)
    boltapi_apply_sanitizers(boltapi_engine_e2e)
    add_test(NAME boltapi_engine_e2e COMMAND boltapi_engine_e2e)

    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Benchmarks (hand-rolled std::chrono harness; NOT registered with ctest).
# ---------------------------------------------------------------------------
if(BOLTAPI_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

message(STATUS "Bolt API ${PROJECT_VERSION}: tests=${BOLTAPI_BUILD_TESTS} examples=${BOLTAPI_BUILD_EXAMPLES} benchmarks=${BOLTAPI_BUILD_BENCHMARKS} sanitize=${BOLTAPI_SANITIZE} tls=${BOLTAPI_ENABLE_TLS}")
