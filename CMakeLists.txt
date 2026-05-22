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
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/bolt/CMakeLists.txt)
    message(FATAL_ERROR
        "extern/bolt is missing. Run: git submodule update --init --recursive")
endif()
set(BOLT_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(BOLT_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(BOLT_BUILD_IO         OFF CACHE BOOL "" FORCE)
set(BOLT_BUILD_PARSE      OFF CACHE BOOL "" FORCE)
set(BOLT_BUILD_INGEST     OFF CACHE BOOL "" FORCE)
add_subdirectory(extern/bolt EXCLUDE_FROM_ALL)

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
    ${BOLTAPI_ENGINE_SOURCES}
)
add_library(boltapi::boltapi ALIAS boltapi)
target_include_directories(boltapi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(boltapi PUBLIC cxx_std_20)
target_link_libraries(boltapi PUBLIC bolt::bolt OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi PUBLIC ws2_32 mswsock)
endif()

# gzip seam: PUBLIC so app.h/compression.h consumers and tests compile against
# the same BOLTAPI_HAVE_GZIP value the library was built with.
target_compile_definitions(boltapi PUBLIC BOLTAPI_HAVE_GZIP=${BOLTAPI_HAVE_GZIP})
if(BOLTAPI_HAVE_GZIP)
    target_link_libraries(boltapi PUBLIC ZLIB::ZLIB)
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
target_link_libraries(boltapi_headers INTERFACE bolt::bolt)

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
