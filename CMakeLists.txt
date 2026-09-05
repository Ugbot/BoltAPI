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

# Declared HERE, with the other options, NOT next to the install block at the
# bottom of this file. bolt hit exactly that ordering bug: BOLT_INSTALL was
# declared beside its install rules, ~400 lines after the subdirectory that
# gated a header install on it, so the header shipped missing while the target
# exported fine. Nothing in boltapi reads BOLTAPI_INSTALL early today — but a
# tests/ or examples/ subdirectory that grows an install rule would, and by
# then the bug is silent. Keep option declarations in one block at the top.
option(BOLTAPI_INSTALL "Generate install/export rules for boltapi" ${BOLTAPI_IS_TOPLEVEL})
if(SKBUILD)
    # scikit-build packages whatever cmake-install produces; static archives
    # have no business inside a Python wheel.
    set(BOLTAPI_INSTALL OFF)
endif()

# Feature toggles. Every one of these is READ somewhere below — a declared knob
# that does nothing is worse than no knob, because it tells a consumer a
# capability is configurable when it is not.
option(BOLTAPI_WITH_GZIP    "gzip response compression (zlib stopgap)" ON)
option(BOLTAPI_WITH_HTTP3   "Enable HTTP/3 seam (scaffold)"     OFF)
option(BOLTAPI_WITH_WEBRTC  "Enable WebRTC seam (scaffold)"     OFF)
# Neo4j's CLIENT WIRE PROTOCOL (raw TCP + PackStream). Unrelated to extern/bolt,
# our columnar core -- the two just share a word. OPTIONAL and default OFF: a
# default configure compiles no Neo4j-Bolt TU and pays nothing.
option(BOLTAPI_WITH_NEO4J_BOLT "Enable the Neo4j Bolt client wire protocol" OFF)
option(BOLTAPI_USE_BOLT_ARENA "Use bolt::Arena for request buffers" OFF) # risk-gated

# DELETED (2026-08-17), all four were declared and then never referenced again
# anywhere in this repo — verified by grep across CMake, C++ and headers:
#
#   BOLTAPI_WITH_BROTLI / BOLTAPI_WITH_ZSTD  no brotli/zstd codec exists.
#       src/compression.cpp implements gzip only (see docs/COMPRESSION.md).
#       Setting either did nothing; the response was still identity or gzip.
#   BOLTAPI_WITH_JSON  "Enable simdjson JSON parsing" — simdjson is BANNED by
#       this repo's dependency policy (JSON is bolt::parse / fionn, see
#       docs/JSON.md). The option could never do anything but mislead.
#   BOLTAPI_ENABLE_TLS  inert. `find_package(OpenSSL REQUIRED)` below is
#       UNCONDITIONAL and boltapi links OpenSSL::SSL + OpenSSL::Crypto
#       unconditionally, because the engine needs libcrypto even for cleartext
#       (WebSocket accept-key SHA-1, HTTP/2, DTLS/SRTP, QUIC). Gating the find
#       on the option would not build — so the option is removed and the truth
#       documented: TLS is not optional in boltapi, OpenSSL 3.x is a hard
#       dependency, and boltapi-config.cmake find_dependency()s it accordingly.
#
# Passing -DBOLTAPI_ENABLE_TLS=ON (etc.) still configures; CMake merely notes
# the variable was unused. No consumer in this family sets any of them.

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(BoltApiCompileOptions)
include(BoltApiSanitizers)   # option(BOLTAPI_SANITIZE) + boltapi_apply_sanitizers()

# ---------------------------------------------------------------------------
# Bolt submodule (zero-dependency compute core). Build only what we link.
# ---------------------------------------------------------------------------
# THREE ways bolt can arrive, tried in this order. Every branch announces
# itself, because "which bolt am I linking" is the first question when a build
# misbehaves and it used to be unanswerable from the log.
#
#   1. Already defined  — a superproject (Gestalt2) added bolt before us and
#      shares ONE bolt::bolt across every consumer. See Gestalt2/README.md.
#   2. find_package     — an INSTALLED bolt (cmake --install + CMAKE_PREFIX_PATH).
#      This branch did not exist before; without it, a boltapi checkout whose
#      nested extern/bolt is deliberately empty (which is exactly the state
#      under the shared-bolt rule) could not configure standalone AT ALL — the
#      EXISTS check below fired a FATAL_ERROR telling you to init a submodule
#      the superproject intends to stay empty.
#   3. Vendored submodule — a plain standalone clone with the submodule inited.
if(TARGET bolt::bolt)
    message(STATUS "boltapi: bolt supplied by the enclosing project (shared target)")
else()
    find_package(bolt QUIET)
    if(bolt_FOUND)
        message(STATUS "boltapi: bolt found as an installed package (${bolt_DIR})")
    elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/bolt/CMakeLists.txt)
        message(STATUS "boltapi: building the vendored extern/bolt submodule")
        set(BOLT_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
        set(BOLT_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
        set(BOLT_BUILD_IO         OFF CACHE BOOL "" FORCE)
        # bolt::parse hosts fionn — Bolt's skip-aware JSON parser. It is the canonical
        # JSON path for Bolt API (include/boltapi/json.h wraps it). See docs/JSON.md.
        set(BOLT_BUILD_PARSE      ON  CACHE BOOL "" FORCE)
        set(BOLT_BUILD_INGEST     OFF CACHE BOOL "" FORCE)
        # The reactor (event loop + async I/O) now lives in bolt::reactor (STATION-78).
        set(BOLT_BUILD_REACTOR    ON  CACHE BOOL "" FORCE)
        add_subdirectory(extern/bolt EXCLUDE_FROM_ALL)
    else()
        message(FATAL_ERROR
            "boltapi: no bolt found. Either\n"
            "  (a) install bolt and point at it:\n"
            "        cmake -S <bolt> -B b -DBOLT_BUILD_PARSE=ON -DBOLT_BUILD_REACTOR=ON\n"
            "        cmake --build b && cmake --install b --prefix <pfx>\n"
            "        cmake -S . -B build -DCMAKE_PREFIX_PATH=<pfx>\n"
            "  or (b) vendor it:\n"
            "        git submodule update --init --recursive")
    endif()
endif()

# boltapi needs MORE than bolt::bolt: bolt::parse (fionn, the JSON path) and
# bolt::reactor (the async event loop + I/O, hoisted out of boltapi by
# STATION-78) are both hard link deps further down.
#
# On the vendored branch above we FORCE those bolt options ON, so they are
# guaranteed. On the other two branches we do not control how bolt was built —
# the superproject may have left BOLT_BUILD_REACTOR at its default (OFF for a
# non-top-level bolt), and an installed bolt may simply not carry the targets.
# Both cases previously surfaced ~150 lines later as `Target "boltapi" links to
# target "bolt::reactor" but the target was not found`, which does not say what
# to turn on. Ask here, name the flag.
set(_boltapi_missing_bolt "")
foreach(_boltapi_req IN ITEMS bolt::bolt bolt::parse bolt::reactor)
    if(NOT TARGET ${_boltapi_req})
        list(APPEND _boltapi_missing_bolt ${_boltapi_req})
    endif()
endforeach()
if(_boltapi_missing_bolt)
    string(REPLACE ";" ", " _boltapi_missing_str "${_boltapi_missing_bolt}")
    message(FATAL_ERROR
        "boltapi: the bolt in use is missing: ${_boltapi_missing_str}.\n"
        "boltapi requires bolt::parse (fionn JSON, include/boltapi/json.h) and "
        "bolt::reactor (async event loop + I/O, STATION-78).\n"
        "Rebuild/reinstall bolt with -DBOLT_BUILD_PARSE=ON -DBOLT_BUILD_REACTOR=ON, "
        "or — if a superproject supplies bolt — set those two CACHE variables "
        "before it calls add_subdirectory(bolt).")
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
    # The reactor — async_io / event_loop / io_dispatcher / coro_tcp_listener /
    # tcp_socket / worker_pool / logger (+ per-OS backends) — was hoisted into
    # bolt::reactor (STATION-78); boltapi links it below. TLS + HTTP stay here.
    # net (portable, non-reactor)
    src/net/coro_tls_socket.cpp
    src/net/tcp_listener.cpp
    src/net/tls_cert_generator.cpp
    src/net/tls_context.cpp
    src/net/tls_socket.cpp
    # http
    src/http/client.cpp     # Gateway Phase 0: outbound HTTP/1.1 client (upstream forwarding)
    src/http/tls_client.cpp # Synchronous TLS+HTTP/1.1 outbound (OIDC discovery / JWKS / token)
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

# Per-OS async I/O + event loop backends (IOCP / epoll+io_uring / kqueue) now
# live in bolt::reactor (STATION-78), gated there behind the same OS switch.

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
    # auth toolkit (boltapi::auth submodule — reusable enterprise primitives;
    # OpenSSL-EVP-backed, exception-free, allocation-bounded). One library;
    # consumers get them by linking boltapi::boltapi.
    src/auth/totp.cpp
    src/auth/signed_token.cpp
    src/auth/password_policy.cpp
    src/auth/ratelimit_key.cpp
    src/auth/scim.cpp
    src/auth/smtp_client.cpp
    src/auth/mtls_identity.cpp
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
target_link_libraries(boltapi PUBLIC bolt::bolt bolt::parse bolt::reactor OpenSSL::SSL OpenSSL::Crypto)
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
# Neo4j Bolt client wire protocol (EXTENSION protocol, same recipe as above).
#
# Raw TCP with its own 20-byte handshake and 2-byte chunk framing, so it does
# NOT ride the HTTP router -- it plugs in as an IProtocol via ProtocolRegistry.
# The define is PUBLIC so proto/neo4j_bolt.h consumers and tests compile against
# the same flag value the library was built with.
# ---------------------------------------------------------------------------
if(BOLTAPI_WITH_NEO4J_BOLT)
    target_sources(boltapi PRIVATE
        src/proto/neo4j_bolt_packstream.cpp
        src/proto/neo4j_bolt_server.cpp)
    target_compile_definitions(boltapi PUBLIC BOLTAPI_WITH_NEO4J_BOLT=1)
    message(STATUS "Bolt API Neo4j-Bolt wire protocol: ENABLED (PackStream v2, Bolt 4.4 + 5.0-5.4)")
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

# ---------------------------------------------------------------------------
# Install + export
#
# Gated on BOLTAPI_INSTALL (declared at the TOP of this file). These rules did
# not exist at all before: `$<INSTALL_INTERFACE:include>` appeared on both
# library targets, promising an installed layout that nothing implemented, and
# there was no install(), no export(), and no package config file — so
# `find_package(boltapi)` could never succeed and boltapi was consumable only
# by add_subdirectory.
#
# Gated rather than unconditional for the same two reasons bolt is: an embedded
# build acquires install rules it never asked for, and under scikit-build's
# cmake-install packaging the static archive lands inside a Python wheel.
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(BOLTAPI_INSTALL)

install(DIRECTORY include/boltapi
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ONE VOCABULARY. Without EXPORT_NAME, `install(EXPORT ... NAMESPACE boltapi::)`
# exports boltapi::boltapi_headers, while add_subdirectory gives
# boltapi::headers. Only boltapi::boltapi coincides. A consumer written against
# one resolution mode would then fail to configure against the other — the exact
# silent trap this reform exists to remove. The EXPORT_NAME below is derived the
# same way the in-tree aliases are: `boltapi::` + the target name with its
# `boltapi_` prefix stripped (boltapi -> boltapi, boltapi_headers -> headers),
# which is verified for both aliases in this file.
foreach(_boltapi_t IN ITEMS boltapi boltapi_headers)
    string(REGEX REPLACE "^boltapi_" "" _boltapi_export_name "${_boltapi_t}")
    set_target_properties(${_boltapi_t} PROPERTIES EXPORT_NAME ${_boltapi_export_name})
endforeach()

install(TARGETS boltapi boltapi_headers
    EXPORT boltapi-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(EXPORT boltapi-targets
    FILE      boltapi-targets.cmake
    NAMESPACE boltapi::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boltapi
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/boltapi-config-version.cmake
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/boltapi-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/boltapi-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boltapi
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/boltapi-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/boltapi-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boltapi
)

# An installed boltapi's exported interface names bolt::bolt / bolt::parse /
# bolt::reactor, so a consumer needs bolt to be an installed PACKAGE. If this
# boltapi was built against a bolt that arrived via add_subdirectory (the
# superproject or the vendored submodule), those targets exist in this build
# tree but there is no bolt-config.cmake for the consumer to find, and
# `find_package(boltapi)` fails on undefined imported targets. That is invisible
# until someone unpacks the install elsewhere, so say it at the moment the
# package is about to be produced.
if(NOT bolt_FOUND)
    message(WARNING
        "boltapi: BOLTAPI_INSTALL is ON but bolt was NOT resolved via "
        "find_package, so no installed bolt package is guaranteed to exist. "
        "boltapi-config.cmake calls find_dependency(bolt) and the consumer's "
        "configure will fail unless a matching bolt is installed and on "
        "CMAKE_PREFIX_PATH. Install bolt first and reconfigure boltapi with "
        "-DCMAKE_PREFIX_PATH=<bolt-prefix> for a distributable package.")
endif()

endif()  # BOLTAPI_INSTALL

message(STATUS "Bolt API ${PROJECT_VERSION}: tests=${BOLTAPI_BUILD_TESTS} examples=${BOLTAPI_BUILD_EXAMPLES} benchmarks=${BOLTAPI_BUILD_BENCHMARKS} sanitize=${BOLTAPI_SANITIZE} install=${BOLTAPI_INSTALL} gzip=${BOLTAPI_HAVE_GZIP} http3=${BOLTAPI_WITH_HTTP3} webrtc=${BOLTAPI_WITH_WEBRTC} neo4j_bolt=${BOLTAPI_WITH_NEO4J_BOLT}")
