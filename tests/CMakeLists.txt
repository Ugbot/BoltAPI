# Bolt API tests. M0 uses a dependency-free smoke test (no gtest yet — gtest is
# wired in at M1 alongside the first real units, mirroring Bolt's BoltGTest.cmake).

add_executable(boltapi_smoke_test smoke_test.cpp)
target_link_libraries(boltapi_smoke_test PRIVATE boltapi::boltapi)
boltapi_apply_hardening(boltapi_smoke_test)
boltapi_apply_sanitizers(boltapi_smoke_test)
add_test(NAME boltapi_smoke COMMAND boltapi_smoke_test)

# Bolt-native router unit test (plain main(), no gtest).
add_executable(boltapi_router_test router_test.cpp)
target_link_libraries(boltapi_router_test PRIVATE boltapi::boltapi)
boltapi_apply_hardening(boltapi_router_test)
boltapi_apply_sanitizers(boltapi_router_test)
add_test(NAME boltapi_router COMMAND boltapi_router_test)

# gtest-based units (http_fuzz generator). Uses boltapi_add_test() from BoltApiGTest.
boltapi_add_test(boltapi_util_fuzz_test util_fuzz_test.cpp)

# Router fan-out regression: >16 distinct sibling literal/param routes (would
# have OOB'd the old fixed [16] per-node child array).
boltapi_add_test(boltapi_router_fanout_test router_fanout_test.cpp)

# M1: App facade integration test — spins a real App on an ephemeral cleartext
# HTTP/1.1 port and drives it with a raw client socket + http_fuzz inputs.
boltapi_add_test(boltapi_app_integration_test app_integration_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_app_integration_test PRIVATE ws2_32 mswsock)
endif()

# M1: middleware onion — chain order, short-circuit (401), sync+async mix.
boltapi_add_test(boltapi_middleware_test middleware_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_middleware_test PRIVATE ws2_32 mswsock)
endif()

# M4 hardening: zero heap allocation across Router::match() and the http1
# parser hot paths (global operator new/delete counter).
boltapi_add_test(boltapi_no_alloc_test no_alloc_test.cpp)

# M4 hardening: bounded resources — App rejects oversized body (413) /
# headers (431), stays responsive after rejects, and Router handles
# over-deep / over-param paths gracefully (no UB).
boltapi_add_test(boltapi_bounded_resource_test bounded_resource_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_bounded_resource_test PRIVATE ws2_32 mswsock)
endif()

# M2: WebSocket echo end-to-end through App — RFC6455 handshake (101 +
# Sec-WebSocket-Accept), masked client text frames echoed back unmasked,
# multiple messages on one connection, and a close frame.
boltapi_add_test(boltapi_ws_echo_test ws_echo_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_ws_echo_test PRIVATE ws2_32 mswsock)
endif()

# M2: coroutine SSE end-to-end through App — text/event-stream content type and
# ordered data:/event: frames parsed off the wire, bounded with a read timeout.
boltapi_add_test(boltapi_sse_test sse_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_sse_test PRIVATE ws2_32 mswsock)
endif()

# M2: response compression — gzip middleware. Passes in BOTH modes: with zlib
# (asserts Content-Encoding: gzip + roundtrip) and without (asserts identity).
boltapi_add_test(boltapi_compression_test compression_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_compression_test PRIVATE ws2_32 mswsock)
endif()

# M3: HTTP/3 + WebRTC seam — ProtocolRegistry mechanism (register/has/create),
# a dummy IProtocol returning NotImplemented, and (when the compile flags are
# ON) the real H3/WebRTC stub factories registering. Flag-AWARE: passes in the
# default flags-OFF build via a dummy protocol; does NOT require the flags on.
boltapi_add_test(boltapi_protocol_seam_test protocol_seam_test.cpp)
