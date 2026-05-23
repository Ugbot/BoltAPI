# benchmarks/CMakeLists.txt — hand-rolled std::chrono micro/throughput benches.
#
# Gated by BOLTAPI_BUILD_BENCHMARKS (see root CMakeLists). NOT registered with
# ctest — these are run manually / in a dedicated CI bench leg. No third-party
# benchmark dependency (no google-benchmark); timing is std::chrono.

# Router micro-benchmark: SwissTable/trie router vs linear & unordered_map
# baselines. Pure CPU, no sockets.
add_executable(boltapi_router_bench router_bench.cpp)
target_link_libraries(boltapi_router_bench PRIVATE boltapi::boltapi)
boltapi_apply_hardening(boltapi_router_bench)
boltapi_apply_sanitizers(boltapi_router_bench)

# Throughput benchmark: real App on loopback cleartext HTTP/1.1, keep-alive.
add_executable(boltapi_throughput_bench throughput_bench.cpp)
target_link_libraries(boltapi_throughput_bench PRIVATE boltapi::boltapi)
if(WIN32)
    target_link_libraries(boltapi_throughput_bench PRIVATE ws2_32 mswsock)
endif()
boltapi_apply_hardening(boltapi_throughput_bench)
boltapi_apply_sanitizers(boltapi_throughput_bench)

# Body-path throughput: POSTs a >stack-buffer body to exercise the request-body
# buffer (slot-pool vs bolt::Arena). This is the bench that reveals the
# BOLTAPI_USE_BOLT_ARENA swap's effect.
add_executable(boltapi_body_throughput_bench body_throughput_bench.cpp)
target_link_libraries(boltapi_body_throughput_bench PRIVATE boltapi::boltapi)
if(WIN32)
    target_link_libraries(boltapi_body_throughput_bench PRIVATE ws2_32 mswsock)
endif()
boltapi_apply_hardening(boltapi_body_throughput_bench)
boltapi_apply_sanitizers(boltapi_body_throughput_bench)
