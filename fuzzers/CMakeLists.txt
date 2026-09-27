# libFuzzer harnesses (BOLTAPI_BUILD_FUZZERS=ON) / corpus-replay ctests
# (default). One subdirectory per protocol area; see cmake/BoltApiFuzz.cmake.
add_subdirectory(http)
add_subdirectory(quic)
