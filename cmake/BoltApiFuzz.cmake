# BoltApiFuzz.cmake — libFuzzer targets and their corpus-replay ctests.
#
# BOLTAPI_BUILD_FUZZERS=ON (clang with libFuzzer, e.g. Homebrew LLVM):
#   every TU in the build, bolt included, gets
#   -fsanitize=fuzzer-no-link,address,undefined; each harness links
#   -fsanitize=fuzzer and becomes a libFuzzer binary `fuzz_<name>`.
#
# BOLTAPI_BUILD_FUZZERS=OFF (the normal build, any compiler):
#   each harness is linked with fuzzers/replay_main.cpp into
#   `boltapi_fuzz_replay_<name>` and registered as a ctest that feeds every
#   file of the seed corpus and the regression corpus through it. The parser
#   TUs a harness names in INSTRUMENT are compiled into that executable with
#   ASan/UBSan (non-MSVC), so a reverted memory-safety fix fails the replay
#   in the plain build too.

include_guard(GLOBAL)

if(BOLTAPI_BUILD_FUZZERS)
    if(MSVC OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BOLTAPI_BUILD_FUZZERS needs clang with libFuzzer "
                            "(macOS: -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++)")
    endif()
    set(_boltapi_fuzz_flags
        "-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1")
    string(APPEND CMAKE_CXX_FLAGS " ${_boltapi_fuzz_flags}")
    string(APPEND CMAKE_C_FLAGS " ${_boltapi_fuzz_flags}")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=address,undefined")
    message(STATUS "Bolt API fuzzers: ON (${_boltapi_fuzz_flags})")
endif()

# boltapi_add_fuzz_target(<name> SOURCE <harness.cpp> [INSTRUMENT <src>...])
function(boltapi_add_fuzz_target name)
    cmake_parse_arguments(F "" "SOURCE" "INSTRUMENT" ${ARGN})
    if(NOT F_SOURCE)
        message(FATAL_ERROR "boltapi_add_fuzz_target(${name}): SOURCE is required")
    endif()
    set(corpus_dir ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
    set(regress_dir ${CMAKE_CURRENT_SOURCE_DIR}/regressions/${name})

    if(BOLTAPI_BUILD_FUZZERS)
        add_executable(fuzz_${name} ${F_SOURCE})
        target_link_libraries(fuzz_${name} PRIVATE boltapi::boltapi)
        target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
        return()
    endif()

    set(exe boltapi_fuzz_replay_${name})
    add_executable(${exe} ${F_SOURCE} ${PROJECT_SOURCE_DIR}/fuzzers/replay_main.cpp)
    target_link_libraries(${exe} PRIVATE boltapi::boltapi)
    if(NOT MSVC)
        # Only the named parser TUs (and the harness) are instrumented; the
        # rest resolves from the uninstrumented libboltapi.a.
        set(_san -fsanitize=address,undefined -fno-sanitize-recover=all
                 -fno-omit-frame-pointer)
        target_sources(${exe} PRIVATE ${F_INSTRUMENT})
        target_compile_options(${exe} PRIVATE ${_san})
        target_link_options(${exe} PRIVATE ${_san})
    endif()
    add_test(NAME ${exe} COMMAND ${exe} ${corpus_dir} ${regress_dir})
    # Mixed instrumented/uninstrumented libc++ containers false-positive the
    # container-overflow check.
    set_tests_properties(${exe} PROPERTIES
        ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0:abort_on_error=1;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
endfunction()
