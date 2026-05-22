# Throwaway validation harness for tests/util/http_fuzz.h + util_fuzz_test.cpp.
#
# This is NOT part of the Bolt API build. It exists only so the fuzz utility and
# its gtest can be compiled + run in isolation (no boltapi:: link dependency),
# proving the header and test are correct before integration into tests/.
#
# Build/run (Windows, MSVC via VS generator — NEVER MinGW):
#   cmake -S tools/fuzz_check -B build/fuzz-check -G "Visual Studio 17 2022" -A x64
#   cmake --build build/fuzz-check --config Release
#   ctest --test-dir build/fuzz-check -C Release --output-on-failure

cmake_minimum_required(VERSION 3.21)
project(boltapi_fuzz_check LANGUAGES CXX)

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK   OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

add_executable(util_fuzz_test
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/util_fuzz_test.cpp
)
target_include_directories(util_fuzz_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
target_link_libraries(util_fuzz_test PRIVATE GTest::gtest_main)

if(MSVC)
    target_compile_options(util_fuzz_test PRIVATE
        /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor /EHsc /utf-8
        /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS)
endif()

gtest_discover_tests(util_fuzz_test)
