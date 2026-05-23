# Throwaway self-validation build for the header-only QPACK (RFC 9204) module.
# Does NOT touch the project's root/tests CMake. Builds qpack_test.cpp as a
# standalone gtest exe against the header-only include tree + Bolt includes.
cmake_minimum_required(VERSION 3.21)
project(boltapi_qpack_check CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK  OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(boltapi_qpack_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/qpack_test.cpp
)

target_include_directories(boltapi_qpack_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/bolt/include
)

target_link_libraries(boltapi_qpack_check PRIVATE GTest::gtest_main)

if(MSVC)
    target_compile_options(boltapi_qpack_check PRIVATE /W4 /permissive- /EHsc)
endif()

enable_testing()
add_test(NAME boltapi_qpack_check COMMAND boltapi_qpack_check)
