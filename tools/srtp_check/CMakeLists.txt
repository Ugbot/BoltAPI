# Throwaway self-validation build for the Bolt-native SRTP/SRTCP module.
# Does NOT touch the project's root/tests CMake. Builds the header-only SRTP
# module's gate test (tests/srtp_test.cpp) as a standalone gtest exe against the
# header tree + OpenSSL. Self-contained: fetches googletest via FetchContent.
cmake_minimum_required(VERSION 3.21)
project(boltapi_srtp_check CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# OpenSSL (Windows install at C:/Program Files/OpenSSL-Win64).
if(WIN32 AND NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
endif()
find_package(OpenSSL REQUIRED)

# googletest (match MSVC shared CRT).
include(FetchContent)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

add_executable(boltapi_srtp_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/srtp_test.cpp
)

target_include_directories(boltapi_srtp_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/bolt/include
)

target_link_libraries(boltapi_srtp_check PRIVATE
    GTest::gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(MSVC)
    target_compile_options(boltapi_srtp_check PRIVATE /W4 /permissive- /EHsc)
endif()
