# Throwaway self-validation build for the Bolt-native RTP/RTCP codec.
# Does NOT touch the project's root/tests CMake. Builds the header-only RTP/RTCP
# codec + its test as a standalone exe against the header-only Bolt include tree.
cmake_minimum_required(VERSION 3.21)
project(boltapi_rtp_check CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(boltapi_rtp_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/rtp_test.cpp
)

# Standalone mode: the test file provides its own gtest shim + main(), so no
# gtest dependency is needed for self-validation.
target_compile_definitions(boltapi_rtp_check PRIVATE BOLTAPI_RTP_TEST_STANDALONE)

target_include_directories(boltapi_rtp_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/bolt/include
)

if(MSVC)
    target_compile_options(boltapi_rtp_check PRIVATE /W4 /permissive- /EHsc)
endif()
