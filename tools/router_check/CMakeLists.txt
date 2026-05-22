# Throwaway self-validation build for the Bolt-native router.
# Does NOT touch the project's root/tests CMake. Builds router.cpp + the test
# as a standalone exe against the header-only Bolt include tree.
cmake_minimum_required(VERSION 3.21)
project(boltapi_router_check CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(boltapi_router_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/router.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/router_test.cpp
)

target_include_directories(boltapi_router_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/bolt/include
)

if(MSVC)
    target_compile_options(boltapi_router_check PRIVATE /W4 /permissive- /EHsc)
endif()
