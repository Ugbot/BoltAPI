# BoltApiGTest.cmake — finds GTest, falling back to FetchContent on miss.
# Adapted from extern/bolt/cmake/BoltGTest.cmake (BOLT_/bolt_ -> BOLTAPI_/boltapi_).
# Keeps the Windows out-of-box build path working without vcpkg.
#
# Toolchain policy: Windows = MSVC (or clang-cl). NEVER MinGW.
#
# Also provides boltapi_add_test(<name> <sources...>) which:
#   * creates a test executable from the given sources
#   * links GTest::gtest_main + boltapi::boltapi
#   * applies boltapi_apply_hardening (TigerStyle flags, see BoltApiCompileOptions)
#   * registers it with gtest_discover_tests (falls back to add_test)

include_guard(GLOBAL)

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

if(NOT TARGET GTest::gtest)
    message(STATUS "boltapi: GTest not found locally, fetching via FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2          # googletest 1.15.2 release tag
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)  # MSVC runtime match
    set(BUILD_GMOCK  OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# GoogleTest CMake integration provides gtest_discover_tests().
include(GoogleTest OPTIONAL RESULT_VARIABLE BOLTAPI_GOOGLETEST_MODULE)

# boltapi_add_test(<name> <sources...>)
function(boltapi_add_test name)
    if(ARGC LESS 2)
        message(FATAL_ERROR "boltapi_add_test(${name}): at least one source required")
    endif()

    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE
        GTest::gtest_main
        boltapi::boltapi
    )
    # tests include from <repo>/tests (for util/ helpers) and <repo>/include.
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
    )
    boltapi_apply_hardening(${name})

    if(COMMAND gtest_discover_tests)
        gtest_discover_tests(${name})
    else()
        add_test(NAME ${name} COMMAND ${name})
    endif()
endfunction()
