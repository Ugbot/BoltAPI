# BoltApiCompileOptions.cmake — TigerStyle hardening flags for boltapi targets.
#
# Mirrors Bolt's bolt_apply_hardening (see extern/bolt/cmake/BoltCompileOptions.cmake):
# our own code is exception-free / RTTI-free, enforced by `noexcept` discipline
# plus the compiler flags below applied PRIVATE (never propagated via INTERFACE,
# so consumers that need exceptions/RTTI are unaffected).
#
# Toolchain policy: Windows = MSVC (or clang-cl). NEVER MinGW. GCC/Clang are for
# the Linux/macOS CI legs only.

include_guard(GLOBAL)

function(boltapi_apply_hardening tgt)
    get_target_property(type ${tgt} TYPE)
    if(type STREQUAL "INTERFACE_LIBRARY")
        set(scope INTERFACE)
    else()
        set(scope PRIVATE)
    endif()

    if(MSVC)
        target_compile_options(${tgt} ${scope}
            /W4
            /permissive-
            /Zc:__cplusplus
            /Zc:preprocessor
            /EHsc            # exceptions enabled at ABI level (stdlib needs it);
                             # our code stays exception-free by noexcept discipline
            /utf-8
            /wd4324          # padding due to alignas — deliberate (cache-line)
            /DNOMINMAX
            /D_CRT_SECURE_NO_WARNINGS
        )
        if(NOT scope STREQUAL "INTERFACE")
            target_compile_options(${tgt} PRIVATE /GR-)   # no RTTI in our TUs
        endif()
    else()
        target_compile_options(${tgt} ${scope}
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-unused-parameter
        )
        if(NOT scope STREQUAL "INTERFACE")
            target_compile_options(${tgt} PRIVATE -fno-exceptions -fno-rtti)
        endif()
    endif()

    if(BOLTAPI_WARNINGS_AS_ERRORS)
        if(MSVC)
            target_compile_options(${tgt} ${scope} /WX)
        else()
            target_compile_options(${tgt} ${scope} -Werror)
        endif()
    endif()
endfunction()
