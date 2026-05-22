# BoltApiSanitizers.cmake — opt-in AddressSanitizer / UndefinedBehaviorSanitizer.
#
# Toolchain policy: Windows = MSVC (or clang-cl), NEVER MinGW. The Linux/macOS
# CI legs (clang/gcc) exercise the full ASan+UBSan combination; MSVC supports
# /fsanitize=address (UBSan is not available on the MSVC toolchain).
#
# Usage:
#   include(BoltApiSanitizers)            # once, from the root CMakeLists
#   boltapi_apply_sanitizers(<target>)    # per target, guarded by BOLTAPI_SANITIZE
#
# When BOLTAPI_SANITIZE is ON the root build wires this onto the boltapi library
# and every test executable so the whole suite runs instrumented.

include_guard(GLOBAL)

option(BOLTAPI_SANITIZE "Build with ASan/UBSan" OFF)

# Apply the configured sanitizers to <tgt> (compile + link). No-op when
# BOLTAPI_SANITIZE is OFF so callers can unconditionally invoke it.
function(boltapi_apply_sanitizers tgt)
    if(NOT BOLTAPI_SANITIZE)
        return()
    endif()

    get_target_property(type ${tgt} TYPE)
    if(type STREQUAL "INTERFACE_LIBRARY")
        # Header-only targets carry no object code to instrument.
        return()
    endif()

    if(MSVC)
        # MSVC: AddressSanitizer only (no UBSan on this toolchain). The ASan
        # runtime ships with VS2022; it links automatically. Edit-and-continue
        # debug info conflicts with ASan, so force a compatible debug format.
        target_compile_options(${tgt} PRIVATE /fsanitize=address)
        target_compile_options(${tgt} PRIVATE
            $<$<CONFIG:Debug>:/Zi>
            $<$<CONFIG:RelWithDebInfo>:/Zi>
        )
    else()
        # Clang / GCC: ASan + UBSan, frame pointers kept for readable traces,
        # and abort-on-first-error so CI fails loudly instead of continuing.
        set(_san_flags
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
            -fno-sanitize-recover=all
        )
        target_compile_options(${tgt} PRIVATE ${_san_flags})
        target_link_options(${tgt} PRIVATE ${_san_flags})
    endif()
endfunction()
