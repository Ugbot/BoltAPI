// version.cpp — version string + Bolt-integration smoke.
#include "boltapi/version.h"

#include <bolt/bolt_arena.h>

namespace bolt::api {

const char* version() noexcept {
    return "0.1.0";
}

bool bolt_integration_ok() noexcept {
    // Exercise a Bolt allocator to prove the submodule is compiled, linked, and
    // usable under our flags. TigerStyle: bounded, no exceptions, explicit
    // nullptr check.
    bolt::Arena arena;
    void* a = arena.allocate(64);
    void* b = arena.allocate(128);
    if (a == nullptr || b == nullptr) {
        return false;
    }
    // Distinct, suitably-aligned allocations from the same arena.
    return a != b && (reinterpret_cast<uintptr_t>(a) % 64u) == 0u;
}

}  // namespace bolt::api
