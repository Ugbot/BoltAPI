// fuzz_util.h — shared helpers for the HTTP harnesses.
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace boltapi_fuzz {

// Deterministic split points: the first input byte seeds a splitmix64, so the
// fuzzer controls how a stream is cut into reads without spending payload.
struct Splitter {
    std::uint64_t s;
    explicit Splitter(std::uint8_t seed) noexcept : s(0x9E3779B97F4A7C15ULL ^ seed) {}
    std::uint64_t next() noexcept {
        std::uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    // A read size in [1, max]; small sizes dominate to stress partial input.
    std::size_t chunk(std::size_t max) noexcept {
        assert(max > 0);
        const std::uint64_t r = next();
        const std::size_t cap = (r & 3) == 0 ? max : ((r >> 2) & 63) + 1;
        const std::size_t n = cap < max ? cap : max;
        assert(n >= 1 && n <= max);
        return n;
    }
};

// True when `v` lies entirely inside [base, base + len).
inline bool within(std::string_view v, const void* base, std::size_t len) noexcept {
    if (v.empty()) return true;
    const auto b = reinterpret_cast<std::uintptr_t>(base);
    const auto p = reinterpret_cast<std::uintptr_t>(v.data());
    return p >= b && p + v.size() <= b + len;
}

}  // namespace boltapi_fuzz

#define FUZZ_CHECK(cond)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "FUZZ_CHECK failed: %s at %s:%d\n", #cond,   \
                         __FILE__, __LINE__);                                \
            std::abort();                                                    \
        }                                                                    \
    } while (0)
