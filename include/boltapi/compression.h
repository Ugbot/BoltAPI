// boltapi/compression.h — response compression codec seam (gzip).
//
// STOPGAP NOTICE (per repo deps policy: "prefer Bolt over third-party"):
//   Bolt currently ships no compression codec, so this seam uses zlib as a
//   stopgap gzip backend, gated behind BOLTAPI_HAVE_GZIP at compile time. When a
//   Bolt-native deflate/gzip codec lands, swap the body of gzip_encode() to call
//   it and drop the zlib dependency — the public surface here stays identical.
//
//   BOLTAPI_HAVE_GZIP is defined by the build (root CMakeLists):
//     * 1  -> zlib found AND BOLTAPI_WITH_GZIP=ON; gzip_encode() really compresses
//     * 0  -> graceful identity mode; gzip_available() == false, encode is no-op
//
// Design rules (TigerStyle): bounded, no recursion, the Accept-Encoding parser is
// allocation-light (no per-token heap churn beyond the small token compare), and
// the codec reports availability so the middleware can fall back to identity.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

// Default the feature macro so the header is self-contained if a TU includes it
// without the CMake-injected define (e.g. a header-only consumer). The library
// TU (compression.cpp) is always compiled with the authoritative value.
#ifndef BOLTAPI_HAVE_GZIP
#define BOLTAPI_HAVE_GZIP 0
#endif

namespace bolt::api {
namespace compression {

// True iff a real gzip backend is compiled in. When false the encoder is a
// no-op and the App compression middleware must pass bodies through unchanged.
constexpr bool gzip_available() noexcept {
#if BOLTAPI_HAVE_GZIP
    return true;
#else
    return false;
#endif
}

// Returns true if `accept_encoding` (the raw value of the request's
// Accept-Encoding header) lists "gzip" with a non-zero / unspecified q-value.
//
// Handles the common forms: "gzip", "gzip, deflate, br", "*", and rejects an
// explicit "gzip;q=0". Case-insensitive on the coding token. Allocation-free.
bool accepts_gzip(std::string_view accept_encoding) noexcept;

// gzip-compress `input` and return the gzip stream (RFC 1952). When
// BOLTAPI_HAVE_GZIP==0 this returns an empty string and `ok` is set to false so
// callers fall back to the identity body. On success `ok` is true.
//
// The two-argument overload throws nothing (TigerStyle: no exceptions); on any
// backend error it reports failure via `ok`.
std::string gzip_encode(std::string_view input, bool& ok);

// Convenience overload: returns the compressed bytes, or an empty string if the
// backend is unavailable or failed. Prefer the `ok`-returning form when the
// caller must distinguish "empty input compressed" from "compression failed".
inline std::string gzip_encode(std::string_view input) {
    bool ok = false;
    std::string out = gzip_encode(input, ok);
    return ok ? out : std::string{};
}

}  // namespace compression
}  // namespace bolt::api
