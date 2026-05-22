// http_fuzz.h — header-only, std-only, seeded random HTTP/1.1 request generator.
//
// For Bolt API integration tests. TigerStyle: fixed bounds (named constants),
// noexcept where the operation cannot throw, no global mutable state (the RNG is
// always passed by reference so test runs are deterministic and reproducible).
//
// Usage:
//   boltapi::test::FuzzRng rng{0xC0FFEEu};
//   boltapi::test::GeneratedRequest req = boltapi::test::generate_request(rng);
//   std::string raw = boltapi::test::serialize_request(req);
//
// Determinism contract: two FuzzRng seeded with the same value produce the
// identical sequence of GeneratedRequest values and serialized buffers.

#ifndef BOLTAPI_TEST_HTTP_FUZZ_H
#define BOLTAPI_TEST_HTTP_FUZZ_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace boltapi::test {

// --------------------------------------------------------------------------
// Bounds — all generator limits live here as named constants (TigerStyle).
// --------------------------------------------------------------------------
inline constexpr std::size_t kMaxPathSegments  = 6;    // 1..N path segments
inline constexpr std::size_t kMaxSegmentLen    = 12;   // chars per segment
inline constexpr std::size_t kMaxQueryParams   = 4;    // 0..N query params
inline constexpr std::size_t kMaxQueryKeyLen   = 8;
inline constexpr std::size_t kMaxQueryValLen   = 10;
inline constexpr std::size_t kMaxHeaders       = 8;    // 0..N extra headers
inline constexpr std::size_t kMaxHeaderNameLen = 16;
inline constexpr std::size_t kMaxHeaderValLen  = 24;
inline constexpr std::size_t kMaxBodyLen       = 256;  // 0..N body bytes

// --------------------------------------------------------------------------
// RNG — splitmix64. Tiny, fast, fully deterministic from a single seed.
// No global state: every consumer holds its own instance.
// --------------------------------------------------------------------------
class FuzzRng {
public:
    explicit FuzzRng(std::uint64_t seed) noexcept : state_(seed) {}

    // Raw 64-bit draw (splitmix64).
    std::uint64_t next_u64() noexcept {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    // Uniform-ish in [0, bound). bound must be > 0. Modulo bias is acceptable
    // for test input shaping (bounds are small relative to 2^64).
    std::size_t below(std::size_t bound) noexcept {
        // Assertion via contract: callers never pass 0 (see helpers below).
        if (bound == 0) {
            return 0;
        }
        return static_cast<std::size_t>(next_u64() % bound);
    }

    // Inclusive range [lo, hi]. Requires lo <= hi.
    std::size_t in_range(std::size_t lo, std::size_t hi) noexcept {
        if (hi <= lo) {
            return lo;
        }
        return lo + below(hi - lo + 1);
    }

    bool coin() noexcept { return (next_u64() & 1ULL) != 0ULL; }

private:
    std::uint64_t state_;
};

// --------------------------------------------------------------------------
// Methods.
// --------------------------------------------------------------------------
enum class Method : std::uint8_t {
    GET = 0, HEAD, POST, PUT, DELETE, PATCH, OPTIONS
};
inline constexpr std::size_t kMethodCount = 7;

inline const char* method_name(Method m) noexcept {
    switch (m) {
        case Method::GET:     return "GET";
        case Method::HEAD:    return "HEAD";
        case Method::POST:    return "POST";
        case Method::PUT:     return "PUT";
        case Method::DELETE:  return "DELETE";
        case Method::PATCH:   return "PATCH";
        case Method::OPTIONS: return "OPTIONS";
    }
    return "GET";  // unreachable; keeps the function total/noexcept-safe.
}

// Methods that may legitimately carry a request body.
inline bool method_allows_body(Method m) noexcept {
    return m == Method::POST || m == Method::PUT || m == Method::PATCH;
}

inline Method random_method(FuzzRng& rng) noexcept {
    return static_cast<Method>(rng.below(kMethodCount));
}

// --------------------------------------------------------------------------
// Character alphabets — kept small and URL/token safe so generated requests
// are always parseable without escaping concerns.
// --------------------------------------------------------------------------
namespace detail {

// URL-safe path/query characters (unreserved set per RFC 3986).
inline constexpr char kUrlSafe[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
inline constexpr std::size_t kUrlSafeLen = sizeof(kUrlSafe) - 1;

// HTTP token characters (RFC 7230 tchar subset) for header names.
inline constexpr char kTokenChars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
inline constexpr std::size_t kTokenLen = sizeof(kTokenChars) - 1;

// Printable header-value characters (VCHAR subset, no CR/LF, no leading/trailing
// space issues since we only place these mid-value).
inline constexpr char kValueChars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:/-_";
inline constexpr std::size_t kValueLen = sizeof(kValueChars) - 1;

// Body bytes: printable ASCII so Content-Length math is unambiguous in tests.
inline constexpr char kBodyChars[] =
    "abcdefghijklmnopqrstuvwxyz0123456789{}[]\":, ";
inline constexpr std::size_t kBodyLen = sizeof(kBodyChars) - 1;

inline std::string random_string(FuzzRng& rng, const char* alphabet,
                                 std::size_t alphabet_len, std::size_t len) {
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(alphabet[rng.below(alphabet_len)]);
    }
    return out;
}

}  // namespace detail

// --------------------------------------------------------------------------
// Generated request model.
// --------------------------------------------------------------------------
struct Header {
    std::string name;
    std::string value;
};

struct GeneratedRequest {
    Method method = Method::GET;
    std::string path;                 // always begins with '/', non-empty
    std::string query;                // without leading '?'; may be empty
    std::vector<Header> headers;      // user headers (Host added at serialize)
    std::string body;                 // may be empty
};

// --------------------------------------------------------------------------
// Field generators.
// --------------------------------------------------------------------------
inline std::string random_path(FuzzRng& rng) {
    const std::size_t segments = rng.in_range(1, kMaxPathSegments);
    std::string path;
    path.reserve(segments * (kMaxSegmentLen + 1) + 1);
    for (std::size_t i = 0; i < segments; ++i) {
        path.push_back('/');
        const std::size_t seg_len = rng.in_range(1, kMaxSegmentLen);
        path += detail::random_string(rng, detail::kUrlSafe,
                                      detail::kUrlSafeLen, seg_len);
    }
    return path;
}

inline std::string random_query(FuzzRng& rng) {
    const std::size_t params = rng.below(kMaxQueryParams + 1);  // 0..N
    if (params == 0) {
        return std::string{};
    }
    std::string query;
    for (std::size_t i = 0; i < params; ++i) {
        if (i != 0) {
            query.push_back('&');
        }
        const std::size_t klen = rng.in_range(1, kMaxQueryKeyLen);
        const std::size_t vlen = rng.below(kMaxQueryValLen + 1);  // value may be empty
        query += detail::random_string(rng, detail::kUrlSafe,
                                       detail::kUrlSafeLen, klen);
        query.push_back('=');
        query += detail::random_string(rng, detail::kUrlSafe,
                                       detail::kUrlSafeLen, vlen);
    }
    return query;
}

inline std::string random_header_name(FuzzRng& rng) {
    // Prefix with "X-" to avoid colliding with reserved/standard headers
    // (Host, Content-Length) that serialize_request manages itself.
    const std::size_t len = rng.in_range(1, kMaxHeaderNameLen);
    return "X-" + detail::random_string(rng, detail::kTokenChars,
                                        detail::kTokenLen, len);
}

inline std::string random_header_value(FuzzRng& rng) {
    const std::size_t len = rng.in_range(1, kMaxHeaderValLen);
    std::string v = detail::random_string(rng, detail::kValueChars,
                                          detail::kValueLen, len);
    // Trim a possible trailing space so the value has no awkward OWS at the end.
    while (!v.empty() && v.back() == ' ') {
        v.back() = '.';
    }
    // Trim a possible leading space similarly.
    if (!v.empty() && v.front() == ' ') {
        v.front() = '.';
    }
    return v;
}

inline std::vector<Header> random_headers(FuzzRng& rng) {
    const std::size_t count = rng.below(kMaxHeaders + 1);  // 0..N
    std::vector<Header> headers;
    headers.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        headers.push_back(Header{random_header_name(rng), random_header_value(rng)});
    }
    return headers;
}

inline std::string random_body(FuzzRng& rng) {
    const std::size_t len = rng.below(kMaxBodyLen + 1);  // 0..N
    return detail::random_string(rng, detail::kBodyChars, detail::kBodyLen, len);
}

// One full request. Bodies only attach to verbs that allow them; even then a
// body is optional so tests see both body and no-body POST/PUT/PATCH.
inline GeneratedRequest generate_request(FuzzRng& rng) {
    GeneratedRequest req;
    req.method  = random_method(rng);
    req.path    = random_path(rng);
    req.query   = random_query(rng);
    req.headers = random_headers(rng);
    // Body decision uses the already-chosen method: only body-bearing verbs,
    // and even then optional, so tests see both body and no-body cases.
    if (method_allows_body(req.method) && rng.coin()) {
        req.body = random_body(rng);
    }
    return req;
}

// --------------------------------------------------------------------------
// Serialization to a raw HTTP/1.1 request buffer.
//   request-line  = METHOD SP request-target SP HTTP/1.1 CRLF
//   *( header-field CRLF )
//   CRLF
//   [ body ]
// Content-Length is always emitted (0 when no body) so the framing is explicit.
// --------------------------------------------------------------------------
inline constexpr char kCRLF[] = "\r\n";

inline std::string serialize_request(const GeneratedRequest& req,
                                     const std::string& host = "localhost") {
    std::string out;
    out.reserve(64 + req.path.size() + req.query.size() + req.body.size() +
                req.headers.size() * (kMaxHeaderNameLen + kMaxHeaderValLen + 8));

    // Request line.
    out += method_name(req.method);
    out.push_back(' ');
    out += req.path;
    if (!req.query.empty()) {
        out.push_back('?');
        out += req.query;
    }
    out += " HTTP/1.1";
    out += kCRLF;

    // Host (mandatory in HTTP/1.1).
    out += "Host: ";
    out += host;
    out += kCRLF;

    // User headers.
    for (const Header& h : req.headers) {
        out += h.name;
        out += ": ";
        out += h.value;
        out += kCRLF;
    }

    // Content-Length always present and correct.
    out += "Content-Length: ";
    out += std::to_string(req.body.size());
    out += kCRLF;

    // End of headers.
    out += kCRLF;

    // Body.
    out += req.body;

    return out;
}

}  // namespace boltapi::test

#endif  // BOLTAPI_TEST_HTTP_FUZZ_H
