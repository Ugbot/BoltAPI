// boltapi/router.h — Bolt-native HTTP router (flagship fast path).
//
// Two-tier matching:
//   1. Static (exact method+path) routes resolve through a bolt::SwissTable
//      keyed on swiss_mix(method, fnv1a(path)) — one hash + one probe, O(1).
//   2. Parametric ('{name}') / wildcard ('*') routes resolve through a flat,
//      index-based segment trie iterated with a bounded loop (no recursion,
//      no pointer chasing on the hot path).
//
// Design rules (TigerStyle + HFT mechanical sympathy):
//   * No exceptions, noexcept everywhere, POD-ish payloads.
//   * No heap allocation in match() — all match-time state is stack-local.
//   * Build-time structures live in a member bolt::Arena.
//   * Every function asserts >= 2 invariants; everything is bounded by
//     explicit named constants.
//
// Public boundary uses std::string_view; bolt types are an implementation
// detail and stay out of this header.
#pragma once

#include <cstdint>
#include <string_view>

namespace bolt::api {

// ---------------------------------------------------------------------------
// HTTP method. 'Delete' (not 'DELETE') because DELETE is a Windows macro.
// ---------------------------------------------------------------------------
enum class Method : uint8_t {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Unknown,
};

// Parse a case-sensitive HTTP method token. Unknown/invalid -> Method::Unknown.
Method method_from(std::string_view token) noexcept;

// Canonical upper-case name for a method, e.g. Method::Get -> "GET".
const char* method_name(Method m) noexcept;

// ---------------------------------------------------------------------------
// Bounds (explicit, asserted at registration / match time).
// ---------------------------------------------------------------------------
inline constexpr uint32_t kMaxParams      = 16;          // params captured per match
inline constexpr uint32_t kMaxRoutes      = 4096;        // total routes registered
inline constexpr uint32_t kMaxSegments    = 32;          // path depth (segments)
inline constexpr uint32_t kMaxMethods     = 8;           // == enum count incl. Unknown
inline constexpr uint32_t kInvalidRoute   = 0xFFFFFFFFu; // "no match" sentinel

struct RouteParam {
    std::string_view name;   // interned literal: '{name}' -> "name"
    std::string_view value;  // view INTO the path passed to match()
};

struct MatchResult {
    uint32_t   route_id   = kInvalidRoute;  // == kInvalidRoute if no match
    uint32_t   param_count = 0;
    RouteParam params[kMaxParams];
    bool matched() const noexcept { return route_id != kInvalidRoute; }
};

// Opaque internal storage (pimpl) so bolt headers stay out of this header.
struct RouterImpl;

// ---------------------------------------------------------------------------
// Router — register at startup, build() once, match() on the hot path.
// ---------------------------------------------------------------------------
class Router {
public:
    Router() noexcept;
    ~Router() noexcept;

    Router(const Router&)            = delete;
    Router& operator=(const Router&) = delete;
    Router(Router&&)                 = delete;
    Router& operator=(Router&&)      = delete;

    // Registration (startup only). `path` supports literal segments,
    // '{name}' params and a trailing '*' wildcard. Returns a route id
    // (monotonic from 0) or kInvalidRoute on bounds/format violation.
    uint32_t add(Method m, std::string_view path) noexcept;

    // Finalize after all add() calls: build static SwissTable + trie and
    // sort priority. Call exactly once before match().
    void build() noexcept;

    // Hot path: allocation-free, no recursion. Captured param values are
    // string_views INTO `path` (caller owns the buffer's lifetime).
    MatchResult match(Method m, std::string_view path) const noexcept;

    uint32_t route_count() const noexcept;

private:
    RouterImpl* impl_;
};

}  // namespace bolt::api
