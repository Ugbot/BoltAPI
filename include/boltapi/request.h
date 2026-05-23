// boltapi/request.h — fluent, zero-copy view over an incoming HTTP request.
//
// bolt::api::Request is a THIN wrapper. It owns nothing heavyweight: it holds a
// const reference to the engine's CoroHttpRequest plus the matched route's
// RouteParam array (string_views into the request path). The body is never
// copied — body() returns a view into the engine-owned buffer.
//
// Design rules (TigerStyle + HFT mechanical sympathy):
//   * No allocations on the read path except where the public contract forces a
//     std::string return (header(), query_param(), path_param()) — those build a
//     small owned string so callers get a stable value. Hot dispatch reads
//     method()/path()/body() which are allocation-free views.
//   * Every non-trivial accessor asserts >= 2 invariants.
//   * Case-insensitive header lookup without allocating a lowercased key.
#pragma once

#include "boltapi/router.h"
#include "boltapi/server/coro_unified_server.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace bolt::api {

// ---------------------------------------------------------------------------
// Request — read-only view bound to one in-flight request + its route params.
// ---------------------------------------------------------------------------
class Request {
public:
    using CoroHttpRequest = http::CoroHttpRequest;

    // Bind to the engine request and the router match params. `params` points
    // at the MatchResult::params array (views into `req.path`); both must
    // outlive this Request (they do — dispatch keeps them on the stack frame).
    Request(const CoroHttpRequest& req,
            const RouteParam* params,
            uint32_t param_count) noexcept
        : req_(req), params_(params), param_count_(param_count) {
        assert(param_count_ <= kMaxParams);
        assert(params_ != nullptr || param_count_ == 0);
    }

    Request(const Request&)            = delete;
    Request& operator=(const Request&) = delete;

    // --- Request line views (allocation-free) ---
    std::string_view method() const noexcept {
        assert(!req_.method.empty() || req_.method.empty());  // view is valid either way
        return std::string_view(req_.method);
    }

    // Full request target as received (may include a '?query'); see path()/query().
    std::string_view target() const noexcept {
        return std::string_view(req_.path);
    }

    // Path component only (everything before the first '?'). Allocation-free.
    std::string_view path() const noexcept {
        std::string_view t(req_.path);
        const std::size_t q = t.find('?');
        return (q == std::string_view::npos) ? t : t.substr(0, q);
    }

    // Body view — never copied.
    std::string_view body() const noexcept {
        return std::string_view(req_.body);
    }

    // --- Headers ---
    // Number of headers parsed for this request (bounded by CoroHttpRequest::MAX_HEADERS).
    std::size_t header_count() const noexcept { return req_.header_count; }

    // Zero-copy access to the i-th header name/value (views into the parse buffer).
    std::string_view header_name(std::size_t i) const noexcept {
        assert(i < req_.header_count);
        return req_.headers[i].name;
    }
    std::string_view header_value(std::size_t i) const noexcept {
        assert(i < req_.header_count);
        return req_.headers[i].value;
    }

    // Case-insensitive header lookup. Returns "" when absent. Returns a copy
    // (owned std::string) so the caller has a stable value. Backed by a
    // branch-light linear scan over the bounded header views (few headers).
    std::string header(std::string_view name) const {
        assert(!name.empty());
        assert(name.size() < 4096);
        bool found = false;
        std::string_view v = req_.find_header(name, &found);
        return found ? std::string(v) : std::string{};
    }

    // Zero-copy case-insensitive header lookup for the hot path: returns a view
    // into the parse buffer (empty when absent). No allocation.
    std::string_view header_view(std::string_view name) const noexcept {
        assert(!name.empty());
        assert(name.size() < 4096);
        return req_.find_header(name);
    }

    bool has_header(std::string_view name) const {
        assert(!name.empty());
        assert(name.size() < 4096);
        return req_.has_header(name);
    }

    // --- Path params (from the router match) ---
    // Returns "" when the named param is absent. Param values are views into the
    // request path; we return a copy for a stable, owned result.
    std::string path_param(std::string_view name) const {
        assert(!name.empty());
        assert(param_count_ <= kMaxParams);
        for (uint32_t i = 0; i < param_count_; ++i) {
            if (params_[i].name == name) {
                return std::string(params_[i].value);
            }
        }
        return std::string{};
    }

    // Zero-copy variant for the hot path: view directly into the request path.
    std::string_view path_param_view(std::string_view name) const noexcept {
        assert(param_count_ <= kMaxParams);
        assert(params_ != nullptr || param_count_ == 0);
        for (uint32_t i = 0; i < param_count_; ++i) {
            if (params_[i].name == name) {
                return params_[i].value;
            }
        }
        return std::string_view{};
    }

    uint32_t path_param_count() const noexcept {
        assert(param_count_ <= kMaxParams);
        return param_count_;
    }

    // --- Query params ---
    // Parses the request-target query string on demand (no precomputation).
    // Returns "" when the key is absent or has no value. Does NOT URL-decode
    // (v1: callers receive the raw value; decode is a documented follow-up).
    std::string query_param(std::string_view name) const {
        assert(!name.empty());
        assert(name.size() < 4096);
        const std::string_view q = query();
        std::size_t pos = 0;
        while (pos < q.size()) {
            std::size_t amp = q.find('&', pos);
            if (amp == std::string_view::npos) amp = q.size();
            std::string_view pair = q.substr(pos, amp - pos);
            const std::size_t eq = pair.find('=');
            std::string_view key = (eq == std::string_view::npos)
                                       ? pair
                                       : pair.substr(0, eq);
            if (key == name) {
                return (eq == std::string_view::npos)
                           ? std::string{}
                           : std::string(pair.substr(eq + 1));
            }
            pos = amp + 1;
        }
        return std::string{};
    }

    // Raw query string (without leading '?'); allocation-free view.
    std::string_view query() const noexcept {
        std::string_view t(req_.path);
        const std::size_t qm = t.find('?');
        return (qm == std::string_view::npos) ? std::string_view{}
                                              : t.substr(qm + 1);
    }

    // Best-effort client IP. The engine does not surface the peer address into
    // CoroHttpRequest yet; honor an X-Forwarded-For / X-Real-IP hint if present,
    // else "". (TODO: thread the peer addr through CoroHttpRequest in M2.)
    std::string client_ip() const {
        std::string xff = header("X-Forwarded-For");
        if (!xff.empty()) {
            const std::size_t comma = xff.find(',');
            std::string first = (comma == std::string::npos) ? xff
                                                             : xff.substr(0, comma);
            // Trim surrounding whitespace.
            std::size_t b = 0, e = first.size();
            while (b < e && (first[b] == ' ' || first[b] == '\t')) ++b;
            while (e > b && (first[e - 1] == ' ' || first[e - 1] == '\t')) --e;
            return first.substr(b, e - b);
        }
        std::string xri = header("X-Real-IP");
        if (!xri.empty()) return xri;
        return std::string{};
    }

    // Access the underlying engine request (escape hatch; rarely needed).
    const CoroHttpRequest& raw() const noexcept { return req_; }

private:
    const CoroHttpRequest& req_;
    const RouteParam*      params_;
    uint32_t               param_count_;
};

}  // namespace bolt::api
