// boltapi/http/response_headers.h — owned, flat, bounded response-header store.
//
// Replaces the per-response std::unordered_map<std::string,std::string> that
// CoroHttpResponse used to carry. Same reasoning as the request side's flat
// CoroHttpHeaderView array: std::unordered_map is node-based — a heap alloc per
// entry, pointer chasing, poor cache locality. For the handful of headers a
// response carries (~5: Content-Type, Content-Length, Connection, Date, plus a
// few user/CORS ones) a contiguous flat array with a linear, case-insensitive
// scan beats hashing — no per-entry heap node, cache-friendly, vectorisable.
//
// Stores OWNED std::string name/value pairs (vs. the request side's views)
// because response header values are produced by the handler/middleware, not
// parsed from a live buffer.
//
// Lives in its own header so both the engine (coro_unified_server.h) and the
// HTTP/2 path (http2_connection.h) can consume CoroHttpResponse.headers without
// an include cycle (coro_unified_server.h already includes http2_connection.h).
//
// TigerStyle: fixed capacity (MAX_RESPONSE_HEADERS), bounded loops, asserts on
// invariants, graceful overflow handling (drop rather than UB — the engine's
// header bounds fire well before this cap).
//
// API surface kept map-compatible where public/test code relies on it:
//   * operator[](key) -> std::string&  (find-or-create; supports `h[k] = v` and
//     `h[k] += v`, exactly like the old map — middleware_test depends on this).
//   * find(key)/end()                  (pointer-based; find() is case-insensitive).
//   * set(name, value)                 (replace-or-append, case-insensitive).
//   * append(name, value)              (always append, no de-dup).
//   * range-based for over Entry{name,value} for serialization & HPACK.
//   * size()/empty().
#pragma once

#include <cassert>
#include <cstddef>
#include <string>
#include <string_view>

namespace bolt::api {
namespace http {

struct CoroResponseHeaders {
    // Inline, fixed capacity. Kept small on purpose: the whole container is
    // embedded by value in CoroHttpResponse, which is constructed and
    // move-assigned on the coroutine frame for EVERY request. Each slot is a
    // pair of std::string (~64 B on MSVC), so capacity directly sets the inline
    // footprint (16 -> ~1 KiB; 64 was ~4 KiB and measurably regressed the GET
    // hot path). Real responses carry a handful of headers (Content-Type,
    // Content-Length, Connection, Date + a few user/CORS), well under this.
    // Overflow past the cap is dropped gracefully (see append()).
    static constexpr size_t MAX_RESPONSE_HEADERS = 16;

    struct Entry {
        std::string name;
        std::string value;
    };

    Entry entries[MAX_RESPONSE_HEADERS];
    size_t count = 0;

    using iterator = Entry*;
    using const_iterator = const Entry*;

    iterator begin() noexcept { return entries; }
    iterator end() noexcept { return entries + count; }
    const_iterator begin() const noexcept { return entries; }
    const_iterator end() const noexcept { return entries + count; }

    size_t size() const noexcept { return count; }
    bool empty() const noexcept { return count == 0; }

    // ASCII case-insensitive linear lookup. Returns end() when absent. Few
    // headers => branch-light and cache-friendly vs. a hash probe.
    iterator find(std::string_view name) noexcept {
        for (size_t i = 0; i < count; ++i) {
            if (iequals_ci(entries[i].name, name)) return &entries[i];
        }
        return end();
    }
    const_iterator find(std::string_view name) const noexcept {
        for (size_t i = 0; i < count; ++i) {
            if (iequals_ci(entries[i].name, name)) return &entries[i];
        }
        return end();
    }

    // Replace-or-append (case-insensitive on name). Preserves the original
    // header's stored name casing on replace (matches no-realloc map intent).
    void set(std::string_view name, std::string_view value) {
        iterator it = find(name);
        if (it != end()) {
            it->value.assign(value.data(), value.size());
            return;
        }
        append(name, value);
    }

    // Always append; bounded — drops past capacity (TigerStyle: handle, no UB).
    void append(std::string_view name, std::string_view value) {
        assert(count <= MAX_RESPONSE_HEADERS);
        if (count >= MAX_RESPONSE_HEADERS) return;  // graceful drop on overflow
        entries[count].name.assign(name.data(), name.size());
        entries[count].value.assign(value.data(), value.size());
        ++count;
    }

    // Map-compatible find-or-create. Returns a mutable ref to the value so
    // callers can do `h[k] = v` (replace) or `h[k] += v` (append-in-place).
    std::string& operator[](std::string_view name) {
        iterator it = find(name);
        if (it != end()) return it->value;
        assert(count < MAX_RESPONSE_HEADERS);
        // On overflow we still must return a valid lvalue; reuse the last slot
        // rather than invoke UB. The engine bounds headers well below this.
        if (count >= MAX_RESPONSE_HEADERS) return entries[MAX_RESPONSE_HEADERS - 1].value;
        entries[count].name.assign(name.data(), name.size());
        entries[count].value.clear();
        return entries[count++].value;
    }

    void clear() noexcept {
        for (size_t i = 0; i < count; ++i) {
            entries[i].name.clear();
            entries[i].value.clear();
        }
        count = 0;
    }

private:
    static bool iequals_ci(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i], cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    }
};

}  // namespace http
}  // namespace bolt::api
