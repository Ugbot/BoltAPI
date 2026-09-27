// boltapi/http3/hq_connection.h — hq-interop: HTTP/0.9 over QUIC, the ALPN the
// QUIC interop runner (github.com/quic-interop/quic-interop-runner) uses for
// its transport test cases. A client opens a bidi stream, sends
// "GET /path\r\n" and FIN; the server answers with the raw body and FIN.
//
// Bounded: one request-line buffer per concurrent peer bidi stream (the QUIC
// layer grants no more), each kHqMaxRequestLine bytes. A malformed or oversize
// request line resets the stream; peer input never asserts.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string_view>

#include "boltapi/quic/connection.h"
#include "boltapi/quic/quic_limits.h"
#include "boltapi/wire_limits.h"

namespace bolt::api::http3 {

// H3_REQUEST_REJECTED-style code for a stream we refuse (hq has no status).
inline constexpr std::uint64_t kHqRequestRejected = 0x10b;

struct HqRequest {
    std::uint64_t stream_id = 0;
    std::string_view path;  // valid for the callback only
};
using HqRequestFn = std::function<void(const HqRequest&)>;

class HqConnection {
public:
    HqConnection() noexcept = default;
    HqConnection(const HqConnection&) = delete;
    HqConnection& operator=(const HqConnection&) = delete;

    void attach(quic::QuicConnection& conn) noexcept {
        assert(qc_ == nullptr && "hq attach called twice");
        qc_ = &conn;
        assert(qc_ != nullptr && "hq attach: null connection");
    }
    void set_request_handler(HqRequestFn fn) noexcept {
        assert(static_cast<bool>(fn) && "null hq request handler");
        on_request_ = std::move(fn);
    }

    // QUIC stream data for this connection (routed here once ALPN is hq).
    void on_stream_data(std::uint64_t id, const std::uint8_t* d, std::size_t n,
                        bool fin) noexcept {
        assert((d != nullptr || n == 0) && "hq stream data null");
        assert(qc_ != nullptr && "hq stream data before attach");
        if (!quic::stream_is_bidi(id) || !quic::stream_is_client_initiated(id)) return;
        Slot* s = slot_for(id);
        if (s == nullptr) { qc_->reset_stream(id, kHqRequestRejected); return; }
        if (!s->served) {
            if (s->len + n > sizeof(s->line)) {
                s->served = true;
                qc_->reset_stream(id, kHqRequestRejected);
            } else {
                std::memcpy(s->line + s->len, d, n);
                s->len += n;
                serve_if_complete(*s, fin);
            }
        }
        if (fin) s->in_use = false;  // nothing more arrives on this stream
    }

private:
    struct Slot {
        bool in_use = false;
        bool served = false;
        std::uint64_t id = 0;
        std::size_t len = 0;
        char line[kHqMaxRequestLine];
    };

    // A request is complete at the first line break (or FIN).
    void serve_if_complete(Slot& s, bool fin) noexcept {
        assert(s.in_use && !s.served && "serve on a done slot");
        assert(s.len <= sizeof(s.line) && "hq line overrun");
        std::size_t end = 0;
        while (end < s.len && s.line[end] != '\n' && s.line[end] != '\r') ++end;
        if (end == s.len && !fin) return;  // need more bytes
        s.served = true;
        const std::string_view line(s.line, end);
        std::string_view path;
        if (!parse_get(line, path)) {
            qc_->reset_stream(s.id, kHqRequestRejected);
            return;
        }
        if (on_request_) on_request_(HqRequest{s.id, path});
    }

    // "GET <path>" with a path starting '/'; anything else is refused.
    static bool parse_get(std::string_view line, std::string_view& path) noexcept {
        assert(line.size() <= kHqMaxRequestLine && "hq line too long");
        if (line.size() < 5 || line.substr(0, 4) != "GET ") return false;
        std::string_view rest = line.substr(4);
        const std::size_t sp = rest.find(' ');
        if (sp != std::string_view::npos) rest = rest.substr(0, sp);  // "HTTP/x"
        if (rest.empty() || rest[0] != '/') return false;
        path = rest;
        assert(!path.empty() && path[0] == '/' && "hq path shape");
        return true;
    }

    Slot* slot_for(std::uint64_t id) noexcept {
        assert(id <= quic::kVarIntMax && "hq id out of range");
        for (Slot& s : slots_) if (s.in_use && s.id == id) return &s;
        for (Slot& s : slots_) {
            if (s.in_use) continue;
            s.in_use = true; s.served = false; s.id = id; s.len = 0;
            return &s;
        }
        return nullptr;
    }

    quic::QuicConnection* qc_ = nullptr;
    HqRequestFn on_request_;
    Slot slots_[quic::kPeerBidiStreamsMax];
};

}  // namespace bolt::api::http3
