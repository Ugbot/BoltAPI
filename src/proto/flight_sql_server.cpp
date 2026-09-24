// src/proto/flight_sql_server.cpp — Arrow Flight SQL over gRPC over h2c.
// See boltapi/proto/flight_sql.h for scope and the no-gRPC/no-protobuf
// design note. Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
//
// Structure mirrors postgres_wire_server.cpp: raw blocking sockets,
// select()-gated bounded reads, a fixed worker pool (one connection per
// worker at a time), every buffer sized once per worker.

#include "boltapi/proto/flight_sql.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include "boltapi/http/hpack.h"
#include "boltapi/net/sys_compat.h"
#include "boltapi/proto/flight_sql_codec.h"

#include <bolt/api/core/stacked_thread.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#if !defined(_WIN32)
#include <netinet/tcp.h>
#endif

namespace bolt::api::proto::flightsql {

namespace {

namespace cd = codec;

// ---------------------------------------------------------------------------
// HTTP/2 constants (RFC 9113).
// ---------------------------------------------------------------------------
constexpr std::uint8_t kFrameData = 0x0;
constexpr std::uint8_t kFrameHeaders = 0x1;
constexpr std::uint8_t kFrameRstStream = 0x3;
constexpr std::uint8_t kFrameSettings = 0x4;
constexpr std::uint8_t kFramePing = 0x6;
constexpr std::uint8_t kFrameGoaway = 0x7;
constexpr std::uint8_t kFrameWindowUpdate = 0x8;
constexpr std::uint8_t kFrameContinuation = 0x9;

constexpr std::uint8_t kFlagEndStream = 0x1;
constexpr std::uint8_t kFlagAck = 0x1;
constexpr std::uint8_t kFlagEndHeaders = 0x4;
constexpr std::uint8_t kFlagPadded = 0x8;
constexpr std::uint8_t kFlagPriority = 0x20;

constexpr std::uint32_t kErrProtocol = 0x1;
constexpr std::uint32_t kErrFlowControl = 0x3;
constexpr std::uint32_t kErrFrameSize = 0x6;
constexpr std::uint32_t kErrRefusedStream = 0x7;

constexpr std::uint16_t kSettingsHeaderTableSize = 0x1;
constexpr std::uint16_t kSettingsMaxConcurrent = 0x3;
constexpr std::uint16_t kSettingsInitialWindow = 0x4;
constexpr std::uint16_t kSettingsMaxFrameSize = 0x5;

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = 24;

constexpr std::uint32_t kMaxStreams = 16;
constexpr std::size_t kOurMaxFrame = 16384;           // SETTINGS default
constexpr std::size_t kHeaderBlockCap = 16384;
constexpr std::size_t kStreamBodyCap = kMaxQueryBytes + 8192;
constexpr std::size_t kAuthCap = 1024;
constexpr std::int64_t kDefaultWindow = 65535;
constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;
constexpr std::size_t kMaxIpcMessages = 1u << 16;
constexpr int kMaxFramesPerWait = 1 << 20;

constexpr std::string_view kServicePrefix = "/arrow.flight.protocol.FlightService/";

enum class Method : std::uint8_t {
    kUnknown, kHandshake, kListFlights, kGetFlightInfo, kGetSchema, kDoGet,
    kListActions,
};

Method method_for(std::string_view path) noexcept {
    if (path.substr(0, kServicePrefix.size()) != kServicePrefix) return Method::kUnknown;
    const std::string_view m = path.substr(kServicePrefix.size());
    if (m == "Handshake") return Method::kHandshake;
    if (m == "ListFlights") return Method::kListFlights;
    if (m == "GetFlightInfo") return Method::kGetFlightInfo;
    if (m == "GetSchema") return Method::kGetSchema;
    if (m == "DoGet") return Method::kDoGet;
    if (m == "ListActions") return Method::kListActions;
    return Method::kUnknown;
}

std::uint32_t be_u32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void put_be_u32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

int wait_readable(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms >= 0);
    fd_set rd;
    FD_ZERO(&rd);
#if defined(_WIN32)
    FD_SET(static_cast<SOCKET>(fd), &rd);
#else
    if (fd >= FD_SETSIZE) return -1;
    FD_SET(fd, &rd);
#endif
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int r = ::select(fd + 1, &rd, nullptr, nullptr, &tv);
    return (r < 0) ? -1 : r;
}

// HPACK integer with an N-bit prefix (RFC 7541 5.1).
void hpack_put_int(std::string* out, std::uint8_t first, int prefix_bits,
                   std::size_t v) {
    assert(out != nullptr && prefix_bits > 0 && prefix_bits <= 8);
    const std::size_t max_prefix = (std::size_t{1} << prefix_bits) - 1;
    if (v < max_prefix) {
        out->push_back(static_cast<char>(first | v));
        return;
    }
    out->push_back(static_cast<char>(first | max_prefix));
    v -= max_prefix;
    for (int i = 0; i < 10 && v >= 128; ++i) {
        out->push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out->push_back(static_cast<char>(v));
}

// Literal header field without indexing, new name, no Huffman.
void hpack_literal(std::string* out, std::string_view name, std::string_view value) {
    out->push_back(0x00);
    hpack_put_int(out, 0x00, 7, name.size());
    out->append(name.data(), name.size());
    hpack_put_int(out, 0x00, 7, value.size());
    out->append(value.data(), value.size());
}

struct Stream {
    bool          in_use = false;
    bool          ready = false;       // request complete, awaiting dispatch
    bool          active = false;      // being dispatched; slot must not be reused
    bool          reset = false;       // peer sent RST_STREAM
    bool          overflow = false;    // body exceeded kStreamBodyCap
    Method        method = Method::kUnknown;
    std::uint32_t id = 0;
    std::int64_t  send_window = kDefaultWindow;
    std::size_t   body_len = 0;
    std::size_t   auth_len = 0;
    char          auth[kAuthCap] = {};
    char          path[160] = {};
    std::uint8_t* body = nullptr;      // kStreamBodyCap, owned by Conn
};

// ---------------------------------------------------------------------------
// One HTTP/2 connection. Owned by a worker, reused across connections.
// ---------------------------------------------------------------------------
class Conn {
public:
    Conn(const Config& cfg, IQueryExecutor& exec, IAuthenticator& auth,
         const std::atomic<bool>& stopping)
        : cfg_(cfg), exec_(exec), auth_(auth), stopping_(stopping),
          frame_(kOurMaxFrame), out_(kOurMaxFrame), hblock_(kHeaderBlockCap),
          bodies_(static_cast<std::size_t>(kMaxStreams) * kStreamBodyCap) {
        for (std::uint32_t i = 0; i < kMaxStreams; ++i) {
            streams_[i].body = bodies_.data() + static_cast<std::size_t>(i) * kStreamBodyCap;
        }
        headers_.reserve(128);
        ipc_.reserve(1u << 20);
        msg_.reserve(1u << 20);
        assert(frame_.size() == kOurMaxFrame);
    }

    void serve(int fd) noexcept;

private:
    // ---- I/O -------------------------------------------------------------
    bool read_exact(void* dst, std::size_t n) noexcept {
        assert(dst != nullptr || n == 0);
        auto* p = static_cast<std::uint8_t*>(dst);
        std::size_t got = 0;
        while (got < n) {                                  // bounded by n / idle budget
            if (stopping_.load(std::memory_order_acquire)) return false;
            const int ready = wait_readable(fd_, cfg_.accept_poll_ms);
            if (ready < 0) return false;
            if (ready == 0) {
                idle_budget_ -= cfg_.accept_poll_ms;
                if (idle_budget_ <= 0) return false;
                continue;
            }
            const ssize_t r = net::sys::recv_bytes(fd_, p + got, n - got);
            if (r <= 0) return false;
            got += static_cast<std::size_t>(r);
        }
        idle_budget_ = cfg_.idle_timeout_ms;
        assert(got == n);
        return true;
    }

    bool write_all(const void* src, std::size_t n) noexcept {
        assert(src != nullptr || n == 0);
        const auto* p = static_cast<const std::uint8_t*>(src);
        std::size_t sent = 0;
        while (sent < n) {
            const ssize_t w = net::sys::send_bytes(fd_, p + sent, n - sent);
            if (w <= 0) { dead_ = true; return false; }
            sent += static_cast<std::size_t>(w);
        }
        assert(sent == n);
        return true;
    }

    bool send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
                    const void* payload, std::size_t len) noexcept {
        assert(len <= 0xFFFFFFu);
        assert((sid & 0x80000000u) == 0);
        std::uint8_t h[9];
        h[0] = static_cast<std::uint8_t>(len >> 16);
        h[1] = static_cast<std::uint8_t>(len >> 8);
        h[2] = static_cast<std::uint8_t>(len);
        h[3] = type;
        h[4] = flags;
        put_be_u32(h + 5, sid);
        return write_all(h, 9) && write_all(payload, len);
    }

    void goaway(std::uint32_t err) noexcept {
        std::uint8_t p[8];
        put_be_u32(p, last_stream_id_);
        put_be_u32(p + 4, err);
        (void)send_frame(kFrameGoaway, 0, 0, p, 8);
        dead_ = true;
    }

    void window_update(std::uint32_t sid, std::uint32_t inc) noexcept {
        assert(inc > 0 && inc <= 0x7FFFFFFFu);
        std::uint8_t p[4];
        put_be_u32(p, inc);
        (void)send_frame(kFrameWindowUpdate, 0, sid, p, 4);
    }

    // ---- frame handling --------------------------------------------------
    bool read_and_handle_frame() noexcept;
    void handle_settings(std::uint8_t flags, const std::uint8_t* p, std::size_t n) noexcept;
    void handle_headers(std::uint32_t sid, std::uint8_t flags, const std::uint8_t* p,
                        std::size_t n) noexcept;
    void handle_data(std::uint32_t sid, std::uint8_t flags, const std::uint8_t* p,
                     std::size_t n) noexcept;
    void finish_header_block(std::uint32_t sid, bool end_stream) noexcept;
    Stream* find(std::uint32_t sid) noexcept {
        for (auto& s : streams_) {
            if (s.in_use && s.id == sid) return &s;
        }
        return nullptr;
    }
    Stream* alloc(std::uint32_t sid) noexcept {
        for (auto& s : streams_) {
            if (!s.in_use) {
                std::uint8_t* body = s.body;
                s = Stream{};
                s.body = body;
                s.in_use = true;
                s.id = sid;
                s.send_window = peer_initial_window_;
                return &s;
            }
        }
        return nullptr;
    }

    // ---- responses -------------------------------------------------------
    bool send_response_headers(Stream& s) noexcept;
    bool send_trailers(Stream& s, GrpcCode code, std::string_view msg,
                       bool with_status_line) noexcept;
    bool send_message(Stream& s, std::string_view payload) noexcept;
    bool wait_for_window(Stream& s) noexcept;
    void respond_error(Stream& s, GrpcCode code, std::string_view msg) noexcept {
        (void)send_trailers(s, code, msg, true);
    }

    // ---- RPCs --------------------------------------------------------------
    void dispatch(Stream& s) noexcept;
    bool authorized(const Stream& s) noexcept;
    bool statement_from_descriptor(Stream& s, std::string_view msg,
                                   std::string_view* sql) noexcept;
    bool run_query(Stream& s, std::string_view sql, std::int64_t* rows,
                   cd::IpcMessage* schema) noexcept;
    void rpc_get_flight_info(Stream& s, std::string_view msg) noexcept;
    void rpc_get_schema(Stream& s, std::string_view msg) noexcept;
    void rpc_do_get(Stream& s, std::string_view msg) noexcept;

    const Config&            cfg_;
    IQueryExecutor&          exec_;
    IAuthenticator&          auth_;
    const std::atomic<bool>& stopping_;

    int           fd_ = -1;
    int           idle_budget_ = 0;
    bool          dead_ = false;
    std::uint32_t last_stream_id_ = 0;
    std::int64_t  conn_send_window_ = kDefaultWindow;
    std::int64_t  peer_initial_window_ = kDefaultWindow;
    std::size_t   peer_max_frame_ = kOurMaxFrame;

    // CONTINUATION accumulation.
    std::uint32_t hblock_sid_ = 0;
    bool          hblock_end_stream_ = false;
    std::size_t   hblock_len_ = 0;

    std::vector<std::uint8_t>      frame_;
    std::vector<std::uint8_t>      out_;
    std::vector<std::uint8_t>      hblock_;
    std::vector<std::uint8_t>      bodies_;
    Stream                         streams_[kMaxStreams];
    std::unique_ptr<http::HPACKDecoder> hpack_;
    std::vector<http::HPACKHeader> headers_;
    std::string                    ipc_;
    std::string                    msg_;
    std::string                    scratch_;
};

void Conn::serve(int fd) noexcept {
    assert(fd >= 0);
    fd_ = fd;
    dead_ = false;
    idle_budget_ = cfg_.idle_timeout_ms;
    last_stream_id_ = 0;
    conn_send_window_ = kDefaultWindow;
    peer_initial_window_ = kDefaultWindow;
    peer_max_frame_ = kOurMaxFrame;
    hblock_sid_ = 0;
    hblock_len_ = 0;
    for (auto& s : streams_) s.in_use = false;
    hpack_ = std::make_unique<http::HPACKDecoder>();

    char preface[kPrefaceLen];
    if (!read_exact(preface, kPrefaceLen) ||
        std::memcmp(preface, kPreface, kPrefaceLen) != 0) {
        return;   // not h2c prior-knowledge: nothing sensible to answer
    }
    std::uint8_t settings[6];
    settings[0] = 0;
    settings[1] = static_cast<std::uint8_t>(kSettingsMaxConcurrent);
    put_be_u32(settings + 2, kMaxStreams);
    if (!send_frame(kFrameSettings, 0, 0, settings, sizeof(settings))) return;

    while (!dead_ && !stopping_.load(std::memory_order_acquire)) {
        if (!read_and_handle_frame()) break;
        for (std::uint32_t k = 0; k < kMaxStreams && !dead_; ++k) {
            // Lowest stream id first: requests dispatch in arrival order.
            Stream* next = nullptr;
            for (auto& s : streams_) {
                if (s.in_use && s.ready && (next == nullptr || s.id < next->id)) next = &s;
            }
            if (next == nullptr) break;
            next->ready = false;
            next->active = true;
            dispatch(*next);
            next->active = false;
            next->in_use = false;
        }
    }
}

bool Conn::read_and_handle_frame() noexcept {
    std::uint8_t h[9];
    if (!read_exact(h, 9)) return false;
    const std::size_t len = (static_cast<std::size_t>(h[0]) << 16) |
                            (static_cast<std::size_t>(h[1]) << 8) | h[2];
    const std::uint8_t type = h[3];
    const std::uint8_t flags = h[4];
    const std::uint32_t sid = be_u32(h + 5) & 0x7FFFFFFFu;
    if (len > kOurMaxFrame) { goaway(kErrFrameSize); return false; }
    if (len > 0 && !read_exact(frame_.data(), len)) return false;
    const std::uint8_t* p = frame_.data();

    if (hblock_sid_ != 0 && type != kFrameContinuation) {
        goaway(kErrProtocol);   // a header block must be contiguous
        return false;
    }
    switch (type) {
        case kFrameSettings:
            handle_settings(flags, p, len);
            break;
        case kFramePing:
            if (len != 8) { goaway(kErrFrameSize); break; }
            if ((flags & kFlagAck) == 0) (void)send_frame(kFramePing, kFlagAck, 0, p, 8);
            break;
        case kFrameWindowUpdate: {
            if (len != 4) { goaway(kErrFrameSize); break; }
            const std::int64_t inc = be_u32(p) & 0x7FFFFFFFu;
            if (sid == 0) {
                conn_send_window_ += inc;
                if (conn_send_window_ > kMaxWindow) goaway(kErrFlowControl);
            } else if (Stream* s = find(sid)) {
                s->send_window += inc;
            }
            break;
        }
        case kFrameHeaders:
            handle_headers(sid, flags, p, len);
            break;
        case kFrameContinuation: {
            if (sid == 0 || sid != hblock_sid_) { goaway(kErrProtocol); break; }
            if (hblock_len_ + len > hblock_.size()) { goaway(kErrProtocol); break; }
            std::memcpy(hblock_.data() + hblock_len_, p, len);
            hblock_len_ += len;
            if (flags & kFlagEndHeaders) finish_header_block(sid, hblock_end_stream_);
            break;
        }
        case kFrameData:
            handle_data(sid, flags, p, len);
            break;
        case kFrameRstStream:
            if (Stream* s = find(sid)) {
                s->reset = true;
                if (!s->ready && !s->active) s->in_use = false;
            }
            break;
        case kFrameGoaway:
            dead_ = true;
            break;
        default:
            break;   // PRIORITY, PUSH_PROMISE (never sent to a server), unknown
    }
    return !dead_;
}

void Conn::handle_settings(std::uint8_t flags, const std::uint8_t* p, std::size_t n) noexcept {
    if (flags & kFlagAck) return;
    if (n % 6 != 0) { goaway(kErrFrameSize); return; }
    for (std::size_t off = 0; off + 6 <= n; off += 6) {    // bounded by n
        const std::uint16_t id = static_cast<std::uint16_t>((p[off] << 8) | p[off + 1]);
        const std::uint32_t v = be_u32(p + off + 2);
        if (id == kSettingsInitialWindow) {
            if (v > 0x7FFFFFFFu) { goaway(kErrFlowControl); return; }
            const std::int64_t delta = static_cast<std::int64_t>(v) - peer_initial_window_;
            peer_initial_window_ = v;
            for (auto& s : streams_) {
                if (s.in_use) s.send_window += delta;
            }
        } else if (id == kSettingsMaxFrameSize) {
            if (v < 16384u || v > 16777215u) { goaway(kErrProtocol); return; }
            peer_max_frame_ = v < 65536u ? v : 65536u;
        } else if (id == kSettingsHeaderTableSize) {
            // Our responses never use the dynamic table; nothing to resize.
        }
    }
    (void)send_frame(kFrameSettings, kFlagAck, 0, nullptr, 0);
}

void Conn::handle_headers(std::uint32_t sid, std::uint8_t flags, const std::uint8_t* p,
                          std::size_t n) noexcept {
    if (sid == 0) { goaway(kErrProtocol); return; }
    std::size_t off = 0;
    std::size_t pad = 0;
    if (flags & kFlagPadded) {
        if (n < 1) { goaway(kErrProtocol); return; }
        pad = p[0];
        off = 1;
    }
    if (flags & kFlagPriority) off += 5;
    if (off + pad > n) { goaway(kErrProtocol); return; }
    const std::size_t frag = n - off - pad;
    if (frag > hblock_.size()) { goaway(kErrProtocol); return; }
    std::memcpy(hblock_.data(), p + off, frag);
    hblock_len_ = frag;
    const bool end_stream = (flags & kFlagEndStream) != 0;
    if (flags & kFlagEndHeaders) {
        finish_header_block(sid, end_stream);
    } else {
        hblock_sid_ = sid;
        hblock_end_stream_ = end_stream;
    }
}

void Conn::finish_header_block(std::uint32_t sid, bool end_stream) noexcept {
    hblock_sid_ = 0;
    headers_.clear();
    // Always decode: the HPACK dynamic table must track every block, even
    // for a stream about to be refused.
    if (hpack_->decode(hblock_.data(), hblock_len_, headers_, 128) != 0) {
        goaway(kErrProtocol);
        return;
    }
    Stream* s = find(sid);
    if (s == nullptr) {
        if (sid <= last_stream_id_ || (sid & 1u) == 0) return;   // trailers on a closed stream
        last_stream_id_ = sid;
        s = alloc(sid);
        if (s == nullptr) {
            std::uint8_t e[4];
            put_be_u32(e, kErrRefusedStream);
            (void)send_frame(kFrameRstStream, 0, sid, e, 4);
            return;
        }
        for (const auto& hh : headers_) {
            if (hh.name == ":path") {
                const std::size_t n = hh.value.size() < sizeof(s->path) - 1
                                          ? hh.value.size() : sizeof(s->path) - 1;
                std::memcpy(s->path, hh.value.data(), n);
                s->path[n] = '\0';
            } else if (hh.name == "authorization") {
                s->auth_len = hh.value.size() < kAuthCap ? hh.value.size() : kAuthCap;
                std::memcpy(s->auth, hh.value.data(), s->auth_len);
            }
        }
        s->method = method_for(s->path);
    }
    if (end_stream) s->ready = true;
    assert(s->in_use);
}

void Conn::handle_data(std::uint32_t sid, std::uint8_t flags, const std::uint8_t* p,
                       std::size_t n) noexcept {
    if (sid == 0) { goaway(kErrProtocol); return; }
    std::size_t off = 0;
    std::size_t pad = 0;
    if (flags & kFlagPadded) {
        if (n < 1) { goaway(kErrProtocol); return; }
        pad = p[0];
        off = 1;
    }
    if (off + pad > n) { goaway(kErrProtocol); return; }
    const std::size_t payload = n - off - pad;
    const bool end_stream = (flags & kFlagEndStream) != 0;
    if (n > 0) window_update(0, static_cast<std::uint32_t>(n));
    Stream* s = find(sid);
    if (s == nullptr || s->ready || s->active) return;   // closed or complete
    if (s->body_len + payload > kStreamBodyCap) {
        s->overflow = true;
    } else {
        std::memcpy(s->body + s->body_len, p + off, payload);
        s->body_len += payload;
    }
    if (end_stream) {
        s->ready = true;
    } else {
        if (n > 0) window_update(sid, static_cast<std::uint32_t>(n));
        // Handshake is bidirectional: the client may wait for our reply
        // before half-closing, so one complete message is enough.
        std::string_view m;
        std::size_t used = 0;
        if (s->method == Method::kHandshake &&
            cd::grpc_unframe({reinterpret_cast<const char*>(s->body), s->body_len}, &m,
                             &used) == cd::GrpcFrame::kOk) {
            s->ready = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------
bool Conn::send_response_headers(Stream& s) noexcept {
    scratch_.clear();
    scratch_.push_back(static_cast<char>(0x88));    // :status 200 (static index 8)
    hpack_literal(&scratch_, "content-type", "application/grpc");
    assert(scratch_.size() < peer_max_frame_);
    return send_frame(kFrameHeaders, kFlagEndHeaders, s.id, scratch_.data(), scratch_.size());
}

bool Conn::send_trailers(Stream& s, GrpcCode code, std::string_view msg,
                         bool with_status_line) noexcept {
    if (s.reset || dead_) return false;
    scratch_.clear();
    if (with_status_line) {
        scratch_.push_back(static_cast<char>(0x88));
        hpack_literal(&scratch_, "content-type", "application/grpc");
    }
    char num[8];
    std::snprintf(num, sizeof(num), "%u", static_cast<unsigned>(code));
    hpack_literal(&scratch_, "grpc-status", num);
    if (!msg.empty()) {
        char enc[1024];
        const std::size_t n = cd::grpc_percent_encode(msg, enc, sizeof(enc));
        hpack_literal(&scratch_, "grpc-message", std::string_view(enc, n));
    }
    assert(scratch_.size() < kOurMaxFrame);
    return send_frame(kFrameHeaders, kFlagEndHeaders | kFlagEndStream, s.id,
                      scratch_.data(), scratch_.size());
}

bool Conn::wait_for_window(Stream& s) noexcept {
    for (int i = 0; i < kMaxFramesPerWait; ++i) {       // bounded
        if (dead_ || s.reset) return false;
        if (conn_send_window_ > 0 && s.send_window > 0) return true;
        if (!read_and_handle_frame()) return false;
    }
    return false;
}

bool Conn::send_message(Stream& s, std::string_view payload) noexcept {
    assert(payload.size() <= 0xFFFFFFFFu);
    std::uint8_t prefix[5];
    cd::grpc_frame_prefix(prefix, static_cast<std::uint32_t>(payload.size()));
    // Two logical pieces (prefix, payload) chunked into DATA frames as the
    // connection and stream windows allow.
    const std::string_view parts[2] = {
        {reinterpret_cast<const char*>(prefix), 5}, payload};
    std::size_t part = 0;
    std::size_t off = 0;
    std::vector<std::uint8_t>& buf = out_;
    const std::size_t total = 5 + payload.size();
    std::size_t sent = 0;
    while (sent < total) {                                  // bounded by total
        if (!wait_for_window(s)) return false;
        std::int64_t room = conn_send_window_ < s.send_window ? conn_send_window_
                                                              : s.send_window;
        const std::size_t max_frame = peer_max_frame_ < buf.size() ? peer_max_frame_
                                                                   : buf.size();
        std::size_t n = static_cast<std::size_t>(room) < max_frame
                            ? static_cast<std::size_t>(room) : max_frame;
        if (n > total - sent) n = total - sent;
        std::size_t filled = 0;
        while (filled < n) {                               // <= 2 parts
            const std::size_t take = (parts[part].size() - off) < (n - filled)
                                         ? parts[part].size() - off : n - filled;
            std::memcpy(buf.data() + filled, parts[part].data() + off, take);
            filled += take;
            off += take;
            if (off == parts[part].size()) { ++part; off = 0; }
        }
        if (!send_frame(kFrameData, 0, s.id, buf.data(), n)) return false;
        conn_send_window_ -= static_cast<std::int64_t>(n);
        s.send_window -= static_cast<std::int64_t>(n);
        sent += n;
    }
    assert(sent == total);
    return true;
}

// ---------------------------------------------------------------------------
// RPCs.
// ---------------------------------------------------------------------------
bool Conn::authorized(const Stream& s) noexcept {
    const std::string_view h(s.auth, s.auth_len);
    auto ieq_prefix = [&](std::string_view pfx) {
        if (h.size() < pfx.size()) return false;
        for (std::size_t i = 0; i < pfx.size(); ++i) {
            char c = h[i];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (c != pfx[i]) return false;
        }
        return true;
    };
    if (ieq_prefix("bearer ")) {
        return auth_.authenticate("bearer", {}, h.substr(7));
    }
    if (ieq_prefix("basic ")) {
        char dec[kAuthCap];
        std::size_t n = 0;
        if (!cd::base64_decode(h.substr(6), dec, sizeof(dec), &n)) return false;
        const std::string_view up(dec, n);
        const std::size_t colon = up.find(':');
        if (colon == std::string_view::npos) return false;
        return auth_.authenticate("basic", up.substr(0, colon), up.substr(colon + 1));
    }
    return auth_.authenticate("none", {}, {});
}

void Conn::dispatch(Stream& s) noexcept {
    assert(s.in_use);
    if (s.reset) return;
    if (!authorized(s)) {
        respond_error(s, GrpcCode::kUnauthenticated,
                      "authentication required: send an authorization header "
                      "(Bearer <token> or Basic <user:password>)");
        return;
    }
    if (s.overflow) {
        respond_error(s, GrpcCode::kResourceExhausted, "request message too large");
        return;
    }
    if (s.method == Method::kUnknown) {
        char m[224];
        std::snprintf(m, sizeof(m), "%s is not implemented by this Flight SQL endpoint",
                      s.path[0] != '\0' ? s.path : "(no :path)");
        respond_error(s, GrpcCode::kUnimplemented, m);
        return;
    }
    if (s.method == Method::kListFlights || s.method == Method::kListActions) {
        (void)send_trailers(s, GrpcCode::kOk, {}, true);   // empty stream
        return;
    }
    std::string_view msg;
    std::size_t used = 0;
    const cd::GrpcFrame fr = cd::grpc_unframe(
        {reinterpret_cast<const char*>(s.body), s.body_len}, &msg, &used);
    if (fr == cd::GrpcFrame::kCompressed) {
        respond_error(s, GrpcCode::kUnimplemented,
                      "compressed gRPC messages are not supported (identity only)");
        return;
    }
    if (fr != cd::GrpcFrame::kOk) {
        respond_error(s, GrpcCode::kInvalidArgument, "missing or malformed request message");
        return;
    }
    switch (s.method) {
        case Method::kHandshake: {
            // HandshakeResponse{protocol_version=1, payload=2}: echo the
            // request's fields back, no token exchange.
            if (!send_response_headers(s) || !send_message(s, msg)) return;
            (void)send_trailers(s, GrpcCode::kOk, {}, false);
            return;
        }
        case Method::kGetFlightInfo: rpc_get_flight_info(s, msg); return;
        case Method::kGetSchema:     rpc_get_schema(s, msg);      return;
        case Method::kDoGet:         rpc_do_get(s, msg);          return;
        default: break;
    }
    respond_error(s, GrpcCode::kInternal, "unrouted Flight method");
}

bool Conn::statement_from_descriptor(Stream& s, std::string_view msg,
                                     std::string_view* sql) noexcept {
    assert(sql != nullptr);
    cd::Descriptor d;
    if (!cd::decode_descriptor(msg, &d)) {
        respond_error(s, GrpcCode::kInvalidArgument, "malformed FlightDescriptor");
        return false;
    }
    if (d.type != 2) {
        respond_error(s, GrpcCode::kUnimplemented,
                      "only CMD FlightDescriptors (Flight SQL commands) are supported");
        return false;
    }
    cd::AnyMsg any;
    if (!cd::decode_any(d.cmd, &any)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "FlightDescriptor.cmd is not a google.protobuf.Any");
        return false;
    }
    if (any.type_name != "arrow.flight.protocol.sql.CommandStatementQuery") {
        char m[256];
        const std::string_view name = any.type_name.substr(0, 160);
        std::snprintf(m, sizeof(m),
                      "Flight SQL command %.*s is not supported yet; this endpoint "
                      "serves CommandStatementQuery only",
                      static_cast<int>(name.size()), name.data());
        respond_error(s, GrpcCode::kUnimplemented, m);
        return false;
    }
    std::string_view txn;
    if (!cd::decode_statement_query(any.value, sql, &txn)) {
        respond_error(s, GrpcCode::kInvalidArgument, "malformed CommandStatementQuery");
        return false;
    }
    if (!txn.empty()) {
        respond_error(s, GrpcCode::kUnimplemented, "transactions are not supported");
        return false;
    }
    return true;
}

bool Conn::run_query(Stream& s, std::string_view sql, std::int64_t* rows,
                     cd::IpcMessage* schema) noexcept {
    assert(rows != nullptr && schema != nullptr);
    if (sql.empty()) {
        respond_error(s, GrpcCode::kInvalidArgument, "empty query");
        return false;
    }
    if (sql.size() > kMaxQueryBytes) {
        respond_error(s, GrpcCode::kInvalidArgument, "query exceeds 65536 bytes");
        return false;
    }
    QueryFailure f;
    ipc_.clear();
    *rows = 0;
    if (!exec_.execute(sql, &ipc_, rows, f)) {
        respond_error(s, f.code, f.message != nullptr ? f.message : "query failed");
        return false;
    }
    std::size_t pos = 0;
    bool bad = false;
    if (!cd::ipc_next_message(ipc_, &pos, schema, &bad) ||
        schema->header_type != cd::kIpcHeaderSchema) {
        respond_error(s, GrpcCode::kInternal,
                      "executor produced an Arrow IPC stream without a leading schema");
        return false;
    }
    return true;
}

void Conn::rpc_get_flight_info(Stream& s, std::string_view msg) noexcept {
    std::string_view sql;
    if (!statement_from_descriptor(s, msg, &sql)) return;
    std::int64_t rows = 0;
    cd::IpcMessage schema;
    if (!run_query(s, sql, &rows, &schema)) return;
    // The ticket carries the statement itself; see flight_sql.h SCOPE.
    std::string handle;
    cd::pb_put_bytes(&handle, 1, sql);
    std::string ticket;
    cd::encode_any(&ticket, "TicketStatementQuery", handle);
    msg_.clear();
    cd::encode_flight_info(&msg_, schema.encapsulated, msg, ticket, rows);
    if (!send_response_headers(s) || !send_message(s, msg_)) return;
    (void)send_trailers(s, GrpcCode::kOk, {}, false);
}

void Conn::rpc_get_schema(Stream& s, std::string_view msg) noexcept {
    std::string_view sql;
    if (!statement_from_descriptor(s, msg, &sql)) return;
    std::int64_t rows = 0;
    cd::IpcMessage schema;
    if (!run_query(s, sql, &rows, &schema)) return;
    msg_.clear();
    cd::pb_put_bytes(&msg_, 1, schema.encapsulated);
    if (!send_response_headers(s) || !send_message(s, msg_)) return;
    (void)send_trailers(s, GrpcCode::kOk, {}, false);
}

void Conn::rpc_do_get(Stream& s, std::string_view msg) noexcept {
    std::string_view ticket;
    cd::AnyMsg any;
    std::string_view sql;
    if (!cd::decode_single_bytes(msg, &ticket) || !cd::decode_any(ticket, &any) ||
        any.type_name != "arrow.flight.protocol.sql.TicketStatementQuery" ||
        !cd::decode_single_bytes(any.value, &sql)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "ticket is not a TicketStatementQuery issued by this endpoint");
        return;
    }
    std::int64_t rows = 0;
    cd::IpcMessage m;
    if (!run_query(s, sql, &rows, &m)) return;
    if (!send_response_headers(s)) return;
    // ipc_ stays untouched while streaming: run_query is not re-entered.
    std::size_t pos = 0;
    bool bad = false;
    for (std::size_t i = 0; i < kMaxIpcMessages; ++i) {
        if (!cd::ipc_next_message(ipc_, &pos, &m, &bad)) break;
        msg_.clear();
        cd::encode_flight_data(&msg_, m.metadata, m.body);
        if (!send_message(s, msg_)) return;
    }
    if (bad) {
        (void)send_trailers(s, GrpcCode::kInternal, "malformed Arrow IPC stream", false);
        return;
    }
    (void)send_trailers(s, GrpcCode::kOk, {}, false);
}

}  // namespace

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------
class Listener {
public:
    Listener(std::string host, std::uint16_t port) noexcept
        : host_(std::move(host)), requested_port_(port) {
        assert(!host_.empty());
    }
    ~Listener() { stop(); }

    Status start() noexcept {
        assert(fd_.load(std::memory_order_acquire) < 0);
        net::sys::startup();
        const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd < 0) return Status(core::error_code::host_error);
        int on = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&on), sizeof(on));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(requested_port_);
        if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1 ||
            ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(fd, 128) != 0) {
            net::sys::close_socket(fd);
            return Status(core::error_code::host_error);
        }
        sockaddr_in actual{};
        socklen_t alen = sizeof(actual);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &alen) == 0) {
            port_.store(ntohs(actual.sin_port), std::memory_order_release);
        }
        fd_.store(fd, std::memory_order_release);
        assert(fd_.load(std::memory_order_acquire) >= 0);
        return ok_status();
    }

    void stop() noexcept {
        const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
        if (fd >= 0) net::sys::close_socket(fd);
    }

    std::uint16_t local_port() const noexcept { return port_.load(std::memory_order_acquire); }

    int accept_one(int timeout_ms) noexcept {
        assert(timeout_ms >= 0);
        const int fd = fd_.load(std::memory_order_acquire);
        if (fd < 0) return -1;
        if (wait_readable(fd, timeout_ms) <= 0) return -1;
        if (fd_.load(std::memory_order_acquire) < 0) return -1;
        const int c = static_cast<int>(::accept(fd, nullptr, nullptr));
        if (c >= 0) {
            int one = 1;
            (void)::setsockopt(c, IPPROTO_TCP, TCP_NODELAY,
                               reinterpret_cast<const char*>(&one), sizeof(one));
        }
        return c;
    }

private:
    std::string                host_;
    std::uint16_t              requested_port_;
    std::atomic<int>           fd_{-1};
    std::atomic<std::uint16_t> port_{0};
};

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------
Protocol::Protocol(const Config& cfg, IExecutorFactory& factory,
                   IAuthenticator* auth) noexcept
    : cfg_(cfg), factory_(factory), auth_(auth) {
    assert(cfg_.max_connections > 0);
    assert(cfg_.accept_poll_ms > 0);
}

Protocol::~Protocol() { stop(); }

std::uint16_t Protocol::local_port() const noexcept {
    return listener_ ? listener_->local_port() : 0;
}

void Protocol::worker_loop(IQueryExecutor& exec, std::uint16_t worker_id) noexcept {
    assert(worker_id < cfg_.max_connections);
    IAuthenticator& a = auth_ != nullptr ? *auth_ : default_auth_;
    auto conn = std::make_unique<Conn>(cfg_, exec, a, stopping_);
    while (!stopping_.load(std::memory_order_acquire)) {
        const int fd = listener_->accept_one(cfg_.accept_poll_ms);
        if (fd < 0) continue;
        conn->serve(fd);
        net::sys::close_socket(fd);
    }
}

Status Protocol::start_background() noexcept {
    if (listener_ != nullptr) return Status(core::error_code::invalid_state);
    listener_ = std::make_unique<Listener>(cfg_.host, cfg_.port);
    const Status s = listener_->start();
    if (s.is_err()) { listener_.reset(); return s; }
    assert(listener_->local_port() != 0);

    stopping_.store(false, std::memory_order_release);
    execs_.reserve(cfg_.max_connections);
    workers_.reserve(cfg_.max_connections);
    for (std::uint16_t k = 0; k < cfg_.max_connections; ++k) {   // bounded
        IQueryExecutor* e = factory_.create();
        if (e == nullptr) break;
        execs_.push_back(e);
        workers_.push_back(std::make_unique<core::StackedThread>(
            cfg_.worker_stack_bytes, [this, k, e]() noexcept { worker_loop(*e, k); }));
    }
    if (execs_.empty()) {
        listener_->stop();
        listener_.reset();
        return Status(core::error_code::internal_error);
    }
    running_.store(true, std::memory_order_release);
    return ok_status();
}

void Protocol::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (listener_ != nullptr) listener_->stop();
    for (auto& t : workers_) {
        if (t->joinable()) t->join();
    }
    workers_.clear();
    for (IQueryExecutor* e : execs_) factory_.destroy(e);
    execs_.clear();
    listener_.reset();
    running_.store(false, std::memory_order_release);
}

}  // namespace bolt::api::proto::flightsql

#endif  // BOLTAPI_WITH_FLIGHT_SQL
