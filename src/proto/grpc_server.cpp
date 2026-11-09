// src/proto/grpc_server.cpp — generic gRPC over h2c / TLS. See
// boltapi/proto/grpc_server.h. The HTTP/2 connection machinery follows
// flight_sql_server.cpp (same frame handling, flow control and TLS accept);
// what differs is that requests are routed to a host IService by path,
// bodies grow on demand to a configured cap, and short control calls can be
// dispatched while a streaming call is still sending.

#include "boltapi/proto/grpc_server.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include "boltapi/http/hpack.h"
#include "boltapi/net/sys_compat.h"
#include "boltapi/net/tls_context.h"
#include "boltapi/proto/flight_sql_codec.h"
#include "socket_wait.h"

#include <bolt/api/core/stacked_thread.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#if !defined(_WIN32)
#include <netinet/tcp.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace bolt::api::proto::grpc {

namespace cd = flightsql::codec;

namespace {

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

constexpr std::uint16_t kSettingsMaxConcurrent = 0x3;
constexpr std::uint16_t kSettingsInitialWindow = 0x4;
constexpr std::uint16_t kSettingsMaxFrameSize = 0x5;

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = 24;

constexpr std::uint32_t kMaxStreamsCap = 128;
constexpr std::size_t kOurMaxFrame = 16384;
constexpr std::size_t kHeaderBlockCap = 65536;
constexpr std::size_t kAuthCap = 4096;
constexpr std::size_t kPathCap = 256;
constexpr std::size_t kAgentCap = 256;
constexpr std::int64_t kDefaultWindow = 65535;
constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;
// Our receive window, advertised once at connection start: large requests
// (a client's Arrow payload) need not crawl at 64 KiB per round trip.
constexpr std::uint32_t kRecvWindow = 16u * 1024u * 1024u;
constexpr int kMaxFramesPerWait = 1 << 20;
constexpr int kMaxTlsRetries = 1024;
constexpr int kMaxPollFrames = 4096;
constexpr std::size_t kWriteCoalesce = 256u * 1024u;

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

void hpack_put_int(std::string* out, std::uint8_t first, int prefix_bits, std::size_t v) {
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

void hpack_literal(std::string* out, std::string_view name, std::string_view value) {
    out->push_back(0x00);
    hpack_put_int(out, 0x00, 7, name.size());
    out->append(name.data(), name.size());
    hpack_put_int(out, 0x00, 7, value.size());
    out->append(value.data(), value.size());
}

// grpc-timeout: 1..8 ASCII digits then one unit (H M S m u n).
std::int64_t parse_timeout_ms(std::string_view v) noexcept {
    if (v.size() < 2 || v.size() > 9) return -1;
    std::int64_t n = 0;
    for (std::size_t i = 0; i + 1 < v.size(); ++i) {
        if (v[i] < '0' || v[i] > '9') return -1;
        n = n * 10 + (v[i] - '0');
    }
    switch (v.back()) {
        case 'H': return n * 3600000;
        case 'M': return n * 60000;
        case 'S': return n * 1000;
        case 'm': return n;
        case 'u': return n / 1000;
        case 'n': return n / 1000000;
        default:  return -1;
    }
}

void copy_header(char* dst, std::size_t cap, std::size_t* len, std::string_view v) noexcept {
    assert(cap > 0);
    const std::size_t n = v.size() < cap - 1 ? v.size() : cap - 1;
    std::memcpy(dst, v.data(), n);
    dst[n] = '\0';
    if (len != nullptr) *len = n;
}

struct Stream {
    bool          in_use = false;
    bool          ready = false;
    bool          active = false;
    bool          reset = false;
    bool          overflow = false;
    bool          headers_sent = false;
    bool          finished = false;
    std::uint32_t id = 0;
    std::int64_t  send_window = kDefaultWindow;
    std::int64_t  timeout_ms = -1;
    std::size_t   path_len = 0;
    std::size_t   auth_len = 0;
    std::size_t   agent_len = 0;
    char          path[kPathCap] = {};
    char          auth[kAuthCap] = {};
    char          agent[kAgentCap] = {};
    std::string   body;
};

}  // namespace

bool next_message(std::string_view body, std::size_t* pos, std::string_view* msg,
                  bool* malformed) noexcept {
    assert(pos != nullptr && msg != nullptr && malformed != nullptr);
    *malformed = false;
    if (*pos >= body.size()) return false;
    std::size_t used = 0;
    const cd::GrpcFrame f = cd::grpc_unframe(body.substr(*pos), msg, &used);
    if (f != cd::GrpcFrame::kOk) {
        *malformed = true;
        return false;
    }
    *pos += used;
    assert(*pos <= body.size());
    return true;
}

// ---------------------------------------------------------------------------
// One HTTP/2 connection, reused by its worker across connections.
// ---------------------------------------------------------------------------
class Conn {
public:
    Conn(const Config& cfg, IService& svc, const std::atomic<bool>& stopping)
        : cfg_(cfg), svc_(svc), stopping_(stopping),
          max_streams_(cfg.max_streams < kMaxStreamsCap ? cfg.max_streams : kMaxStreamsCap),
          frame_(kOurMaxFrame), out_(kOurMaxFrame), hblock_(kHeaderBlockCap),
          streams_(max_streams_) {
        assert(max_streams_ > 0);
        headers_.reserve(128);
    }

    void serve(int fd, SSL* ssl) noexcept;

    // ---- responder surface ------------------------------------------------
    bool send_message(Stream& s, std::string_view payload) noexcept;
    void finish(Stream& s, Code code, std::string_view msg,
                std::string_view details = {}) noexcept;
    void poll() noexcept;
    bool stream_dead(const Stream& s) const noexcept { return dead_ || s.reset; }

private:
    bool read_exact(void* dst, std::size_t n) noexcept;
    ssize_t recv_some(std::uint8_t* p, std::size_t n) noexcept;
    bool write_all(const void* src, std::size_t n) noexcept;
    bool send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
                    const void* payload, std::size_t len) noexcept;
    bool flush() noexcept;
    void goaway(std::uint32_t err) noexcept {
        std::uint8_t p[8];
        put_be_u32(p, last_stream_id_);
        put_be_u32(p + 4, err);
        (void)send_frame(kFrameGoaway, 0, 0, p, 8);
        (void)flush();
        dead_ = true;
    }
    void window_update(std::uint32_t sid, std::uint32_t inc) noexcept {
        assert(inc > 0 && inc <= 0x7FFFFFFFu);
        std::uint8_t p[4];
        put_be_u32(p, inc);
        (void)send_frame(kFrameWindowUpdate, 0, sid, p, 4);
    }
    bool readable_now() noexcept {
        if (ssl_ != nullptr && SSL_pending(ssl_) > 0) return true;
        return ::bolt::api::proto::detail::wait_readable(fd_, 0) > 0;
    }

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
    Stream* alloc(std::uint32_t sid) noexcept;
    bool send_headers(Stream& s) noexcept;
    bool wait_for_window(Stream& s) noexcept;
    void dispatch(Stream& s) noexcept;
    void dispatch_ready(bool nestable_only) noexcept;

    const Config&            cfg_;
    IService&                svc_;
    const std::atomic<bool>& stopping_;
    const std::uint32_t      max_streams_;

    int           fd_ = -1;
    SSL*          ssl_ = nullptr;
    int           tls_retries_ = 0;
    int           idle_budget_ = 0;
    bool          dead_ = false;
    int           nest_depth_ = 0;
    std::uint32_t last_stream_id_ = 0;
    std::int64_t  conn_send_window_ = kDefaultWindow;
    std::int64_t  peer_initial_window_ = kDefaultWindow;
    std::size_t   peer_max_frame_ = kOurMaxFrame;

    std::uint32_t hblock_sid_ = 0;
    bool          hblock_end_stream_ = false;
    std::size_t   hblock_len_ = 0;

    std::vector<std::uint8_t>           frame_;
    std::vector<std::uint8_t>           out_;
    std::vector<std::uint8_t>           hblock_;
    std::vector<Stream>                 streams_;
    std::unique_ptr<http::HPACKDecoder> hpack_;
    std::vector<http::HPACKHeader>      headers_;
    std::string                         scratch_;
    std::string                         wbuf_;
};

namespace {

class StreamResponder final : public Responder {
public:
    StreamResponder(Conn& c, Stream& s) noexcept : c_(c), s_(s) {}
    bool send(std::string_view message) noexcept override {
        if (s_.finished) return false;
        const bool ok = c_.send_message(s_, message);
        if (ok) c_.poll();
        return ok && !c_.stream_dead(s_);
    }
    void finish(Code code, std::string_view message) noexcept override {
        c_.finish(s_, code, message);
    }
    void finish_with_details(Code code, std::string_view message,
                             std::string_view details) noexcept override {
        c_.finish(s_, code, message, details);
    }
    bool cancelled() const noexcept override { return c_.stream_dead(s_); }
    void poll() noexcept override { c_.poll(); }

private:
    Conn&   c_;
    Stream& s_;
};

}  // namespace

Stream* Conn::alloc(std::uint32_t sid) noexcept {
    for (auto& s : streams_) {
        if (!s.in_use) {
            std::string body = std::move(s.body);
            s = Stream{};
            s.body = std::move(body);
            s.body.clear();
            s.in_use = true;
            s.id = sid;
            s.send_window = peer_initial_window_;
            return &s;
        }
    }
    return nullptr;
}

bool Conn::read_exact(void* dst, std::size_t n) noexcept {
    assert(dst != nullptr || n == 0);
    if (!flush()) return false;
    auto* p = static_cast<std::uint8_t*>(dst);
    std::size_t got = 0;
    while (got < n) {
        if (stopping_.load(std::memory_order_acquire)) return false;
        const int ready = (ssl_ != nullptr && SSL_pending(ssl_) > 0)
                              ? 1 : ::bolt::api::proto::detail::wait_readable(fd_, cfg_.accept_poll_ms);
        if (ready < 0) return false;
        if (ready == 0) {
            idle_budget_ -= cfg_.accept_poll_ms;
            if (idle_budget_ <= 0) return false;
            continue;
        }
        const ssize_t r = recv_some(p + got, n - got);
        if (r < 0) return false;
        got += static_cast<std::size_t>(r);
    }
    idle_budget_ = cfg_.idle_timeout_ms;
    assert(got == n);
    return true;
}

ssize_t Conn::recv_some(std::uint8_t* p, std::size_t n) noexcept {
    assert(p != nullptr && n > 0);
    if (ssl_ == nullptr) {
        const ssize_t r = net::sys::recv_bytes(fd_, p, n);
        return r <= 0 ? -1 : r;
    }
    const int cap = n > 0x40000000u ? 0x40000000 : static_cast<int>(n);
    const int r = SSL_read(ssl_, p, cap);
    if (r > 0) { tls_retries_ = 0; return r; }
    const int e = SSL_get_error(ssl_, r);
    if ((e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) && ++tls_retries_ < kMaxTlsRetries) {
        return 0;
    }
    return -1;
}

bool Conn::write_all(const void* src, std::size_t n) noexcept {
    assert(src != nullptr || n == 0);
    const auto* p = static_cast<const std::uint8_t*>(src);
    std::size_t sent = 0;
    for (int retries = 0; sent < n;) {
        ssize_t w = 0;
        if (ssl_ == nullptr) {
            w = net::sys::send_bytes(fd_, p + sent, n - sent);
        } else {
            const std::size_t left = n - sent;
            const int r = SSL_write(ssl_, p + sent,
                                    left > 0x40000000u ? 0x40000000 : static_cast<int>(left));
            const int e = r > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl_, r);
            if (r <= 0 && (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) &&
                ++retries < kMaxTlsRetries) {
                continue;
            }
            w = r;
        }
        if (w <= 0) { dead_ = true; return false; }
        sent += static_cast<std::size_t>(w);
    }
    assert(sent == n);
    return true;
}

bool Conn::send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
                      const void* payload, std::size_t len) noexcept {
    assert(len <= 0xFFFFFFu);
    assert((sid & 0x80000000u) == 0);
    if (dead_) return false;
    std::uint8_t h[9];
    h[0] = static_cast<std::uint8_t>(len >> 16);
    h[1] = static_cast<std::uint8_t>(len >> 8);
    h[2] = static_cast<std::uint8_t>(len);
    h[3] = type;
    h[4] = flags;
    put_be_u32(h + 5, sid);
    // Frames coalesce in wbuf_ and leave in one write: before any read
    // (flush()) or once the buffer passes kWriteCoalesce.
    wbuf_.append(reinterpret_cast<const char*>(h), 9);
    if (len > 0) wbuf_.append(static_cast<const char*>(payload), len);
    return wbuf_.size() < kWriteCoalesce || flush();
}

bool Conn::flush() noexcept {
    if (wbuf_.empty()) return !dead_;
    const bool ok = write_all(wbuf_.data(), wbuf_.size());
    wbuf_.clear();
    return ok;
}

void Conn::serve(int fd, SSL* ssl) noexcept {
    assert(fd >= 0);
    fd_ = fd;
    ssl_ = ssl;
    tls_retries_ = 0;
    dead_ = false;
    nest_depth_ = 0;
    idle_budget_ = cfg_.idle_timeout_ms;
    last_stream_id_ = 0;
    conn_send_window_ = kDefaultWindow;
    peer_initial_window_ = kDefaultWindow;
    peer_max_frame_ = kOurMaxFrame;
    hblock_sid_ = 0;
    hblock_len_ = 0;
    for (auto& s : streams_) {
        s.in_use = false;
        s.body.clear();
        s.body.shrink_to_fit();
    }
    hpack_ = std::make_unique<http::HPACKDecoder>();
    wbuf_.clear();

    char preface[kPrefaceLen];
    if (!read_exact(preface, kPrefaceLen) || std::memcmp(preface, kPreface, kPrefaceLen) != 0) {
        return;
    }
    std::uint8_t settings[12];
    settings[0] = 0;
    settings[1] = static_cast<std::uint8_t>(kSettingsMaxConcurrent);
    put_be_u32(settings + 2, max_streams_);
    settings[6] = 0;
    settings[7] = static_cast<std::uint8_t>(kSettingsInitialWindow);
    put_be_u32(settings + 8, kRecvWindow);
    if (!send_frame(kFrameSettings, 0, 0, settings, sizeof(settings))) return;
    window_update(0, kRecvWindow - static_cast<std::uint32_t>(kDefaultWindow));

    while (!dead_ && !stopping_.load(std::memory_order_acquire)) {
        if (!read_and_handle_frame()) break;
        dispatch_ready(false);
    }
    for (auto& s : streams_) {
        if (s.body.capacity() > (1u << 20)) {
            s.body.clear();
            s.body.shrink_to_fit();
        }
    }
}

void Conn::dispatch_ready(bool nestable_only) noexcept {
    for (std::uint32_t k = 0; k < max_streams_ && !dead_; ++k) {
        Stream* next = nullptr;
        for (auto& s : streams_) {
            if (!s.in_use || !s.ready || s.active) continue;
            if (nestable_only && !svc_.nestable(std::string_view(s.path, s.path_len))) continue;
            if (next == nullptr || s.id < next->id) next = &s;
        }
        if (next == nullptr) return;
        next->ready = false;
        next->active = true;
        dispatch(*next);
        next->active = false;
        next->in_use = false;
        if (next->body.capacity() > (8u << 20)) {
            next->body.clear();
            next->body.shrink_to_fit();
        }
    }
}

void Conn::poll() noexcept {
    for (int i = 0; i < kMaxPollFrames && !dead_; ++i) {
        if (!readable_now()) break;
        if (!read_and_handle_frame()) break;
    }
    if (nest_depth_ == 0 && !dead_) {
        ++nest_depth_;
        dispatch_ready(true);
        --nest_depth_;
    }
}

bool Conn::read_and_handle_frame() noexcept {
    std::uint8_t h[9];
    if (!read_exact(h, 9)) { dead_ = true; return false; }
    const std::size_t len = (static_cast<std::size_t>(h[0]) << 16) |
                            (static_cast<std::size_t>(h[1]) << 8) | h[2];
    const std::uint8_t type = h[3];
    const std::uint8_t flags = h[4];
    const std::uint32_t sid = be_u32(h + 5) & 0x7FFFFFFFu;
    if (len > kOurMaxFrame) { goaway(kErrFrameSize); return false; }
    if (len > 0 && !read_exact(frame_.data(), len)) { dead_ = true; return false; }
    const std::uint8_t* p = frame_.data();

    if (hblock_sid_ != 0 && type != kFrameContinuation) {
        goaway(kErrProtocol);
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
                if (!s->active) s->in_use = false;
            }
            break;
        case kFrameGoaway:
            dead_ = true;
            break;
        default:
            break;
    }
    return !dead_;
}

void Conn::handle_settings(std::uint8_t flags, const std::uint8_t* p, std::size_t n) noexcept {
    if (flags & kFlagAck) return;
    if (n % 6 != 0) { goaway(kErrFrameSize); return; }
    for (std::size_t off = 0; off + 6 <= n; off += 6) {
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
    if (hpack_->decode(hblock_.data(), hblock_len_, headers_, 128) != 0) {
        goaway(kErrProtocol);
        return;
    }
    Stream* s = find(sid);
    if (s == nullptr) {
        if (sid <= last_stream_id_ || (sid & 1u) == 0) return;
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
                copy_header(s->path, kPathCap, &s->path_len, hh.value);
            } else if (hh.name == "authorization") {
                copy_header(s->auth, kAuthCap, &s->auth_len, hh.value);
            } else if (hh.name == "user-agent") {
                copy_header(s->agent, kAgentCap, &s->agent_len, hh.value);
            } else if (hh.name == "grpc-timeout") {
                s->timeout_ms = parse_timeout_ms(hh.value);
            }
        }
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
    if (s == nullptr || s->ready || s->active) return;
    if (s->body.size() + payload > cfg_.max_request_bytes) {
        s->overflow = true;
    } else if (!s->overflow) {
        s->body.append(reinterpret_cast<const char*>(p + off), payload);
    }
    if (end_stream) {
        s->ready = true;
    } else if (n > 0) {
        window_update(sid, static_cast<std::uint32_t>(n));
    }
}

bool Conn::send_headers(Stream& s) noexcept {
    if (s.headers_sent) return true;
    scratch_.clear();
    scratch_.push_back(static_cast<char>(0x88));
    hpack_literal(&scratch_, "content-type", "application/grpc");
    s.headers_sent = true;
    return send_frame(kFrameHeaders, kFlagEndHeaders, s.id, scratch_.data(), scratch_.size());
}

// RFC 4648 base64 without padding, as gRPC's -bin metadata.
static void base64_append(std::string* out, std::string_view in) {
    static constexpr char kAlpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto byte = [&in](std::size_t i) { return static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[i])); };
    std::size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        const std::uint32_t v = (byte(i) << 16) | (byte(i + 1) << 8) | byte(i + 2);
        out->push_back(kAlpha[(v >> 18) & 63]);
        out->push_back(kAlpha[(v >> 12) & 63]);
        out->push_back(kAlpha[(v >> 6) & 63]);
        out->push_back(kAlpha[v & 63]);
    }
    const std::size_t rest = in.size() - i;
    if (rest == 1) {
        const std::uint32_t v = byte(i) << 16;
        out->push_back(kAlpha[(v >> 18) & 63]);
        out->push_back(kAlpha[(v >> 12) & 63]);
    } else if (rest == 2) {
        const std::uint32_t v = (byte(i) << 16) | (byte(i + 1) << 8);
        out->push_back(kAlpha[(v >> 18) & 63]);
        out->push_back(kAlpha[(v >> 12) & 63]);
        out->push_back(kAlpha[(v >> 6) & 63]);
    }
}

void Conn::finish(Stream& s, Code code, std::string_view msg, std::string_view details) noexcept {
    if (s.finished) return;
    s.finished = true;
    if (s.reset || dead_) return;
    scratch_.clear();
    if (!s.headers_sent) {
        scratch_.push_back(static_cast<char>(0x88));
        hpack_literal(&scratch_, "content-type", "application/grpc");
        s.headers_sent = true;
    }
    char num[8];
    std::snprintf(num, sizeof(num), "%u", static_cast<unsigned>(code));
    hpack_literal(&scratch_, "grpc-status", num);
    if (!msg.empty()) {
        char enc[2048];
        const std::size_t n = cd::grpc_percent_encode(msg, enc, sizeof(enc));
        hpack_literal(&scratch_, "grpc-message", std::string_view(enc, n));
    }
    if (!details.empty() && details.size() <= 8192) {
        std::string b64;
        b64.reserve(details.size() * 4 / 3 + 4);
        base64_append(&b64, details);
        hpack_literal(&scratch_, "grpc-status-details-bin", b64);
    }
    assert(scratch_.size() < kOurMaxFrame);
    (void)send_frame(kFrameHeaders, kFlagEndHeaders | kFlagEndStream, s.id, scratch_.data(),
                     scratch_.size());
    (void)flush();
}

bool Conn::wait_for_window(Stream& s) noexcept {
    for (int i = 0; i < kMaxFramesPerWait; ++i) {
        if (dead_ || s.reset) return false;
        if (conn_send_window_ > 0 && s.send_window > 0) return true;
        if (!read_and_handle_frame()) return false;
    }
    return false;
}

bool Conn::send_message(Stream& s, std::string_view payload) noexcept {
    assert(payload.size() <= 0xFFFFFFFFu);
    if (!send_headers(s)) return false;
    std::uint8_t prefix[5];
    cd::grpc_frame_prefix(prefix, static_cast<std::uint32_t>(payload.size()));
    const std::string_view parts[2] = {{reinterpret_cast<const char*>(prefix), 5}, payload};
    std::size_t part = 0;
    std::size_t off = 0;
    const std::size_t total = 5 + payload.size();
    std::size_t sent = 0;
    while (sent < total) {
        if (!wait_for_window(s)) return false;
        const std::int64_t room = conn_send_window_ < s.send_window ? conn_send_window_
                                                                    : s.send_window;
        const std::size_t max_frame = peer_max_frame_ < out_.size() ? peer_max_frame_ : out_.size();
        std::size_t n = static_cast<std::size_t>(room) < max_frame ? static_cast<std::size_t>(room)
                                                                   : max_frame;
        if (n > total - sent) n = total - sent;
        std::size_t filled = 0;
        while (filled < n) {
            const std::size_t take = (parts[part].size() - off) < (n - filled)
                                         ? parts[part].size() - off : n - filled;
            std::memcpy(out_.data() + filled, parts[part].data() + off, take);
            filled += take;
            off += take;
            if (off == parts[part].size()) { ++part; off = 0; }
        }
        if (!send_frame(kFrameData, 0, s.id, out_.data(), n)) return false;
        conn_send_window_ -= static_cast<std::int64_t>(n);
        s.send_window -= static_cast<std::int64_t>(n);
        sent += n;
    }
    assert(sent == total);
    return true;
}

void Conn::dispatch(Stream& s) noexcept {
    assert(s.in_use && s.active);
    if (s.reset) return;
    StreamResponder r(*this, s);
    if (s.overflow) {
        r.finish(Code::kResourceExhausted,
                 "request larger than the server's max_request_bytes");
        return;
    }
    Call call;
    call.method = std::string_view(s.path, s.path_len);
    call.authorization = std::string_view(s.auth, s.auth_len);
    call.user_agent = std::string_view(s.agent, s.agent_len);
    call.timeout_ms = s.timeout_ms;
    call.body = s.body;
    svc_.handle(call, r);
    if (!s.finished) r.finish(Code::kInternal, "handler returned without a status");
    assert(s.finished);
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------
class Listener {
public:
    Listener(std::string host, std::uint16_t port, std::string unix_path) noexcept
        : host_(std::move(host)), unix_path_(std::move(unix_path)), requested_port_(port) {}
    ~Listener() { stop(); }

    Status start() noexcept {
        net::sys::startup();
        if (!unix_path_.empty()) return start_unix();
        const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd < 0) return Status(core::error_code::host_error);
        int on = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&on),
                           sizeof(on));
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
        return Status();
    }

    void stop() noexcept {
        const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
        if (fd >= 0) net::sys::close_socket(fd);
#if !defined(_WIN32)
        if (fd >= 0 && !unix_path_.empty()) (void)::unlink(unix_path_.c_str());
#endif
    }

    std::uint16_t local_port() const noexcept { return port_.load(std::memory_order_acquire); }

    Status start_unix() noexcept {
#if defined(_WIN32)
        return Status(core::error_code::host_error);
#else
        sockaddr_un addr{};
        if (unix_path_.size() >= sizeof(addr.sun_path)) return Status(core::error_code::host_error);
        const int fd = static_cast<int>(::socket(AF_UNIX, SOCK_STREAM, 0));
        if (fd < 0) return Status(core::error_code::host_error);
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, unix_path_.c_str(), unix_path_.size() + 1);
        (void)::unlink(unix_path_.c_str());
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(fd, 128) != 0) {
            net::sys::close_socket(fd);
            return Status(core::error_code::host_error);
        }
        port_.store(0, std::memory_order_release);
        fd_.store(fd, std::memory_order_release);
        return Status();
#endif
    }

    int accept_one(int timeout_ms) noexcept {
        const int fd = fd_.load(std::memory_order_acquire);
        if (fd < 0) return -1;
        if (::bolt::api::proto::detail::wait_readable(fd, timeout_ms) <= 0) return -1;
        if (fd_.load(std::memory_order_acquire) < 0) return -1;
        const int c = static_cast<int>(::accept(fd, nullptr, nullptr));
        if (c >= 0 && unix_path_.empty()) {
            int one = 1;
            (void)::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one),
                               sizeof(one));
        }
        return c;
    }

private:
    std::string                host_;
    std::string                unix_path_;
    std::uint16_t              requested_port_;
    std::atomic<int>           fd_{-1};
    std::atomic<std::uint16_t> port_{0};
};

namespace {

SSL* tls_accept(SSL_CTX* ctx, int fd, int timeout_ms) noexcept {
    assert(ctx != nullptr && fd >= 0);
#if defined(_WIN32)
    const DWORD tv = static_cast<DWORD>(timeout_ms);
#else
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#endif
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    SSL* ssl = SSL_new(ctx);
    if (ssl == nullptr) return nullptr;
    if (SSL_set_fd(ssl, fd) != 1 || SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        return nullptr;
    }
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &len);
    if (len != 2 || std::memcmp(proto, "h2", 2) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

}  // namespace

Server::Server(const Config& cfg, IServiceFactory& factory) noexcept
    : cfg_(cfg), factory_(factory) {
    assert(cfg_.max_connections > 0);
    assert(cfg_.accept_poll_ms > 0);
}

Server::~Server() { stop(); }

std::uint16_t Server::local_port() const noexcept {
    return listener_ ? listener_->local_port() : 0;
}

void Server::worker_loop(IService& svc, std::uint16_t worker_id) noexcept {
    assert(worker_id < cfg_.max_connections);
    auto conn = std::make_unique<Conn>(cfg_, svc, stopping_);
    SSL_CTX* ctx = tls_ != nullptr ? tls_->get_ssl_ctx() : nullptr;
    while (!stopping_.load(std::memory_order_acquire)) {
        const int fd = listener_->accept_one(cfg_.accept_poll_ms);
        if (fd < 0) continue;
        SSL* ssl = ctx != nullptr ? tls_accept(ctx, fd, 30000) : nullptr;
        if (ctx == nullptr || ssl != nullptr) conn->serve(fd, ssl);
        if (ssl != nullptr) {
            (void)SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        net::sys::close_socket(fd);
    }
}

Status Server::start_background() noexcept {
    if (listener_ != nullptr) return Status(core::error_code::invalid_state);
    if (cfg_.tls_enabled()) {
        net::TlsContextConfig tc;
        tc.cert_file = cfg_.tls_cert_file;
        tc.key_file = cfg_.tls_key_file;
        tc.cert_data = cfg_.tls_cert_pem;
        tc.key_data = cfg_.tls_key_pem;
        tc.alpn_protocols = {"h2"};
        tls_ = net::TlsContext::create_server(tc);
        if (tls_ == nullptr || !tls_->is_valid()) {
            tls_.reset();
            return Status(core::error_code::invalid_state);
        }
    }
    listener_ = std::make_unique<Listener>(cfg_.host, cfg_.port, cfg_.unix_path);
    const Status s = listener_->start();
    if (s.is_err()) { listener_.reset(); return s; }

    stopping_.store(false, std::memory_order_release);
    services_.reserve(cfg_.max_connections);
    workers_.reserve(cfg_.max_connections);
    for (std::uint16_t k = 0; k < cfg_.max_connections; ++k) {
        IService* e = factory_.create();
        if (e == nullptr) break;
        services_.push_back(e);
        workers_.push_back(std::make_unique<core::StackedThread>(
            cfg_.worker_stack_bytes, [this, k, e]() noexcept { worker_loop(*e, k); }));
    }
    if (services_.empty()) {
        listener_->stop();
        listener_.reset();
        return Status(core::error_code::internal_error);
    }
    running_.store(true, std::memory_order_release);
    return Status();
}

void Server::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (listener_ != nullptr) listener_->stop();
    for (auto& t : workers_) {
        if (t->joinable()) t->join();
    }
    workers_.clear();
    for (IService* e : services_) factory_.destroy(e);
    services_.clear();
    listener_.reset();
    tls_.reset();
    running_.store(false, std::memory_order_release);
}

}  // namespace bolt::api::proto::grpc

#endif  // BOLTAPI_WITH_FLIGHT_SQL
