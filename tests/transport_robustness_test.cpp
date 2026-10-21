// transport_robustness_test.cpp — G2ETL-114 regressions on a real server:
//   * a TLS response larger than the socket send buffer reaches a slow reader
//     intact (TlsSocket used to drop records a would-block send left behind);
//   * a client that resets mid-response costs one connection, not the process
//     (writes raised SIGPIPE, exit 141);
//   * an HTTP/2 response larger than one frame and one flow-control window is
//     framed to SETTINGS_MAX_FRAME_SIZE and paced by WINDOW_UPDATE, over h2c
//     (prior knowledge) and TLS (ALPN h2).

#include "boltapi/app.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPlainPort = 19471;
constexpr uint16_t kTlsPort = 19472;
constexpr std::size_t kBodySize = 3u * 1024u * 1024u;
constexpr int kMaxIo = 4'000'000;

const std::string& big_body() {
    static const std::string* body = [] {
        auto* s = new std::string();
        s->reserve(kBodySize);
        for (std::size_t i = 0; i < kBodySize; ++i) {
            s->push_back(static_cast<char>('a' + (i * 13 + i / 5000) % 26));
        }
        return s;
    }();
    return *body;
}

// One client connection, cleartext or TLS (blocking socket, small receive
// buffer so the server's writes go partial).
struct Conn {
    int fd = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    bool open(uint16_t port, bool tls, const char* alpn) {
        fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd < 0) return false;
        int rcv = 16 * 1024;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcv), sizeof(rcv));
#ifdef _WIN32
        DWORD tv = 10000;
#else
        timeval tv{10, 0};
#endif
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        if (!tls) return true;
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == nullptr) return false;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);  // self-signed test cert
        ssl = SSL_new(ctx);
        if (alpn != nullptr) {
            const std::size_t n = std::strlen(alpn);
            std::vector<unsigned char> wire(1 + n);
            wire[0] = static_cast<unsigned char>(n);
            std::memcpy(wire.data() + 1, alpn, n);
            SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned>(wire.size()));
        }
        SSL_set_fd(ssl, fd);
        return SSL_connect(ssl) == 1;
    }
    bool send_all(const void* p, std::size_t n) {
        const char* c = static_cast<const char*>(p);
        std::size_t off = 0;
        for (int i = 0; i < kMaxIo && off < n; ++i) {
            const int w = ssl ? SSL_write(ssl, c + off, static_cast<int>(n - off))
                              : static_cast<int>(sys::send_bytes(fd, c + off, n - off));
            if (w <= 0) return false;
            off += static_cast<std::size_t>(w);
        }
        return off == n;
    }
    int recv_some(char* p, std::size_t n) {
        return ssl ? SSL_read(ssl, p, static_cast<int>(n))
                   : static_cast<int>(sys::recv_bytes(fd, p, n));
    }
    bool recv_exact(void* p, std::size_t n) {
        char* c = static_cast<char*>(p);
        std::size_t off = 0;
        for (int i = 0; i < kMaxIo && off < n; ++i) {
            const int r = recv_some(c + off, n - off);
            if (r <= 0) return false;
            off += static_cast<std::size_t>(r);
        }
        return off == n;
    }
    void reset() {  // RST: SO_LINGER 0, then close without a TLS close_notify
        linger lg{1, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
        close();
    }
    void close() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        ssl = nullptr;
        ctx = nullptr;
        if (fd >= 0) sys::close_socket(fd);
        fd = -1;
    }
    ~Conn() { close(); }
};

std::string http1_get(uint16_t port, bool tls, const char* path, bool slow) {
    Conn c;
    if (!c.open(port, tls, tls ? "http/1.1" : nullptr)) return {};
    std::string req = std::string("GET ") + path +
                      " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    if (!c.send_all(req.data(), req.size())) return {};
    if (slow) std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::string out;
    char tmp[8192];
    for (int i = 0; i < kMaxIo; ++i) {
        const int n = c.recv_some(tmp, sizeof(tmp));
        if (n <= 0) break;
        out.append(tmp, static_cast<std::size_t>(n));
        if (slow && (i & 63) == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        if (out.size() > 2 * kBodySize) break;
    }
    return out;
}

std::string body_of(const std::string& raw) {
    const std::size_t he = raw.find("\r\n\r\n");
    return he == std::string::npos ? std::string() : raw.substr(he + 4);
}

void put_frame(std::string& out, uint8_t type, uint8_t flags, uint32_t sid, const std::string& p) {
    const uint32_t n = static_cast<uint32_t>(p.size());
    const char h[9] = {static_cast<char>(n >> 16), static_cast<char>(n >> 8), static_cast<char>(n),
                       static_cast<char>(type), static_cast<char>(flags),
                       static_cast<char>(sid >> 24), static_cast<char>(sid >> 16),
                       static_cast<char>(sid >> 8), static_cast<char>(sid)};
    out.append(h, 9);
    out += p;
}

std::string u32(uint32_t v) {
    const char b[4] = {static_cast<char>(v >> 24), static_cast<char>(v >> 16),
                       static_cast<char>(v >> 8), static_cast<char>(v)};
    return std::string(b, 4);
}

// GET /big over HTTP/2 with the default 65535 windows: the client credits
// the windows only after it has consumed DATA, so the server must stop at the
// window edge and resume on WINDOW_UPDATE. Returns the reassembled body.
std::string h2_get_big(uint16_t port, bool tls, std::size_t* max_frame, bool* window_ok) {
    Conn c;
    if (!c.open(port, tls, tls ? "h2" : nullptr)) return {};
    std::string out = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    put_frame(out, 4, 0, 0, "");  // SETTINGS, all defaults
    // :method GET, :scheme http|https, :path "/big" (literal, indexed name 4).
    std::string hb = tls ? "\x82\x87" : "\x82\x86";
    hb += "\x04\x04/big";
    put_frame(out, 1, 0x5, 1, hb);  // HEADERS END_STREAM|END_HEADERS
    if (!c.send_all(out.data(), out.size())) return {};
    std::string body;
    int64_t conn_window = 65535, stream_window = 65535;
    *max_frame = 0;
    *window_ok = true;
    for (int i = 0; i < kMaxIo; ++i) {
        unsigned char h[9];
        if (!c.recv_exact(h, 9)) return {};
        const uint32_t len = (uint32_t(h[0]) << 16) | (uint32_t(h[1]) << 8) | h[2];
        std::string p(len, '\0');
        if (len > 0 && !c.recv_exact(p.data(), len)) return {};
        if (h[3] == 7 || h[3] == 3) return {};  // GOAWAY / RST_STREAM
        if (h[3] == 4 && (h[4] & 1) == 0) {     // server SETTINGS: ack it
            std::string ack;
            put_frame(ack, 4, 1, 0, "");
            if (!c.send_all(ack.data(), ack.size())) return {};
        }
        if (h[3] != 0) continue;
        *max_frame = std::max<std::size_t>(*max_frame, len);
        conn_window -= len;
        stream_window -= len;
        if (conn_window < 0 || stream_window < 0) *window_ok = false;
        body += p;
        if (h[4] & 1) return body;  // END_STREAM
        if (len > 0) {              // credit what we consumed
            std::string wu;
            put_frame(wu, 8, 0, 0, u32(len));
            put_frame(wu, 8, 0, 1, u32(len));
            conn_window += len;
            stream_window += len;
            if (!c.send_all(wu.data(), wu.size())) return {};
        }
    }
    return {};
}

class TransportRobustness : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        (void)big_body();
        api::App::Config cfg;
        cfg.server.enable_tls = true;
        cfg.server.tls_port = kTlsPort;
        cfg.server.host = "127.0.0.1";
        app_ = new api::App(cfg);
        app_->get("/big", [](api::Request&, api::Response& res) { res.ok().text(big_body()); });
        app_->get("/ping", [](api::Request&, api::Response& res) { res.ok().text("pong"); });
        app_->sse_coro("/events",
            [](bolt::api::net::IODispatcher& io, int fd, const bolt::api::http::CoroHttpRequest&)
                -> bolt::api::core::coro_task<void> {
                bolt::api::http::SSEWriter sse(io, fd);
                if (!co_await sse.send_event("tick", "a\r\nb", "1")) co_return;
                // A line break in the event type would forge a field: refused.
                if (co_await sse.send_event("tick\nevent: forged", "x", "2")) co_return;
                co_await sse.send_event("", std::string(100000, 's'), "3");
            });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPlainPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
    static void TearDownTestSuite() {
        if (app_ != nullptr) {
            app_->stop();
            delete app_;
            app_ = nullptr;
        }
    }
    static api::App* app_;
};

api::App* TransportRobustness::app_ = nullptr;

TEST_F(TransportRobustness, TlsSlowReaderGetsWholeBody) {
    const std::string body = body_of(http1_get(kTlsPort, true, "/big", true));
    ASSERT_EQ(body.size(), kBodySize);
    EXPECT_TRUE(body == big_body());
}

TEST_F(TransportRobustness, PeerResetMidResponseKeepsServerUp) {
    for (bool tls : {false, true, false, true}) {
        Conn c;
        ASSERT_TRUE(c.open(tls ? kTlsPort : kPlainPort, tls, tls ? "http/1.1" : nullptr));
        const std::string req = "GET /big HTTP/1.1\r\nHost: x\r\n\r\n";
        ASSERT_TRUE(c.send_all(req.data(), req.size()));
        char one[1];
        ASSERT_GT(c.recv_some(one, 1), 0);
        c.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    EXPECT_EQ(body_of(http1_get(kPlainPort, false, "/ping", false)), "pong");
    EXPECT_EQ(body_of(http1_get(kTlsPort, true, "/ping", false)), "pong");
}

// SSE over TLS: SSEWriter(io, fd) must write through the TLS socket (it used
// to write cleartext into the TLS stream).
TEST_F(TransportRobustness, SseOverTlsIsEncryptedAndFramed) {
    Conn c;
    ASSERT_TRUE(c.open(kTlsPort, true, "http/1.1"));
    const std::string req = "GET /events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n";
    ASSERT_TRUE(c.send_all(req.data(), req.size()));
    std::string raw;
    char tmp[8192];
    for (int i = 0; i < kMaxIo && raw.find("id: 3") == std::string::npos; ++i) {
        const int n = c.recv_some(tmp, sizeof(tmp));
        if (n <= 0) break;
        raw.append(tmp, static_cast<std::size_t>(n));
    }
    for (int i = 0; i < kMaxIo && raw.size() < 100000; ++i) {
        const int n = c.recv_some(tmp, sizeof(tmp));
        if (n <= 0) break;
        raw.append(tmp, static_cast<std::size_t>(n));
    }
    const std::string body = body_of(raw);
    EXPECT_EQ(body.rfind("id: 1\nevent: tick\ndata: a\ndata: b\n\n", 0), 0u) << body.substr(0, 200);
    EXPECT_EQ(body.find("forged"), std::string::npos);
    EXPECT_NE(body.find("id: 3\ndata: " + std::string(100000, 's') + "\n\n"), std::string::npos);
}

TEST_F(TransportRobustness, H2cLargeResponseIsFramedAndFlowControlled) {
    std::size_t max_frame = 0;
    bool window_ok = false;
    const std::string body = h2_get_big(kPlainPort, false, &max_frame, &window_ok);
    ASSERT_EQ(body.size(), kBodySize);
    EXPECT_TRUE(body == big_body());
    EXPECT_LE(max_frame, 16384u);
    EXPECT_TRUE(window_ok);
}

TEST_F(TransportRobustness, H2OverTlsLargeResponseIsFramedAndFlowControlled) {
    std::size_t max_frame = 0;
    bool window_ok = false;
    const std::string body = h2_get_big(kTlsPort, true, &max_frame, &window_ok);
    ASSERT_EQ(body.size(), kBodySize);
    EXPECT_TRUE(body == big_body());
    EXPECT_LE(max_frame, 16384u);
    EXPECT_TRUE(window_ok);
}

constexpr uint16_t kFixedPlainPort = 19473, kFixedTlsPort = 19474;
constexpr std::size_t kMaterializationCap = 16;
struct FixedCase {
    const char* path;
    uint64_t declared;
    const char* first;
    const char* second;
    uint16_t expected_status;
    const char* expected_body;
};
constexpr std::array<FixedCase, 6> kFixedCases{{
    {"/below", 15, "0123456789abcde", "", 207, "0123456789abcde"},
    {"/at", 16, "0123456789abcdef", "", 207, "0123456789abcdef"},
    {"/above", 17, "MUST-NOT-RUN", "", 500, ""},
    {"/short", 16, "SHORT", "", 500, ""},
    {"/over", 16, "0123456789", "OVERRUN-SENTINEL", 500, ""},
    {"/empty", 0, "", "", 207, ""},
}};
std::array<std::atomic<unsigned>, kFixedCases.size()> g_fixed_calls{};
std::atomic<unsigned> g_bodyless_calls{0};

struct H2Reply {
    uint16_t status = 0;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
    unsigned data_events = 0, data_frames = 0;
    bool complete = false, reset = false;
    std::string header(std::string_view name) const {
        for (const auto& field : headers) if (field.first == name) return field.second;
        return {};
    }
};

// Use the native client decoder: status/headers and completion are checked,
// rather than treating every DATA body (including a successful error) as 200.
class FixedH2Session {
public:
    bool open(bool tls) {
        if (!wire_.open(tls ? kFixedTlsPort : kFixedPlainPort, tls, tls ? "h2" : nullptr)) return false;
        if (tls) {
            const unsigned char* protocol = nullptr;
            unsigned length = 0;
            SSL_get0_alpn_selected(wire_.ssl, &protocol, &length);
            if (length != 2 || std::memcmp(protocol, "h2", 2) != 0) return false;
        }
        tls_ = tls;
        client_.set_response_callback([this](const auto& event) {
            if (event.stream_id != wanted_) return;
            using Kind = api::http2::Http2Connection::ResponseEventKind;
            if (event.kind == Kind::Headers) {
                reply_.status = event.status;
                for (std::size_t i = 0; i < event.header_count; ++i)
                    reply_.headers.emplace_back(event.headers[i].name, event.headers[i].value);
            } else if (event.kind == Kind::Data) {
                reply_.body.append(event.data);
                ++reply_.data_events;
            } else if (event.kind == Kind::Complete) reply_.complete = true;
            else if (event.kind == Kind::Reset) reply_.reset = true;
        });
        return flush();
    }
    bool request(const char* method, const char* path, H2Reply& reply) {
        reply_ = H2Reply{};
        const std::array<api::http::HPACKHeader, 4> fields{{
            {":method", method}, {":scheme", tls_ ? "https" : "http"},
            {":path", path}, {":authority", "localhost"}}};
        const auto sent = client_.send_request(fields.data(), fields.size());
        if (sent.is_err()) return false;
        wanted_ = sent.value();
        if (!flush()) return false;
        for (unsigned i = 0; i < 128 && !reply_.complete && !reply_.reset; ++i) {
            std::array<uint8_t, 9 + api::http2::Http2Connection::kLocalMaxFrameSize> frame{};
            if (!wire_.recv_exact(frame.data(), 9)) return false;
            const auto parsed = api::http2::parse_frame_header(frame.data());
            if (parsed.is_err() || parsed.value().length > api::http2::Http2Connection::kLocalMaxFrameSize) return false;
            const auto& header = parsed.value();
            if (header.length > 0 && !wire_.recv_exact(frame.data() + 9, header.length)) return false;
            if (header.type == api::http2::FrameType::DATA && header.stream_id == wanted_)
                ++reply_.data_frames; // includes empty DATA, independently of callbacks
            const std::size_t size = 9 + header.length;
            const auto read = client_.process_input(frame.data(), size);
            if (read.is_err() || read.value() != size || !flush()) return false;
        }
        reply = reply_;
        return reply.complete && !reply.reset;
    }
private:
    bool flush() {
        for (unsigned i = 0; i < 128; ++i) {
            const uint8_t* data = nullptr;
            std::size_t size = 0;
            if (!client_.get_output(&data, &size)) return true;
            if (!wire_.send_all(data, size)) return false;
            client_.commit_output(size);
        }
        return false;
    }
    Conn wire_;
    api::http2::Http2Connection client_{false};
    H2Reply reply_;
    uint32_t wanted_ = 0;
    bool tls_ = false;
};

class FixedMaterialization : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        api::App::Config cfg;
        cfg.server.enable_tls = true;
        cfg.server.tls_port = kFixedTlsPort;
        cfg.server.num_workers = 1;
        cfg.server.num_streaming_workers = 2;
        cfg.server.max_fixed_materialization_bytes = kMaterializationCap;
        app_ = new api::App(cfg);
        for (std::size_t i = 0; i < kFixedCases.size(); ++i) {
            app_->get(kFixedCases[i].path, [i](api::Request&, api::Response& res) {
                const FixedCase& c = kFixedCases[i];
                res.status(207).header("Content-Range", "bytes 0-15/100")
                    .header("Content-Encoding", "gzip").header("ETag", "old-representation")
                    .send_fixed(c.declared, [i](const api::Response::StreamSink& sink) {
                        g_fixed_calls[i].fetch_add(1);
                        sink(kFixedCases[i].first);
                        sink(kFixedCases[i].second);
                        if (i == 4) sink("abcdef"); // must stay refused after overrun
                    });
            });
        }
        for (const uint16_t status : std::array<uint16_t, 3>{200, 204, 304}) {
            const std::string path = "/bodyless" + std::to_string(status);
            const auto handler = [status](api::Request&, api::Response& res) {
                res.status(status).send_fixed(17, [](const api::Response::StreamSink& sink) {
                    g_bodyless_calls.fetch_add(1);
                    sink("MUST-NOT-RUN");
                });
                if (status == 204) {
                    res.raw().headers.append("content-length", "17");
                    res.raw().headers.append("transfer-encoding", "chunked");
                }
            };
            app_->head(path, handler);
            if (status != 200) app_->get(path, handler);
        }
        app_->head("/bodylessfull", [](api::Request&, api::Response& res) {
            for (std::size_t i = 0; i < api::http::CoroResponseHeaders::MAX_RESPONSE_HEADERS; ++i)
                res.raw().headers.append("X-Fill-" + std::to_string(i), "x");
            res.send_fixed(17, [](const api::Response::StreamSink& sink) {
                g_bodyless_calls.fetch_add(1);
                sink("MUST-NOT-RUN");
            });
        });
        app_->get("/ok", [](api::Request&, api::Response& res) { res.status(207).text("CHECK"); });
        ASSERT_EQ(app_->start_background("127.0.0.1", kFixedPlainPort), 0);
    }
    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }
    static api::App* app_;
};
api::App* FixedMaterialization::app_ = nullptr;

void expect_h2_materialization(bool tls) {
    FixedH2Session session;
    ASSERT_TRUE(session.open(tls));
    for (std::size_t i = 0; i < kFixedCases.size(); ++i) {
        SCOPED_TRACE(kFixedCases[i].path);
        const unsigned before = g_fixed_calls[i].load();
        H2Reply reply;
        ASSERT_TRUE(session.request("GET", kFixedCases[i].path, reply));
        EXPECT_EQ(reply.status, kFixedCases[i].expected_status);
        EXPECT_EQ(reply.body, kFixedCases[i].expected_body);
        EXPECT_EQ(g_fixed_calls[i].load(), before + (i == 2 ? 0u : 1u));
        if (reply.status == 500) {
            EXPECT_EQ(reply.header("content-length"), "0");
            EXPECT_TRUE(reply.header("content-range").empty());
            EXPECT_TRUE(reply.header("content-encoding").empty());
            EXPECT_TRUE(reply.header("etag").empty());
        }
        ASSERT_TRUE(session.request("GET", "/ok", reply));
        EXPECT_EQ(reply.status, 207);
        EXPECT_EQ(reply.body, "CHECK");
    }
}

TEST_F(FixedMaterialization, H2cValidatesFixedBodiesBeforeSuccessHeaders) {
    expect_h2_materialization(false);
}

TEST_F(FixedMaterialization, AlpnH2ValidatesFixedBodiesBeforeSuccessHeaders) {
    expect_h2_materialization(true);
}

TEST_F(FixedMaterialization, BodylessH2SkipsProducerAndCapBeforeHeaders) {
    for (const bool tls : {false, true}) {
        FixedH2Session session;
        ASSERT_TRUE(session.open(tls));
        for (const uint16_t status : std::array<uint16_t, 3>{200, 204, 304}) {
            SCOPED_TRACE(status);
            const unsigned before = g_bodyless_calls.load();
            H2Reply reply;
            const std::string path = "/bodyless" + std::to_string(status);
            ASSERT_TRUE(session.request(status == 200 ? "HEAD" : "GET", path.c_str(), reply));
            EXPECT_EQ(reply.status, status);
            EXPECT_TRUE(reply.body.empty());
            EXPECT_EQ(reply.data_events, 0u);
            EXPECT_EQ(reply.data_frames, 0u);
            EXPECT_EQ(reply.header("content-length"), status == 204 ? "" : "17");
            EXPECT_TRUE(reply.header("transfer-encoding").empty());
            EXPECT_EQ(g_bodyless_calls.load(), before);
            ASSERT_TRUE(session.request("GET", "/ok", reply));
            EXPECT_EQ(reply.status, 207);
            EXPECT_EQ(reply.body, "CHECK");
        }
        const unsigned before = g_bodyless_calls.load();
        H2Reply full;
        ASSERT_TRUE(session.request("HEAD", "/bodylessfull", full));
        EXPECT_EQ(full.status, 200);
        EXPECT_EQ(full.data_events, 0u);
        EXPECT_EQ(full.data_frames, 0u);
        EXPECT_TRUE(full.header("content-length").empty());
        EXPECT_EQ(g_bodyless_calls.load(), before);
    }
}

struct FixedH1Reply {
    std::string head, body;
    uint16_t status = 0;
};

bool fixed_h1_request(Conn& c, const char* method, const char* path, FixedH1Reply& reply) {
    reply = FixedH1Reply{};
    const std::string request = std::string(method) + " " + path +
        " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    if (!c.send_all(request.data(), request.size())) return false;
    char byte = 0;
    for (unsigned i = 0; i < 8192; ++i) {
        if (!c.recv_exact(&byte, 1)) return false;
        reply.head += byte;
        if (reply.head.ends_with("\r\n\r\n")) break;
    }
    if (!reply.head.starts_with("HTTP/1.1 ") || !reply.head.ends_with("\r\n\r\n")) return false;
    const auto parsed = std::from_chars(reply.head.data() + 9, reply.head.data() + 12, reply.status);
    if (parsed.ec != std::errc{}) return false;
    if (std::strcmp(method, "HEAD") == 0 || reply.status == 204 || reply.status == 304) return true;
    const std::size_t field = reply.head.find("\r\nContent-Length: ");
    if (field == std::string::npos) return false;
    std::size_t length = 0;
    const char* begin = reply.head.data() + field + std::strlen("\r\nContent-Length: ");
    const auto size = std::from_chars(begin, reply.head.data() + reply.head.size(), length);
    if (size.ec != std::errc{} || length > kMaterializationCap) return false;
    reply.body.resize(length);
    return length == 0 || c.recv_exact(reply.body.data(), length);
}

TEST_F(FixedMaterialization, TlsH1RejectsMismatchBeforeHeadersAndReusesConnection) {
    Conn wire;
    ASSERT_TRUE(wire.open(kFixedTlsPort, true, "http/1.1"));
    for (std::size_t i = 0; i < kFixedCases.size(); ++i) {
        SCOPED_TRACE(kFixedCases[i].path);
        const unsigned before = g_fixed_calls[i].load();
        FixedH1Reply reply;
        ASSERT_TRUE(fixed_h1_request(wire, "GET", kFixedCases[i].path, reply));
        EXPECT_EQ(reply.status, kFixedCases[i].expected_status);
        EXPECT_EQ(reply.body, kFixedCases[i].expected_body);
        EXPECT_EQ(g_fixed_calls[i].load(), before + (i == 2 ? 0u : 1u));
        if (reply.status == 500) {
            EXPECT_NE(reply.head.find("\r\nContent-Length: 0\r\n"), std::string::npos);
            EXPECT_EQ(reply.head.find("Content-Range"), std::string::npos);
            EXPECT_EQ(reply.head.find("Content-Encoding"), std::string::npos);
            EXPECT_EQ(reply.head.find("ETag"), std::string::npos);
        }
        ASSERT_TRUE(fixed_h1_request(wire, "GET", "/ok", reply));
        EXPECT_EQ(reply.status, 207);
        EXPECT_EQ(reply.body, "CHECK");
    }
}

TEST_F(FixedMaterialization, BodylessTlsH1SkipsMaterializationAndKeepsWireAligned) {
    Conn wire;
    ASSERT_TRUE(wire.open(kFixedTlsPort, true, "http/1.1"));
    for (const uint16_t status : std::array<uint16_t, 3>{200, 204, 304}) {
        SCOPED_TRACE(status);
        const unsigned before = g_bodyless_calls.load();
        const std::string path = "/bodyless" + std::to_string(status);
        FixedH1Reply reply;
        ASSERT_TRUE(fixed_h1_request(wire, status == 200 ? "HEAD" : "GET", path.c_str(), reply));
        EXPECT_EQ(reply.status, status);
        EXPECT_TRUE(reply.body.empty());
        EXPECT_EQ(reply.head.find("Transfer-Encoding"), std::string::npos);
        if (status == 204) EXPECT_EQ(reply.head.find("Content-Length"), std::string::npos);
        else EXPECT_NE(reply.head.find("Content-Length: 17\r\n"), std::string::npos);
        EXPECT_EQ(g_bodyless_calls.load(), before);
        ASSERT_TRUE(fixed_h1_request(wire, "GET", "/ok", reply));
        EXPECT_EQ(reply.status, 207);
        EXPECT_EQ(reply.body, "CHECK");
    }
}

TEST(FixedMaterializationConfig, RefusesZeroAndUnrepresentablePublicFixedLimit) {
    api::http::CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_http1_cleartext = false;
    config.enable_signal_handlers = false;
    config.max_fixed_materialization_bytes = 0;
    api::http::CoroUnifiedServer zero(config);
    EXPECT_NE(zero.start_background(), 0);
    if constexpr (sizeof(std::size_t) >= sizeof(uint64_t)) {
        config.max_fixed_materialization_bytes = static_cast<std::size_t>(api::kMaxFixedResponseBytes + 1);
        api::http::CoroUnifiedServer excessive(config);
        EXPECT_NE(excessive.start_background(), 0);
    }
}

}  // namespace
