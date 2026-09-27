// transport_robustness_test.cpp — G2ETL-114 regressions on a real server:
//   * a TLS response larger than the socket send buffer reaches a slow reader
//     intact (TlsSocket used to drop records a would-block send left behind);
//   * a client that resets mid-response costs one connection, not the process
//     (writes raised SIGPIPE, exit 141);
//   * an HTTP/2 response larger than one frame and one flow-control window is
//     framed to SETTINGS_MAX_FRAME_SIZE and paced by WINDOW_UPDATE, over h2c
//     (prior knowledge) and TLS (ALPN h2).

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
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
        timeval tv{10, 0};
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

}  // namespace
