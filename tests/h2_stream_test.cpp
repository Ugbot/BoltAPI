// Streamed HTTP/2 responses from blocking workers (App::h2_stream): data far
// past the flow-control windows arrives intact behind WINDOW_UPDATEs, other
// streams are served while one is open, a client RST_STREAM reaches the
// handler as cancelled(), and a handler that ends without trailers resets.
#include "boltapi/app.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/net/sys_compat.h"
#include <gtest/gtest.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;
namespace h2 = bolt::api::http2;

namespace {
constexpr uint16_t kPort = 19493;
constexpr std::size_t kChunk = 16384;
constexpr int kChunks = 200;   // 3.2 MB: ~50x the default stream window

std::atomic<bool> g_hold_cancelled{false};
std::atomic<bool> g_hold_started{false};

char pattern(std::size_t i) { return static_cast<char>('a' + (i * 7 + i / 977) % 26); }

struct Reply {
    uint16_t status = 0;
    std::string body;
    std::map<std::string, std::string> trailers;
    bool complete = false, reset = false;
};

class Session {
public:
    bool open() {
        fd_ = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd_ < 0) return false;
        timeval tv{10, 0};
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(kPort);
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) return false;
        client_.set_max_response_body(64u << 20);
        client_.set_response_callback([this](const auto& e) {
            Reply& r = replies_[e.stream_id];
            using K = h2::Http2Connection::ResponseEventKind;
            if (e.kind == K::Headers) r.status = e.status;
            else if (e.kind == K::Data) r.body.append(e.data);
            else if (e.kind == K::Trailers) {
                for (std::size_t i = 0; i < e.header_count; ++i)
                    r.trailers[std::string(e.headers[i].name)] = std::string(e.headers[i].value);
            } else if (e.kind == K::Complete) r.complete = true;
            else if (e.kind == K::Reset) r.reset = true;
        });
        return flush();
    }
    ~Session() { if (fd_ >= 0) sys::close_socket(fd_); }
    uint32_t get(const char* path) {
        const std::array<api::http::HPACKHeader, 4> f{{
            {":method", "GET"}, {":scheme", "http"}, {":path", path}, {":authority", "localhost"}}};
        const auto id = client_.send_request(f.data(), f.size());
        if (id.is_err() || !flush()) return 0;
        return id.value();
    }
    bool reset(uint32_t id) {
        return client_.send_rst_stream(id, h2::ErrorCode::CANCEL).is_ok() && flush();
    }
    // Read frames until `done` holds (bounded).
    template <class F> bool pump(F done) {
        for (int i = 0; i < 100000 && !done(); ++i) {
            std::array<uint8_t, 9 + h2::Http2Connection::kLocalMaxFrameSize> fr{};
            if (!recv_exact(fr.data(), 9)) return false;
            const auto hdr = h2::parse_frame_header(fr.data());
            if (hdr.is_err()) return false;
            const auto len = hdr.value().length;
            if (len > 0 && !recv_exact(fr.data() + 9, len)) return false;
            if (client_.process_input(fr.data(), 9 + len).is_err() || !flush()) return false;
        }
        return done();
    }
    Reply& reply(uint32_t id) { return replies_[id]; }
private:
    bool flush() {
        for (int i = 0; i < 1024; ++i) {
            const uint8_t* d = nullptr;
            std::size_t n = 0;
            if (!client_.get_output(&d, &n)) return true;
            std::size_t off = 0;
            while (off < n) {
                const auto w = sys::send_bytes(fd_, reinterpret_cast<const char*>(d) + off, n - off);
                if (w <= 0) return false;
                off += static_cast<std::size_t>(w);
            }
            client_.commit_output(n);
        }
        return false;
    }
    bool recv_exact(void* p, std::size_t n) {
        auto* c = static_cast<char*>(p);
        std::size_t off = 0;
        while (off < n) {
            const auto r = sys::recv_bytes(fd_, c + off, n - off);
            if (r <= 0) return false;
            off += static_cast<std::size_t>(r);
        }
        return true;
    }
    int fd_ = -1;
    h2::Http2Connection client_{false};
    std::map<uint32_t, Reply> replies_;
};

class H2Stream : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        api::App::Config cfg;
        cfg.server.num_workers = 2;
        cfg.server.num_streaming_workers = 4;
        app_ = new api::App(cfg);
        app_->get("/ok", [](api::Request&, api::Response& res) { res.status(200).text("unary"); });
        app_->h2_stream(
            [](const api::http::CoroHttpRequest& r) { return r.path != "/ok"; },
            [](const api::http::CoroHttpRequest& r, api::http::H2StreamWriter& w) {
                api::http::CoroResponseHeaders head;
                head.append("content-type", "application/grpc");
                if (!w.head(200, head)) return;
                if (r.path == "/stream") {
                    std::string chunk(kChunk, '\0');
                    for (int c = 0; c < kChunks; ++c) {
                        for (std::size_t i = 0; i < kChunk; ++i) chunk[i] = pattern(c * kChunk + i);
                        if (!w.data(chunk)) return;
                    }
                    api::http::CoroResponseHeaders t;
                    t.append("grpc-status", "0");
                    (void)w.trailers(t);
                } else if (r.path == "/hold") {
                    g_hold_started = true;
                    (void)w.data("x");
                    for (int i = 0; i < 5000 && !w.cancelled(); ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    g_hold_cancelled = w.cancelled();
                } else {
                    (void)w.data("partial");   // "/abandon": no trailers
                }
            });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
    }
    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }
    static api::App* app_;
};
api::App* H2Stream::app_ = nullptr;

TEST_F(H2Stream, StreamsPastTheWindowsWhileOtherStreamsAreServed) {
    Session s;
    ASSERT_TRUE(s.open());
    const uint32_t big = s.get("/stream");
    ASSERT_NE(big, 0u);
    ASSERT_TRUE(s.pump([&] { return s.reply(big).body.size() >= kChunk; }));
    const uint32_t ok = s.get("/ok");
    ASSERT_TRUE(s.pump([&] { return s.reply(ok).complete; }));
    EXPECT_EQ(s.reply(ok).body, "unary");
    EXPECT_FALSE(s.reply(big).complete);   // still streaming when /ok finished
    ASSERT_TRUE(s.pump([&] { return s.reply(big).complete || s.reply(big).reset; }));
    const Reply& r = s.reply(big);
    ASSERT_TRUE(r.complete);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.trailers.at("grpc-status"), "0");
    ASSERT_EQ(r.body.size(), kChunk * kChunks);
    std::size_t bad = 0;
    for (std::size_t i = 0; i < r.body.size(); ++i) bad += r.body[i] != pattern(i);
    EXPECT_EQ(bad, 0u);
}

TEST_F(H2Stream, ClientResetReachesTheHandler) {
    Session s;
    ASSERT_TRUE(s.open());
    const uint32_t id = s.get("/hold");
    ASSERT_TRUE(s.pump([&] { return !s.reply(id).body.empty(); }));
    ASSERT_TRUE(g_hold_started.load());
    ASSERT_TRUE(s.reset(id));
    // The reset is seen on the server's next read; give it one more request.
    const uint32_t ok = s.get("/ok");
    ASSERT_TRUE(s.pump([&] { return s.reply(ok).complete; }));
    for (int i = 0; i < 3000 && !g_hold_cancelled.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(g_hold_cancelled.load());
}

TEST_F(H2Stream, HandlerWithoutTrailersResetsTheStream) {
    Session s;
    ASSERT_TRUE(s.open());
    const uint32_t id = s.get("/abandon");
    ASSERT_TRUE(s.pump([&] { return s.reply(id).complete || s.reply(id).reset; }));
    EXPECT_TRUE(s.reply(id).reset);
    EXPECT_FALSE(s.reply(id).complete);
}

}  // namespace
