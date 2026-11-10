// proto/grpc_server.h over a real TCP socket, driven by boltapi's own HTTP/2
// client: unary echo, server streaming with trailers, unknown method,
// grpc-status-details-bin, and a nestable call dispatched mid-stream.
#include "boltapi/proto/grpc_server.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/proto/flight_sql_codec.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

namespace g = bolt::api::proto::grpc;
namespace cd = bolt::api::proto::flightsql::codec;
using Connection = bolt::api::http2::Http2Connection;
using Kind = Connection::ResponseEventKind;
using bolt::api::http::HPACKHeader;

class TestService final : public g::IService {
public:
    bool nestable(std::string_view m) noexcept override { return m == "/t.S/Ping"; }
    void handle(const g::Call& call, g::Responder& out) noexcept override {
        std::size_t pos = 0;
        std::string_view msg;
        bool bad = false;
        std::string all;
        while (g::next_message(call.body, &pos, &msg, &bad)) all.append(msg);
        if (call.method == "/t.S/Echo") {
            if (out.send(all)) out.finish(g::Code::kOk, {});
        } else if (call.method == "/t.S/Stream") {
            for (int i = 0; i < 50; ++i) {
                if (!out.send(std::string(4000, static_cast<char>('a' + i % 26)))) return;
            }
            out.finish(g::Code::kOk, {});
        } else if (call.method == "/t.S/Fail") {
            out.finish_with_details(g::Code::kInvalidArgument, "bad thing", "\x08\x03");
        } else if (call.method == "/t.S/Ping") {
            if (out.send("pong")) out.finish(g::Code::kOk, {});
        } else {
            out.finish(g::Code::kUnimplemented, "no such method");
        }
    }
};

class Factory final : public g::IServiceFactory {
public:
    g::IService* create() noexcept override { return new TestService(); }
    void destroy(g::IService* s) noexcept override { delete s; }
};

struct Response {
    std::string data;
    std::map<std::string, std::string> trailers;
    bool complete = false;
};

// One client connection over TCP; requests are unary-framed gRPC messages.
class Client {
public:
    explicit Client(std::uint16_t port) : conn_(false) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        connected_ = ::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
        conn_.set_response_callback([this](const Connection::ResponseEvent& e) {
            Response& r = responses_[e.stream_id];
            if (e.kind == Kind::Data) r.data.append(e.data);
            if (e.kind == Kind::Trailers || (e.kind == Kind::Headers && e.end_stream)) {
                for (std::size_t i = 0; i < e.header_count; ++i) {
                    r.trailers[std::string(e.headers[i].name)] = std::string(e.headers[i].value);
                }
            }
            if (e.kind == Kind::Complete || e.kind == Kind::Reset) r.complete = true;
        });
    }
    ~Client() { if (fd_ >= 0) ::close(fd_); }
    bool ok() const { return connected_; }

    std::uint32_t call(const std::string& path, const std::string& payload) {
        std::uint8_t prefix[5];
        cd::grpc_frame_prefix(prefix, static_cast<std::uint32_t>(payload.size()));
        bodies_.push_back(std::string(reinterpret_cast<char*>(prefix), 5) + payload);
        paths_.push_back(path);
        const HPACKHeader h[] = {{":method", "POST"}, {":scheme", "http"}, {":path", paths_.back()},
                                 {":authority", "local"}, {"content-type", "application/grpc"},
                                 {"te", "trailers"}};
        auto r = conn_.send_request(h, 6, bodies_.back());
        return r.is_ok() ? r.value() : 0;
    }

    // Pump until stream `id` completes or the deadline passes.
    bool wait(std::uint32_t id, int ms = 5000) {
        const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        std::uint8_t buf[65536];
        while (std::chrono::steady_clock::now() < end) {
            flush();
            if (responses_[id].complete) return true;
            timeval tv{0, 20000};
            fd_set rs;
            FD_ZERO(&rs);
            FD_SET(fd_, &rs);
            if (::select(fd_ + 1, &rs, nullptr, nullptr, &tv) <= 0) continue;
            const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
            if (n <= 0) return false;
            if (conn_.process_input(buf, static_cast<std::size_t>(n)).is_err()) return false;
        }
        return false;
    }
    Response& operator[](std::uint32_t id) { return responses_[id]; }

private:
    void flush() {
        const std::uint8_t* p = nullptr;
        std::size_t n = 0;
        while (conn_.get_output(&p, &n) && n > 0) {
            const ssize_t w = ::send(fd_, p, n, 0);
            if (w <= 0) return;
            conn_.commit_output(static_cast<std::size_t>(w));
        }
    }

    int fd_ = -1;
    bool connected_ = false;
    Connection conn_;
    std::map<std::uint32_t, Response> responses_;
    std::vector<std::string> bodies_;
    std::vector<std::string> paths_;
};

std::string unframe_all(const std::string& data) {
    std::string out;
    std::size_t pos = 0;
    std::string_view m;
    bool bad = false;
    while (g::next_message(data, &pos, &m, &bad)) out.append(m);
    EXPECT_FALSE(bad);
    return out;
}

// Both hosts: thread per connection, and the boltapi reactor (Config::reactor).
class GrpcServerTest : public ::testing::TestWithParam<bool> {
protected:
    void SetUp() override {
        g::Config cfg;
        cfg.max_connections = 2;
        cfg.reactor = GetParam();
        if (cfg.reactor) cfg.port = 19517;
        server_ = std::make_unique<g::Server>(cfg, factory_);
        ASSERT_TRUE(server_->start_background().is_ok());
        ASSERT_NE(server_->local_port(), 0);
    }
    void TearDown() override { server_->stop(); }
    Factory factory_;
    std::unique_ptr<g::Server> server_;
};

TEST_P(GrpcServerTest, UnaryEchoAndUnknownMethod) {
    Client c(server_->local_port());
    ASSERT_TRUE(c.ok());
    const auto a = c.call("/t.S/Echo", "hello");
    ASSERT_TRUE(c.wait(a));
    EXPECT_EQ(unframe_all(c[a].data), "hello");
    EXPECT_EQ(c[a].trailers["grpc-status"], "0");
    const auto b = c.call("/t.S/Nope", "");
    ASSERT_TRUE(c.wait(b));
    EXPECT_EQ(c[b].trailers["grpc-status"], "12");
    EXPECT_EQ(c[b].trailers["grpc-message"], "no such method");
}

TEST_P(GrpcServerTest, ServerStreamPastTheWindowThenTrailers) {
    Client c(server_->local_port());
    ASSERT_TRUE(c.ok());
    const auto s = c.call("/t.S/Stream", "");
    ASSERT_TRUE(c.wait(s));
    const std::string all = unframe_all(c[s].data);
    ASSERT_EQ(all.size(), 50u * 4000u);
    EXPECT_EQ(all[0], 'a');
    EXPECT_EQ(all[4000], 'b');
    EXPECT_EQ(c[s].trailers["grpc-status"], "0");
}

TEST_P(GrpcServerTest, ErrorDetailsTrailer) {
    Client c(server_->local_port());
    ASSERT_TRUE(c.ok());
    const auto f = c.call("/t.S/Fail", "");
    ASSERT_TRUE(c.wait(f));
    EXPECT_EQ(c[f].trailers["grpc-status"], "3");
    EXPECT_EQ(c[f].trailers["grpc-status-details-bin"], "CAM");   // base64("\x08\x03"), unpadded
}

TEST_P(GrpcServerTest, NestableCallAnsweredWhileAStreamIsOpen) {
    Client c(server_->local_port());
    ASSERT_TRUE(c.ok());
    const auto s = c.call("/t.S/Stream", "");
    const auto p = c.call("/t.S/Ping", "");
    ASSERT_TRUE(c.wait(p));
    EXPECT_EQ(unframe_all(c[p].data), "pong");
    ASSERT_TRUE(c.wait(s));
    EXPECT_EQ(unframe_all(c[s].data).size(), 50u * 4000u);
}

INSTANTIATE_TEST_SUITE_P(Hosts, GrpcServerTest, ::testing::Values(false, true),
                         [](const ::testing::TestParamInfo<bool>& i) { return i.param ? "Reactor" : "Threads"; });

}  // namespace
