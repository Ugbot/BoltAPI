// large_buffered_response_test.cpp — G2ETL-70: a buffered HTTP/1.1 body larger
// than the socket send buffer must arrive in full at a slow reader.
//
// The buffered paths issued a single async_write and ignored a short count, so
// once the kernel send buffer filled the tail of the body was dropped and the
// client saw fewer bytes than Content-Length declared. The client here shrinks
// its receive buffer and reads slowly to force partial writes on the server.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19281;
constexpr std::size_t kBodySize = 3u * 1024u * 1024u;

const std::string& big_body() {
    static const std::string* body = [] {
        auto* s = new std::string();
        s->reserve(kBodySize);
        for (std::size_t i = 0; i < kBodySize; ++i) {
            s->push_back(static_cast<char>('a' + (i * 7 + i / 4096) % 26));
        }
        return s;
    }();
    return *body;
}

int connect_slow_client() {
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return -1;
    int rcv = 16 * 1024;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcv), sizeof(rcv));
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return -1;
    }
    return fd;
}

// Sends the request, stalls so the server's send buffer fills, then drains the
// socket in small slow reads until the peer closes. Returns everything read.
std::string fetch_slowly(const char* target) {
    const int fd = connect_slow_client();
    if (fd < 0) return {};
    std::string req = "GET ";
    req += target;
    req += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    std::size_t sent = 0;
    while (sent < req.size()) {
        ssize_t n = sys::send_bytes(fd, req.data() + sent, req.size() - sent);
        if (n <= 0) { sys::close_socket(fd); return {}; }
        sent += static_cast<std::size_t>(n);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::string out;
    char tmp[8192];
    for (int i = 0; i < 1'000'000; ++i) {
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        out.append(tmp, static_cast<std::size_t>(n));
        if ((i & 63) == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        if (out.size() > 2 * kBodySize) break;
    }
    sys::close_socket(fd);
    return out;
}

std::string dechunk(const std::string& s) {
    std::string out;
    std::size_t pos = 0;
    for (int i = 0; i < 1'000'000 && pos < s.size(); ++i) {
        const std::size_t eol = s.find("\r\n", pos);
        if (eol == std::string::npos) return {};
        const std::size_t n = std::stoul(s.substr(pos, eol - pos), nullptr, 16);
        if (n == 0) return out;
        if (eol + 2 + n + 2 > s.size()) return {};
        out.append(s, eol + 2, n);
        pos = eol + 2 + n + 2;
    }
    return {};
}

class LargeBufferedResponse : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        (void)big_body();
        app_ = new api::App();
        app_->get("/big", [](api::Request&, api::Response& res) {
            res.ok().text(big_body());
        });
        app_->get("/bigchunked", [](api::Request&, api::Response& res) {
            res.ok().header("Transfer-Encoding", "chunked").text(big_body());
        });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }
    static void TearDownTestSuite() {
        if (app_) {
            app_->stop();
            delete app_;
            app_ = nullptr;
        }
    }
    static api::App* app_;
};

api::App* LargeBufferedResponse::app_ = nullptr;

TEST_F(LargeBufferedResponse, IdentityBodyArrivesInFull) {
    const std::string raw = fetch_slowly("/big");
    const std::size_t he = raw.find("\r\n\r\n");
    ASSERT_NE(he, std::string::npos);
    const std::string head = raw.substr(0, he);
    EXPECT_NE(head.find("Content-Length: " + std::to_string(kBodySize)), std::string::npos) << head;
    const std::string body = raw.substr(he + 4);
    ASSERT_EQ(body.size(), kBodySize);
    EXPECT_TRUE(body == big_body());
}

TEST_F(LargeBufferedResponse, ChunkedBodyArrivesInFull) {
    const std::string raw = fetch_slowly("/bigchunked");
    const std::size_t he = raw.find("\r\n\r\n");
    ASSERT_NE(he, std::string::npos);
    const std::string body = dechunk(raw.substr(he + 4));
    ASSERT_EQ(body.size(), kBodySize);
    EXPECT_TRUE(body == big_body());
}

}  // namespace
