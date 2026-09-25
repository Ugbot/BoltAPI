// ws_large_frame_test.cpp — G2ETL-83: a WebSocket frame larger than the socket
// send buffer must arrive byte-exact at a slow reader.
//
// The WS loop issued a single conn_write per queued frame and popped it
// regardless of the count written, so the tail of any frame bigger than the
// free kernel send buffer was dropped and the stream was mis-framed. The client
// shrinks its receive buffer and stalls before reading to force partial writes.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19283;
constexpr std::size_t kFrameSize = 2u * 1024u * 1024u;

const std::string& big_payload() {
    static const std::string* body = [] {
        auto* s = new std::string();
        s->reserve(kFrameSize);
        for (std::size_t i = 0; i < kFrameSize; ++i) {
            s->push_back(static_cast<char>((i * 131 + i / 8191) & 0xFF));
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

void set_recv_timeout(int fd, int ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(ms);
#else
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
#endif
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
}

bool send_all(int fd, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = sys::send_bytes(fd, data.data() + sent, data.size() - sent);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

std::string masked_text_frame(const std::string& payload) {
    std::string f;
    f.push_back(static_cast<char>(0x81));
    f.push_back(static_cast<char>(0x80 | payload.size()));
    const uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    for (uint8_t m : mask) f.push_back(static_cast<char>(m));
    for (std::size_t i = 0; i < payload.size(); ++i) {
        f.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]));
    }
    return f;
}

// Parses one unmasked server frame at `pos`; false if incomplete.
bool parse_frame(const std::string& buf, std::size_t& pos, uint8_t& opcode, std::string& payload,
                 bool* fin = nullptr) {
    if (pos + 2 > buf.size()) return false;
    opcode = static_cast<uint8_t>(buf[pos]) & 0x0F;
    if (fin != nullptr) *fin = (static_cast<uint8_t>(buf[pos]) & 0x80) != 0;
    uint64_t len = static_cast<uint8_t>(buf[pos + 1]) & 0x7F;
    std::size_t hdr = pos + 2;
    const std::size_t ext = len == 126 ? 2 : (len == 127 ? 8 : 0);
    if (hdr + ext > buf.size()) return false;
    if (ext > 0) {
        len = 0;
        for (std::size_t i = 0; i < ext; ++i) len = (len << 8) | static_cast<uint8_t>(buf[hdr + i]);
        hdr += ext;
    }
    if (hdr + len > buf.size()) return false;
    payload.assign(buf, hdr, static_cast<std::size_t>(len));
    pos = hdr + static_cast<std::size_t>(len);
    return true;
}

// Reads slowly until `need` bytes are buffered or the peer stops sending.
void recv_slowly(int fd, std::string& buf, std::size_t need) {
    char tmp[8192];
    for (int i = 0; i < 1'000'000 && buf.size() < need; ++i) {
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if ((i & 63) == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

class WsLargeFrame : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        (void)big_payload();
        app_ = new api::App();
        app_->websocket("/ws", [](api::http::WebSocketConnection& ws) {
            ws.on_text_message = [&ws](const std::string& msg) {
                if (msg == "big") {
                    const std::string& p = big_payload();
                    ws.send_binary(reinterpret_cast<const uint8_t*>(p.data()), p.size());
                    ws.send_text("after");
                } else {
                    ws.send_text(msg);
                }
            };
        });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }
    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }
    static api::App* app_;
};
api::App* WsLargeFrame::app_ = nullptr;

TEST_F(WsLargeFrame, LargeBinaryFrameArrivesByteExact) {
    const int fd = connect_slow_client();
    ASSERT_GE(fd, 0);
    set_recv_timeout(fd, 3000);
    ASSERT_TRUE(send_all(fd,
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"));
    std::string buf;
    recv_slowly(fd, buf, 1);
    for (int i = 0; i < 100 && buf.find("\r\n\r\n") == std::string::npos; ++i) {
        recv_slowly(fd, buf, buf.size() + 1);
    }
    const std::size_t he = buf.find("\r\n\r\n");
    ASSERT_NE(he, std::string::npos) << buf;
    ASSERT_NE(buf.find(" 101 "), std::string::npos) << buf;
    std::string frames = buf.substr(he + 4);

    ASSERT_TRUE(send_all(fd, masked_text_frame("big")));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    recv_slowly(fd, frames, kFrameSize + (kFrameSize / 65536) * 4 + 7);

    std::size_t pos = 0;
    uint8_t opcode = 0;
    std::string payload;
    // The server auto-fragments; reassemble the message from its continuation frames.
    std::string message;
    bool fin = false;
    for (int i = 0; i < 4096 && !fin; ++i) {
        ASSERT_TRUE(parse_frame(frames, pos, opcode, payload, &fin))
            << "truncated at fragment " << i << "; have " << frames.size() << " bytes";
        EXPECT_EQ(opcode, i == 0 ? 0x2 : 0x0);
        message += payload;
    }
    ASSERT_TRUE(fin);
    ASSERT_EQ(message.size(), kFrameSize);
    EXPECT_TRUE(message == big_payload());

    ASSERT_TRUE(parse_frame(frames, pos, opcode, payload)) << "second frame missing";
    EXPECT_EQ(opcode, 0x1);
    EXPECT_EQ(payload, "after");
    EXPECT_EQ(pos, frames.size());

    ASSERT_TRUE(send_all(fd, masked_text_frame("ping-after-big")));
    frames.erase(0, pos);
    recv_slowly(fd, frames, 2 + 14);
    pos = 0;
    ASSERT_TRUE(parse_frame(frames, pos, opcode, payload));
    EXPECT_EQ(payload, "ping-after-big");
    sys::close_socket(fd);
}

}  // namespace
