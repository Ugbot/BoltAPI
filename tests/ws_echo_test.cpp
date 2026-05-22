// ws_echo_test.cpp — gtest end-to-end coverage for WebSocket through bolt::api::App.
//
// Spins a REAL App (background threads) on an ephemeral cleartext HTTP/1.1 port
// with a single app.websocket("/ws", echo) handler, then drives it from a raw
// client socket implementing the minimal RFC6455 client side:
//   * GET handshake with Upgrade/Connection/Sec-WebSocket-Key/-Version: 13
//   * assert 101 Switching Protocols + correct Sec-WebSocket-Accept
//   * send a MASKED text frame (opcode 0x1); assert the server echoes the same
//     payload back in an UNMASKED text frame
//   * send a second message on the SAME connection; assert it echoes too
//   * send a CLOSE frame; assert the server responds / the stream ends
//
// We use the RFC6455 canonical handshake example key so the expected accept can
// be hardcoded (no OpenSSL in the test):
//   key    = "dGhlIHNhbXBsZSBub25jZQ=="
//   accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19271;
constexpr const char* kKey    = "dGhlIHNhbXBsZSBub25jZQ==";
constexpr const char* kAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// ---------------------------------------------------------------------------
// Raw client connection helper.
// ---------------------------------------------------------------------------
int connect_client() {
    sys::startup();
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return -1;
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

bool send_all(int fd, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = sys::send_bytes(fd, data.data() + sent, data.size() - sent);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

// Receive at least `need` bytes (appends to `buf`), with a wall-clock timeout.
// Returns true if buf.size() reached at least `need`.
bool recv_until(int fd, std::string& buf, std::size_t need, int timeout_ms) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    char tmp[2048];
    while (buf.size() < need) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        // Non-blocking poll-ish read: rely on a short blocking recv with the
        // socket left blocking; the server responds promptly. To avoid an
        // indefinite block we set a per-recv timeout via SO_RCVTIMEO below.
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n > 0) {
            buf.append(tmp, static_cast<std::size_t>(n));
        } else if (n == 0) {
            return buf.size() >= need;  // peer closed
        } else {
            // timeout or transient error; loop checks deadline
        }
    }
    return true;
}

void set_recv_timeout(int fd, int ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

// ---------------------------------------------------------------------------
// Minimal client-side RFC6455 framing.
// ---------------------------------------------------------------------------
std::string build_masked_text_frame(const std::string& payload) {
    std::string f;
    f.push_back(static_cast<char>(0x80 | 0x1));  // FIN + opcode TEXT
    const std::size_t len = payload.size();
    const uint8_t mask_bit = 0x80;
    if (len < 126) {
        f.push_back(static_cast<char>(mask_bit | static_cast<uint8_t>(len)));
    } else if (len <= 0xFFFF) {
        f.push_back(static_cast<char>(mask_bit | 126));
        f.push_back(static_cast<char>((len >> 8) & 0xFF));
        f.push_back(static_cast<char>(len & 0xFF));
    } else {
        f.push_back(static_cast<char>(mask_bit | 127));
        for (int s = 56; s >= 0; s -= 8) {
            f.push_back(static_cast<char>((len >> s) & 0xFF));
        }
    }
    const uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    for (int i = 0; i < 4; ++i) f.push_back(static_cast<char>(mask[i]));
    for (std::size_t i = 0; i < len; ++i) {
        f.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^
                                      mask[i % 4]));
    }
    return f;
}

std::string build_masked_close_frame() {
    std::string f;
    f.push_back(static_cast<char>(0x80 | 0x8));  // FIN + opcode CLOSE
    // payload: 2-byte close code 1000, masked.
    const uint8_t mask[4] = {0x01, 0x02, 0x03, 0x04};
    f.push_back(static_cast<char>(0x80 | 2));  // mask + len 2
    for (int i = 0; i < 4; ++i) f.push_back(static_cast<char>(mask[i]));
    const uint8_t code[2] = {0x03, 0xe8};  // 1000
    for (int i = 0; i < 2; ++i) {
        f.push_back(static_cast<char>(code[i] ^ mask[i % 4]));
    }
    return f;
}

// Parse one unmasked server frame from `buf` starting at offset `pos`.
// On success sets opcode + payload and advances `pos` past the frame; returns
// true. Returns false if not enough bytes yet.
bool parse_server_frame(const std::string& buf, std::size_t& pos,
                        uint8_t& opcode, std::string& payload) {
    if (pos + 2 > buf.size()) return false;
    const uint8_t b0 = static_cast<uint8_t>(buf[pos]);
    const uint8_t b1 = static_cast<uint8_t>(buf[pos + 1]);
    opcode = b0 & 0x0F;
    const bool masked = (b1 & 0x80) != 0;
    uint64_t len = b1 & 0x7F;
    std::size_t hdr = pos + 2;
    if (len == 126) {
        if (hdr + 2 > buf.size()) return false;
        len = (static_cast<uint8_t>(buf[hdr]) << 8) |
              static_cast<uint8_t>(buf[hdr + 1]);
        hdr += 2;
    } else if (len == 127) {
        if (hdr + 8 > buf.size()) return false;
        len = 0;
        for (int i = 0; i < 8; ++i) {
            len = (len << 8) | static_cast<uint8_t>(buf[hdr + i]);
        }
        hdr += 8;
    }
    std::size_t mask_off = 0;
    if (masked) {
        if (hdr + 4 > buf.size()) return false;
        mask_off = hdr;
        hdr += 4;
    }
    if (hdr + len > buf.size()) return false;
    payload.assign(len, '\0');
    for (uint64_t i = 0; i < len; ++i) {
        uint8_t c = static_cast<uint8_t>(buf[hdr + i]);
        if (masked) c ^= static_cast<uint8_t>(buf[mask_off + (i % 4)]);
        payload[static_cast<std::size_t>(i)] = static_cast<char>(c);
    }
    pos = hdr + static_cast<std::size_t>(len);
    return true;
}

// ---------------------------------------------------------------------------
// Fixture: one App with a WS echo handler for the whole suite.
// ---------------------------------------------------------------------------
class WsEcho : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();
        app_->get("/health", [](api::Request&, api::Response& res) {
            res.ok().text("up");
        });
        app_->websocket("/ws", [](api::http::WebSocketConnection& ws) {
            ws.on_text_message = [&ws](const std::string& msg) {
                ws.send_text(msg);
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
api::App* WsEcho::app_ = nullptr;

std::string handshake_request() {
    std::string r;
    r += "GET /ws HTTP/1.1\r\n";
    r += "Host: 127.0.0.1\r\n";
    r += "Upgrade: websocket\r\n";
    r += "Connection: Upgrade\r\n";
    r += "Sec-WebSocket-Key: ";
    r += kKey;
    r += "\r\n";
    r += "Sec-WebSocket-Version: 13\r\n";
    r += "\r\n";
    return r;
}

// ---------------------------------------------------------------------------
TEST_F(WsEcho, HandshakeEchoMultiAndClose) {
    int fd = connect_client();
    ASSERT_GE(fd, 0);
    set_recv_timeout(fd, 400);

    ASSERT_TRUE(send_all(fd, handshake_request()));

    // Read the handshake response (up to and including the CRLFCRLF).
    std::string buf;
    bool got_headers = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        char tmp[1024];
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n > 0) {
            buf.append(tmp, static_cast<std::size_t>(n));
            if (buf.find("\r\n\r\n") != std::string::npos) { got_headers = true; break; }
        } else if (n == 0) {
            break;
        }
    }
    ASSERT_TRUE(got_headers) << "no handshake response; got: " << buf;

    const std::size_t hdr_end = buf.find("\r\n\r\n");
    const std::string headers = buf.substr(0, hdr_end);
    EXPECT_NE(headers.find("101"), std::string::npos) << headers;
    EXPECT_NE(headers.find("Switching Protocols"), std::string::npos) << headers;
    EXPECT_NE(headers.find(std::string("Sec-WebSocket-Accept: ") + kAccept),
              std::string::npos)
        << "accept mismatch in:\n" << headers;

    // Any frame bytes already received after the header block.
    std::string frames = buf.substr(hdr_end + 4);

    // ---- Message 1 ----
    const std::string msg1 = "hello-bolt-websocket";
    ASSERT_TRUE(send_all(fd, build_masked_text_frame(msg1)));
    // Need at least msg1.size()+2 bytes for an unmasked text frame.
    ASSERT_TRUE(recv_until(fd, frames, msg1.size() + 2, 2000))
        << "did not receive echo 1; have " << frames.size() << " bytes";
    {
        std::size_t pos = 0;
        uint8_t opcode = 0;
        std::string payload;
        ASSERT_TRUE(parse_server_frame(frames, pos, opcode, payload));
        EXPECT_EQ(opcode, 0x1);          // text
        EXPECT_EQ(payload, msg1);
        frames.erase(0, pos);            // consume frame 1
    }

    // ---- Message 2 on the same connection ----
    const std::string msg2 = "second-message-1234567890";
    ASSERT_TRUE(send_all(fd, build_masked_text_frame(msg2)));
    ASSERT_TRUE(recv_until(fd, frames, msg2.size() + 2, 2000))
        << "did not receive echo 2; have " << frames.size() << " bytes";
    {
        std::size_t pos = 0;
        uint8_t opcode = 0;
        std::string payload;
        ASSERT_TRUE(parse_server_frame(frames, pos, opcode, payload));
        EXPECT_EQ(opcode, 0x1);
        EXPECT_EQ(payload, msg2);
        frames.erase(0, pos);
    }

    // ---- Close ----
    ASSERT_TRUE(send_all(fd, build_masked_close_frame()));
    // The server either replies with a close frame or ends the stream. Drain a
    // little; assert no crash and that any frame received is a CLOSE (0x8).
    recv_until(fd, frames, frames.size() + 2, 600);
    if (frames.size() >= 2) {
        std::size_t pos = 0;
        uint8_t opcode = 0;
        std::string payload;
        if (parse_server_frame(frames, pos, opcode, payload)) {
            EXPECT_EQ(opcode, 0x8) << "expected CLOSE opcode after close";
        }
    }

    sys::close_socket(fd);
}

}  // namespace
