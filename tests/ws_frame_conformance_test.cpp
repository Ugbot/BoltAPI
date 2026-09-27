// ws_frame_conformance_test.cpp — RFC 6455 receive-side rules of
// WebSocketConnection::feed (G2ETL-114). Frames are fed in randomized read
// sizes, including frames far larger than the server's 16 KiB read buffer.

#include "boltapi/http/websocket.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace ws = bolt::api::http;

namespace {

std::vector<std::uint8_t> frame(std::uint8_t op, const std::vector<std::uint8_t>& p,
                                bool fin = true, bool mask = true, std::uint8_t rsv = 0) {
    std::vector<std::uint8_t> f;
    f.push_back(static_cast<std::uint8_t>((fin ? 0x80 : 0) | rsv | op));
    const std::uint8_t mbit = mask ? 0x80 : 0;
    if (p.size() < 126) {
        f.push_back(static_cast<std::uint8_t>(mbit | p.size()));
    } else if (p.size() < 65536) {
        f.push_back(mbit | 126);
        f.push_back(static_cast<std::uint8_t>(p.size() >> 8));
        f.push_back(static_cast<std::uint8_t>(p.size()));
    } else {
        f.push_back(mbit | 127);
        for (int i = 7; i >= 0; --i) f.push_back(static_cast<std::uint8_t>(p.size() >> (8 * i)));
    }
    const std::uint8_t key[4] = {0x37, 0xfa, 0x21, 0x3d};
    if (mask) f.insert(f.end(), key, key + 4);
    for (std::size_t i = 0; i < p.size(); ++i)
        f.push_back(mask ? static_cast<std::uint8_t>(p[i] ^ key[i % 4]) : p[i]);
    return f;
}

std::vector<std::uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

struct Peer {
    ws::WebSocketConnection conn{1, config()};
    std::vector<std::string> texts;
    std::vector<std::vector<std::uint8_t>> bins;
    std::vector<std::uint16_t> closes;

    static ws::WebSocketConnection::Config config() {
        ws::WebSocketConnection::Config c;
        c.max_message_size = 1 << 20;
        return c;
    }
    Peer() {
        conn.on_text_message = [this](const std::string& m) { texts.push_back(m); };
        conn.on_binary_message = [this](const std::uint8_t* d, std::size_t n) {
            bins.emplace_back(d, d + n);
        };
        conn.on_close = [this](std::uint16_t c, const char*) { closes.push_back(c); };
    }
    // Feed like the server: a 16 KiB buffer and random read sizes.
    void feed(const std::vector<std::uint8_t>& in, std::uint32_t seed) {
        std::mt19937 rng(seed);
        std::vector<std::uint8_t> buf;
        std::size_t pos = 0;
        while (pos < in.size() && conn.is_open()) {
            const std::size_t space = 16384 - buf.size();
            std::size_t n = 1 + rng() % 3000;
            if (n > space) n = space;
            if (n > in.size() - pos) n = in.size() - pos;
            ASSERT_GT(n, 0u) << "read buffer full with " << buf.size() << " bytes";
            buf.insert(buf.end(), in.begin() + static_cast<long>(pos),
                       in.begin() + static_cast<long>(pos + n));
            pos += n;
            const std::size_t used = conn.feed(buf.data(), buf.size());
            buf.erase(buf.begin(), buf.begin() + static_cast<long>(used));
        }
    }
    // Close code of the close frame the server queued (0 if none, 1005 empty).
    std::uint16_t sent_close_code() {
        std::uint16_t code = 0;
        while (const std::string* out = conn.get_pending_output()) {
            const auto* p = reinterpret_cast<const std::uint8_t*>(out->data());
            if ((p[0] & 0x0F) == 0x8) code = (p[1] & 0x7F) >= 2
                ? static_cast<std::uint16_t>((p[2] << 8) | p[3]) : 1005;
            conn.pop_pending_output();
        }
        return code;
    }
};

}  // namespace

TEST(WsFrameConformance, LargeMessageStreamsThroughSmallBuffer) {
    std::mt19937 rng(7);
    std::vector<std::uint8_t> payload(300000);
    for (auto& b : payload) b = static_cast<std::uint8_t>(rng());
    for (std::uint32_t seed = 1; seed <= 5; ++seed) {
        Peer p;
        p.feed(frame(0x2, payload), seed);
        ASSERT_EQ(p.bins.size(), 1u);
        EXPECT_EQ(p.bins[0], payload);
        EXPECT_TRUE(p.conn.is_open());
    }
}

TEST(WsFrameConformance, FragmentedTextWithInterleavedPing) {
    Peer p;
    std::vector<std::uint8_t> in = frame(0x1, bytes("hel"), false);
    const auto ping = frame(0x9, bytes("x"));
    const auto tail = frame(0x0, bytes("lo"), true);
    in.insert(in.end(), ping.begin(), ping.end());
    in.insert(in.end(), tail.begin(), tail.end());
    p.feed(in, 3);
    ASSERT_EQ(p.texts.size(), 1u);
    EXPECT_EQ(p.texts[0], "hello");
}

TEST(WsFrameConformance, ProtocolErrorsClose1002) {
    const std::vector<std::vector<std::uint8_t>> bad = {
        frame(0x1, bytes("x"), true, /*mask=*/false),        // unmasked client frame
        frame(0x3, bytes("x")),                              // reserved opcode
        frame(0x1, bytes("x"), true, true, /*rsv1=*/0x40),   // RSV1 without extension
        frame(0x9, std::vector<std::uint8_t>(126, 'a')),     // control > 125 bytes
        frame(0x9, bytes("x"), /*fin=*/false),               // fragmented control
        frame(0x0, bytes("x")),                              // continuation, no message
        frame(0x8, {0x03, 0xED}),                            // close code 1005 on the wire
        frame(0x8, {0x03}),                                  // 1-byte close body
    };
    for (std::size_t i = 0; i < bad.size(); ++i) {
        Peer p;
        p.feed(bad[i], 11);
        EXPECT_FALSE(p.conn.is_open()) << "case " << i;
        EXPECT_EQ(p.sent_close_code(), 1002) << "case " << i;
        EXPECT_TRUE(p.texts.empty()) << "case " << i;
    }
}

TEST(WsFrameConformance, CloseHandshake) {
    Peer echo;
    echo.feed(frame(0x8, {0x0F, 0xA0, 'o', 'k'}), 5);  // 4000 "ok"
    EXPECT_EQ(echo.sent_close_code(), 4000);
    EXPECT_EQ(echo.closes.size(), 1u);
    Peer empty;
    empty.feed(frame(0x8, {}), 5);
    EXPECT_EQ(empty.sent_close_code(), 1005);  // empty body answered with empty body
}

TEST(WsFrameConformance, InvalidUtf8AndOversize) {
    Peer utf;
    utf.feed(frame(0x1, {0xED, 0xA0, 0x80}), 2);  // surrogate
    EXPECT_EQ(utf.sent_close_code(), 1007);
    Peer big;
    big.feed(frame(0x2, std::vector<std::uint8_t>((1 << 20) + 1, 'z')), 2);
    EXPECT_EQ(big.sent_close_code(), 1009);
    EXPECT_TRUE(big.bins.empty());
}
