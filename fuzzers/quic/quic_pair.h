// quic_pair.h — an in-memory client/server QuicConnection pair for fuzzing.
//
// Datagrams move through bounded queues (no sockets, no threads), so a run is
// driven only by the fuzz input. Fuzzed frames are sealed by the REAL peer's
// packet builder (QuicConnectionTestAccess) and enter the target through
// feed_datagram — the same path a UDP datagram takes in the server.
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "boltapi/quic/connection.h"

namespace bolt::api::quic {

struct QuicConnectionTestAccess {
    // Seal `payload` (plaintext frames) at `level` as `c` would and send it
    // through c's send callback. Returns false if c has no keys at that level.
    static bool send_frames(QuicConnection& c, TlsLevel level,
                            const std::uint8_t* payload, std::size_t len) noexcept {
        assert((payload != nullptr || len == 0) && "send_frames: null payload");
        assert(len <= kMaxPayloadSize && "send_frames: oversize payload");
        if (len == 0) return false;
        if (level == TlsLevel::kApplication) {
            if (!c.one_rtt_keys_ready()) return false;
            return c.send_app_packet(payload, len, true, nullptr, 0);
        }
        PacketProtection* pp = c.write_protection(level);
        if (pp == nullptr || !pp->is_initialized()) return false;
        const PacketForm form = level == TlsLevel::kInitial ? PacketForm::kLongInitial
                                                            : PacketForm::kLongHandshake;
        c.build_and_send_long(level, form, payload, len, true, nullptr, 0);
        return true;
    }
};

}  // namespace bolt::api::quic

namespace boltapi_fuzz {

namespace q = bolt::api::quic;

// Fixed-capacity datagram queue (drops when full; bounded per run).
struct DgramQueue {
    static constexpr std::size_t kCap = 64;
    std::uint8_t buf[kCap][q::kMaxDatagramSize];
    std::size_t len[kCap];
    std::size_t head = 0, count = 0;

    void push(const std::uint8_t* d, std::size_t n) noexcept {
        assert(n <= q::kMaxDatagramSize && "datagram above MTU budget");
        if (count == kCap) return;
        const std::size_t slot = (head + count) % kCap;
        std::memcpy(buf[slot], d, n);
        len[slot] = n;
        ++count;
    }
    bool pop(std::uint8_t* out, std::size_t& n) noexcept {
        if (count == 0) return false;
        n = len[head];
        std::memcpy(out, buf[head], n);
        head = (head + 1) % kCap;
        --count;
        assert(n <= q::kMaxDatagramSize && "queued datagram oversize");
        return true;
    }
};

struct Pair {
    q::QuicConnection client, server;
    DgramQueue to_server, to_client;

    bool init() noexcept {
        const bool c = client.init(false, [this](const std::uint8_t* d, std::size_t n) {
            to_server.push(d, n);
        });
        const bool s = server.init(true, [this](const std::uint8_t* d, std::size_t n) {
            to_client.push(d, n);
        });
        return c && s;
    }

    // Deliver every queued datagram in both directions, `rounds` times.
    void pump(int rounds) noexcept {
        assert(rounds >= 0 && rounds <= 64 && "pump rounds bound");
        std::uint8_t d[q::kMaxDatagramSize];
        std::size_t n = 0;
        for (int r = 0; r < rounds; ++r) {
            for (std::size_t i = 0; i < DgramQueue::kCap && to_server.pop(d, n); ++i)
                server.feed_datagram(d, n);
            for (std::size_t i = 0; i < DgramQueue::kCap && to_client.pop(d, n); ++i)
                client.feed_datagram(d, n);
        }
    }

    // Drive a real TLS 1.3 handshake to Established (both sides).
    bool handshake() noexcept {
        if (!client.start()) return false;
        for (int i = 0; i < 16; ++i) {
            pump(1);
            if (client.is_established() && server.is_established()) break;
        }
        pump(2);
        return client.one_rtt_keys_ready() && server.one_rtt_keys_ready();
    }
};

inline std::unique_ptr<Pair> make_pair() {
    auto p = std::make_unique<Pair>();
    if (!p->init()) return nullptr;
    return p;
}

}  // namespace boltapi_fuzz
