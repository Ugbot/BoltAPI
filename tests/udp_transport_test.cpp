// udp_transport_test.cpp — gtest coverage for bolt::api::net::UdpTransport.
//
// Binds a UdpTransport on an EPHEMERAL UDP port, then drives it from a raw
// client UDP socket:
//   * client sendto's a STUN-classified datagram (first byte 0..3); the
//     transport's STUN handler fires with the CORRECT source address + payload;
//   * the handler (and the test) sends a reply back via the transport; the
//     client recvfrom's it;
//   * a DTLS-classified datagram (first byte 20..63) routes to the datagram
//     handler; an "other" first byte is dropped (drop counter increments);
//   * clean start()/stop() with no hang (bounded by a wall-clock deadline).
//
// Per CLAUDE.md the test exercises MULTIPLE packet classes + a real round-trip,
// not a hello-world single send.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace net  = bolt::api::net;
namespace sys  = bolt::api::net::sys;
namespace core = bolt::api::core;

namespace {

// Shared event-loop fixture: spins a real IODispatcher (worker pool + async_io
// backend) so the UdpTransport receive coroutine runs on the unified loop —
// exactly the production path. One dispatcher is shared across the suite to
// avoid per-test thread churn; UdpTransport instances attach to it explicitly.
struct EventLoop {
    std::unique_ptr<core::WorkerThreadPool> pool;
    std::unique_ptr<net::IODispatcher>      disp;

    EventLoop() {
        pool = std::make_unique<core::WorkerThreadPool>(core::WorkerPoolConfig{});
        pool->start();
        disp = std::make_unique<net::IODispatcher>(pool.get());
        disp->start();
    }
    ~EventLoop() {
        disp->stop();
        pool->stop();
    }
};

net::IODispatcher& shared_dispatcher() {
    static EventLoop loop;
    return *loop.disp;
}

// A raw client UDP socket bound to an ephemeral port, with a receive timeout so
// recvfrom can't hang the test.
struct ClientSocket {
    net::socket_t fd = net::kInvalidSocket;

    bool open() {
        sys::startup();
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == net::kInvalidSocket) return false;
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        any.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&any), sizeof(any)) != 0)
            return false;
        // 2s receive timeout.
#ifdef _WIN32
        DWORD tmo = 2000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
        timeval tmo{2, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif
        return true;
    }
    void close() {
        if (fd != net::kInvalidSocket) { sys::close_socket(fd); fd = net::kInvalidSocket; }
    }
    ~ClientSocket() { close(); }
};

sockaddr_in server_addr(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

}  // namespace

TEST(UdpTransport, BindEphemeralReportsPort) {
    net::UdpTransport t(shared_dispatcher());
    ASSERT_TRUE(t.bind("127.0.0.1", 0));
    EXPECT_NE(t.bound_port(), 0);
    t.stop();
}

TEST(UdpTransport, RoundTripWithSourceAddressAndDemux) {
    net::UdpTransport t(shared_dispatcher());
    ASSERT_TRUE(t.bind("127.0.0.1", 0));
    const std::uint16_t port = t.bound_port();
    ASSERT_NE(port, 0);

    // Capture what the STUN handler sees.
    std::atomic<bool> stun_fired{false};
    std::atomic<bool> dtls_fired{false};
    std::vector<std::uint8_t> stun_payload;
    sockaddr_in stun_src{};
    std::atomic<std::uint16_t> stun_src_port{0};

    t.set_stun_handler([&](const sockaddr* peer, int /*plen*/,
                           const std::uint8_t* data, std::size_t len) {
        // Record the source + payload, then echo a reply back to the peer.
        if (peer->sa_family == AF_INET) {
            std::memcpy(&stun_src, peer, sizeof(sockaddr_in));
            stun_src_port.store(ntohs(stun_src.sin_port));
        }
        stun_payload.assign(data, data + len);
        stun_fired.store(true);
        // Reply: prefix 0x01 + the received payload (so the client can verify).
        std::vector<std::uint8_t> reply;
        reply.push_back(0x01);
        reply.insert(reply.end(), data, data + len);
        t.send(peer, static_cast<int>(sizeof(sockaddr_in)), reply.data(),
               reply.size());
    });
    t.set_datagram_handler([&](const sockaddr*, int, const std::uint8_t*,
                               std::size_t) { dtls_fired.store(true); });

    ASSERT_TRUE(t.start());

    ClientSocket c;
    ASSERT_TRUE(c.open());
    // Discover the client's own bound port to assert source-addr correctness.
    sockaddr_in cli{};
    socklen_t cli_len = sizeof(cli);
    ASSERT_EQ(::getsockname(c.fd, reinterpret_cast<sockaddr*>(&cli), &cli_len), 0);
    const std::uint16_t client_port = ntohs(cli.sin_port);

    sockaddr_in dst = server_addr(port);

    // --- STUN-classified datagram (first byte 0..3) ---
    const std::uint8_t stun_dgram[] = {0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_EQ(::sendto(c.fd, reinterpret_cast<const char*>(stun_dgram),
                       sizeof(stun_dgram), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)),
              static_cast<ssize_t>(sizeof(stun_dgram)));

    // Receive the echoed reply (bounded by the socket RCVTIMEO).
    std::uint8_t rbuf[64];
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const ssize_t rn = ::recvfrom(c.fd, reinterpret_cast<char*>(rbuf),
                                  sizeof(rbuf), 0,
                                  reinterpret_cast<sockaddr*>(&from), &from_len);
    ASSERT_GT(rn, 0) << "no reply from transport (timed out)";
    EXPECT_EQ(rbuf[0], 0x01);
    EXPECT_EQ(std::memcmp(rbuf + 1, stun_dgram, sizeof(stun_dgram)), 0);

    EXPECT_TRUE(stun_fired.load());
    // The transport must have captured the CLIENT's source port as the peer.
    EXPECT_EQ(stun_src_port.load(), client_port);
    ASSERT_EQ(stun_payload.size(), sizeof(stun_dgram));
    EXPECT_EQ(std::memcmp(stun_payload.data(), stun_dgram, sizeof(stun_dgram)), 0);

    // --- DTLS-classified datagram (first byte 20..63) ---
    const std::uint8_t dtls_dgram[] = {0x17, 0xFE, 0xFD};  // 0x17 = 23 -> DTLS
    ASSERT_EQ(::sendto(c.fd, reinterpret_cast<const char*>(dtls_dgram),
                       sizeof(dtls_dgram), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)),
              static_cast<ssize_t>(sizeof(dtls_dgram)));

    // --- "Other" datagram (first byte 16) -> dropped ---
    // First bytes 4..19 are unassigned by RFC 7983 (between STUN 0..3 and DTLS
    // 20..63) and below the QUIC range (>=64), so they are dropped by the demux.
    // (0x80 used to be "other" but is now a QUIC long-header byte routed to the
    // datagram handler — see classify() in src/net/udp_transport.cpp.)
    const std::uint8_t other_dgram[] = {0x10, 0x00};
    ASSERT_EQ(::sendto(c.fd, reinterpret_cast<const char*>(other_dgram),
                       sizeof(other_dgram), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)),
              static_cast<ssize_t>(sizeof(other_dgram)));

    // Poll (bounded) for the dtls + drop to register.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while ((!dtls_fired.load() || t.dropped() == 0) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(dtls_fired.load());
    EXPECT_GE(t.dropped(), 1u);     // the "other" datagram was dropped
    EXPECT_GE(t.received(), 3u);    // stun + dtls + other
    EXPECT_GE(t.sent(), 1u);        // the echoed reply

    t.stop();
    EXPECT_FALSE(t.is_running());
}

TEST(UdpTransport, StopWithoutStartIsClean) {
    net::UdpTransport t(shared_dispatcher());
    ASSERT_TRUE(t.bind("127.0.0.1", 0));
    t.stop();  // never started — must not hang or crash
    t.stop();  // idempotent
    EXPECT_FALSE(t.is_running());
}
