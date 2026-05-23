// quic_connection_test.cpp — wave 4 GATE: a REAL QUIC handshake completes
// end-to-end over UDP loopback, both roles, to ESTABLISHED.
//
// Two QuicConnections (one client, one server) run on two net::UdpTransports
// bound to ephemeral loopback ports. Each transport's datagram handler feeds the
// owning connection (feed_datagram); each connection's outbound send fn pushes a
// built datagram to the peer via UdpTransport::send. The client start()s the
// handshake; a bounded driver loop ticks both sides until BOTH report
// Established (or a wall-clock deadline trips — no hang).
//
// Asserts (the wave-4 gate):
//   * BOTH connections reach ConnState::kEstablished;
//   * 1-RTT (Application) read+write keys installed on BOTH sides;
//   * ALPN negotiated to "h3" on both;
//   * transport parameters exchanged (each side decoded the other's);
//   * a 1-RTT packet SEALED by one side OPENS on the other — a PING+ACK round
//     trip over real UDP (proves the 1-RTT keys agree end-to-end).
//
// This is the loopback handshake gate; curl/quiche/aiortc-h3 interop is a later
// wave. OpenSSL is always linked, so this runs in the default suite.

#include "boltapi/quic/connection.h"
#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

namespace q    = bolt::api::quic;
namespace net  = bolt::api::net;
namespace core = bolt::api::core;

namespace {

// A shared engine event loop (worker pool + IODispatcher), like the DTLS gate.
struct EventLoop {
    std::unique_ptr<core::WorkerThreadPool> pool;
    std::unique_ptr<net::IODispatcher>      disp;
    EventLoop() {
        pool = std::make_unique<core::WorkerThreadPool>(core::WorkerPoolConfig{});
        pool->start();
        disp = std::make_unique<net::IODispatcher>(pool.get());
        disp->start();
    }
    ~EventLoop() { disp->stop(); pool->stop(); }
};

net::IODispatcher& shared_dispatcher() {
    static EventLoop loop;
    return *loop.disp;
}

// Build a loopback sockaddr_in for a given port.
sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

}  // namespace

TEST(QuicConnection, LoopbackHandshakeToEstablished) {
    // --- transports on ephemeral loopback ports ----------------------------
    net::UdpTransport client_udp(shared_dispatcher());
    net::UdpTransport server_udp(shared_dispatcher());
    ASSERT_TRUE(client_udp.bind("127.0.0.1", 0));
    ASSERT_TRUE(server_udp.bind("127.0.0.1", 0));
    const std::uint16_t client_port = client_udp.bound_port();
    const std::uint16_t server_port = server_udp.bound_port();
    ASSERT_NE(client_port, 0);
    ASSERT_NE(server_port, 0);

    const sockaddr_in server_addr = loopback(server_port);
    const sockaddr_in client_addr = loopback(client_port);

    // The connection layer touches its own state on feed/flush; serialize the
    // I/O-thread callbacks and the driver loop with one mutex per connection.
    std::mutex client_mtx, server_mtx;
    q::QuicConnection client, server;

    // Outbound send fns: push the built datagram to the peer's transport.
    auto client_send = [&](const std::uint8_t* d, std::size_t n) {
        client_udp.send(reinterpret_cast<const sockaddr*>(&server_addr),
                        sizeof(server_addr), d, n);
    };
    auto server_send = [&](const std::uint8_t* d, std::size_t n) {
        server_udp.send(reinterpret_cast<const sockaddr*>(&client_addr),
                        sizeof(client_addr), d, n);
    };

    ASSERT_TRUE(client.init(/*is_server=*/false, client_send));
    ASSERT_TRUE(server.init(/*is_server=*/true, server_send));

    // Inbound: feed each datagram into the owning connection (under its lock).
    client_udp.set_datagram_handler(
        [&](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
            std::lock_guard<std::mutex> lk(client_mtx);
            client.feed_datagram(d, n);
        });
    server_udp.set_datagram_handler(
        [&](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
            std::lock_guard<std::mutex> lk(server_mtx);
            server.feed_datagram(d, n);
        });

    ASSERT_TRUE(client_udp.start());
    ASSERT_TRUE(server_udp.start());

    // --- drive the handshake ----------------------------------------------
    {
        std::lock_guard<std::mutex> lk(client_mtx);
        ASSERT_TRUE(client.start());  // first Initial (ClientHello)
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        bool c_est, s_est;
        {
            std::lock_guard<std::mutex> lk(client_mtx);
            client.tick();
            c_est = client.is_established();
        }
        {
            std::lock_guard<std::mutex> lk(server_mtx);
            server.tick();
            s_est = server.is_established();
        }
        if (c_est && s_est) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // --- assert ESTABLISHED both sides ------------------------------------
    {
        std::lock_guard<std::mutex> lk(client_mtx);
        EXPECT_EQ(client.state(), q::ConnState::kEstablished)
            << "client stuck in " << q::conn_state_name(client.state());
        EXPECT_TRUE(client.one_rtt_keys_ready());
        EXPECT_TRUE(client.alpn_is_h3());
        EXPECT_TRUE(client.tls().have_peer_transport_params());
        EXPECT_TRUE(client.tls().peer_transport_params().initial_max_data_present);
    }
    {
        std::lock_guard<std::mutex> lk(server_mtx);
        EXPECT_EQ(server.state(), q::ConnState::kEstablished)
            << "server stuck in " << q::conn_state_name(server.state());
        EXPECT_TRUE(server.one_rtt_keys_ready());
        EXPECT_TRUE(server.alpn_is_h3());
        EXPECT_TRUE(server.tls().have_peer_transport_params());
        EXPECT_TRUE(server.tls().peer_transport_params().initial_max_data_present);
    }

    // --- prove a 1-RTT round-trip over real UDP ---------------------------
    // The client already OPENED at least one server-sealed 1-RTT packet during
    // the handshake (the server's HANDSHAKE_DONE rides a 1-RTT short header), so
    // its Application-space largest_received is already >= 0. Now we send FRESH
    // 1-RTT PING+ACK packets in BOTH directions and assert each side opens the
    // other's, advancing its Application-space largest_received — a real 1-RTT
    // seal-on-one / open-on-other round-trip over the wire.
    std::int64_t client_app_before, server_app_before;
    {
        std::lock_guard<std::mutex> lk(client_mtx);
        client_app_before = client.app_largest_received();
    }
    {
        std::lock_guard<std::mutex> lk(server_mtx);
        server_app_before = server.app_largest_received();
        ASSERT_TRUE(server.one_rtt_keys_ready());
        EXPECT_TRUE(server.send_one_rtt_ping());  // server seals a 1-RTT PING
    }
    {
        std::lock_guard<std::mutex> lk(client_mtx);
        ASSERT_TRUE(client.one_rtt_keys_ready());
        EXPECT_TRUE(client.send_one_rtt_ping());  // client seals a 1-RTT PING
    }

    bool c_opened = false, s_opened = false;
    const auto rt_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < rt_deadline) {
        {
            std::lock_guard<std::mutex> lk(client_mtx);
            c_opened = client.app_largest_received() > client_app_before;
        }
        {
            std::lock_guard<std::mutex> lk(server_mtx);
            s_opened = server.app_largest_received() > server_app_before;
        }
        if (c_opened && s_opened) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_TRUE(c_opened)
        << "client did not open a fresh server-sealed 1-RTT packet";
    EXPECT_TRUE(s_opened)
        << "server did not open a fresh client-sealed 1-RTT packet";
    // The handshake itself already opened >=1 1-RTT packet on the client.
    {
        std::lock_guard<std::mutex> lk(client_mtx);
        EXPECT_GE(client.app_largest_received(), 0);
    }

    client_udp.stop();
    server_udp.stop();
}
