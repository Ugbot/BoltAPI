// turn_test.cpp — THE TURN GATE (RFC 5766 / RFC 8656), in-process, loopback,
// deadline-bounded (DEFAULT suite, no external servers).
//
// Our OWN TurnClient against our OWN minimal in-process TurnServer over loopback
// UDP. The server owns a CONTROL socket (clients talk TURN to it) and a RELAY
// socket (its bound address becomes the relayed transport address; peers send
// application data there). A third raw socket plays the PEER.
//
// Flow asserted end-to-end:
//   1. Allocate (long-term cred): first attempt 401 -> client learns REALM+NONCE
//      -> authenticated retry -> success carrying XOR-RELAYED-ADDRESS (the relay
//      candidate) + LIFETIME.
//   2. CreatePermission(peer) -> success.
//   3. ChannelBind(peer, 0x4000) -> success.
//   4. Client send_to(peer, data) (Send indication) -> server relays it OUT the
//      relay socket -> the PEER receives the exact bytes.
//   5. PEER sends a reply to the relay socket -> server forwards it back to the
//      client as a ChannelData (channel bound) -> client.relayed_data() matches.
//   6. Refresh(0) releases the allocation.
// Plus a UNIT: the long-term key = MD5(user:realm:pass) and the channel-data
// classifier. Bounded by a wall-clock deadline (no hang).

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/turn.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <thread>

namespace net  = bolt::api::net;
namespace sys  = bolt::api::net::sys;
namespace core = bolt::api::core;
namespace turn = bolt::api::webrtc::turn;

namespace {

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

sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

template <typename Pred>
bool wait_until(Pred p, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }
    return p();
}

constexpr char kRealm[] = "bolt.test";
constexpr char kUser[]  = "turnuser";
constexpr char kPass[]  = "turnpassword";

}  // namespace

// ===========================================================================
// UNIT — long-term key (MD5) + ChannelData classifier.
// ===========================================================================
TEST(Turn, LongTermKeyAndClassifier) {
    std::uint8_t k1[16], k2[16];
    turn::long_term_key(kUser, kRealm, kPass, k1);
    turn::long_term_key(kUser, kRealm, kPass, k2);
    EXPECT_EQ(std::memcmp(k1, k2, 16), 0);              // deterministic
    std::uint8_t k3[16];
    turn::long_term_key(kUser, kRealm, "other", k3);
    EXPECT_NE(std::memcmp(k1, k3, 16), 0);              // password-sensitive

    // ChannelData: first 2 bytes are a channel number in 0x4000..0x7FFF.
    const std::uint8_t cd[8] = {0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4};
    EXPECT_TRUE(turn::is_channel_data(cd, sizeof(cd)));
    const std::uint8_t stun[8] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
    EXPECT_FALSE(turn::is_channel_data(stun, sizeof(stun)));
}

// ===========================================================================
// THE TURN GATE — Allocate -> relay candidate -> permission/channel -> a
// datagram relayed through the server end-to-end (both directions).
// ===========================================================================
TEST(Turn, AllocateRelayPermissionChannelEndToEnd) {
    // --- Server: control + relay sockets ---
    net::UdpTransport ctrl(shared_dispatcher());
    net::UdpTransport relay(shared_dispatcher());
    ASSERT_TRUE(ctrl.bind("127.0.0.1", 0));
    ASSERT_TRUE(relay.bind("127.0.0.1", 0));
    const std::uint16_t ctrl_port = ctrl.bound_port();
    ASSERT_NE(ctrl_port, 0);
    ASSERT_NE(relay.bound_port(), 0);

    turn::TurnServer server;
    server.set_credentials(kRealm, kUser, kPass);
    server.set_sockets(ctrl, relay);

    // Control socket: TURN requests (first byte 0..3) + Send/Data indications.
    ctrl.set_stun_handler([&](const sockaddr* p, int pl, const std::uint8_t* d,
                              std::size_t l) { server.feed(p, pl, d, l); });
    // ChannelData from a client arrives as first-byte 0x40.. -> datagram handler.
    ctrl.set_datagram_handler([&](const sockaddr* p, int pl,
                                  const std::uint8_t* d,
                                  std::size_t l) { server.feed(p, pl, d, l); });
    // The relay socket receives application data from PEERS (any first byte).
    relay.set_stun_handler([&](const sockaddr* p, int pl, const std::uint8_t* d,
                               std::size_t l) { server.feed_relay(p, pl, d, l); });
    relay.set_datagram_handler([&](const sockaddr* p, int pl,
                                   const std::uint8_t* d, std::size_t l) {
        server.feed_relay(p, pl, d, l);
    });
    ASSERT_TRUE(ctrl.start());
    ASSERT_TRUE(relay.start());

    // --- Client transport ---
    net::UdpTransport cli(shared_dispatcher());
    ASSERT_TRUE(cli.bind("127.0.0.1", 0));
    ASSERT_NE(cli.bound_port(), 0);

    turn::TurnClient client;
    const sockaddr_in srv = loopback(ctrl_port);
    client.configure(reinterpret_cast<const sockaddr*>(&srv), sizeof(srv),
                     kUser, kPass);
    cli.set_stun_handler([&](const sockaddr* p, int pl, const std::uint8_t* d,
                             std::size_t l) { client.feed(cli, p, pl, d, l); });
    cli.set_datagram_handler([&](const sockaddr* p, int pl,
                                 const std::uint8_t* d, std::size_t l) {
        client.feed(cli, p, pl, d, l);
    });
    ASSERT_TRUE(cli.start());

    // --- Peer: a raw UDP socket that talks to the relay socket ---
    sys::startup();
    net::socket_t peer = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(peer, net::kInvalidSocket);
    sockaddr_in peer_any = loopback(0);
    ASSERT_EQ(::bind(peer, reinterpret_cast<sockaddr*>(&peer_any),
                     sizeof(peer_any)), 0);
    sockaddr_in peer_addr{};
    socklen_t pal = sizeof(peer_addr);
    ASSERT_EQ(::getsockname(peer, reinterpret_cast<sockaddr*>(&peer_addr), &pal), 0);
#ifdef _WIN32
    DWORD tmo = 2000;
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
    timeval tmo{2, 0};
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif

    // --- 1) Allocate (drives the 401 -> authed retry inside feed()) ---
    ASSERT_TRUE(client.allocate(cli));
    ASSERT_TRUE(wait_until([&] { return client.allocated(); },
                           std::chrono::milliseconds(3000)))
        << "Allocate did not complete";
    EXPECT_GT(client.lifetime(), 0u);
    EXPECT_GT(client.relayed_address_len(), 0);
    // The relayed address is the server's relay socket (loopback:relayPort).
    const auto* ra =
        reinterpret_cast<const sockaddr_in*>(&client.relayed_address());
    EXPECT_EQ(ntohs(ra->sin_port), relay.bound_port());
    EXPECT_EQ(server.allocation_count(), 1u);

    // --- 2) CreatePermission(peer) ---
    ASSERT_TRUE(client.create_permission(
        cli, reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr)));
    ASSERT_TRUE(wait_until([&] { return client.permission_acked(); },
                           std::chrono::milliseconds(2000)));

    // --- 3) ChannelBind(peer, 0x4000) ---
    ASSERT_TRUE(client.channel_bind(
        cli, reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr),
        turn::kChannelBase));
    ASSERT_TRUE(wait_until([&] { return client.channel_acked(); },
                           std::chrono::milliseconds(2000)));

    // --- 4) Client -> peer via Send indication, relayed OUT to the peer ---
    const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33};
    ASSERT_TRUE(client.send_to(
        cli, reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr),
        payload, sizeof(payload)));
    std::uint8_t rx[64];
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    const ssize_t n = ::recvfrom(peer, reinterpret_cast<char*>(rx), sizeof(rx), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fl);
    ASSERT_EQ(n, static_cast<ssize_t>(sizeof(payload)))
        << "peer did not receive the relayed datagram";
    EXPECT_EQ(std::memcmp(rx, payload, sizeof(payload)), 0);
    // The relayed datagram's source is the server's relay socket.
    EXPECT_EQ(ntohs(from.sin_port), relay.bound_port());

    // --- 5) Peer -> client: reply to the relay socket, forwarded back as
    //         ChannelData (channel bound) -> client.relayed_data() ---
    client.clear_relayed();
    const std::uint8_t reply[] = {0xCA, 0xFE, 0xBA, 0xBE, 0x55};
    ASSERT_EQ(::sendto(peer, reinterpret_cast<const char*>(reply), sizeof(reply),
                       0, reinterpret_cast<sockaddr*>(&from), sizeof(from)),
              static_cast<ssize_t>(sizeof(reply)));
    ASSERT_TRUE(wait_until([&] { return client.have_relayed_data(); },
                           std::chrono::milliseconds(2000)))
        << "client did not receive the relayed reply";
    ASSERT_EQ(client.relayed_len(), sizeof(reply));
    EXPECT_EQ(std::memcmp(client.relayed_data(), reply, sizeof(reply)), 0);

    // --- 6) Refresh(0) releases the allocation ---
    ASSERT_TRUE(client.refresh(cli, 0));
    EXPECT_TRUE(wait_until([&] { return server.allocation_count() == 0; },
                           std::chrono::milliseconds(2000)));

    sys::close_socket(peer);
    cli.stop();
    ctrl.stop();
    relay.stop();
}

// ===========================================================================
// CHANNELDATA fast path — once a channel is bound, send_channel() relays the
// 4-byte-framed payload out to the peer end-to-end (no Send indication).
// ===========================================================================
TEST(Turn, ChannelDataFastPath) {
    net::UdpTransport ctrl(shared_dispatcher());
    net::UdpTransport relay(shared_dispatcher());
    ASSERT_TRUE(ctrl.bind("127.0.0.1", 0));
    ASSERT_TRUE(relay.bind("127.0.0.1", 0));

    turn::TurnServer server;
    server.set_credentials(kRealm, kUser, kPass);
    server.set_sockets(ctrl, relay);
    ctrl.set_stun_handler([&](const sockaddr* p, int pl, const std::uint8_t* d,
                              std::size_t l) { server.feed(p, pl, d, l); });
    ctrl.set_datagram_handler([&](const sockaddr* p, int pl,
                                  const std::uint8_t* d,
                                  std::size_t l) { server.feed(p, pl, d, l); });
    ASSERT_TRUE(ctrl.start());
    ASSERT_TRUE(relay.start());

    net::UdpTransport cli(shared_dispatcher());
    ASSERT_TRUE(cli.bind("127.0.0.1", 0));
    turn::TurnClient client;
    const sockaddr_in srv = loopback(ctrl.bound_port());
    client.configure(reinterpret_cast<const sockaddr*>(&srv), sizeof(srv),
                     kUser, kPass);
    cli.set_stun_handler([&](const sockaddr* p, int pl, const std::uint8_t* d,
                             std::size_t l) { client.feed(cli, p, pl, d, l); });
    ASSERT_TRUE(cli.start());

    sys::startup();
    net::socket_t peer = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(peer, net::kInvalidSocket);
    sockaddr_in pa = loopback(0);
    ASSERT_EQ(::bind(peer, reinterpret_cast<sockaddr*>(&pa), sizeof(pa)), 0);
    sockaddr_in peer_addr{};
    socklen_t pal = sizeof(peer_addr);
    ASSERT_EQ(::getsockname(peer, reinterpret_cast<sockaddr*>(&peer_addr), &pal), 0);
#ifdef _WIN32
    DWORD tmo = 2000;
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
    timeval tmo{2, 0};
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif

    ASSERT_TRUE(client.allocate(cli));
    ASSERT_TRUE(wait_until([&] { return client.allocated(); },
                           std::chrono::milliseconds(3000)));
    ASSERT_TRUE(client.channel_bind(
        cli, reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr),
        turn::kChannelBase + 1));
    ASSERT_TRUE(wait_until([&] { return client.channel_acked(); },
                           std::chrono::milliseconds(2000)));

    const std::uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    ASSERT_TRUE(client.send_channel(
        cli, reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr),
        data, sizeof(data)));
    std::uint8_t rx[64];
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    const ssize_t n = ::recvfrom(peer, reinterpret_cast<char*>(rx), sizeof(rx), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fl);
    ASSERT_EQ(n, static_cast<ssize_t>(sizeof(data)));
    EXPECT_EQ(std::memcmp(rx, data, sizeof(data)), 0);

    sys::close_socket(peer);
    cli.stop();
    ctrl.stop();
    relay.stop();
}
