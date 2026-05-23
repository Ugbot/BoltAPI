// quic_stream_test.cpp — wave 5a GATE: QUIC streams + RFC 9002 loss recovery +
// NewReno congestion control + flow control, over UDP loopback after a real
// handshake, plus unit tests for the RTT/PTO math, NewReno transitions, and
// stream-id encoding.
//
// The loopback harness mirrors the wave-4 connection gate: two QuicConnections
// (client + server) on two net::UdpTransports bound to ephemeral loopback
// ports, driven to Established, then exercised at the stream layer:
//   * CleanStreamEcho — client opens a bidi stream, sends a multi-KB message
//     (spanning multiple STREAM frames/packets), the server receives it
//     byte-exact + in order and echoes it back with FIN; the client receives
//     the echo + FIN.
//   * LossyLinkCompletes — ~15% of datagrams (seeded) are dropped between the
//     peers; the same transfer STILL completes correctly via loss recovery /
//     retransmit, and cwnd grows then backs off on loss.
//   * FlowControlNoDeadlock — a small per-stream recv window forces repeated
//     window updates; the full message still arrives with no deadlock.
//
// Bounded by wall-clock deadlines — no hang. OpenSSL + ws2_32/mswsock (WIN32).

#include "boltapi/quic/connection.h"
#include "boltapi/quic/loss.h"
#include "boltapi/quic/stream.h"
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
#include <random>
#include <thread>
#include <vector>

namespace q    = bolt::api::quic;
namespace net  = bolt::api::net;
namespace core = bolt::api::core;

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
    a.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

// Deterministic pseudo-random payload (so server can verify byte-exact).
std::vector<std::uint8_t> make_payload(std::size_t n, std::uint32_t seed) {
    std::vector<std::uint8_t> v(n);
    std::mt19937 rng(seed);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>(rng() & 0xFF);
    return v;
}

// Two QuicConnections cross-wired over loopback UDP. Each connection's send fn
// pushes the built datagram to the peer's bound UDP socket; the I/O thread
// enqueues arrivals into a per-receiver in-order FIFO that the single-threaded
// driver loop drains and feeds to the owning connection. Single-threaded
// draining keeps datagrams in order (no worker-thread reordering), so the clean
// link is genuinely clean; an optional seeded drop rate (applied at drain time)
// models real packet loss for the loss-recovery variant. Real UDP packets cross
// the loopback wire; the FIFO only serializes delivery deterministically.
//
// The driver pumps in a tight inner loop that drains until quiescent before
// sleeping, so transfers are not bottlenecked by the OS timer granularity.
struct Pair {
    net::UdpTransport client_udp{shared_dispatcher()};
    net::UdpTransport server_udp{shared_dispatcher()};
    q::QuicConnection client, server;

    std::mutex qmtx;
    std::vector<std::vector<std::uint8_t>> to_client, to_server;  // FIFOs

    unsigned drop_seed = 0;
    int drop_pct = 0;
    std::uint64_t recv_c = 0, recv_s = 0;  // datagram counters for drop decision

    bool drop(std::uint64_t n) {
        if (drop_pct == 0) return false;
        std::mt19937 rng(drop_seed + static_cast<unsigned>(n) * 2654435761u);
        return (static_cast<int>(rng() % 100) < drop_pct);
    }

    bool setup(int loss_pct, unsigned seed,
               q::QuicStreamDataFn server_on_data,
               q::QuicStreamDataFn client_on_data,
               std::uint64_t /*unused*/ = 0) {
        drop_pct = loss_pct;
        drop_seed = seed;
        if (!client_udp.bind("127.0.0.1", 0)) return false;
        if (!server_udp.bind("127.0.0.1", 0)) return false;
        const auto saddr = loopback(server_udp.bound_port());
        const auto caddr = loopback(client_udp.bound_port());

        auto csend = [this, saddr](const std::uint8_t* d, std::size_t n) {
            client_udp.send(reinterpret_cast<const sockaddr*>(&saddr),
                            sizeof(saddr), d, n);
        };
        auto ssend = [this, caddr](const std::uint8_t* d, std::size_t n) {
            server_udp.send(reinterpret_cast<const sockaddr*>(&caddr),
                            sizeof(caddr), d, n);
        };
        if (!client.init(false, csend)) return false;
        if (!server.init(true, ssend)) return false;
        client.set_stream_data_handler(std::move(client_on_data));
        server.set_stream_data_handler(std::move(server_on_data));

        client_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(qmtx);
                to_client.emplace_back(d, d + n);
            });
        server_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(qmtx);
                to_server.emplace_back(d, d + n);
            });
        if (!client_udp.start() || !server_udp.start()) return false;
        return true;
    }

    // Drain both FIFOs into their connections (in order), applying the seeded
    // drop rate. Returns the number of datagrams delivered.
    std::size_t drain() {
        std::vector<std::vector<std::uint8_t>> c, s;
        { std::lock_guard<std::mutex> lk(qmtx); c.swap(to_client); s.swap(to_server); }
        std::size_t delivered = 0;
        for (auto& dg : c) {
            if (!drop(recv_c++)) { client.feed_datagram(dg.data(), dg.size()); ++delivered; }
        }
        for (auto& dg : s) {
            if (!drop(recv_s++)) { server.feed_datagram(dg.data(), dg.size()); ++delivered; }
        }
        return delivered;
    }

    bool handshake(std::chrono::seconds budget) {
        if (!client.start()) return false;
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            pump_once();
            if (client.is_established() && server.is_established()) return true;
        }
        return false;
    }

    // One driver step: drain pending datagrams (in order, with seeded drops),
    // then tick both sides to process + send. A brief yield lets the I/O thread
    // deliver the resulting flight before the next step.
    void pump_once() {
        drain();
        client.tick();
        server.tick();
        std::this_thread::sleep_for(std::chrono::microseconds(300));
    }

    void stop() { client_udp.stop(); server_udp.stop(); }
};

}  // namespace

// ============================================================================
// UNIT: stream-id encoding (RFC 9000 §2.1).
// ============================================================================
TEST(QuicStreamUnit, StreamIdEncoding) {
    using namespace q;
    // client bidi: ...00 ; server bidi: ...01 ; client uni: ...10 ; server uni: ...11
    EXPECT_EQ(make_stream_id(0, /*server=*/false, /*uni=*/false), 0u);
    EXPECT_EQ(make_stream_id(0, /*server=*/true,  /*uni=*/false), 1u);
    EXPECT_EQ(make_stream_id(0, /*server=*/false, /*uni=*/true),  2u);
    EXPECT_EQ(make_stream_id(0, /*server=*/true,  /*uni=*/true),  3u);
    EXPECT_EQ(make_stream_id(1, /*server=*/false, /*uni=*/false), 4u);
    EXPECT_EQ(make_stream_id(5, /*server=*/true,  /*uni=*/false), (5u << 2) | 1u);

    EXPECT_TRUE(stream_is_client_initiated(0));
    EXPECT_TRUE(stream_is_server_initiated(1));
    EXPECT_TRUE(stream_is_bidi(0));
    EXPECT_TRUE(stream_is_bidi(1));
    EXPECT_TRUE(stream_is_uni(2));
    EXPECT_TRUE(stream_is_uni(3));
}

// ============================================================================
// UNIT: RTT estimation + PTO math (RFC 9002 §5.3 / §6.2.1).
// ============================================================================
TEST(QuicLossUnit, RttAndPto) {
    using namespace q;
    RttEstimator rtt;
    EXPECT_FALSE(rtt.have_sample());
    // First sample initializes smoothed=rtt, rttvar=rtt/2.
    rtt.on_rtt_sample(100000, 0);
    EXPECT_TRUE(rtt.have_sample());
    EXPECT_EQ(rtt.smoothed(), 100000u);
    EXPECT_EQ(rtt.rttvar(), 50000u);
    EXPECT_EQ(rtt.min_rtt(), 100000u);
    // A larger sample pulls smoothed up but not all the way (alpha=1/8).
    rtt.on_rtt_sample(180000, 0);
    EXPECT_GT(rtt.smoothed(), 100000u);
    EXPECT_LT(rtt.smoothed(), 180000u);
    EXPECT_EQ(rtt.min_rtt(), 100000u);  // min unchanged
    // PTO grows with backoff (exponential, RFC 9002 §6.2.1).
    const std::uint64_t pto0 = rtt.pto(25000, 0);
    const std::uint64_t pto1 = rtt.pto(25000, 1);
    const std::uint64_t pto2 = rtt.pto(25000, 2);
    EXPECT_GT(pto0, rtt.smoothed());  // includes 4*rttvar + max_ack_delay
    EXPECT_EQ(pto1, pto0 * 2);
    EXPECT_EQ(pto2, pto0 * 4);
}

// ============================================================================
// UNIT: NewReno transitions (RFC 9002 §7).
// ============================================================================
TEST(QuicCongestionUnit, NewRenoTransitions) {
    using namespace q;
    NewRenoCongestion cc;
    EXPECT_EQ(cc.cwnd(), NewRenoCongestion::kInitialWindow);
    EXPECT_TRUE(cc.in_slow_start());
    EXPECT_EQ(cc.bytes_in_flight(), 0u);

    // Slow start: cwnd grows by acked bytes (exponential).
    cc.on_packet_sent(1200);
    EXPECT_EQ(cc.bytes_in_flight(), 1200u);
    const std::uint64_t cwnd_before = cc.cwnd();
    cc.on_packet_acked(1200, /*sent_time=*/10);
    EXPECT_EQ(cc.cwnd(), cwnd_before + 1200);
    EXPECT_EQ(cc.bytes_in_flight(), 0u);

    // Loss: enter recovery, ssthresh = cwnd/2, cwnd = ssthresh.
    cc.on_packet_sent(1200);
    const std::uint64_t pre_loss = cc.cwnd();
    cc.on_packet_lost(1200);
    cc.on_congestion_event(/*sent_time=*/100, /*now=*/200);
    EXPECT_EQ(cc.cwnd(), pre_loss / 2);
    EXPECT_EQ(cc.ssthresh(), pre_loss / 2);
    EXPECT_FALSE(cc.in_slow_start());  // now in congestion avoidance

    // Congestion avoidance: cwnd grows sub-linearly (< acked bytes).
    const std::uint64_t ca_before = cc.cwnd();
    cc.on_packet_sent(1200);
    cc.on_packet_acked(1200, /*sent_time=*/300);  // after recovery start
    EXPECT_GT(cc.cwnd(), ca_before);
    EXPECT_LT(cc.cwnd() - ca_before, 1200u);

    // Persistent congestion collapses to the minimum window.
    cc.on_persistent_congestion();
    EXPECT_EQ(cc.cwnd(), NewRenoCongestion::kMinimumWindow);

    // can_send respects the window.
    NewRenoCongestion cc2;
    EXPECT_TRUE(cc2.can_send(1200));
    cc2.on_packet_sent(cc2.cwnd());
    EXPECT_FALSE(cc2.can_send(1));
}

// ============================================================================
// UNIT: per-stream ordered reassembly (in-order + out-of-order).
// ============================================================================
TEST(QuicStreamUnit, OrderedReassembly) {
    using namespace q;
    Stream s;
    s.open(/*id=*/0, /*send_max=*/0, /*recv_max=*/64 * 1024);
    const std::uint8_t a[] = {1, 2, 3, 4};
    const std::uint8_t b[] = {5, 6, 7, 8};
    // Deliver second chunk first (out of order): nothing contiguous yet.
    EXPECT_TRUE(s.receive(4, b, 4, false));
    EXPECT_EQ(s.recv_available(), 0u);
    // Now the first chunk fills the gap: all 8 bytes become contiguous.
    EXPECT_TRUE(s.receive(0, a, 4, true));
    EXPECT_EQ(s.recv_available(), 8u);
    const std::uint8_t* p = s.recv_peek();
    for (std::uint8_t i = 0; i < 8; ++i) EXPECT_EQ(p[i], i + 1);
    s.recv_consume(8);
    EXPECT_TRUE(s.recv_finished());
}

// ============================================================================
// GATE: clean stream echo over loopback after handshake.
// ============================================================================
TEST(QuicStream, CleanStreamEcho) {
    constexpr std::size_t kMsg = 16 * 1024;  // multi-KB -> many frames/packets
    const auto payload = make_payload(kMsg, 0xC0FFEE);

    // Server: accumulate inbound stream bytes, and on FIN echo them all back.
    std::vector<std::uint8_t> server_rx;
    bool server_saw_fin = false;
    std::uint64_t echo_stream_id = 0;
    bool echo_pending = false;

    auto p_owner = std::make_unique<Pair>();
    Pair& p = *p_owner;
    auto server_on_data = [&](std::uint64_t id, const std::uint8_t* d,
                              std::size_t n, bool fin) {
        server_rx.insert(server_rx.end(), d, d + n);
        if (fin) { server_saw_fin = true; echo_stream_id = id; echo_pending = true; }
    };

    std::vector<std::uint8_t> client_rx;
    bool client_saw_fin = false;
    auto client_on_data = [&](std::uint64_t, const std::uint8_t* d,
                              std::size_t n, bool fin) {
        client_rx.insert(client_rx.end(), d, d + n);
        if (fin) client_saw_fin = true;
    };

    ASSERT_TRUE(p.setup(0, 1, server_on_data, client_on_data));
    ASSERT_TRUE(p.handshake(std::chrono::seconds(10)));

    const std::uint64_t sid = p.client.open_bidi();
    p.client.stream_write(sid, payload.data(), payload.size(), /*fin=*/true);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        // Once the server has the full message, echo it back on the same stream.
        if (echo_pending) {
            echo_pending = false;
            p.server.stream_write(echo_stream_id, server_rx.data(),
                                  server_rx.size(), /*fin=*/true);
        }
        p.pump_once();
        if (client_saw_fin && client_rx.size() == kMsg) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_TRUE(server_saw_fin);
    ASSERT_EQ(server_rx.size(), kMsg) << "server did not receive full message";
    EXPECT_EQ(0, std::memcmp(server_rx.data(), payload.data(), kMsg))
        << "server received bytes not byte-exact";
    EXPECT_TRUE(client_saw_fin) << "client never saw echo FIN";
    ASSERT_EQ(client_rx.size(), kMsg) << "client did not receive full echo";
    EXPECT_EQ(0, std::memcmp(client_rx.data(), payload.data(), kMsg))
        << "echo not byte-exact";
    p.stop();
}

// ============================================================================
// GATE: lossy link (~15% drop) still completes via loss recovery; cwnd evolves.
// ============================================================================
TEST(QuicStream, LossyLinkCompletes) {
    constexpr std::size_t kMsg = 24 * 1024;
    const auto payload = make_payload(kMsg, 0xBADF00D);

    std::vector<std::uint8_t> server_rx;
    bool server_saw_fin = false;

    auto p_owner = std::make_unique<Pair>();
    Pair& p = *p_owner;
    auto server_on_data = [&](std::uint64_t, const std::uint8_t* d,
                              std::size_t n, bool fin) {
        server_rx.insert(server_rx.end(), d, d + n);
        if (fin) server_saw_fin = true;
    };
    auto client_on_data = [&](std::uint64_t, const std::uint8_t*, std::size_t, bool) {};

    // Handshake on a clean link first (so it reliably reaches Established),
    // then enable 15% drops for the data transfer.
    ASSERT_TRUE(p.setup(0, 7, server_on_data, client_on_data));
    ASSERT_TRUE(p.handshake(std::chrono::seconds(10)));
    p.drop_pct = 15;

    const std::uint64_t initial_cwnd = p.client.congestion().cwnd();
    const std::uint64_t sid = p.client.open_bidi();
    p.client.stream_write(sid, payload.data(), payload.size(), true);

    std::uint64_t max_cwnd = initial_cwnd;
    bool grew = false, backed_off = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(25);
    while (std::chrono::steady_clock::now() < deadline) {
        p.pump_once();
        const std::uint64_t cw = p.client.congestion().cwnd();
        if (cw > max_cwnd) { max_cwnd = cw; grew = true; }
        if (grew && cw < max_cwnd) backed_off = true;
        if (server_saw_fin && server_rx.size() == kMsg) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    ASSERT_EQ(server_rx.size(), kMsg) << "lossy transfer incomplete";
    EXPECT_EQ(0, std::memcmp(server_rx.data(), payload.data(), kMsg))
        << "lossy transfer corrupted";
    EXPECT_TRUE(server_saw_fin);
    EXPECT_TRUE(grew) << "cwnd never grew during transfer";
    EXPECT_TRUE(backed_off) << "cwnd never backed off under loss";
    p.stop();
}

// ============================================================================
// GATE: small per-stream recv window forces window updates; no deadlock.
// ============================================================================
TEST(QuicStream, FlowControlNoDeadlock) {
    constexpr std::size_t kMsg = 20 * 1024;
    const auto payload = make_payload(kMsg, 0x5EED);

    std::vector<std::uint8_t> server_rx;
    bool server_saw_fin = false;

    auto p_owner = std::make_unique<Pair>();
    Pair& p = *p_owner;
    auto server_on_data = [&](std::uint64_t, const std::uint8_t* d,
                              std::size_t n, bool fin) {
        server_rx.insert(server_rx.end(), d, d + n);
        if (fin) server_saw_fin = true;
    };
    auto client_on_data = [&](std::uint64_t, const std::uint8_t*, std::size_t, bool) {};

    ASSERT_TRUE(p.setup(0, 11, server_on_data, client_on_data));
    ASSERT_TRUE(p.handshake(std::chrono::seconds(10)));

    // The server's advertised per-stream recv window (kStreamRecvWindow, 128KB
    // initially) is smaller than this message would need without growth as the
    // server consumes; delivery therefore depends on the server issuing
    // MAX_STREAM_DATA / MAX_DATA window updates as it reads — exercising the
    // flow-control window-update path. The transfer must complete with no
    // deadlock.
    const std::uint64_t sid = p.client.open_bidi();
    p.client.stream_write(sid, payload.data(), payload.size(), true);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        p.pump_once();
        if (server_saw_fin && server_rx.size() == kMsg) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    ASSERT_EQ(server_rx.size(), kMsg) << "flow-controlled transfer deadlocked/incomplete";
    EXPECT_EQ(0, std::memcmp(server_rx.data(), payload.data(), kMsg));
    EXPECT_TRUE(server_saw_fin);
    p.stop();
}
