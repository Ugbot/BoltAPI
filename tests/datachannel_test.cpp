// datachannel_test.cpp — THE WEBRTC DATA-CHANNEL GATE (unconditional, gtest).
//
// Proves the final WebRTC-as-transport piece end to end:
//   * CRC-32c (RFC 3309) against known vectors.
//   * SCTP association 4-way handshake (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK)
//     driven between two in-process SctpAssociation endpoints (no network), then
//     a reliable+ordered DATA round-trip with SACK.
//   * END-TO-END LOOPBACK: our full server stack (UdpTransport + DTLS server +
//     DtlsSessionManager + WebRtcPeerHub with an App-shaped on_data_channel echo
//     handler) over real loopback UDP, against a CLIENT that uses our own stack
//     as the ACTIVE side: a real OpenSSL DTLS client carrying our SCTP active
//     association + DCEP DATA_CHANNEL_OPEN. Asserts the App handler fires with
//     the right label, receives the string message, echoes it, and the client
//     receives the echo. Bounded by a deadline (no hang).
//
// This is the loopback-with-our-stack gate (browser/aiortc interop is a later
// validation, noted in docs/WEBRTC_PLAN.md §10).

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/sctp.h"
#include "boltapi/webrtc/data_channel.h"
#include "boltapi/webrtc/peer_hub.h"

#include "bolt/io/bolt_crc32c.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace net  = bolt::api::net;
namespace sys  = bolt::api::net::sys;
namespace core = bolt::api::core;
namespace wrtc = bolt::api::webrtc;

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

}  // namespace

// ===========================================================================
// 1) CRC-32c (RFC 3309) known vectors.
// ===========================================================================
TEST(SctpCrc32c, KnownVectors) {
    // The canonical CRC32C check value: crc32c("123456789") == 0xE3069283.
    const char* s = "123456789";
    EXPECT_EQ(bolt::io::crc32c(s, std::strlen(s), 0u), 0xE3069283u);

    // Empty input -> 0.
    EXPECT_EQ(bolt::io::crc32c("", 0u, 0u), 0u);

    // 32 zero bytes -> 0x8A9136AA (iSCSI/RFC 3720 Appendix B test vector).
    std::uint8_t zeros[32] = {0};
    EXPECT_EQ(bolt::io::crc32c(zeros, sizeof(zeros), 0u), 0x8A9136AAu);

    // 32 0xFF bytes -> 0x62A8AB43 (RFC 3720 Appendix B).
    std::uint8_t ffs[32];
    std::memset(ffs, 0xFF, sizeof(ffs));
    EXPECT_EQ(bolt::io::crc32c(ffs, sizeof(ffs), 0u), 0x62A8AB43u);

    // sctp_crc32c on a 12-byte all-zero common header (checksum zeroed) must
    // equal crc over 12 zero bytes -> 0x756EC955 (RFC 3720 incrementing? no:
    // compute directly and assert self-consistency: zeroing field [8..12) of an
    // all-zero buffer is the buffer itself).
    std::uint8_t hdr[12] = {0};
    EXPECT_EQ(wrtc::sctp_crc32c(hdr, sizeof(hdr)),
              bolt::io::crc32c(hdr, sizeof(hdr), 0u));
}

// ===========================================================================
// 2) SCTP association handshake + DATA/SACK round trip (two endpoints, no net).
// ===========================================================================
TEST(Sctp, HandshakeAndDataRoundTrip) {
    using Assoc = wrtc::SctpAssociation;

    // Cross-wire the two associations directly: each one's packet sink hands the
    // bytes to the other's feed(). We buffer to avoid reentrancy (feed inside a
    // sink inside a feed), draining in a bounded loop.
    // Heap-allocate: SctpAssociation embeds large preallocated rings (send ring
    // + reorder buffers), too big for the stack (TigerStyle: bounded, but bound
    // is generous — they belong on the heap, as DataChannelStack does).
    auto passive_p = std::make_unique<Assoc>();
    auto active_p  = std::make_unique<Assoc>();
    Assoc& passive = *passive_p;  // answerer
    Assoc& active  = *active_p;    // initiator

    std::vector<std::string> to_passive, to_active;

    std::vector<std::pair<std::uint16_t, std::string>> passive_rx, active_rx;

    passive.init(Assoc::Role::Passive,
        [&](const std::uint8_t* p, std::size_t n) -> bool {
            to_active.emplace_back(reinterpret_cast<const char*>(p), n);
            return true;
        },
        [&](const wrtc::SctpRecvMessage& m) {
            passive_rx.emplace_back(m.stream_id,
                std::string(reinterpret_cast<const char*>(m.data), m.len));
        });

    active.init(Assoc::Role::Active,
        [&](const std::uint8_t* p, std::size_t n) -> bool {
            to_passive.emplace_back(reinterpret_cast<const char*>(p), n);
            return true;
        },
        [&](const wrtc::SctpRecvMessage& m) {
            active_rx.emplace_back(m.stream_id,
                std::string(reinterpret_cast<const char*>(m.data), m.len));
        });

    // Kick off the handshake from the active side.
    ASSERT_TRUE(active.connect());

    // Pump the cross-wired queues until both are Established or we give up.
    auto pump = [&](int max_rounds) {
        for (int r = 0; r < max_rounds; ++r) {
            std::vector<std::string> a = std::move(to_active);
            std::vector<std::string> p = std::move(to_passive);
            to_active.clear();
            to_passive.clear();
            for (auto& pkt : a)
                active.feed(reinterpret_cast<const std::uint8_t*>(pkt.data()),
                            pkt.size());
            for (auto& pkt : p)
                passive.feed(reinterpret_cast<const std::uint8_t*>(pkt.data()),
                             pkt.size());
            if (to_active.empty() && to_passive.empty()) break;
        }
    };
    pump(20);

    ASSERT_EQ(active.state(), Assoc::State::Established);
    ASSERT_EQ(passive.state(), Assoc::State::Established);
    EXPECT_NE(active.local_tag(), 0u);
    EXPECT_NE(passive.local_tag(), 0u);
    EXPECT_EQ(active.peer_tag(), passive.local_tag());
    EXPECT_EQ(passive.peer_tag(), active.local_tag());

    // ---- Reliable+ordered DATA both ways, multiple messages, two streams. ----
    const std::uint32_t kStr = static_cast<std::uint32_t>(wrtc::Ppid::String);
    ASSERT_TRUE(active.send(0, kStr,
        reinterpret_cast<const std::uint8_t*>("hello"), 5));
    ASSERT_TRUE(active.send(0, kStr,
        reinterpret_cast<const std::uint8_t*>("world"), 5));
    ASSERT_TRUE(active.send(3, kStr,
        reinterpret_cast<const std::uint8_t*>("stream3"), 7));
    pump(20);

    ASSERT_EQ(passive_rx.size(), 3u);
    EXPECT_EQ(passive_rx[0].first, 0);
    EXPECT_EQ(passive_rx[0].second, "hello");
    EXPECT_EQ(passive_rx[1].second, "world");
    EXPECT_EQ(passive_rx[2].first, 3);
    EXPECT_EQ(passive_rx[2].second, "stream3");

    // Reply from passive -> active.
    ASSERT_TRUE(passive.send(0, kStr,
        reinterpret_cast<const std::uint8_t*>("ack-back"), 8));
    pump(20);
    ASSERT_EQ(active_rx.size(), 1u);
    EXPECT_EQ(active_rx[0].second, "ack-back");
}

// ===========================================================================
// 3) END-TO-END LOOPBACK over real DTLS + our SCTP/DCEP.
// ===========================================================================
namespace {

// A DTLS+SCTP CLIENT (the active side) using our own SctpAssociation/DCEP over a
// real OpenSSL DTLS client on a connected loopback UDP socket. SCTP packets ride
// as DTLS app records (SSL_write); inbound app records (SSL_read) feed SCTP.
struct E2EClient {
    SSL_CTX*      ctx  = nullptr;
    SSL*          ssl  = nullptr;
    net::socket_t fd   = net::kInvalidSocket;
    EVP_PKEY*     pkey = nullptr;
    X509*         cert = nullptr;

    wrtc::DataChannelStack stack;
    wrtc::DataChannel*     channel = nullptr;
    std::vector<std::string> received;  // messages echoed back from the server

    static int permissive_verify(int, X509_STORE_CTX*) { return 1; }

    bool make_cert() {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (kctx) {
            if (EVP_PKEY_keygen_init(kctx) > 0 &&
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                    kctx, NID_X9_62_prime256v1) > 0) {
                EVP_PKEY_keygen(kctx, &pkey);
            }
            EVP_PKEY_CTX_free(kctx);
        }
        if (!pkey) return false;
        cert = X509_new();
        if (!cert) return false;
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 3);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("DcTestClient"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        return X509_sign(cert, pkey, EVP_sha256()) != 0;
    }

    std::string fingerprint() const {
        std::string out;
        wrtc::x509_sha256_fingerprint(cert, out);
        return out;
    }

    bool open(std::uint16_t server_port) {
        sys::startup();
        if (!make_cert()) return false;
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == net::kInvalidSocket) return false;
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        any.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&any), sizeof(any)) != 0)
            return false;
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(server_port);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0)
            return false;
#ifdef _WIN32
        DWORD tmo = 200;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
        timeval tmo{0, 200 * 1000};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif
        ctx = SSL_CTX_new(DTLS_client_method());
        if (!ctx) return false;
        SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, permissive_verify);
        if (SSL_CTX_use_certificate(ctx, cert) != 1) return false;
        if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return false;
        ssl = SSL_new(ctx);
        if (!ssl) return false;
        BIO* bio = BIO_new_dgram(static_cast<int>(fd), BIO_NOCLOSE);
        if (!bio) return false;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dst);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_connect_state(ssl);
        return true;
    }

    bool handshake(std::chrono::steady_clock::time_point deadline) {
        for (;;) {
            const int rc = SSL_connect(ssl);
            if (rc == 1) return true;
            const int err = SSL_get_error(ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (std::chrono::steady_clock::now() >= deadline) return false;
                continue;
            }
            return false;
        }
    }

    // Wire the SCTP active stack: sink = SSL_write; messages -> received.
    void setup_stack() {
        SSL* s = ssl;
        stack.init(wrtc::SctpAssociation::Role::Active,
            [s](const std::uint8_t* pkt, std::size_t n) -> bool {
                return SSL_write(s, pkt, static_cast<int>(n)) > 0;
            },
            [this](wrtc::DataChannel& ch) {
                // Our own opened channel got established; capture echoes.
                ch.on_message([this](const void* d, std::size_t n, bool) {
                    received.emplace_back(
                        reinterpret_cast<const char*>(d), n);
                });
            });
    }

    // Pump inbound DTLS app records into SCTP for a bounded time.
    void pump(std::chrono::milliseconds dur) {
        const auto end = std::chrono::steady_clock::now() + dur;
        std::uint8_t buf[2048];
        while (std::chrono::steady_clock::now() < end) {
            const int n = SSL_read(ssl, buf, sizeof(buf));
            if (n > 0) {
                stack.feed(buf, static_cast<std::size_t>(n));
            }
            stack.tick_retransmit();
        }
    }

    void close_all() {
        if (ssl)  { SSL_free(ssl);  ssl  = nullptr; }
        if (ctx)  { SSL_CTX_free(ctx); ctx = nullptr; }
        if (cert) { X509_free(cert); cert = nullptr; }
        if (pkey) { EVP_PKEY_free(pkey); pkey = nullptr; }
        if (fd != net::kInvalidSocket) { sys::close_socket(fd); fd = net::kInvalidSocket; }
    }
    ~E2EClient() { close_all(); }
};

}  // namespace

TEST(DataChannel, EndToEndLoopbackEcho) {
    // ---- SERVER STACK (our answerer): transport + DTLS + hub + App handler. ----
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    wrtc::DtlsSessionManager mgr(*dctx, transport);
    wrtc::WebRtcPeerHub hub(mgr, transport);

    // App-shaped on_data_channel("chat", echo) handler: when a channel opens,
    // attach an on_message that echoes the bytes back on the same channel.
    std::atomic<bool> handler_fired{false};
    std::string seen_label;
    std::atomic<int> server_msgs{0};
    hub.set_channel_ready([&](wrtc::DataChannel& ch) {
        handler_fired.store(true);
        seen_label = ch.label();
        wrtc::DataChannel* chp = &ch;
        ch.on_message([&, chp](const void* d, std::size_t n, bool is_bin) {
            ++server_msgs;
            // Echo it straight back (the App handler's reply path).
            if (is_bin) chp->send_binary(d, n);
            else        chp->send_text(std::string_view(
                            reinterpret_cast<const char*>(d), n));
        });
    });

    transport.set_datagram_handler(
        [&](const sockaddr* peer, int plen, const std::uint8_t* data,
            std::size_t len) { hub.feed(peer, plen, data, len); });
    ASSERT_TRUE(transport.start());

    // ---- CLIENT (active side, our SCTP over real OpenSSL DTLS). ----
    // Heap-allocate: embeds a DataChannelStack with large preallocated rings.
    auto client_p = std::make_unique<E2EClient>();
    E2EClient& client = *client_p;
    ASSERT_TRUE(client.open(port));

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);

    // DTLS handshake (client drives; server pumps on its I/O thread).
    std::atomic<bool> dtls_ok{false};
    std::thread hs([&] { dtls_ok.store(client.handshake(deadline)); });
    hs.join();
    ASSERT_TRUE(dtls_ok.load()) << "client DTLS handshake failed";

    // Now drive SCTP: the client is the SCTP ACTIVE side. Open a "chat" channel.
    client.setup_stack();
    client.channel = client.stack.open_channel("chat");
    ASSERT_NE(client.channel, nullptr);
    ASSERT_TRUE(client.stack.connect());  // emit INIT

    // Drive the SCTP handshake + DCEP open: client SSL_write goes to the server
    // via DTLS, the server I/O thread feeds the hub which runs SCTP + DCEP and
    // replies (INIT-ACK/COOKIE-ACK/DCEP ACK) back as DTLS records. The client
    // pump() drains those and advances. Bounded.
    {
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < t_end &&
               !client.stack.established()) {
            client.pump(std::chrono::milliseconds(50));
        }
    }
    ASSERT_TRUE(client.stack.established())
        << "SCTP association did not establish over DTLS";

    // The channel must be open (DCEP ACK received) before we send the message.
    {
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < t_end &&
               !client.channel->is_open()) {
            client.pump(std::chrono::milliseconds(50));
        }
    }
    ASSERT_TRUE(client.channel->is_open()) << "DCEP channel did not open";
    EXPECT_TRUE(handler_fired.load()) << "App on_data_channel handler never fired";
    EXPECT_EQ(seen_label, "chat");

    // Send a string message; the server echoes; the client receives it back.
    const std::string msg = "bolt-datachannel-roundtrip-9876543210";
    ASSERT_TRUE(client.channel->send_text(msg));

    {
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < t_end &&
               client.received.empty()) {
            client.pump(std::chrono::milliseconds(50));
        }
    }

    ASSERT_FALSE(client.received.empty()) << "client never received the echo";
    EXPECT_EQ(client.received.front(), msg);
    EXPECT_GE(server_msgs.load(), 1) << "server handler did not see the message";

    // ---- Multiple, varied messages: a second string + a binary message, both
    //      echoed back in order (reliable+ordered semantics over the channel). --
    const std::string msg2 = "second-message-with-different-content";
    const std::string bin  = std::string("\x00\x01\x02\xFF\xFE", 5);
    ASSERT_TRUE(client.channel->send_text(msg2));
    ASSERT_TRUE(client.channel->send_binary(bin.data(), bin.size()));

    {
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < t_end &&
               client.received.size() < 3) {
            client.pump(std::chrono::milliseconds(50));
        }
    }
    ASSERT_GE(client.received.size(), 3u) << "did not receive both echoes";
    EXPECT_EQ(client.received[1], msg2);
    EXPECT_EQ(client.received[2], bin);
    EXPECT_GE(server_msgs.load(), 3);

    // ---- LARGE MESSAGE over the REAL DTLS+UDP path: a 64 KiB binary message is
    //      fragmented into many SCTP DATA chunks, echoed by the server, and
    //      reassembled byte-exact on the client. Exercises fragmentation +
    //      reassembly + SACK/cwnd end-to-end through OpenSSL DTLS records. -------
    std::string big;
    big.resize(64 * 1024);
    {
        std::mt19937 rng{4242};
        for (auto& c : big) c = static_cast<char>(rng() & 0xFF);
    }
    const std::size_t base_received = client.received.size();
    ASSERT_TRUE(client.channel->send_binary(big.data(), big.size()));
    {
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::seconds(15);
        while (std::chrono::steady_clock::now() < t_end &&
               client.received.size() <= base_received) {
            client.pump(std::chrono::milliseconds(50));
        }
    }
    ASSERT_GT(client.received.size(), base_received)
        << "client never received the 64 KiB echo (fragmentation/reassembly)";
    EXPECT_EQ(client.received.back().size(), big.size());
    EXPECT_EQ(client.received.back(), big) << "64 KiB echo not byte-exact";

    transport.stop();
}
