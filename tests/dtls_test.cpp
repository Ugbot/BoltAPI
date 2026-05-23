// dtls_test.cpp — THE LIVE DTLS GATE for the WebRTC DTLS server (answerer).
//
// We stand up our SERVER side: a UdpTransport on an ephemeral loopback UDP port,
// a shared DtlsContext (DTLS_server_method + self-signed cert), and a
// DtlsSessionManager wired as the transport's datagram handler. The transport
// demuxes first-byte 20..63 (DTLS) to the manager, which creates/feeds a
// per-peer DtlsSession driving SSL_do_handshake over memory BIOs and sending
// records back via the transport.
//
// We then run a REAL OpenSSL DTLS CLIENT: a connected UDP socket + BIO_new_dgram
// + DTLS_client_method; SSL_connect drives the handshake. The client presents
// its own self-signed cert. We feed the client cert's SHA-256 fingerprint to the
// server as the "SDP offer fingerprint" so the server's fingerprint binding is
// exercised end-to-end.
//
// Asserts (per CLAUDE.md: real path, multiple cases, not hello-world):
//   * BOTH sides complete the handshake; server session == Established.
//   * Server read the client's cert; fingerprint verification PASSED.
//   * NEGATIVE: a WRONG offer fingerprint -> server session Failed (rejected).
//   * App-data round trip: client SSL_write -> server read_app echoes via
//     send_app -> client SSL_read returns the same bytes.
// Bounded by a wall-clock deadline so a stuck handshake fails instead of hanging.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/dtls.h"

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
#include <string>
#include <thread>

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

// --- A minimal OpenSSL DTLS CLIENT over a connected UDP socket -------------
// Owns the socket, the DTLS_client_method SSL, a connected datagram BIO, and a
// self-signed client cert. handshake() drives SSL_connect with a deadline.
struct DtlsClient {
    SSL_CTX*      ctx  = nullptr;
    SSL*          ssl  = nullptr;
    net::socket_t fd   = net::kInvalidSocket;
    EVP_PKEY*     pkey = nullptr;
    X509*         cert = nullptr;

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
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("DtlsTestClient"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        return X509_sign(cert, pkey, EVP_sha256()) != 0;
    }

    // The client cert SHA-256 fingerprint "AA:BB:.." — this is what the server
    // verifies against (as if it came from the SDP offer's a=fingerprint).
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
        // CONNECT the UDP socket so the datagram BIO can use send/recv and the
        // server's replies (to our source addr) arrive here.
        if (::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0)
            return false;

        // Receive timeout so SSL_connect's BIO reads can't block forever.
#ifdef _WIN32
        DWORD tmo = 400;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
        timeval tmo{0, 400 * 1000};
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
        // Tell the dgram BIO the connected peer so it routes correctly.
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dst);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_connect_state(ssl);
        return true;
    }

    // Drive SSL_connect to completion (or failure) within `deadline`.
    bool handshake(std::chrono::steady_clock::time_point deadline) {
        for (;;) {
            const int rc = SSL_connect(ssl);
            if (rc == 1) return true;
            const int err = SSL_get_error(ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (std::chrono::steady_clock::now() >= deadline) return false;
                continue;  // BIO read timed out (RCVTIMEO) -> retry/retransmit
            }
            return false;  // fatal
        }
    }

    void close_all() {
        if (ssl)  { SSL_free(ssl);  ssl  = nullptr; }   // frees the BIO too
        if (ctx)  { SSL_CTX_free(ctx); ctx = nullptr; }
        if (cert) { X509_free(cert); cert = nullptr; }
        if (pkey) { EVP_PKEY_free(pkey); pkey = nullptr; }
        if (fd != net::kInvalidSocket) { sys::close_socket(fd); fd = net::kInvalidSocket; }
    }
    ~DtlsClient() { close_all(); }
};

// Pump the server's DtlsSession established state for `peer` until established
// or the deadline; the manager's feed runs on the transport I/O thread, so we
// just poll the session here. Returns the session (may be null if never seen).
wrtc::DtlsSession* wait_session(wrtc::DtlsSessionManager& mgr,
                                const sockaddr* peer, int plen,
                                std::chrono::steady_clock::time_point deadline) {
    wrtc::DtlsSession* s = nullptr;
    while (std::chrono::steady_clock::now() < deadline) {
        s = mgr.find(peer, plen);
        if (s && (s->established() ||
                  s->state() == wrtc::DtlsSession::State::Failed))
            return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return s;
}

}  // namespace

// ===========================================================================
// Context-level: fingerprint generation + parsing helpers.
// ===========================================================================
TEST(DtlsContext, CreatesValidContextAndFingerprint) {
    auto ctx = wrtc::DtlsContext::create();
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(ctx->is_valid());
    // SHA-256 fingerprint is 32 bytes -> "AA:" * 31 + "AA" = 95 chars.
    const std::string& fp = ctx->fingerprint();
    EXPECT_EQ(fp.size(), 95u);
    EXPECT_EQ(fp[2], ':');
    // Hex + colons only.
    for (char c : fp) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || c == ':');
    }
}

TEST(DtlsFingerprint, EqualityToleratesAlgoPrefixAndCase) {
    EXPECT_TRUE(wrtc::fingerprints_equal("AB:CD:EF", "ab:cd:ef"));
    EXPECT_TRUE(wrtc::fingerprints_equal("sha-256 AB:CD:EF", "AB:CD:EF"));
    EXPECT_TRUE(wrtc::fingerprints_equal("  AB:CD:EF  ", "AB:CD:EF"));
    EXPECT_FALSE(wrtc::fingerprints_equal("AB:CD:EF", "AB:CD:11"));
    EXPECT_FALSE(wrtc::fingerprints_equal("", ""));
}

// ===========================================================================
// THE LIVE DTLS HANDSHAKE — both sides complete, fingerprint verify, app data.
// ===========================================================================
TEST(Dtls, LiveHandshakeFingerprintVerifyAndAppData) {
    // ---- Server side: transport + DTLS context + session manager ----
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    wrtc::DtlsSessionManager mgr(*dctx, transport);

    // ---- Client cert fingerprint plays the role of the SDP offer fp ----
    DtlsClient client;
    ASSERT_TRUE(client.open(port));
    const std::string client_fp = client.fingerprint();
    ASSERT_EQ(client_fp.size(), 95u);
    mgr.set_offer_fingerprint(client_fp);

    transport.set_datagram_handler(
        [&](const sockaddr* peer, int plen, const std::uint8_t* data,
            std::size_t len) { mgr.feed(peer, plen, data, len); });
    ASSERT_TRUE(transport.start());

    // The client's source addr (so we can find its server-side session).
    sockaddr_in cli{};
    socklen_t cli_len = sizeof(cli);
    ASSERT_EQ(::getsockname(client.fd, reinterpret_cast<sockaddr*>(&cli),
                            &cli_len), 0);

    // ---- Drive the client handshake in a thread; server pumps on its I/O
    //      thread via the datagram handler. ----
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    std::atomic<bool> client_ok{false};
    std::thread client_thread([&] {
        client_ok.store(client.handshake(deadline));
    });

    // Wait for the server session to reach Established (or Failed).
    wrtc::DtlsSession* s = wait_session(
        mgr, reinterpret_cast<sockaddr*>(&cli),
        static_cast<int>(cli_len), deadline);

    client_thread.join();

    ASSERT_TRUE(client_ok.load()) << "client SSL_connect did not complete";
    ASSERT_NE(s, nullptr) << "server never created a session for the peer";
    EXPECT_EQ(s->state(), wrtc::DtlsSession::State::Established);
    EXPECT_TRUE(s->established());

    // Server read the client cert + fingerprint matched the "offer" fp.
    EXPECT_TRUE(wrtc::fingerprints_equal(s->peer_fingerprint(), client_fp));
    EXPECT_GE(s->records_in(), 1u);
    EXPECT_GE(s->records_out(), 1u);

    // ---- App-data round trip: client -> server (read_app) -> echo -> client.
    // Server-side echo runs from the datagram handler path; but read_app is on
    // the established session, so to keep the test deterministic we echo from a
    // small server pump thread that drains read_app and calls send_app.
    std::atomic<bool> stop_pump{false};
    std::thread server_pump([&] {
        std::uint8_t buf[2048];
        while (!stop_pump.load()) {
            const int n = s->read_app(buf, sizeof(buf));
            if (n > 0) {
                s->send_app(buf, static_cast<std::size_t>(n));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    });

    const char* msg = "bolt-dtls-roundtrip-0123456789";
    const int wn = SSL_write(client.ssl,
                             reinterpret_cast<const std::uint8_t*>(msg),
                             static_cast<int>(std::strlen(msg)));
    EXPECT_EQ(wn, static_cast<int>(std::strlen(msg)));

    // Read the echo back (bounded). The client socket has a 400ms RCVTIMEO; loop
    // until we get the echo or the overall deadline passes.
    std::string got;
    const auto rt_deadline = std::chrono::steady_clock::now() +
                             std::chrono::seconds(5);
    std::uint8_t rbuf[2048];
    while (got.size() < std::strlen(msg) &&
           std::chrono::steady_clock::now() < rt_deadline) {
        const int rn = SSL_read(client.ssl, rbuf, sizeof(rbuf));
        if (rn > 0) got.append(reinterpret_cast<char*>(rbuf),
                               static_cast<std::size_t>(rn));
    }
    stop_pump.store(true);
    server_pump.join();

    EXPECT_EQ(got, std::string(msg)) << "DTLS app-data echo mismatch";

    transport.stop();
}

// ===========================================================================
// NEGATIVE: a WRONG offer fingerprint must REJECT the peer (session Failed).
// ===========================================================================
TEST(Dtls, FingerprintMismatchRejected) {
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    wrtc::DtlsSessionManager mgr(*dctx, transport);

    DtlsClient client;
    ASSERT_TRUE(client.open(port));

    // Deliberately set an offer fingerprint that does NOT match the client cert.
    mgr.set_offer_fingerprint(
        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF");

    transport.set_datagram_handler(
        [&](const sockaddr* peer, int plen, const std::uint8_t* data,
            std::size_t len) { mgr.feed(peer, plen, data, len); });
    ASSERT_TRUE(transport.start());

    sockaddr_in cli{};
    socklen_t cli_len = sizeof(cli);
    ASSERT_EQ(::getsockname(client.fd, reinterpret_cast<sockaddr*>(&cli),
                            &cli_len), 0);

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    std::thread client_thread([&] { client.handshake(deadline); });

    // The DTLS handshake itself completes (mismatch is detected AFTER, when the
    // server pulls the peer cert), so we wait for the session and assert Failed.
    wrtc::DtlsSession* s = wait_session(
        mgr, reinterpret_cast<sockaddr*>(&cli),
        static_cast<int>(cli_len), deadline);
    client_thread.join();

    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->state(), wrtc::DtlsSession::State::Failed);
    EXPECT_FALSE(s->established());

    transport.stop();
}
