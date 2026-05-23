// dtls_srtp_test.cpp — THE LIVE DTLS-SRTP KEYING GATE (WM1, RFC 5764).
//
// Mirrors tests/dtls_test.cpp: our SERVER side is a UdpTransport on an ephemeral
// loopback UDP port + a shared DtlsContext (DTLS_server_method, use_srtp) + a
// DtlsSessionManager wired as the transport's datagram handler. We then run a
// REAL OpenSSL DTLS CLIENT (connected UDP socket + BIO_new_dgram +
// DTLS_client_method) that ALSO advertises the use_srtp extension.
//
// After BOTH sides complete the handshake we assert:
//   * the server-side DtlsSession is Established + fingerprint verified;
//   * BOTH sides negotiate the SAME SRTP profile;
//   * BOTH export keying material and build inbound/outbound SrtpSessions;
//   * END-TO-END KEY AGREEMENT: the CLIENT SRTP-protects an RTP packet (built
//     with our rtp.h), the SERVER SRTP-unprotects it -> byte-exact recovery,
//     AND the reverse direction (server protect -> client unprotect). This only
//     succeeds if the role-mapped keys agree across the two stacks.
// Bounded by a wall-clock deadline so a stuck handshake fails instead of hanging.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"

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
namespace srtp = bolt::api::webrtc::srtp;
namespace rtp  = bolt::api::webrtc::rtp;

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

// A minimal OpenSSL DTLS CLIENT with the use_srtp extension enabled. Exports its
// own SRTP keying after the handshake (client role: outbound = client-write
// keys, inbound = server-write keys — the mirror of our server's mapping).
struct DtlsSrtpClient {
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
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 3);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("DtlsSrtpTestClient"), -1, -1, 0);
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
        // Advertise the same profiles as the server so a profile is negotiated.
        if (SSL_CTX_set_tlsext_use_srtp(
                ctx, "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80") != 0)
            return false;
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

    // Export keying material on the client (DTLS client role) and build the
    // client-side SRTP sessions. Client outbound = client-write keys, client
    // inbound = server-write keys (the reverse of the server's mapping).
    bool make_srtp(srtp::SrtpSession& inbound, srtp::SrtpSession& outbound,
                   wrtc::SrtpProfileId* prof_out) {
        SRTP_PROTECTION_PROFILE* prof = SSL_get_selected_srtp_profile(ssl);
        if (prof == nullptr) return false;
        wrtc::SrtpKeying k;
        if (prof->id == 0x0007) k.profile = wrtc::SrtpProfileId::kAeadAes128Gcm;
        else if (prof->id == 0x0001)
            k.profile = wrtc::SrtpProfileId::kAesCm128HmacSha1_80;
        else return false;
        *prof_out = k.profile;
        k.is_server = false;  // the client role

        const std::size_t klen = wrtc::kSrtpMasterKeyLen;
        const std::size_t slen = wrtc::srtp_salt_len(k.profile);
        const std::size_t total = 2 * klen + 2 * slen;
        std::uint8_t block[wrtc::kSrtpKeyingMax]{};
        static const char kLabel[] = "EXTRACTOR-dtls_srtp";
        if (SSL_export_keying_material(ssl, block, total, kLabel,
                                       sizeof(kLabel) - 1, nullptr, 0, 0) != 1)
            return false;
        std::size_t off = 0;
        std::memcpy(k.client_key, block + off, klen); off += klen;
        std::memcpy(k.server_key, block + off, klen); off += klen;
        std::memcpy(k.client_salt, block + off, slen); off += slen;
        std::memcpy(k.server_salt, block + off, slen); off += slen;
        return k.build_sessions(inbound, outbound);
    }

    void close_all() {
        if (ssl)  { SSL_free(ssl);  ssl  = nullptr; }
        if (ctx)  { SSL_CTX_free(ctx); ctx = nullptr; }
        if (cert) { X509_free(cert); cert = nullptr; }
        if (pkey) { EVP_PKEY_free(pkey); pkey = nullptr; }
        if (fd != net::kInvalidSocket) { sys::close_socket(fd); fd = net::kInvalidSocket; }
    }
    ~DtlsSrtpClient() { close_all(); }
};

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

// Build a valid RTP packet (12-byte header + payload) via rtp.h serialize().
std::size_t build_rtp(std::uint8_t* buf, std::size_t cap, std::uint16_t seq,
                      std::uint32_t ssrc, std::uint32_t ts,
                      const std::uint8_t* payload, std::size_t plen) {
    rtp::Header h{};
    h.payload_type = 96;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;
    std::size_t written = 0;
    const rtp::RtpError e = rtp::serialize(h, payload, plen, 0, buf, cap, written);
    EXPECT_EQ(e, rtp::RtpError::Ok);
    return written;
}

}  // namespace

// ===========================================================================
// THE LIVE DTLS-SRTP KEYING GATE — both sides export, profiles match, and an
// RTP packet survives a protect->unprotect cross the two stacks (both ways).
// ===========================================================================
TEST(DtlsSrtp, LiveKeyingExportAndCrossStackRtpRoundTrip) {
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    wrtc::DtlsSessionManager mgr(*dctx, transport);

    DtlsSrtpClient client;
    ASSERT_TRUE(client.open(port));
    const std::string client_fp = client.fingerprint();
    ASSERT_EQ(client_fp.size(), 95u);
    mgr.set_offer_fingerprint(client_fp);

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
    std::atomic<bool> client_ok{false};
    std::thread client_thread([&] { client_ok.store(client.handshake(deadline)); });

    wrtc::DtlsSession* s = wait_session(
        mgr, reinterpret_cast<sockaddr*>(&cli),
        static_cast<int>(cli_len), deadline);
    client_thread.join();

    ASSERT_TRUE(client_ok.load()) << "client SSL_connect did not complete";
    ASSERT_NE(s, nullptr) << "server never created a session for the peer";
    ASSERT_EQ(s->state(), wrtc::DtlsSession::State::Established);
    EXPECT_TRUE(wrtc::fingerprints_equal(s->peer_fingerprint(), client_fp));

    // ---- Server side: export keying + build inbound/outbound SRTP. ----
    wrtc::SrtpKeying server_keying;
    ASSERT_TRUE(s->export_srtp_keying(server_keying));
    ASSERT_TRUE(server_keying.valid());
    ASSERT_TRUE(server_keying.is_server);
    srtp::SrtpSession srv_in, srv_out;
    ASSERT_TRUE(server_keying.build_sessions(srv_in, srv_out));
    EXPECT_TRUE(srv_in.is_initialized());
    EXPECT_TRUE(srv_out.is_initialized());

    // ---- Client side: export keying + build inbound/outbound SRTP. ----
    srtp::SrtpSession cli_in, cli_out;
    wrtc::SrtpProfileId cli_prof = wrtc::SrtpProfileId::kNone;
    ASSERT_TRUE(client.make_srtp(cli_in, cli_out, &cli_prof));

    // BOTH sides negotiated the SAME profile.
    EXPECT_EQ(server_keying.profile, cli_prof);
    EXPECT_NE(server_keying.profile, wrtc::SrtpProfileId::kNone);

    // ---- Cross-stack RTP: client protects -> server unprotects. ----
    const std::uint8_t payload_a[] = "bolt-srtp-c2s-payload-0123456789";
    std::uint8_t rtp_a[256];
    const std::size_t rtp_a_len =
        build_rtp(rtp_a, sizeof(rtp_a), 1000, 0x11223344u, 90000, payload_a,
                  sizeof(payload_a));
    ASSERT_GT(rtp_a_len, 12u);

    std::uint8_t prot_a[512];
    std::size_t prot_a_len = 0;
    ASSERT_EQ(cli_out.protect_rtp(rtp_a, rtp_a_len, prot_a, sizeof(prot_a),
                                  &prot_a_len),
              srtp::Error::kOk);
    ASSERT_GT(prot_a_len, rtp_a_len);  // tag (and GCM expansion) appended

    std::uint8_t recov_a[512];
    std::size_t recov_a_len = 0;
    ASSERT_EQ(srv_in.unprotect_rtp(prot_a, prot_a_len, recov_a, sizeof(recov_a),
                                   &recov_a_len),
              srtp::Error::kOk);
    ASSERT_EQ(recov_a_len, rtp_a_len);
    EXPECT_EQ(std::memcmp(recov_a, rtp_a, rtp_a_len), 0)
        << "client->server SRTP recovery mismatch";

    // ---- Reverse: server protects -> client unprotects. ----
    const std::uint8_t payload_b[] = "bolt-srtp-s2c-reply-abcdefghij";
    std::uint8_t rtp_b[256];
    const std::size_t rtp_b_len =
        build_rtp(rtp_b, sizeof(rtp_b), 2000, 0x55667788u, 48000, payload_b,
                  sizeof(payload_b));
    ASSERT_GT(rtp_b_len, 12u);

    std::uint8_t prot_b[512];
    std::size_t prot_b_len = 0;
    ASSERT_EQ(srv_out.protect_rtp(rtp_b, rtp_b_len, prot_b, sizeof(prot_b),
                                  &prot_b_len),
              srtp::Error::kOk);

    std::uint8_t recov_b[512];
    std::size_t recov_b_len = 0;
    ASSERT_EQ(cli_in.unprotect_rtp(prot_b, prot_b_len, recov_b, sizeof(recov_b),
                                   &recov_b_len),
              srtp::Error::kOk);
    ASSERT_EQ(recov_b_len, rtp_b_len);
    EXPECT_EQ(std::memcmp(recov_b, rtp_b, rtp_b_len), 0)
        << "server->client SRTP recovery mismatch";

    transport.stop();
}
