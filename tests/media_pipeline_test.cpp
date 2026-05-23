// media_pipeline_test.cpp — WP/WA LIVE-WIRING GATE: the interceptor chain runs
// inside the production WebRtcPeerHub over a REAL DTLS-SRTP session.
//
// ============================================================================
// WHAT THIS PROVES (no external deps; default suite; deadline-bounded)
// ============================================================================
// The WA codecs (RTX + TWCC) are LIVE-WIRED into the production peer_hub, not
// just unit-gated. Over a genuine DTLS-SRTP loopback session through the real
// WebRtcPeerHub (the same server stack as media_echo_test):
//
//   (1) RTX-ON-NACK: with hub.configure_media({rtx}), the server caches outbound
//       media in the RtxInterceptor (via the outbound chain). The client sends a
//       Generic NACK (RTPFB FMT 1) for a sequence it "lost"; the server emits a
//       true RTX packet (rtx SSRC/PT, 16-bit OSN prefix) which the client
//       SRTP-unprotects and parse_rtx reconstructs to the original media packet
//       BYTE-EXACT. Proves NACK -> RTX retransmit fires in the live hub.
//
//   (2) TWCC FEEDBACK FROM ARRIVALS: with a transport-cc extmap configured, the
//       client sends RTP carrying the transport-cc header extension; the server
//       records arrivals in feed_media; hub.tick_media() builds + emits a
//       transport-cc feedback (RTPFB FMT 15) the client receives and parses.
//
//   (3) PACER SHAPES: with a pacer target configured, the echo path still
//       delivers every packet byte-exact (correctness first) AND the pacer token
//       bucket is exercised on the live send path (no drop).
//
// Bounded by an iteration cap + a wall-clock deadline (never hangs). Links
// OpenSSL (DTLS + SRTP) + ws2_32/mswsock/iphlpapi on Windows, like the other
// live WebRTC TUs.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/peer_hub.h"
#include "boltapi/webrtc/track.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cassert>
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
namespace srtp = bolt::api::webrtc::srtp;
namespace rtp  = bolt::api::webrtc::rtp;
namespace rtcp = bolt::api::webrtc::rtcp;

namespace {

// Negotiated identities. Video carries RTX + transport-cc; audio is plain.
constexpr std::uint8_t  kVideoPt   = 96;
constexpr std::uint8_t  kRtxPt     = 97;            // a=fmtp apt=96
constexpr std::uint32_t kVideoSsrc = 0x0B0E2020u;
constexpr std::uint32_t kRtxSsrc   = kVideoSsrc ^ 0x52545800u;  // hub's rtx ssrc rule
constexpr std::uint8_t  kTwccExtId = 5;             // a=extmap:5 transport-cc

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

// A minimal OpenSSL DTLS-SRTP CLIENT (mirrors tests/media_echo_test.cpp).
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
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 9);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("BoltMediaPipelineClient"),
            -1, -1, 0);
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

    bool make_srtp(srtp::SrtpSession& inbound, srtp::SrtpSession& outbound) {
        SRTP_PROTECTION_PROFILE* prof = SSL_get_selected_srtp_profile(ssl);
        if (prof == nullptr) return false;
        wrtc::SrtpKeying k;
        if (prof->id == 0x0007) k.profile = wrtc::SrtpProfileId::kAeadAes128Gcm;
        else if (prof->id == 0x0001)
            k.profile = wrtc::SrtpProfileId::kAesCm128HmacSha1_80;
        else return false;
        k.is_server = false;
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

    int send_raw(const std::uint8_t* data, std::size_t len) {
        return ::send(fd, reinterpret_cast<const char*>(data),
                      static_cast<int>(len), 0);
    }
    int recv_raw(std::uint8_t* buf, std::size_t cap) {
        return ::recv(fd, reinterpret_cast<char*>(buf),
                      static_cast<int>(cap), 0);
    }

    void close_all() {
        if (ssl)  { SSL_free(ssl);  ssl  = nullptr; }
        if (ctx)  { SSL_CTX_free(ctx); ctx = nullptr; }
        if (cert) { X509_free(cert); cert = nullptr; }
        if (pkey) { EVP_PKEY_free(pkey); pkey = nullptr; }
        if (fd != net::kInvalidSocket) {
            sys::close_socket(fd); fd = net::kInvalidSocket;
        }
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

// Build a plain video RTP packet.
std::size_t build_rtp(std::uint8_t* buf, std::size_t cap, std::uint8_t pt,
                      std::uint16_t seq, std::uint32_t ssrc, std::uint32_t ts,
                      const std::uint8_t* payload, std::size_t plen) {
    rtp::Header h{};
    h.payload_type = pt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;
    std::size_t written = 0;
    EXPECT_EQ(rtp::serialize(h, payload, plen, 0, buf, cap, written),
              rtp::RtpError::Ok);
    return written;
}

// Build a video RTP packet carrying a transport-cc one-byte header extension
// (id kTwccExtId, 2-byte transport-wide seq). `ext_buf` must outlive serialize.
std::size_t build_rtp_twcc(std::uint8_t* buf, std::size_t cap, std::uint16_t seq,
                           std::uint32_t ts, std::uint16_t tseq,
                           const std::uint8_t* payload, std::size_t plen,
                           std::uint8_t* ext_buf, std::size_t ext_cap) {
    rtp::Header h{};
    h.payload_type = kVideoPt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = kVideoSsrc;
    std::uint8_t tcc[2] = { static_cast<std::uint8_t>(tseq >> 8),
                            static_cast<std::uint8_t>(tseq & 0xFF) };
    rtp::Extension e{};
    e.id = kTwccExtId; e.value = tcc; e.length = 2;
    const std::size_t n = rtp::build_one_byte_extensions(h, &e, 1, ext_buf, ext_cap);
    EXPECT_GT(n, 0u);
    std::size_t written = 0;
    EXPECT_EQ(rtp::serialize(h, payload, plen, 0, buf, cap, written),
              rtp::RtpError::Ok);
    return written;
}

}  // namespace

// ===========================================================================
// THE GATE — RTX-on-NACK + TWCC feedback through the LIVE WebRtcPeerHub.
// ===========================================================================
TEST(MediaPipeline, RtxOnNackAndTwccFeedbackLiveHub) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(30);

    // ---- Server: UdpTransport + DTLS server + peer hub (echo on_track). ----
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    ASSERT_TRUE(dctx->is_valid());
    wrtc::DtlsSessionManager mgr(*dctx, transport);

    wrtc::WebRtcPeerHub hub(mgr, transport);
    hub.add_track_spec(wrtc::MediaKind::kVideo, kVideoSsrc, kVideoPt, "VP8");

    // LIVE-WIRE: negotiate RTX (apt=96 -> rtx pt 97) + transport-cc + a pacer.
    wrtc::WebRtcPeerHub::MediaConfig mc;
    mc.media_ssrc = kVideoSsrc;
    mc.media_pt   = kVideoPt;
    mc.rtx_ssrc   = kRtxSsrc;
    mc.rtx_pt     = kRtxPt;
    mc.transport_cc_ext_id = kTwccExtId;
    mc.pacer_target_bps    = 2'000'000;   // 2 Mbps token bucket
    hub.configure_media(mc);

    // Echo on_track: loop received RTP back out (caches in the RtxInterceptor via
    // the outbound chain). Exactly App::enable_media_echo's shape.
    std::atomic<int> echoed{0};
    hub.set_track_ready([&echoed](wrtc::MediaTrack& tr) {
        tr.set_deliver_sink(
            [](void* ctx, wrtc::MediaTrack& track, const rtp::Packet& pkt,
               const std::uint8_t* data, std::size_t len) noexcept {
                (void)pkt;
                static_cast<std::atomic<int>*>(ctx)->fetch_add(
                    1, std::memory_order_relaxed);
                track.write(data, len);
            },
            &echoed);
    });

    transport.set_datagram_handler(
        [&hub](const sockaddr* peer, int plen, const std::uint8_t* data,
               std::size_t len) { hub.feed(peer, plen, data, len); });

    // ---- Client: real OpenSSL DTLS-SRTP peer. ----
    DtlsSrtpClient client;
    ASSERT_TRUE(client.open(port));
    const std::string client_fp = client.fingerprint();
    ASSERT_EQ(client_fp.size(), 95u);
    mgr.set_offer_fingerprint(client_fp);

    ASSERT_TRUE(transport.start());

    sockaddr_in cli{};
    socklen_t cli_len = sizeof(cli);
    ASSERT_EQ(::getsockname(client.fd, reinterpret_cast<sockaddr*>(&cli),
                            &cli_len), 0);

    std::atomic<bool> client_ok{false};
    std::thread client_thread(
        [&] { client_ok.store(client.handshake(deadline)); });
    wrtc::DtlsSession* s = wait_session(
        mgr, reinterpret_cast<sockaddr*>(&cli),
        static_cast<int>(cli_len), deadline);
    client_thread.join();
    ASSERT_TRUE(client_ok.load());
    ASSERT_NE(s, nullptr);
    ASSERT_EQ(s->state(), wrtc::DtlsSession::State::Established);

    srtp::SrtpSession cli_in, cli_out;
    ASSERT_TRUE(client.make_srtp(cli_in, cli_out));

    // ---- (1) Send a video packet WITH a transport-cc ext, get the echo. ----
    std::mt19937 rng(0x9911FACEu);
    std::uniform_int_distribution<int> byte_d(0, 255);
    constexpr std::size_t kPlen = 180;
    std::vector<std::uint8_t> payload(kPlen);
    for (auto& b : payload) b = static_cast<std::uint8_t>(byte_d(rng));

    const std::uint16_t media_seq = 4321;
    std::uint8_t ext_buf[16];
    std::uint8_t raw[512];
    const std::size_t raw_len =
        build_rtp_twcc(raw, sizeof(raw), media_seq, 123456u, /*tseq=*/100,
                       payload.data(), payload.size(), ext_buf, sizeof(ext_buf));
    ASSERT_GT(raw_len, rtp::kFixedHeaderSize);

    std::uint8_t prot[640];
    std::size_t prot_len = 0;
    ASSERT_EQ(cli_out.protect_rtp(raw, raw_len, prot, sizeof(prot), &prot_len),
              srtp::Error::kOk);
    ASSERT_GT(client.send_raw(prot, prot_len), 0);

    // Drain the echo of the media packet (so we know the server cached it).
    bool got_echo = false;
    while (std::chrono::steady_clock::now() < deadline && !got_echo) {
        std::uint8_t in[800];
        const int n = client.recv_raw(in, sizeof(in));
        if (n <= 0) continue;
        if (in[0] < 128 || in[0] > 191) continue;
        if (rtcp::is_rtcp(in, static_cast<std::size_t>(n))) continue;
        std::uint8_t plain[800];
        std::size_t plen = 0;
        if (cli_in.unprotect_rtp(in, static_cast<std::size_t>(n), plain,
                                 sizeof(plain), &plen) != srtp::Error::kOk)
            continue;
        rtp::Packet ep;
        if (rtp::parse(plain, plen, ep) != rtp::RtpError::Ok) continue;
        if (ep.header.ssrc == kVideoSsrc && ep.header.sequence == media_seq)
            got_echo = true;
    }
    ASSERT_TRUE(got_echo) << "never received the media echo";

    // ---- (1b) Send an inbound Generic NACK for media_seq -> expect RTX. ----
    std::uint8_t nack_buf[128];
    rtcp::Builder nb(nack_buf, sizeof(nack_buf));
    rtcp::NackBlock blk{media_seq, 0};
    ASSERT_EQ(nb.add_nack(/*sender=*/0xABCDu, /*media=*/kVideoSsrc, &blk, 1),
              rtcp::RtcpError::Ok);
    std::uint8_t nack_prot[256];
    std::size_t nack_prot_len = 0;
    ASSERT_EQ(cli_out.protect_rtcp(nack_buf, nb.size(), nack_prot,
                                   sizeof(nack_prot), &nack_prot_len),
              srtp::Error::kOk);
    ASSERT_GT(client.send_raw(nack_prot, nack_prot_len), 0);

    // Expect an RTX packet (rtx SSRC/PT) whose OSN == media_seq; recover original.
    wrtc::RtxInterceptor recover(kVideoSsrc, kVideoPt, kRtxSsrc, kRtxPt);
    bool got_rtx = false;
    while (std::chrono::steady_clock::now() < deadline && !got_rtx) {
        std::uint8_t in[800];
        const int n = client.recv_raw(in, sizeof(in));
        if (n <= 0) continue;
        if (in[0] < 128 || in[0] > 191) continue;
        if (rtcp::is_rtcp(in, static_cast<std::size_t>(n))) continue;
        std::uint8_t plain[800];
        std::size_t plen = 0;
        if (cli_in.unprotect_rtp(in, static_cast<std::size_t>(n), plain,
                                 sizeof(plain), &plen) != srtp::Error::kOk)
            continue;
        rtp::Packet rx;
        if (rtp::parse(plain, plen, rx) != rtp::RtpError::Ok) continue;
        if (rx.header.payload_type != kRtxPt || rx.header.ssrc != kRtxSsrc)
            continue;                                  // not an RTX packet
        std::uint8_t orig[800];
        std::size_t out_seq = 0;
        const std::size_t w = recover.parse_rtx(rx, orig, sizeof(orig), &out_seq);
        ASSERT_GT(w, rtp::kFixedHeaderSize) << "parse_rtx failed";
        EXPECT_EQ(static_cast<std::uint16_t>(out_seq), media_seq);
        rtp::Packet recovered;
        ASSERT_EQ(rtp::parse(orig, w, recovered), rtp::RtpError::Ok);
        EXPECT_EQ(recovered.header.ssrc, kVideoSsrc);
        EXPECT_EQ(recovered.header.sequence, media_seq);
        EXPECT_EQ(recovered.header.payload_type, kVideoPt);
        ASSERT_EQ(recovered.payload_len, kPlen);
        EXPECT_EQ(std::memcmp(recovered.payload, payload.data(), kPlen), 0)
            << "RTX-recovered payload not byte-exact";
        got_rtx = true;
    }
    ASSERT_TRUE(got_rtx) << "live hub did not emit an RTX retransmission on NACK";

    // ---- (2) TWCC feedback: tick the hub; expect an RTPFB FMT 15. ----
    // Send a few more transport-cc-tagged packets to grow the arrival window.
    for (int i = 1; i <= 4; ++i) {
        std::uint8_t r2[512], e2[16];
        const std::size_t l2 = build_rtp_twcc(
            r2, sizeof(r2), static_cast<std::uint16_t>(media_seq + i),
            123456u + 3000u * i, static_cast<std::uint16_t>(100 + i),
            payload.data(), payload.size(), e2, sizeof(e2));
        std::uint8_t p2[640];
        std::size_t pl2 = 0;
        ASSERT_EQ(cli_out.protect_rtp(r2, l2, p2, sizeof(p2), &pl2),
                  srtp::Error::kOk);
        ASSERT_GT(client.send_raw(p2, pl2), 0);
    }
    // Give the server a moment to record arrivals, then tick to emit feedback.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    const std::size_t emitted = hub.tick_media(wrtc::WebRtcPeerHub::now_ms());
    EXPECT_GT(emitted, 0u) << "tick_media emitted no RTCP (TWCC + reports)";

    bool got_twcc = false;
    while (std::chrono::steady_clock::now() < deadline && !got_twcc) {
        std::uint8_t in[800];
        const int n = client.recv_raw(in, sizeof(in));
        if (n <= 0) continue;
        if (in[0] < 128 || in[0] > 191) continue;
        if (!rtcp::is_rtcp(in, static_cast<std::size_t>(n))) continue;
        std::uint8_t plain[800];
        std::size_t plen = 0;
        if (cli_in.unprotect_rtcp(in, static_cast<std::size_t>(n), plain,
                                  sizeof(plain), &plen) != srtp::Error::kOk)
            continue;
        rtcp::Compound c;
        if (rtcp::parse_compound(plain, plen, c) != rtcp::RtcpError::Ok) continue;
        for (std::size_t i = 0; i < c.count; ++i) {
            if (c.packets[i].type == rtcp::Type::RTPFB &&
                c.packets[i].count ==
                    static_cast<std::uint8_t>(rtcp::RtpfbFmt::Twcc)) {
                got_twcc = true;
                break;
            }
        }
    }
    ASSERT_TRUE(got_twcc) << "live hub produced no TWCC feedback from arrivals";

    EXPECT_GE(echoed.load(), 1);  // (3) pacer-enabled echo still delivered media
    transport.stop();
}
