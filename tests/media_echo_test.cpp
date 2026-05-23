// media_echo_test.cpp — THE WM6 MEDIA-ECHO PRIMARY GATE ("audio+video works").
//
// ============================================================================
// WHAT THIS PROVES (no external deps; default suite; deadline-bounded)
// ============================================================================
// Our OWN stack on BOTH ends drives the REAL server media-echo path end to end:
//
//   SERVER side = our production stack: UdpTransport + DtlsContext (server,
//     use_srtp) + DtlsSessionManager + WebRtcPeerHub, with an on_track ECHO
//     handler (the aiortc `server` shape: track.write(rtp) loops the received
//     RTP straight back out — re-SRTP, relay, NO transcode). This is EXACTLY
//     what App::enable_media_echo() installs.
//   CLIENT side = a REAL OpenSSL DTLS-SRTP client (the same one the live keying
//     gate tests/dtls_srtp_test.cpp uses): completes the DTLS-SRTP handshake,
//     builds its own role-mapped SrtpSessions, then SENDS audio + video RTP and
//     RECEIVES the echo over real loopback UDP.
//
// Flow per packet: client SRTP-protect -> UDP -> server hub (SRTP-unprotect ->
// RFC 5761 demux -> per-SSRC MediaTrack -> echo handler -> track.write ->
// outbound interceptors -> SRTP-protect -> UDP) -> client (SRTP-unprotect).
// We assert the echoed RTP is BYTE-EXACT for BOTH the audio AND the video track,
// over many seeded RANDOMIZED payloads. Bounded by an iteration cap + a
// wall-clock deadline so it can never hang.
//
// Builds in the DEFAULT suite: the peer hub + tracks + interceptors compile
// unconditionally (only App *start* wiring is BOLTAPI_WITH_WEBRTC-gated). Links
// OpenSSL (DTLS + SRTP crypto) + ws2_32/mswsock/iphlpapi on Windows, mirroring
// the other live WebRTC TUs.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"
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

namespace {

// Negotiated identities for the two echoed tracks (relay/echo: PT/SSRC echoed).
constexpr std::uint8_t  kAudioPt   = 111;          // opus-ish dynamic PT
constexpr std::uint8_t  kVideoPt   = 96;           // VP8-ish dynamic PT
constexpr std::uint32_t kAudioSsrc = 0x0A0D1010u;
constexpr std::uint32_t kVideoSsrc = 0x0B0E2020u;

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

// A minimal OpenSSL DTLS-SRTP CLIENT (mirrors tests/dtls_srtp_test.cpp). It
// completes the handshake, exports its role-mapped SRTP keys, and lets the test
// send/recv RAW datagrams (already SRTP-protected) on its connected UDP socket.
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
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 7);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("BoltMediaEchoClient"),
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

    // Build the client-side SRTP sessions (client role: out=client-write keys,
    // in=server-write keys — the mirror of the server's mapping).
    bool make_srtp(srtp::SrtpSession& inbound, srtp::SrtpSession& outbound) {
        SRTP_PROTECTION_PROFILE* prof = SSL_get_selected_srtp_profile(ssl);
        if (prof == nullptr) return false;
        wrtc::SrtpKeying k;
        if (prof->id == 0x0007) k.profile = wrtc::SrtpProfileId::kAeadAes128Gcm;
        else if (prof->id == 0x0001)
            k.profile = wrtc::SrtpProfileId::kAesCm128HmacSha1_80;
        else return false;
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

// Build a valid RTP packet (12-byte header + payload) into `buf` via rtp.h.
std::size_t build_rtp(std::uint8_t* buf, std::size_t cap, std::uint8_t pt,
                      std::uint16_t seq, std::uint32_t ssrc, std::uint32_t ts,
                      const std::uint8_t* payload, std::size_t plen) {
    rtp::Header h{};
    h.payload_type = pt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;
    std::size_t written = 0;
    const rtp::RtpError e =
        rtp::serialize(h, payload, plen, 0, buf, cap, written);
    EXPECT_EQ(e, rtp::RtpError::Ok);
    return written;
}

// The server-side ECHO handler (exactly App::enable_media_echo's shape): loop
// the received RTP straight back out on the SAME track (re-SRTP, no transcode).
struct EchoState { std::atomic<int> echoed{0}; };

void echo_handler(EchoState* st, wrtc::MediaTrack& track,
                  const std::uint8_t* rtp_data, std::size_t rtp_len) {
    assert(st != nullptr && "echo_handler: null state");
    assert(rtp_data != nullptr && rtp_len >= rtp::kFixedHeaderSize &&
           "echo_handler: short rtp");
    st->echoed.fetch_add(1, std::memory_order_relaxed);
    track.write(rtp_data, rtp_len);
}

}  // namespace

// ===========================================================================
// THE GATE — audio + video RTP echo, byte-exact, over a REAL DTLS-SRTP session,
// through the production WebRtcPeerHub echo path, with randomized payloads.
// ===========================================================================
TEST(MediaEcho, AudioAndVideoRtpEchoByteExact) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(30);

    // ---- Server: UdpTransport + DTLS server + peer hub with an echo on_track.
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    auto dctx = wrtc::DtlsContext::create();
    ASSERT_NE(dctx, nullptr);
    ASSERT_TRUE(dctx->is_valid());
    wrtc::DtlsSessionManager mgr(*dctx, transport);

    wrtc::WebRtcPeerHub hub(mgr, transport);
    // Pre-register the two outbound tracks (negotiated SSRC/PT/codec) so the hub
    // binds their write sinks (the echo target SSRC matches the inbound SSRC).
    hub.add_track_spec(wrtc::MediaKind::kAudio, kAudioSsrc, kAudioPt, "opus");
    hub.add_track_spec(wrtc::MediaKind::kVideo, kVideoSsrc, kVideoPt, "VP8");

    EchoState echo_state;
    hub.set_track_ready([&echo_state](wrtc::MediaTrack& tr) {
        tr.set_deliver_sink(
            [](void* ctx, wrtc::MediaTrack& track, const rtp::Packet& pkt,
               const std::uint8_t* data, std::size_t len) noexcept {
                (void)pkt;
                echo_handler(static_cast<EchoState*>(ctx), track, data, len);
            },
            &echo_state);
    });

    // The hub IS the datagram handler (first byte 20..63 DTLS, 128..191 media).
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

    ASSERT_TRUE(client_ok.load()) << "client SSL_connect did not complete";
    ASSERT_NE(s, nullptr) << "server never created a session for the peer";
    ASSERT_EQ(s->state(), wrtc::DtlsSession::State::Established);

    // Client SRTP sessions (built from the same handshake).
    srtp::SrtpSession cli_in, cli_out;
    ASSERT_TRUE(client.make_srtp(cli_in, cli_out));

    // ---- Drive randomized audio + video RTP through the echo path. ----
    std::mt19937 rng(0xECEC2026u);                 // seeded, deterministic
    std::uniform_int_distribution<int> len_d(8, 220);
    std::uniform_int_distribution<int> byte_d(0, 255);

    constexpr int kRounds = 40;                     // bounded (no hang)
    int audio_ok = 0, video_ok = 0;

    for (int i = 0; i < kRounds; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        const bool video = (i % 2) == 1;
        const std::uint8_t  pt   = video ? kVideoPt   : kAudioPt;
        const std::uint32_t ssrc = video ? kVideoSsrc : kAudioSsrc;
        const std::uint16_t seq  = static_cast<std::uint16_t>(2000 + i);

        const std::size_t plen = static_cast<std::size_t>(len_d(rng));
        std::vector<std::uint8_t> payload(plen);
        for (auto& b : payload) b = static_cast<std::uint8_t>(byte_d(rng));

        std::uint8_t raw[512];
        const std::size_t raw_len =
            build_rtp(raw, sizeof(raw), pt, seq, ssrc, 90000u + 160u * i,
                      payload.data(), payload.size());
        ASSERT_GT(raw_len, rtp::kFixedHeaderSize);

        // Client protects + sends.
        std::uint8_t prot[640];
        std::size_t prot_len = 0;
        ASSERT_EQ(cli_out.protect_rtp(raw, raw_len, prot, sizeof(prot),
                                      &prot_len), srtp::Error::kOk);
        ASSERT_GT(client.send_raw(prot, prot_len), 0);

        // Receive the echo (bounded by the socket RCVTIMEO + the deadline). The
        // server's hub does: unprotect -> demux -> echo -> protect -> send.
        bool got = false;
        while (std::chrono::steady_clock::now() < deadline) {
            std::uint8_t in[800];
            const int n = client.recv_raw(in, sizeof(in));
            if (n <= 0) continue;  // RCVTIMEO tick: retry until the deadline
            // Skip any late DTLS record (first byte 20..63); media is 128..191.
            if (in[0] < 128 || in[0] > 191) continue;
            std::uint8_t plain[800];
            std::size_t plain_len = 0;
            if (cli_in.unprotect_rtp(in, static_cast<std::size_t>(n), plain,
                                     sizeof(plain), &plain_len) !=
                srtp::Error::kOk)
                continue;
            rtp::Packet echoed;
            ASSERT_EQ(rtp::parse(plain, plain_len, echoed), rtp::RtpError::Ok);
            // Byte-exact: the echoed RTP equals what we sent (relay/no transcode).
            EXPECT_EQ(echoed.header.ssrc, ssrc);
            EXPECT_EQ(echoed.header.payload_type, pt);
            EXPECT_EQ(echoed.header.sequence, seq);
            ASSERT_EQ(plain_len, raw_len) << "echoed RTP length differs";
            EXPECT_EQ(std::memcmp(plain, raw, raw_len), 0)
                << "echoed RTP not byte-exact (round " << i << ")";
            got = true;
            (video ? video_ok : audio_ok) += 1;
            break;
        }
        ASSERT_TRUE(got) << "no echo received for round " << i
                         << " (kind=" << (video ? "video" : "audio") << ")";
    }

    // BOTH kinds echoed every packet, byte-exact.
    EXPECT_EQ(audio_ok, kRounds - kRounds / 2);
    EXPECT_EQ(video_ok, kRounds / 2);
    EXPECT_GE(echo_state.echoed.load(), kRounds)
        << "server echo handler fired fewer times than packets sent";

    // The hub demuxed both tracks (audio + video, distinct SSRCs).
    wrtc::TrackRegistry* reg = hub.tracks_for(
        reinterpret_cast<sockaddr*>(&cli), static_cast<int>(cli_len));
    ASSERT_NE(reg, nullptr);
    wrtc::MediaTrack* at = reg->by_ssrc(kAudioSsrc);
    wrtc::MediaTrack* vt = reg->by_ssrc(kVideoSsrc);
    ASSERT_NE(at, nullptr);
    ASSERT_NE(vt, nullptr);
    EXPECT_EQ(at->kind(), wrtc::MediaKind::kAudio);
    EXPECT_EQ(vt->kind(), wrtc::MediaKind::kVideo);
    EXPECT_GT(at->packets_recv(), 0u);
    EXPECT_GT(vt->packets_recv(), 0u);
    EXPECT_GT(at->packets_sent(), 0u);  // the echo wrote back out
    EXPECT_GT(vt->packets_sent(), 0u);

    transport.stop();
}
