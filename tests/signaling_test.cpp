// signaling_test.cpp — WebRTC signaling offer->answer unit test (gtest, default
// suite, NO python, NO network).
//
// Drives the SDP signaling exchange the App POST /webrtc/offer route performs:
//   1. parse a REAL captured aiortc data-channel OFFER SDP (with srflx + multi-
//      algo fingerprint lines, exactly as aiortc 1.x emits),
//   2. extract the peer ice-ufrag/ice-pwd + the sha-256 DTLS fingerprint,
//   3. build OUR ANSWER and assert it is well-formed: our ufrag/pwd,
//      a=fingerprint:sha-256, a=setup:passive, a=ice-lite, >= 1 a=candidate, the
//      application m-line, sctp-port, BUNDLE/mid — and that it round-trips
//      through our own parser.
//
// This validates the SDP-codec half of the signaling route WITHOUT bringing up
// the live UDP/DTLS stack (that is exercised by the aiortc interop test under
// WEBRTC=ON). It is therefore unconditional and keeps the default suite green.

#include "boltapi/webrtc/sdp.h"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace sdp = bolt::api::webrtc;

// A REAL aiortc (1.14.0) RTCPeerConnection createDataChannel("chat") offer,
// captured via `uv run --with aiortc python ...`. Note: BUNDLE/mid at session
// scope, in-SDP host + srflx candidates, ice-ufrag/pwd AFTER the candidates,
// THREE a=fingerprint lines (sha-256 / sha-384 / sha-512 — the parser keeps the
// first per key, i.e. sha-256), and a=setup:actpass (offerer is DTLS-flexible).
static constexpr const char* kAiortcOffer =
    "v=0\r\n"
    "o=- 3988536642 3988536642 IN IP4 0.0.0.0\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0\r\n"
    "a=msid-semantic:WMS *\r\n"
    "m=application 54086 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    "c=IN IP4 192.168.1.210\r\n"
    "a=mid:0\r\n"
    "a=sctp-port:5000\r\n"
    "a=max-message-size:65536\r\n"
    "a=candidate:bc0190c818fb47735fce0391b3028d52 1 udp 2130706431 "
    "192.168.1.210 54086 typ host\r\n"
    "a=candidate:9902975a15041f0ea5e81b5ea28b1bca 1 udp 1694498815 "
    "92.21.26.23 54086 typ srflx raddr 192.168.1.210 rport 54086\r\n"
    "a=end-of-candidates\r\n"
    "a=ice-ufrag:2wG7\r\n"
    "a=ice-pwd:jfl1VxO0f1KHVgmvJGi2Zs\r\n"
    "a=fingerprint:sha-256 5B:A0:BD:45:0B:66:B0:BD:67:CF:2F:93:35:D8:AA:7B:1D:"
    "8D:C2:0F:0E:8E:14:38:6E:D4:8D:34:A7:5E:C7:3B\r\n"
    "a=fingerprint:sha-384 9F:36:75:02:6A:AA:60:48:E8:3B:07:C2:A1:15:24:B4:E3:"
    "9A:DC:C1:B0:A9:9A:BC:7E:27:ED:55:A6:13:2F:68:EC:A1:5F:77:68:6D:57:85:2A:"
    "83:91:2C:2E:EF:A3:E2\r\n"
    "a=setup:actpass\r\n";

// Mirror App::handle_webrtc_offer's offer->answer transform with fixed local
// credentials, so the test asserts on the SAME codec path the route uses.
static bool make_answer(std::string_view offer_sdp, std::string& out) {
    sdp::SdpSession offer;
    if (sdp::parse(offer_sdp, offer) != sdp::SdpError::Ok) return false;
    const sdp::SdpMedia* m = offer.application_media();
    if (m == nullptr) return false;

    std::string_view peer_ufrag = m->ice_ufrag();
    std::string_view peer_pwd   = m->ice_pwd();
    std::string_view offer_fp   = m->fingerprint();
    if (peer_ufrag.empty() || peer_pwd.empty() || offer_fp.empty()) return false;

    sdp::AnswerParams p;
    p.mid = m->mid();
    p.ice_ufrag = "BoltAnsw";
    p.ice_pwd   = "boltpwd0123456789abcdefXY";
    // Our cert SHA-256 fingerprint (placeholder hex for the unit test).
    p.fingerprint_sha256 =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:"
        "11:22:33:44:55:66:77:88:99";
    p.setup    = "passive";
    p.ice_lite = true;
    p.sctp_port = 5000;
    p.max_message_size = 262144;

    const std::string_view cands[] = {
        "candidate:1 1 udp 2130706431 192.168.1.50 50000 typ host",
    };
    p.candidates = cands;
    p.candidate_count = 1;

    return sdp::build_answer(p, out) == sdp::SdpError::Ok;
}

TEST(Signaling, ParsesRealAiortcOffer) {
    sdp::SdpSession offer;
    ASSERT_EQ(sdp::parse(kAiortcOffer, offer), sdp::SdpError::Ok);

    const sdp::SdpMedia* m = offer.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->media_type, "application");
    EXPECT_EQ(m->protocol, "UDP/DTLS/SCTP");
    ASSERT_EQ(m->format_count, 1u);
    EXPECT_EQ(m->formats[0], "webrtc-datachannel");

    // Peer ICE credentials (used for STUN USERNAME validation).
    EXPECT_EQ(m->ice_ufrag(), "2wG7");
    EXPECT_EQ(m->ice_pwd(), "jfl1VxO0f1KHVgmvJGi2Zs");
    EXPECT_EQ(m->setup(), "actpass");
    EXPECT_EQ(m->mid(), "0");

    // The FIRST a=fingerprint is the sha-256 one (cert verification key).
    EXPECT_EQ(m->fingerprint().substr(0, 8), "sha-256 ");
    EXPECT_NE(m->fingerprint().find("5B:A0:BD:45"), std::string_view::npos);

    std::uint16_t sctp = 0;
    ASSERT_TRUE(m->sctp_port(&sctp));
    EXPECT_EQ(sctp, 5000);

    // BUNDLE / mid at session scope.
    EXPECT_TRUE(offer.has_session_attr("group"));
    EXPECT_EQ(offer.session_attr("group"), "BUNDLE 0");
}

TEST(Signaling, BuildsWellFormedAnswerFromAiortcOffer) {
    std::string answer;
    ASSERT_TRUE(make_answer(kAiortcOffer, answer)) << "answer build failed";

    // --- Required answer attributes (the interop-critical set). ---
    EXPECT_NE(answer.find("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"),
              std::string::npos)
        << "missing application m-line";
    EXPECT_NE(answer.find("a=setup:passive"), std::string::npos)
        << "answerer must be DTLS server (passive)";
    EXPECT_NE(answer.find("a=ice-lite"), std::string::npos)
        << "Bolt is the ICE-lite controlled peer";
    EXPECT_NE(answer.find("a=fingerprint:sha-256 "), std::string::npos)
        << "missing sha-256 DTLS fingerprint";
    EXPECT_NE(answer.find("a=ice-ufrag:BoltAnsw"), std::string::npos);
    EXPECT_NE(answer.find("a=ice-pwd:boltpwd0123456789abcdefXY"),
              std::string::npos);
    EXPECT_NE(answer.find("a=candidate:"), std::string::npos)
        << "answer must carry >= 1 host candidate";
    EXPECT_NE(answer.find("a=sctp-port:5000"), std::string::npos);
    EXPECT_NE(answer.find("a=group:BUNDLE 0"), std::string::npos);
    EXPECT_NE(answer.find("a=mid:0"), std::string::npos);

    // --- Round-trip the answer through our own parser. ---
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(answer, s), sdp::SdpError::Ok);
    const sdp::SdpMedia* m = s.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->ice_ufrag(), "BoltAnsw");
    EXPECT_EQ(m->ice_pwd(), "boltpwd0123456789abcdefXY");
    EXPECT_EQ(m->setup(), "passive");
    EXPECT_EQ(m->mid(), "0");
    EXPECT_EQ(m->fingerprint().substr(0, 8), "sha-256 ");
    EXPECT_TRUE(m->has_attr("candidate"));
    EXPECT_TRUE(s.has_session_attr("ice-lite"));
}

TEST(Signaling, RejectsOfferWithoutDataChannelMedia) {
    // An audio-only offer has no m=application — signaling must reject it.
    static constexpr const char* kAudioOnly =
        "v=0\r\n"
        "o=- 1 1 IN IP4 0.0.0.0\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        "a=ice-ufrag:aud0\r\n"
        "a=ice-pwd:0123456789abcdef0123456789\r\n"
        "a=fingerprint:sha-256 AB:CD\r\n"
        "a=setup:actpass\r\n";
    std::string answer;
    EXPECT_FALSE(make_answer(kAudioOnly, answer));
    EXPECT_TRUE(answer.empty());
}

TEST(Signaling, RejectsOfferMissingCredentials) {
    // m=application present but no ice-ufrag/pwd/fingerprint -> reject.
    static constexpr const char* kNoCreds =
        "v=0\r\n"
        "o=- 1 1 IN IP4 0.0.0.0\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "a=mid:0\r\n"
        "a=sctp-port:5000\r\n";
    std::string answer;
    EXPECT_FALSE(make_answer(kNoCreds, answer));
}

TEST(Signaling, GarbageOfferDoesNotCrash) {
    std::uint32_t state = 0xDEADBEEFu;
    for (int iter = 0; iter < 128; ++iter) {
        std::string buf;
        const int n = 1 + (int)(state % 300);
        for (int i = 0; i < n; ++i) {
            state = state * 1664525u + 1013904223u;
            buf.push_back(static_cast<char>(state & 0xFF));
        }
        std::string answer;
        volatile bool ok = make_answer(buf, answer);
        (void)ok;
    }
    SUCCEED();
}
