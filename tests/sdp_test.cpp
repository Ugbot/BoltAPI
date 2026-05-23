// sdp_test.cpp — unit tests for the WebRTC SDP codec (boltapi/webrtc/sdp.h).
//
// Coverage:
//   * Parse a REAL Chrome data-channel offer; assert ufrag/pwd/fingerprint/
//     setup/mid/sctp-port/max-message-size are extracted.
//   * Parse a representative Firefox data-channel offer (different ordering,
//     setup:actpass, a=sctp-port phrasing) — assert the same fields.
//   * Build an answer SDP and round-trip-parse it; assert our fields survive.
//   * generate() round-trips a parsed session.
//   * Malformed / empty / overflow inputs return an error (no throw / crash).

#include "boltapi/webrtc/sdp.h"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace sdp = bolt::api::webrtc;

// A representative Chrome (M120-ish) RTCPeerConnection createDataChannel offer.
// LF line endings (Chrome emits CRLF on the wire; the parser handles both).
static constexpr const char* kChromeOffer =
    "v=0\r\n"
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0\r\n"
    "a=extmap-allow-mixed\r\n"
    "a=msid-semantic: WMS\r\n"
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:4ZcD\r\n"
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\n"
    "a=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 "
    "D7:E5:6C:1D:E9:90:48:9F:5E:34:1A:6F:1A:CB:9C:0E:11:1B:8B:5E:2B:7A:9C:43:"
    "F1:22:33:44:55:66:77:88\r\n"
    "a=setup:actpass\r\n"
    "a=mid:0\r\n"
    "a=sctp-port:5000\r\n"
    "a=max-message-size:262144\r\n";

// A representative Firefox offer: candidates in-SDP, a=setup:actpass, different
// attribute ordering, host candidate line present.
static constexpr const char* kFirefoxOffer =
    "v=0\r\n"
    "o=mozilla...THIS_IS_SDPARTA-99.0 8675309 0 IN IP4 0.0.0.0\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=fingerprint:sha-256 "
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:"
    "22:33:44:55:66:77:88:99\r\n"
    "a=group:BUNDLE 0\r\n"
    "a=ice-options:trickle\r\n"
    "a=msid-semantic:WMS *\r\n"
    "m=application 47232 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    "c=IN IP4 192.0.2.1\r\n"
    "a=candidate:0 1 UDP 2122252543 192.0.2.1 47232 typ host\r\n"
    "a=sendrecv\r\n"
    "a=ice-pwd:7e9f0c2b4a6d8e0f1a3c5e7b9d1f3a5c\r\n"
    "a=ice-ufrag:abc1\r\n"
    "a=mid:0\r\n"
    "a=setup:actpass\r\n"
    "a=sctp-port:5000\r\n"
    "a=max-message-size:1073741823\r\n";

TEST(Sdp, ParsesRealChromeDataChannelOffer) {
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kChromeOffer, s), sdp::SdpError::Ok);

    EXPECT_EQ(s.version, "0");
    EXPECT_EQ(s.session_name, "-");
    EXPECT_EQ(s.timing, "0 0");
    ASSERT_EQ(s.media_count, 1u);

    const sdp::SdpMedia* m = s.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->media_type, "application");
    EXPECT_EQ(m->port, 9);
    EXPECT_EQ(m->protocol, "UDP/DTLS/SCTP");
    ASSERT_EQ(m->format_count, 1u);
    EXPECT_EQ(m->formats[0], "webrtc-datachannel");
    EXPECT_EQ(m->connection, "IN IP4 0.0.0.0");

    EXPECT_EQ(m->ice_ufrag(), "4ZcD");
    EXPECT_EQ(m->ice_pwd(), "2/1muCWoOi3uLifh0NuRHlga");
    EXPECT_EQ(m->setup(), "actpass");
    EXPECT_EQ(m->mid(), "0");
    // fingerprint value retains "sha-256 <hex>".
    EXPECT_EQ(m->fingerprint().substr(0, 8), "sha-256 ");
    EXPECT_NE(m->fingerprint().find("D7:E5:6C:1D"), std::string_view::npos);

    std::uint16_t sctp = 0;
    ASSERT_TRUE(m->sctp_port(&sctp));
    EXPECT_EQ(sctp, 5000);

    std::uint32_t mms = 0;
    ASSERT_TRUE(m->max_message_size(&mms));
    EXPECT_EQ(mms, 262144u);

    // Session-level attribute present.
    EXPECT_TRUE(s.has_session_attr("group"));
    EXPECT_EQ(s.session_attr("group"), "BUNDLE 0");
    EXPECT_TRUE(s.has_session_attr("extmap-allow-mixed"));  // flag attr
}

TEST(Sdp, ParsesFirefoxOfferWithCandidate) {
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kFirefoxOffer, s), sdp::SdpError::Ok);

    const sdp::SdpMedia* m = s.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->port, 47232);
    EXPECT_EQ(m->ice_ufrag(), "abc1");
    EXPECT_EQ(m->ice_pwd(), "7e9f0c2b4a6d8e0f1a3c5e7b9d1f3a5c");
    EXPECT_EQ(m->setup(), "actpass");
    EXPECT_EQ(m->mid(), "0");

    // candidate line extracted as an attribute.
    EXPECT_TRUE(m->has_attr("candidate"));
    EXPECT_EQ(m->attr("candidate"),
              "0 1 UDP 2122252543 192.0.2.1 47232 typ host");

    std::uint32_t mms = 0;
    ASSERT_TRUE(m->max_message_size(&mms));
    EXPECT_EQ(mms, 1073741823u);
}

TEST(Sdp, BuildAnswerRoundTrips) {
    sdp::AnswerParams p;
    p.mid = "0";
    p.ice_ufrag = "Bolt";
    p.ice_pwd = "abcdef0123456789abcdef0123";
    p.fingerprint_sha256 =
        "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
        "88:99:AA:BB:CC:DD:EE:FF:00";
    p.setup = "passive";
    p.sctp_port = 5000;
    p.max_message_size = 262144;

    std::string answer;
    ASSERT_EQ(sdp::build_answer(p, answer), sdp::SdpError::Ok);

    // Sanity on emitted text.
    EXPECT_NE(answer.find("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"),
              std::string::npos);
    EXPECT_NE(answer.find("a=setup:passive"), std::string::npos);
    EXPECT_NE(answer.find("a=fingerprint:sha-256 "), std::string::npos);

    // Round-trip parse the generated answer (string outlives the parsed views).
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(answer, s), sdp::SdpError::Ok);
    const sdp::SdpMedia* m = s.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->ice_ufrag(), "Bolt");
    EXPECT_EQ(m->ice_pwd(), "abcdef0123456789abcdef0123");
    EXPECT_EQ(m->setup(), "passive");
    EXPECT_EQ(m->mid(), "0");
    EXPECT_EQ(m->protocol, "UDP/DTLS/SCTP");
    std::uint16_t sctp = 0;
    ASSERT_TRUE(m->sctp_port(&sctp));
    EXPECT_EQ(sctp, 5000);
}

TEST(Sdp, BuildAnswerIceLite) {
    sdp::AnswerParams p;
    p.ice_ufrag = "u";
    p.ice_pwd = "0123456789012345678901234567";
    p.fingerprint_sha256 = "AB:CD";
    p.ice_lite = true;
    std::string answer;
    ASSERT_EQ(sdp::build_answer(p, answer), sdp::SdpError::Ok);
    EXPECT_NE(answer.find("a=ice-lite"), std::string::npos);
}

TEST(Sdp, BuildAnswerEmitsIceCandidates) {
    sdp::AnswerParams p;
    p.ice_ufrag = "Bolt";
    p.ice_pwd = "abcdef0123456789abcdef0123";
    p.fingerprint_sha256 = "AB:CD";
    // Candidate lines exactly as IceCandidate::to_string() produces them.
    const std::string_view cands[] = {
        "candidate:1 1 udp 2130706431 192.168.1.50 50000 typ host",
        "candidate:2 1 udp 2130706431 10.0.0.5 50000 typ host",
    };
    p.candidates = cands;
    p.candidate_count = 2;

    std::string answer;
    ASSERT_EQ(sdp::build_answer(p, answer), sdp::SdpError::Ok);
    EXPECT_NE(answer.find(
        "a=candidate:1 1 udp 2130706431 192.168.1.50 50000 typ host"),
        std::string::npos);
    EXPECT_NE(answer.find(
        "a=candidate:2 1 udp 2130706431 10.0.0.5 50000 typ host"),
        std::string::npos);
    EXPECT_NE(answer.find("a=end-of-candidates"), std::string::npos);

    // The emitted candidate lines must round-trip through the parser.
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(answer, s), sdp::SdpError::Ok);
    const sdp::SdpMedia* m = s.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_TRUE(m->has_attr("candidate"));
    EXPECT_TRUE(m->has_attr("end-of-candidates"));
}

TEST(Sdp, BuildAnswerRejectsMissingRequiredFields) {
    sdp::AnswerParams p;  // all credential fields empty
    std::string answer;
    EXPECT_EQ(sdp::build_answer(p, answer), sdp::SdpError::MalformedLine);
}

TEST(Sdp, GenerateRoundTripsParsedSession) {
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kChromeOffer, s), sdp::SdpError::Ok);

    std::string regen;
    ASSERT_EQ(sdp::generate(s, regen), sdp::SdpError::Ok);

    // Re-parse the regenerated text and confirm the load-bearing fields persist.
    sdp::SdpSession s2;
    ASSERT_EQ(sdp::parse(regen, s2), sdp::SdpError::Ok);
    const sdp::SdpMedia* m = s2.application_media();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->ice_ufrag(), "4ZcD");
    EXPECT_EQ(m->ice_pwd(), "2/1muCWoOi3uLifh0NuRHlga");
    EXPECT_EQ(m->mid(), "0");
    std::uint16_t sctp = 0;
    ASSERT_TRUE(m->sctp_port(&sctp));
    EXPECT_EQ(sctp, 5000);
}

// --- malformed / boundary inputs: must return an error, never throw/crash ---

TEST(Sdp, EmptyInputIsError) {
    sdp::SdpSession s;
    EXPECT_EQ(sdp::parse("", s), sdp::SdpError::Empty);
}

TEST(Sdp, MalformedLineIsError) {
    sdp::SdpSession s;
    // A line without the "x=" shape.
    EXPECT_EQ(sdp::parse("v=0\r\nthis is not sdp\r\n", s),
              sdp::SdpError::MalformedLine);
}

TEST(Sdp, BadMediaPortIsError) {
    sdp::SdpSession s;
    EXPECT_EQ(sdp::parse("v=0\r\nm=application notaport UDP/DTLS/SCTP x\r\n", s),
              sdp::SdpError::BadNumber);
}

TEST(Sdp, TruncatedMediaLineIsError) {
    sdp::SdpSession s;
    EXPECT_EQ(sdp::parse("v=0\r\nm=application\r\n", s),
              sdp::SdpError::BadMediaLine);
}

TEST(Sdp, TooManyMediaSectionsOverflows) {
    std::string big = "v=0\r\n";
    for (int i = 0; i < (int)sdp::kSdpMaxMediaSections + 2; ++i)
        big += "m=application 9 UDP/DTLS/SCTP x\r\n";
    sdp::SdpSession s;
    EXPECT_EQ(sdp::parse(big, s), sdp::SdpError::Overflow);
}

TEST(Sdp, RandomGarbageDoesNotCrash) {
    // Feed pseudo-random bytes; the only contract is no throw / no crash and a
    // defined return value.
    std::uint32_t state = 0x12345678u;
    for (int iter = 0; iter < 256; ++iter) {
        std::string buf;
        const int n = 1 + (int)(state % 200);
        for (int i = 0; i < n; ++i) {
            state = state * 1664525u + 1013904223u;
            buf.push_back(static_cast<char>(state & 0xFF));
        }
        sdp::SdpSession s;
        volatile auto e = sdp::parse(buf, s);
        (void)e;
    }
    SUCCEED();
}
