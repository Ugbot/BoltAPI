// media_sdp_test.cpp — WM4 media (audio + video) SDP negotiation GATE (gtest,
// default suite, NO python, NO network).
//
// Coverage (per the project testing rule: >1 m-line, varied PTs, real input):
//   1. Parse a REAL Chrome audio+video offer SDP (m=audio Opus + m=video
//      VP8/H264, BUNDLE, rtcp-mux, extmap, ssrc, ice-ufrag/pwd, fingerprint
//      sha-256). Assert mids/codecs/fingerprint/ice extracted for BOTH m-lines.
//   2. Intersect the offer against Bolt's supported codecs (audio Opus/PCMU/PCMA,
//      video VP8/VP9/H264) -> negotiation keeps only the common PTs in offer
//      order; unsupported codecs (telephone-event, rtx, etc.) are dropped.
//   3. Build our answer -> assert well-formed (BUNDLE group with both mids,
//      rtcp-mux, setup:passive, ice-lite, negotiated PTs only) and that it
//      round-trips through our own parser.
//   4. Malformed input -> error (no throw / crash).

#include "boltapi/webrtc/sdp.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace sdp = bolt::api::webrtc;

// A representative Chrome (M12x) audio+video offer. Two m-lines (BUNDLE 0 1),
// rtcp-mux, extmap, ssrc, ice creds, sha-256 fingerprint, setup:actpass.
// Audio: Opus(111) + telephone-event(110, unsupported). Video: VP8(96) +
// rtx(97, unsupported) + H264(102) — varied PTs across the two sections.
static constexpr const char* kChromeAvOffer =
    "v=0\r\n"
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0 1\r\n"
    "a=extmap-allow-mixed\r\n"
    "a=msid-semantic: WMS stream0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 110\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:4ZcD\r\n"
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\n"
    "a=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 "
    "D7:E5:6C:1D:E9:90:48:9F:5E:34:1A:6F:1A:CB:9C:0E:11:1B:8B:5E:2B:7A:9C:43:"
    "F1:22:33:44:55:66:77:88\r\n"
    "a=setup:actpass\r\n"
    "a=mid:0\r\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=sendrecv\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
    "a=rtcp-fb:111 transport-cc\r\n"
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
    "a=rtpmap:110 telephone-event/48000\r\n"
    "a=ssrc:1111111111 cname:audioCname\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:4ZcD\r\n"
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\n"
    "a=fingerprint:sha-256 "
    "D7:E5:6C:1D:E9:90:48:9F:5E:34:1A:6F:1A:CB:9C:0E:11:1B:8B:5E:2B:7A:9C:43:"
    "F1:22:33:44:55:66:77:88\r\n"
    "a=setup:actpass\r\n"
    "a=mid:1\r\n"
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    "a=recvonly\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=rtcp-fb:96 nack\r\n"
    "a=rtcp-fb:96 nack pli\r\n"
    "a=rtpmap:97 rtx/90000\r\n"
    "a=fmtp:97 apt=96\r\n"
    "a=rtpmap:102 H264/90000\r\n"
    "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1\r\n"
    "a=ssrc:2222222222 cname:videoCname\r\n";

TEST(MediaSdp, ParseAudioVideoOfferBothSections) {
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kChromeAvOffer, s), sdp::SdpError::Ok);
    ASSERT_EQ(s.media_count, 2u);

    // BUNDLE group at session scope names both mids.
    EXPECT_EQ(s.session_attr("group"), std::string_view("BUNDLE 0 1"));

    // --- Audio section ---
    const sdp::SdpMedia& a = s.media[0];
    EXPECT_EQ(a.media_type, std::string_view("audio"));
    EXPECT_EQ(a.protocol, std::string_view("UDP/TLS/RTP/SAVPF"));
    EXPECT_EQ(a.mid(), std::string_view("0"));
    EXPECT_EQ(a.direction(), std::string_view("sendrecv"));
    EXPECT_TRUE(a.rtcp_mux());
    EXPECT_EQ(a.ice_ufrag(), std::string_view("4ZcD"));
    EXPECT_FALSE(a.fingerprint().empty());
    EXPECT_EQ(a.rtpmap_for(111), std::string_view("opus/48000/2"));
    EXPECT_EQ(a.fmtp_for(111), std::string_view("minptime=10;useinbandfec=1"));
    EXPECT_EQ(a.rtpmap_for(110), std::string_view("telephone-event/48000"));
    EXPECT_FALSE(a.ssrc().empty());

    std::uint8_t apts[16];
    const std::size_t na = a.payload_types(apts, 16);
    ASSERT_EQ(na, 2u);
    EXPECT_EQ(apts[0], 111);
    EXPECT_EQ(apts[1], 110);

    // --- Video section ---
    const sdp::SdpMedia& v = s.media[1];
    EXPECT_EQ(v.media_type, std::string_view("video"));
    EXPECT_EQ(v.mid(), std::string_view("1"));
    EXPECT_EQ(v.direction(), std::string_view("recvonly"));
    EXPECT_TRUE(v.rtcp_mux());
    EXPECT_EQ(v.rtpmap_for(96), std::string_view("VP8/90000"));
    EXPECT_EQ(v.rtpmap_for(102), std::string_view("H264/90000"));
    EXPECT_EQ(v.fmtp_for(102),
              std::string_view("level-asymmetry-allowed=1;packetization-mode=1"));
    EXPECT_EQ(v.rtpmap_for(97), std::string_view("rtx/90000"));

    std::uint8_t vpts[16];
    const std::size_t nv = v.payload_types(vpts, 16);
    ASSERT_EQ(nv, 3u);
    EXPECT_EQ(vpts[0], 96);
    EXPECT_EQ(vpts[1], 97);
    EXPECT_EQ(vpts[2], 102);
}

TEST(MediaSdp, NegotiateKeepsCommonCodecsOnly) {
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kChromeAvOffer, s), sdp::SdpError::Ok);

    sdp::MediaNegotiation neg;
    ASSERT_EQ(sdp::negotiate_media(s, neg), sdp::SdpError::Ok);
    ASSERT_EQ(neg.media_count, 2u);

    // Audio: only Opus(111) supported; telephone-event(110) dropped.
    const sdp::NegotiatedMedia& na = neg.media[0];
    EXPECT_EQ(na.kind, sdp::MediaKind::kAudio);
    EXPECT_EQ(na.mid, std::string_view("0"));
    // offer sendrecv -> we answer sendrecv.
    EXPECT_EQ(na.direction, std::string_view("sendrecv"));
    ASSERT_EQ(na.codec_count, 1u);
    EXPECT_EQ(na.codecs[0].pt, 111);
    EXPECT_EQ(na.codecs[0].rtpmap, std::string_view("opus/48000/2"));
    EXPECT_EQ(na.codecs[0].fmtp,
              std::string_view("minptime=10;useinbandfec=1"));

    // Video: VP8(96) + H264(102) supported; rtx(97) dropped.
    const sdp::NegotiatedMedia& nv = neg.media[1];
    EXPECT_EQ(nv.kind, sdp::MediaKind::kVideo);
    EXPECT_EQ(nv.mid, std::string_view("1"));
    // offer recvonly -> we answer sendonly.
    EXPECT_EQ(nv.direction, std::string_view("sendonly"));
    ASSERT_EQ(nv.codec_count, 2u);
    EXPECT_EQ(nv.codecs[0].pt, 96);
    EXPECT_EQ(nv.codecs[0].rtpmap, std::string_view("VP8/90000"));
    EXPECT_EQ(nv.codecs[1].pt, 102);
    EXPECT_EQ(nv.codecs[1].rtpmap, std::string_view("H264/90000"));

    // #37 — VP8(96) carries an RTX mapping (97 apt=96) + NACK/PLI feedback; H264
    // (102) in this offer has neither. Audio Opus(111) advertises transport-cc.
    EXPECT_EQ(nv.codecs[0].rtx_pt, 97);
    EXPECT_EQ(nv.codecs[0].rtx_rtpmap, std::string_view("rtx/90000"));
    EXPECT_TRUE(nv.codecs[0].fb.nack);
    EXPECT_TRUE(nv.codecs[0].fb.nack_pli);
    EXPECT_EQ(nv.codecs[1].rtx_pt, 0);
    EXPECT_FALSE(nv.codecs[1].fb.any());
    EXPECT_TRUE(na.codecs[0].fb.transport_cc);
    // #37 — abs-send-time extmap kept on video; ssrc-audio-level dropped on audio.
    ASSERT_EQ(nv.extmap_count, 1u);
    EXPECT_EQ(nv.extmaps[0].id, 2);
    EXPECT_EQ(nv.extmaps[0].uri, sdp::kAbsSendTimeExtUri);
    EXPECT_EQ(na.extmap_count, 0u);
}

TEST(MediaSdp, BuildAnswerWellFormedAndRoundTrips) {
    sdp::SdpSession offer;
    ASSERT_EQ(sdp::parse(kChromeAvOffer, offer), sdp::SdpError::Ok);
    sdp::MediaNegotiation neg;
    ASSERT_EQ(sdp::negotiate_media(offer, neg), sdp::SdpError::Ok);

    sdp::MediaAnswerParams p;
    p.ice_ufrag = "boltUfrag";
    p.ice_pwd = "boltPasswordboltPasswordbolt";
    p.fingerprint_sha256 =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
    p.ice_lite = true;
    p.negotiation = &neg;

    std::string answer;
    ASSERT_EQ(sdp::build_media_answer(p, answer), sdp::SdpError::Ok);

    // Surface-level well-formedness.
    EXPECT_NE(answer.find("a=group:BUNDLE 0 1"), std::string::npos);
    EXPECT_NE(answer.find("a=ice-lite"), std::string::npos);
    EXPECT_NE(answer.find("a=setup:passive"), std::string::npos);
    EXPECT_NE(answer.find("a=rtcp-mux"), std::string::npos);
    EXPECT_NE(answer.find("m=audio 9 UDP/TLS/RTP/SAVPF 111"), std::string::npos);
    // #37 — RTX PT (97, apt=96) is now appended to the video m-line after the
    // media PTs (96 102), so a browser turns on retransmission.
    EXPECT_NE(answer.find("m=video 9 UDP/TLS/RTP/SAVPF 96 102 97"),
              std::string::npos);
    EXPECT_NE(answer.find("a=rtpmap:111 opus/48000/2"), std::string::npos);
    EXPECT_NE(answer.find("a=rtpmap:102 H264/90000"), std::string::npos);
    // The unsupported codec must NOT appear in the answer.
    EXPECT_EQ(answer.find("telephone-event"), std::string::npos);

    // #37 — RTCP feedback the offer listed is now advertised back.
    EXPECT_NE(answer.find("a=rtcp-fb:96 nack"), std::string::npos);
    EXPECT_NE(answer.find("a=rtcp-fb:96 nack pli"), std::string::npos);
    EXPECT_NE(answer.find("a=rtcp-fb:111 transport-cc"), std::string::npos);
    // #37 — RTX codec advertised (rtpmap + apt fmtp) so retransmission negotiates.
    EXPECT_NE(answer.find("a=rtpmap:97 rtx/90000"), std::string::npos);
    EXPECT_NE(answer.find("a=fmtp:97 apt=96"), std::string::npos);
    // #37 — supported header extensions echoed at the offer's id (abs-send-time
    // on video). The unsupported ssrc-audio-level extension is dropped.
    EXPECT_NE(answer.find(
        "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"),
        std::string::npos);
    EXPECT_EQ(answer.find("ssrc-audio-level"), std::string::npos);

    // Round-trip: parse our own answer back; assert both negotiated m-lines.
    sdp::SdpSession parsed;
    ASSERT_EQ(sdp::parse(answer, parsed), sdp::SdpError::Ok);
    ASSERT_EQ(parsed.media_count, 2u);
    EXPECT_EQ(parsed.media[0].media_type, std::string_view("audio"));
    EXPECT_EQ(parsed.media[0].mid(), std::string_view("0"));
    EXPECT_EQ(parsed.media[0].setup(), std::string_view("passive"));
    EXPECT_TRUE(parsed.media[0].rtcp_mux());
    EXPECT_EQ(parsed.media[0].rtpmap_for(111), std::string_view("opus/48000/2"));

    EXPECT_EQ(parsed.media[1].media_type, std::string_view("video"));
    EXPECT_EQ(parsed.media[1].mid(), std::string_view("1"));
    EXPECT_EQ(parsed.media[1].rtpmap_for(96), std::string_view("VP8/90000"));
    EXPECT_EQ(parsed.media[1].rtpmap_for(102), std::string_view("H264/90000"));
    // ice-lite is at session scope.
    EXPECT_TRUE(parsed.has_session_attr("ice-lite"));
}

TEST(MediaSdp, AudioOnlyOfferNegotiatesOneSection) {
    static constexpr const char* kAudioOnly =
        "v=0\r\n"
        "o=- 1 2 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 0 8 111\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=mid:0\r\n"
        "a=sendonly\r\n"
        "a=rtcp-mux\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:111 opus/48000/2\r\n";
    sdp::SdpSession s;
    ASSERT_EQ(sdp::parse(kAudioOnly, s), sdp::SdpError::Ok);
    sdp::MediaNegotiation neg;
    ASSERT_EQ(sdp::negotiate_media(s, neg), sdp::SdpError::Ok);
    ASSERT_EQ(neg.media_count, 1u);
    // All three are supported audio codecs (PCMU/PCMA/Opus), kept in order.
    ASSERT_EQ(neg.media[0].codec_count, 3u);
    EXPECT_EQ(neg.media[0].codecs[0].pt, 0);
    EXPECT_EQ(neg.media[0].codecs[1].pt, 8);
    EXPECT_EQ(neg.media[0].codecs[2].pt, 111);
    // offer sendonly -> we answer recvonly.
    EXPECT_EQ(neg.media[0].direction, std::string_view("recvonly"));
}

TEST(MediaSdp, MalformedAndEmptyInputsErrorNoThrow) {
    sdp::SdpSession s;
    EXPECT_EQ(sdp::parse("", s), sdp::SdpError::Empty);
    EXPECT_EQ(sdp::parse("garbage-without-equals\r\n", s),
              sdp::SdpError::MalformedLine);
    // m= line missing port/proto.
    EXPECT_EQ(sdp::parse("v=0\r\nm=audio\r\n", s), sdp::SdpError::BadMediaLine);
    // Non-numeric port.
    EXPECT_EQ(sdp::parse("v=0\r\nm=audio xx UDP/TLS/RTP/SAVPF 111\r\n", s),
              sdp::SdpError::BadNumber);

    // build_media_answer with missing required fields -> MalformedLine, no throw.
    sdp::MediaNegotiation empty_neg;
    sdp::MediaAnswerParams p;
    p.negotiation = &empty_neg;  // zero media sections
    std::string out;
    EXPECT_EQ(sdp::build_media_answer(p, out), sdp::SdpError::MalformedLine);

    // Missing fingerprint/ufrag/pwd even with media -> MalformedLine.
    sdp::SdpSession offer;
    ASSERT_EQ(sdp::parse(kChromeAvOffer, offer), sdp::SdpError::Ok);
    sdp::MediaNegotiation neg;
    ASSERT_EQ(sdp::negotiate_media(offer, neg), sdp::SdpError::Ok);
    sdp::MediaAnswerParams p2;
    p2.negotiation = &neg;  // ufrag/pwd/fingerprint all empty
    std::string out2;
    EXPECT_EQ(sdp::build_media_answer(p2, out2), sdp::SdpError::MalformedLine);
}
