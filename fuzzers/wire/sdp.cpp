// sdp — an SDP offer as the signaling route receives it: parse, the
// accessors the App reads, media negotiation and every answer builder, a
// generate -> parse round-trip; plus trickle candidates and candidate lines.
// First byte: bit0 selects the trickle/candidate path.
#include "fuzz_util.h"

#include "boltapi/webrtc/ice.h"
#include "boltapi/webrtc/sdp.h"

#include <memory>
#include <string>
#include <string_view>

namespace wr = bolt::api::webrtc;

namespace {

void offer(std::string_view text) {
    wr::SdpSession s;
    if (wr::parse(text, s) != wr::SdpError::Ok) return;
    const wr::SdpMedia* app = s.application_media();
    const wr::SdpMedia* x = app != nullptr ? app : (s.media_count > 0 ? &s.media[0] : nullptr);
    (void)s.session_attr("ice-ufrag");
    (void)s.session_attr("fingerprint");
    if (x != nullptr) {
        (void)x->ice_ufrag();
        (void)x->ice_pwd();
        (void)x->fingerprint();
        (void)x->mid();
    }
    const std::string_view cands[1] = {"candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host"};
    std::string out;
    if (app != nullptr) {
        wr::AnswerParams p;
        if (!app->mid().empty()) p.mid = app->mid();
        p.ice_ufrag = "ufrg";
        p.ice_pwd = "pwdpwdpwdpwdpwdpwdpwdp";
        p.fingerprint_sha256 = "AB:CD";
        p.ice_lite = true;
        p.candidates = cands;
        p.candidate_count = 1;
        if (wr::build_answer(p, out) == wr::SdpError::Ok) {
            wr::SdpSession back;
            FUZZ_CHECK(wr::parse(out, back) == wr::SdpError::Ok);
        }
    }
    wr::MediaNegotiation neg;
    if (wr::negotiate_media(s, neg) == wr::SdpError::Ok && neg.media_count > 0) {
        wr::MediaAnswerParams mp;
        mp.ice_ufrag = "ufrg";
        mp.ice_pwd = "pwdpwdpwdpwdpwdpwdpwdp";
        mp.fingerprint_sha256 = "AB:CD";
        mp.negotiation = &neg;
        out.clear();
        (void)wr::build_media_answer(mp, out);
        wr::EchoAnswerParams ep;
        ep.ice_ufrag = mp.ice_ufrag;
        ep.ice_pwd = mp.ice_pwd;
        ep.fingerprint_sha256 = mp.fingerprint_sha256;
        ep.negotiation = &neg;
        ep.data_mid = app != nullptr ? app->mid() : std::string_view();
        ep.candidates = cands;
        ep.candidate_count = 1;
        out.clear();
        (void)wr::build_echo_answer(ep, out);
    }
    out.clear();
    if (wr::generate(s, out) == wr::SdpError::Ok) {
        wr::SdpSession again;
        (void)wr::parse(out, again);
    }
}

void trickle(std::string_view text) {
    wr::TrickleCandidate t;
    if (wr::parse_trickle(text, t) == wr::SdpError::Ok) {
        std::string env;
        (void)wr::generate_trickle(t, env);
        wr::IceCandidate c;
        if (!t.candidate.empty() && wr::IceCandidate::from_string(t.candidate, c)) {
            (void)c.to_string();
        }
    }
    wr::IceCandidate c;
    if (wr::IceCandidate::from_string(text, c)) {
        const std::string line = c.to_string();
        wr::IceCandidate again;
        FUZZ_CHECK(wr::IceCandidate::from_string(line, again));
        FUZZ_CHECK(again.port == c.port && again.priority == c.priority);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    // Exact-size copy: views into it must never be read past its end.
    std::unique_ptr<char[]> buf(new char[size > 1 ? size - 1 : 1]);
    if (size > 1) std::memcpy(buf.get(), data + 1, size - 1);
    const std::string_view text(buf.get(), size - 1);
    if (data[0] & 1) trickle(text);
    else offer(text);
    return 0;
}
