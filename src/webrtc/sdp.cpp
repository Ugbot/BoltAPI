// sdp.cpp — implementation of the SDP codec (boltapi/webrtc/sdp.h).
//
// ADAPTED from FasterAPI src/cpp/webrtc/sdp_parser.cpp:
//   * the line-by-line scan + the m=/a= field split are the same shape;
//   * std::unordered_map attribute store -> fixed SdpAttribute arrays;
//   * std::stoi (THROWS) -> std::from_chars (noexcept);
//   * std::ostringstream generate -> manual std::string append.
//
// Everything here is noexcept-by-contract and allocation-free in parse().

#include "boltapi/webrtc/sdp.h"

#include <charconv>
#include <cstring>

namespace bolt::api {
namespace webrtc {

namespace {

// Trim ASCII space/tab from both ends. Zero-copy.
std::string_view trim(std::string_view s) noexcept {
    std::size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) ++start;
    std::size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t')) --end;
    return s.substr(start, end - start);
}

// Parse an unsigned integer from `s` into `*out`. Returns false on any junk or
// overflow. No exceptions (from_chars never throws).
template <typename T>
bool parse_uint(std::string_view s, T* out) noexcept {
    s = trim(s);
    if (s.empty()) return false;
    T v{};
    const char* first = s.data();
    const char* last  = s.data() + s.size();
    const std::from_chars_result r = std::from_chars(first, last, v);
    if (r.ec != std::errc{} || r.ptr != last) return false;
    *out = v;
    return true;
}

// Append "x=value\r\n" to out.
void append_line(std::string& out, char type, std::string_view value) {
    out.push_back(type);
    out.push_back('=');
    out.append(value.data(), value.size());
    out.append("\r\n", 2);
}

// Append an attribute line: "a=key\r\n" (flag) or "a=key:value\r\n".
void append_attr(std::string& out, std::string_view key, std::string_view value) {
    out.append("a=", 2);
    out.append(key.data(), key.size());
    if (!value.empty()) {
        out.push_back(':');
        out.append(value.data(), value.size());
    }
    out.append("\r\n", 2);
}

// Append a decimal integer.
void append_uint(std::string& out, std::uint64_t v) {
    char buf[20];
    char* last = buf + sizeof(buf);
    const std::to_chars_result r = std::to_chars(buf, last, v);
    out.append(buf, static_cast<std::size_t>(r.ptr - buf));
}

// Split an a= line value into {key, value}. "name:value" -> {name, value};
// "flag" -> {flag, ""}.
SdpAttribute split_attr(std::string_view value) noexcept {
    const std::size_t colon = value.find(':');
    if (colon == std::string_view::npos) {
        return SdpAttribute{trim(value), std::string_view{}};
    }
    return SdpAttribute{trim(value.substr(0, colon)), trim(value.substr(colon + 1))};
}

}  // namespace

// ---------------------------------------------------------------------------
// SdpMedia lookups
// ---------------------------------------------------------------------------
std::string_view SdpMedia::attr(std::string_view key) const noexcept {
    for (std::size_t i = 0; i < attr_count; ++i) {
        if (attrs[i].key == key) return attrs[i].value;
    }
    return std::string_view{};
}

bool SdpMedia::has_attr(std::string_view key) const noexcept {
    for (std::size_t i = 0; i < attr_count; ++i) {
        if (attrs[i].key == key) return true;
    }
    return false;
}

bool SdpMedia::sctp_port(std::uint16_t* out) const noexcept {
    assert(out != nullptr);
    const std::string_view v = attr("sctp-port");
    if (v.empty()) return false;
    return parse_uint(v, out);
}

bool SdpMedia::max_message_size(std::uint32_t* out) const noexcept {
    assert(out != nullptr);
    const std::string_view v = attr("max-message-size");
    if (v.empty()) return false;
    return parse_uint(v, out);
}

namespace {

// Split "<pt> <rest>" -> pt + rest. Returns false if the leading token isn't a
// payload type in [0,127] or there is no following text.
bool split_pt_rest(std::string_view v, std::uint8_t* pt,
                   std::string_view* rest) noexcept {
    assert(pt != nullptr && "split_pt_rest: null pt");
    assert(rest != nullptr && "split_pt_rest: null rest");
    const std::size_t sp = v.find(' ');
    if (sp == std::string_view::npos) return false;
    std::uint16_t n = 0;
    const std::string_view head = v.substr(0, sp);
    const char* first = head.data();
    const char* last  = head.data() + head.size();
    const std::from_chars_result r = std::from_chars(first, last, n);
    if (r.ec != std::errc{} || r.ptr != last || n > 127) return false;
    *pt = static_cast<std::uint8_t>(n);
    std::string_view tail = v.substr(sp + 1);
    while (!tail.empty() && (tail.front() == ' ' || tail.front() == '\t'))
        tail.remove_prefix(1);
    *rest = tail;
    return true;
}

}  // namespace

std::string_view SdpMedia::direction() const noexcept {
    assert(attr_count <= kSdpMaxAttrsPerSection && "direction: attr overflow");
    assert(format_count <= kSdpMaxFormatsPerMedia && "direction: fmt overflow");
    for (std::size_t i = 0; i < attr_count; ++i) {
        const std::string_view k = attrs[i].key;
        if (k == "sendrecv" || k == "recvonly" || k == "sendonly" ||
            k == "inactive")
            return k;
    }
    return std::string_view{"sendrecv"};  // RFC 4566 default
}

std::string_view SdpMedia::rtpmap_for(std::uint8_t pt) const noexcept {
    assert(attr_count <= kSdpMaxAttrsPerSection && "rtpmap_for: attr overflow");
    assert(pt <= 127 && "rtpmap_for: pt range");
    for (std::size_t i = 0; i < attr_count; ++i) {
        if (attrs[i].key != "rtpmap") continue;
        std::uint8_t p = 0;
        std::string_view rest;
        if (split_pt_rest(attrs[i].value, &p, &rest) && p == pt) return rest;
    }
    return std::string_view{};
}

std::string_view SdpMedia::fmtp_for(std::uint8_t pt) const noexcept {
    assert(attr_count <= kSdpMaxAttrsPerSection && "fmtp_for: attr overflow");
    assert(pt <= 127 && "fmtp_for: pt range");
    for (std::size_t i = 0; i < attr_count; ++i) {
        if (attrs[i].key != "fmtp") continue;
        std::uint8_t p = 0;
        std::string_view rest;
        if (split_pt_rest(attrs[i].value, &p, &rest) && p == pt) return rest;
    }
    return std::string_view{};
}

std::size_t SdpMedia::rids(std::string_view* out, std::size_t cap) const noexcept {
    assert(out != nullptr || cap == 0);
    assert(attr_count <= kSdpMaxAttrsPerSection && "rids: attr overflow");
    std::size_t n = 0;
    for (std::size_t i = 0; i < attr_count && n < cap; ++i) {
        if (attrs[i].key != "rid") continue;
        // a=rid:<id> <direction> [<restrictions>] — the id is the first token.
        const std::string_view v = attrs[i].value;
        const std::size_t sp = v.find(' ');
        const std::string_view id = (sp == std::string_view::npos) ? v
                                                                   : v.substr(0, sp);
        if (!id.empty() && id.size() <= kMaxRidLen) out[n++] = trim(id);
    }
    return n;
}

std::uint8_t SdpMedia::rid_extmap_id() const noexcept {
    assert(attr_count <= kSdpMaxAttrsPerSection && "rid_extmap_id: overflow");
    assert(kRidExtUri.size() > 0 && "rid_extmap_id: uri");
    for (std::size_t i = 0; i < attr_count; ++i) {
        if (attrs[i].key != "extmap") continue;
        // a=extmap:<id>[/<dir>] <uri> ...
        const std::string_view v = attrs[i].value;
        const std::size_t sp = v.find(' ');
        if (sp == std::string_view::npos) continue;
        if (v.find(kRidExtUri) == std::string_view::npos) continue;
        std::string_view idtok = v.substr(0, sp);
        const std::size_t slash = idtok.find('/');
        if (slash != std::string_view::npos) idtok = idtok.substr(0, slash);
        std::uint8_t id = 0;
        if (parse_uint(idtok, &id) && id >= 1 && id <= 14) return id;
    }
    return 0;
}

std::size_t SdpMedia::payload_types(std::uint8_t* out,
                                    std::size_t cap) const noexcept {
    assert(out != nullptr || cap == 0);
    assert(format_count <= kSdpMaxFormatsPerMedia && "payload_types: fmt overflow");
    std::size_t n = 0;
    for (std::size_t i = 0; i < format_count && n < cap; ++i) {
        std::uint8_t pt = 0;
        if (parse_uint(formats[i], &pt)) out[n++] = pt;
    }
    return n;
}

// ---------------------------------------------------------------------------
// SdpSession lookups
// ---------------------------------------------------------------------------
std::string_view SdpSession::session_attr(std::string_view key) const noexcept {
    for (std::size_t i = 0; i < session_attr_count; ++i) {
        if (session_attrs[i].key == key) return session_attrs[i].value;
    }
    return std::string_view{};
}

bool SdpSession::has_session_attr(std::string_view key) const noexcept {
    for (std::size_t i = 0; i < session_attr_count; ++i) {
        if (session_attrs[i].key == key) return true;
    }
    return false;
}

const SdpMedia* SdpSession::application_media() const noexcept {
    for (std::size_t i = 0; i < media_count; ++i) {
        if (media[i].media_type == "application") return &media[i];
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------
SdpError parse(std::string_view sdp, SdpSession& out) noexcept {
    out = SdpSession{};
    if (sdp.empty()) return SdpError::Empty;

    SdpMedia* current = nullptr;  // null while in session scope
    SdpMedia  discard;            // sink for m= sections past the section cap (#44)

    std::size_t line_start = 0;
    const std::size_t n = sdp.size();
    std::size_t pos = 0;
    while (pos <= n) {
        if (pos == n || sdp[pos] == '\n') {
            std::size_t line_end = pos;
            if (line_end > line_start && sdp[line_end - 1] == '\r') --line_end;
            std::string_view line = sdp.substr(line_start, line_end - line_start);
            line_start = pos + 1;

            if (line.empty()) { ++pos; continue; }
            if (line.size() < 2 || line[1] != '=') return SdpError::MalformedLine;

            const char type = line[0];
            const std::string_view value = trim(line.substr(2));

            switch (type) {
                case 'v': out.version = value; break;
                case 'o': out.origin = value; break;
                case 's': out.session_name = value; break;
                case 't': out.timing = value; break;
                case 'c':
                    if (current) current->connection = value;
                    else out.connection = value;
                    break;

                case 'm': {
                    // Overflow-tolerant (#44): past the section cap, drop further
                    // m= sections (and their a= lines) rather than rejecting the
                    // whole offer. `current=nullptr` would misroute attrs to the
                    // session scope, so point at a discard sink instead.
                    if (out.media_count >= kSdpMaxMediaSections) {
                        current = &discard;
                        discard = SdpMedia{};
                        break;
                    }
                    SdpMedia& m = out.media[out.media_count];
                    m = SdpMedia{};

                    // m=<type> <port> <proto> <fmt>...
                    const std::size_t s1 = value.find(' ');
                    if (s1 == std::string_view::npos) return SdpError::BadMediaLine;
                    m.media_type = trim(value.substr(0, s1));

                    const std::size_t s2 = value.find(' ', s1 + 1);
                    if (s2 == std::string_view::npos) return SdpError::BadMediaLine;
                    if (!parse_uint(value.substr(s1 + 1, s2 - s1 - 1), &m.port))
                        return SdpError::BadNumber;

                    const std::size_t s3 = value.find(' ', s2 + 1);
                    if (s3 == std::string_view::npos) {
                        m.protocol = trim(value.substr(s2 + 1));
                    } else {
                        m.protocol = trim(value.substr(s2 + 1, s3 - s2 - 1));
                        std::string_view fmts = trim(value.substr(s3 + 1));
                        std::size_t fp = 0;
                        while (fp < fmts.size()) {
                            const std::size_t sp = fmts.find(' ', fp);
                            std::string_view tok = (sp == std::string_view::npos)
                                ? trim(fmts.substr(fp))
                                : trim(fmts.substr(fp, sp - fp));
                            if (!tok.empty() &&
                                m.format_count < kSdpMaxFormatsPerMedia) {
                                m.formats[m.format_count++] = tok;  // else skip (#44)
                            }
                            if (sp == std::string_view::npos) break;
                            fp = sp + 1;
                        }
                    }

                    ++out.media_count;
                    current = &out.media[out.media_count - 1];
                    break;
                }

                case 'a': {
                    const SdpAttribute a = split_attr(value);
                    // Overflow-tolerant (#44): skip a= lines past the cap rather
                    // than rejecting; the cap (256) clears a real Chrome offer.
                    if (current) {
                        if (current->attr_count < kSdpMaxAttrsPerSection)
                            current->attrs[current->attr_count++] = a;
                    } else {
                        if (out.session_attr_count < kSdpMaxAttrsPerSection)
                            out.session_attrs[out.session_attr_count++] = a;
                    }
                    break;
                }

                default:
                    // Unknown line type (b=, k=, r=, z=, i=, u=, e=, p=): skip.
                    break;
            }
        }
        ++pos;
    }

    return SdpError::Ok;
}

// ---------------------------------------------------------------------------
// generate — round-trips a parsed SdpSession back to text.
// ---------------------------------------------------------------------------
SdpError generate(const SdpSession& session, std::string& out) {
    if (!session.version.empty()) append_line(out, 'v', session.version);
    if (!session.origin.empty())  append_line(out, 'o', session.origin);
    append_line(out, 's', session.session_name.empty()
                              ? std::string_view{"-"} : session.session_name);
    if (!session.connection.empty()) append_line(out, 'c', session.connection);
    append_line(out, 't', session.timing.empty()
                              ? std::string_view{"0 0"} : session.timing);

    for (std::size_t i = 0; i < session.session_attr_count; ++i) {
        append_attr(out, session.session_attrs[i].key,
                    session.session_attrs[i].value);
    }

    for (std::size_t mi = 0; mi < session.media_count; ++mi) {
        const SdpMedia& m = session.media[mi];
        out.append("m=", 2);
        out.append(m.media_type.data(), m.media_type.size());
        out.push_back(' ');
        append_uint(out, m.port);
        out.push_back(' ');
        out.append(m.protocol.data(), m.protocol.size());
        for (std::size_t fi = 0; fi < m.format_count; ++fi) {
            out.push_back(' ');
            out.append(m.formats[fi].data(), m.formats[fi].size());
        }
        out.append("\r\n", 2);

        if (!m.connection.empty()) append_line(out, 'c', m.connection);
        for (std::size_t ai = 0; ai < m.attr_count; ++ai) {
            append_attr(out, m.attrs[ai].key, m.attrs[ai].value);
        }
    }
    return SdpError::Ok;
}

// ---------------------------------------------------------------------------
// build_answer — Bolt's data-channel SDP answer (we are the DTLS passive peer).
// ---------------------------------------------------------------------------
SdpError build_answer(const AnswerParams& p, std::string& out) {
    if (p.ice_ufrag.empty() || p.ice_pwd.empty() ||
        p.fingerprint_sha256.empty()) {
        return SdpError::MalformedLine;
    }
    assert(!p.mid.empty());

    out.clear();

    append_line(out, 'v', "0");
    // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-addr>
    out.append("o=- ", 4);
    out.append(p.origin_session_id.data(), p.origin_session_id.size());
    out.append(" 2 IN IP4 127.0.0.1\r\n");
    append_line(out, 's', "-");
    append_line(out, 't', "0 0");

    // BUNDLE the single data m-line by its mid.
    out.append("a=group:BUNDLE ", 15);
    out.append(p.mid.data(), p.mid.size());
    out.append("\r\n", 2);
    append_attr(out, "msid-semantic", " WMS");
    if (p.ice_lite) append_attr(out, "ice-lite", std::string_view{});

    // m=application <port> UDP/DTLS/SCTP webrtc-datachannel
    out.append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    append_line(out, 'c', "IN IP4 0.0.0.0");

    append_attr(out, "ice-ufrag", p.ice_ufrag);
    append_attr(out, "ice-pwd", p.ice_pwd);

    // a=fingerprint:sha-256 <hex>
    {
        std::string fp;
        fp.reserve(8 + p.fingerprint_sha256.size());
        fp.append("sha-256 ");
        fp.append(p.fingerprint_sha256.data(), p.fingerprint_sha256.size());
        append_attr(out, "fingerprint", fp);
    }

    append_attr(out, "setup", p.setup);
    append_attr(out, "mid", p.mid);
    append_attr(out, "sctp-port",
                [&] { std::string s; append_uint(s, p.sctp_port); return s; }());
    append_attr(out, "max-message-size",
                [&] { std::string s; append_uint(s, p.max_message_size); return s; }());

    // a=candidate:... host (and later srflx) lines from the ICE agent. Each
    // entry already carries the "candidate:" token (IceCandidate::to_string),
    // so we emit it verbatim after "a=". If any candidate is present, finish
    // with a=end-of-candidates (RFC 8838) — correct for our non-trickle answer.
    if (p.candidates != nullptr && p.candidate_count > 0) {
        for (std::size_t i = 0; i < p.candidate_count; ++i) {
            const std::string_view c = p.candidates[i];
            if (c.empty()) continue;
            out.append("a=", 2);
            out.append(c.data(), c.size());
            out.append("\r\n", 2);
        }
        append_attr(out, "end-of-candidates", std::string_view{});
    }

    return SdpError::Ok;
}

// ===========================================================================
// WM4 — media negotiation + answer.
// ===========================================================================
namespace {

// Case-insensitive equality of two ASCII spans.
bool ieq(std::string_view a, std::string_view b) noexcept {
    assert(a.size() <= 256 && "ieq: a span bound");
    assert(b.size() <= 256 && "ieq: b span bound");
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = static_cast<char>(cb - 32);
        if (ca != cb) return false;
    }
    return true;
}

// The encoding name from an rtpmap value: "opus/48000/2" -> "opus".
std::string_view encoding_name(std::string_view rtpmap) noexcept {
    assert(rtpmap.size() <= 256 && "encoding_name: span bound");
    const std::size_t slash = rtpmap.find('/');
    const std::string_view name =
        slash == std::string_view::npos ? rtpmap : rtpmap.substr(0, slash);
    assert(name.size() <= rtpmap.size() && "encoding_name: overran");
    return name;
}

// Is `name` a codec Bolt supports for `kind` (relay/echo, no transcode)?
bool is_supported_codec(MediaKind kind, std::string_view name) noexcept {
    assert(name.size() <= 64 && "is_supported_codec: name bound");
    assert((kind == MediaKind::kAudio || kind == MediaKind::kVideo) &&
           "is_supported_codec: bad kind");
    if (kind == MediaKind::kAudio) {
        return ieq(name, "opus") || ieq(name, "PCMU") || ieq(name, "PCMA");
    }
    return ieq(name, "VP8") || ieq(name, "VP9") || ieq(name, "H264");
}

// Map a media_type token to a MediaKind; false for non-audio/video sections.
bool media_kind_of(std::string_view t, MediaKind* k) noexcept {
    assert(k != nullptr && "media_kind_of: null");
    assert(t.size() <= 64 && "media_kind_of: type bound");
    if (t == "audio") { *k = MediaKind::kAudio; return true; }
    if (t == "video") { *k = MediaKind::kVideo; return true; }
    return false;
}

// Pick our answer direction given the offer's direction. We are a relay/echo
// answerer (recvonly default); we only promise sendrecv if the offerer does.
std::string_view answer_direction(std::string_view offer_dir) noexcept {
    assert(offer_dir.size() <= 16 && "answer_direction: dir bound");
    assert(!offer_dir.empty() && "answer_direction: empty dir");
    if (offer_dir == "sendonly") return std::string_view{"recvonly"};
    if (offer_dir == "recvonly") return std::string_view{"sendonly"};
    if (offer_dir == "inactive") return std::string_view{"inactive"};
    return std::string_view{"sendrecv"};
}

// First whitespace-separated token of `v`; advances `v` past it. Bounded.
std::string_view next_token(std::string_view& v) noexcept {
    [[maybe_unused]] const std::size_t in_size = v.size();
    assert(in_size <= 4096 && "next_token: span bound");      // bounded input
    std::size_t b = 0;
    while (b < v.size() && (v[b] == ' ' || v[b] == '\t')) ++b;
    std::size_t e = b;
    while (e < v.size() && v[e] != ' ' && v[e] != '\t') ++e;
    const std::string_view tok = v.substr(b, e - b);
    v = v.substr(e);
    assert(tok.size() <= in_size && "next_token: token overran input");  // postcond
    assert(v.size() <= in_size && "next_token: remainder grew");          // postcond
    return tok;
}

// #37 — read the offer's a=rtcp-fb lines for `pt` and set the flags for the
// feedback types Bolt supports (so the answer advertises ONLY offered feedback).
// "*" applies to every PT. Bounded scan; no allocation.
void parse_rtcp_fb_for_pt(const SdpMedia& m, std::uint8_t pt,
                          RtcpFeedback& fb) noexcept {
    assert(m.attr_count <= kSdpMaxAttrsPerSection && "rtcp-fb: attr overflow");
    assert(m.media_type == "audio" || m.media_type == "video");  // RTP media only
    for (std::size_t i = 0; i < m.attr_count; ++i) {
        if (m.attrs[i].key != "rtcp-fb") continue;
        std::string_view v = m.attrs[i].value;          // "<pt> <type> [param]"
        const std::string_view pt_tok = next_token(v);
        bool applies = (pt_tok == "*");
        if (!applies) {
            std::uint8_t fb_pt = 0;
            if (parse_uint(pt_tok, &fb_pt) && fb_pt == pt) applies = true;
        }
        if (!applies) continue;
        const std::string_view type = next_token(v);
        const std::string_view param = next_token(v);
        if (type == "nack") {
            if (param == "pli") fb.nack_pli = true;
            else                fb.nack = true;
        } else if (type == "ccm" && param == "fir") {
            fb.ccm_fir = true;
        } else if (type == "transport-cc") {
            fb.transport_cc = true;
        } else if (type == "goog-remb") {
            fb.goog_remb = true;
        }
    }
}

// #37 — find the RTX (RFC 4588) PT in this m-line whose fmtp "apt=<media_pt>"
// references `media_pt`. Fills *rtx_pt + *rtx_rtpmap and returns true if found.
bool find_rtx_for_pt(const SdpMedia& m, std::uint8_t media_pt,
                     std::uint8_t* rtx_pt, std::string_view* rtx_rtpmap) noexcept {
    assert(rtx_pt != nullptr && rtx_rtpmap != nullptr && "find_rtx: null out");
    assert(m.format_count <= kSdpMaxFormatsPerMedia && "find_rtx: fmt overflow");
    std::uint8_t pts[kSdpMaxFormatsPerMedia];
    const std::size_t n = m.payload_types(pts, kSdpMaxFormatsPerMedia);
    assert(n <= kSdpMaxFormatsPerMedia && "find_rtx: pt count bound");
    for (std::size_t i = 0; i < n; ++i) {
        const std::string_view rm = m.rtpmap_for(pts[i]);
        if (!ieq(encoding_name(rm), "rtx")) continue;
        const std::string_view fp = m.fmtp_for(pts[i]);     // "apt=<pt>"
        const std::size_t apt = fp.find("apt=");
        if (apt == std::string_view::npos) continue;
        std::uint8_t ap = 0;
        if (!parse_uint(fp.substr(apt + 4), &ap)) continue;
        if (ap != media_pt) continue;
        *rtx_pt = pts[i];
        *rtx_rtpmap = rm;
        return true;
    }
    return false;
}

// #37 — is this extmap URI one Bolt echoes back? (mid/rid for BUNDLE+simulcast
// demux; transport-cc for TWCC; abs-send-time for BWE.)
bool is_supported_extmap(std::string_view uri) noexcept {
    return uri == kMidExtUri || uri == kRidExtUri ||
           uri == kTransportCcExtUri || uri == kAbsSendTimeExtUri;
}

// #37 — collect the offer's a=extmap lines for supported extensions into `out`
// (capacity `cap`), keeping each at the OFFER's id. Returns the count written.
std::size_t collect_supported_extmaps(const SdpMedia& m, NegotiatedExtmap* out,
                                      std::size_t cap) noexcept {
    assert(out != nullptr && "extmap: null out");
    assert(cap > 0 && cap <= kMaxExtmaps && "extmap: bad cap");
    assert(m.attr_count <= kSdpMaxAttrsPerSection && "extmap: attr overflow");
    std::size_t n = 0;
    for (std::size_t i = 0; i < m.attr_count && n < cap; ++i) {
        if (m.attrs[i].key != "extmap") continue;
        std::string_view v = m.attrs[i].value;     // "<id>[/dir] <uri> [attr]"
        std::string_view id_tok = next_token(v);
        const std::size_t slash = id_tok.find('/');
        if (slash != std::string_view::npos) id_tok = id_tok.substr(0, slash);
        std::uint8_t id = 0;
        if (!parse_uint(id_tok, &id) || id < 1 || id > 14) continue;
        const std::string_view uri = next_token(v);
        if (!is_supported_extmap(uri)) continue;
        out[n].id = id;
        out[n].uri = uri;
        ++n;
    }
    assert(n <= cap && "extmap: wrote past cap");  // postcondition
    return n;
}

}  // namespace

SdpError negotiate_media(const SdpSession& offer,
                         MediaNegotiation& out) noexcept {
    assert(offer.media_count <= kSdpMaxMediaSections && "negotiate: media overflow");
    assert(kMaxCodecsPerSection <= kSdpMaxFormatsPerMedia &&
           "negotiate: codec cap > fmt cap");
    out = MediaNegotiation{};

    for (std::size_t mi = 0; mi < offer.media_count; ++mi) {
        const SdpMedia& m = offer.media[mi];
        MediaKind kind{};
        if (!media_kind_of(m.media_type, &kind)) continue;  // skip application
        if (out.media_count >= kMaxMediaSections) return SdpError::Overflow;

        NegotiatedMedia& nm = out.media[out.media_count];
        nm = NegotiatedMedia{};
        nm.kind = kind;
        nm.mid = m.mid();
        nm.direction = answer_direction(m.direction());

        std::uint8_t pts[kSdpMaxFormatsPerMedia];
        const std::size_t npt = m.payload_types(pts, kSdpMaxFormatsPerMedia);
        for (std::size_t i = 0; i < npt; ++i) {
            const std::string_view rm = m.rtpmap_for(pts[i]);
            if (rm.empty()) continue;  // need an rtpmap to relay
            if (!is_supported_codec(kind, encoding_name(rm))) continue;
            if (nm.codec_count >= kMaxCodecsPerSection) return SdpError::Overflow;
            NegotiatedCodec& c = nm.codecs[nm.codec_count++];
            c.pt = pts[i];
            c.rtpmap = rm;
            c.fmtp = m.fmtp_for(pts[i]);
            // #37 — advertise the offered RTCP feedback + RTX for this codec so a
            // browser actually turns NACK/PLI/FIR/REMB/TWCC + RTX retransmission
            // ON. The hub already generates/consumes these (WA live-wiring).
            parse_rtcp_fb_for_pt(m, c.pt, c.fb);
            find_rtx_for_pt(m, c.pt, &c.rtx_pt, &c.rtx_rtpmap);
        }
        // #37 — echo the offer's supported header extensions (mid/rid/
        // transport-cc/abs-send-time) so they are active on the wire.
        nm.extmap_count =
            collect_supported_extmaps(m, nm.extmaps, kMaxExtmaps);
        // WA — simulcast: if the offer m-line has a=simulcast + a=rid lines,
        // echo the rids (bounded) and the RID header-extension id so the answer
        // can mirror the simulcast (RFC 8851/8852). Bounded by kMaxRids.
        if (m.has_simulcast()) {
            std::string_view rid_views[kMaxRids];
            const std::size_t nr = m.rids(rid_views, kMaxRids);
            for (std::size_t r = 0; r < nr; ++r) nm.rids[nm.rid_count++] = rid_views[r];
            nm.rid_ext_id = m.rid_extmap_id();
        }

        // Keep the section even if empty so the answer can mark it inactive; but
        // only count sections that had at least one common codec.
        if (nm.codec_count > 0) ++out.media_count;
    }
    return SdpError::Ok;
}

// #37 — emit the a=rtcp-fb:<pt> <type> lines for the feedback flags set on a
// codec (only those the offer listed, so we never over-promise). Bounded.
static void append_rtcp_fb(std::string& out, std::uint8_t pt,
                           const RtcpFeedback& fb) {
    assert(pt <= 127 && "append_rtcp_fb: pt out of range");      // RTP PT is 7-bit
    [[maybe_unused]] const std::size_t out_before = out.size();
    const auto line = [&](std::string_view type) {
        std::string v;
        append_uint(v, pt);
        v.push_back(' ');
        v.append(type.data(), type.size());
        append_attr(out, "rtcp-fb", v);
    };
    if (fb.nack)         line("nack");
    if (fb.nack_pli)     line("nack pli");
    if (fb.ccm_fir)      line("ccm fir");
    if (fb.transport_cc) line("transport-cc");
    if (fb.goog_remb)    line("goog-remb");
    assert((out.size() >= out_before) && "append_rtcp_fb: output shrank");
    assert((fb.any() || out.size() == out_before) && "append_rtcp_fb: spurious line");
}

// Emit one m= media section into `out` for a negotiated audio/video line.
static void append_media_section(std::string& out, const NegotiatedMedia& nm) {
    assert(nm.codec_count > 0 && "append_media_section: empty");
    assert(nm.codec_count <= kMaxCodecsPerSection && "append_media_section: overflow");

    // m=<kind> 9 UDP/TLS/RTP/SAVPF <media pt>... <rtx pt>...
    out.append("m=", 2);
    out.append(nm.kind == MediaKind::kAudio ? "audio" : "video");
    out.append(" 9 UDP/TLS/RTP/SAVPF", 20);
    for (std::size_t i = 0; i < nm.codec_count; ++i) {
        out.push_back(' ');
        append_uint(out, nm.codecs[i].pt);
    }
    for (std::size_t i = 0; i < nm.codec_count; ++i) {  // #37 — RTX PTs
        if (nm.codecs[i].rtx_pt != 0) {
            out.push_back(' ');
            append_uint(out, nm.codecs[i].rtx_pt);
        }
    }
    out.append("\r\n", 2);
    append_line(out, 'c', "IN IP4 0.0.0.0");
    append_attr(out, "rtcp-mux", std::string_view{});
    if (!nm.mid.empty()) append_attr(out, "mid", nm.mid);
    append_attr(out, nm.direction, std::string_view{});

    // #37 — a=extmap lines (mid/rid/transport-cc/abs-send-time), each at the
    // offer's id, so the corresponding header extensions are active on the wire.
    assert(nm.extmap_count <= kMaxExtmaps && "append_media_section: extmap overflow");
    for (std::size_t e = 0; e < nm.extmap_count; ++e) {
        std::string v;
        append_uint(v, nm.extmaps[e].id);
        v.push_back(' ');
        v.append(nm.extmaps[e].uri.data(), nm.extmaps[e].uri.size());
        append_attr(out, "extmap", v);
    }

    for (std::size_t i = 0; i < nm.codec_count; ++i) {
        const NegotiatedCodec& c = nm.codecs[i];
        {  // a=rtpmap:<pt> <encoding>
            std::string v;
            append_uint(v, c.pt);
            v.push_back(' ');
            v.append(c.rtpmap.data(), c.rtpmap.size());
            append_attr(out, "rtpmap", v);
        }
        // #37 — a=rtcp-fb:<pt> <type> for each feedback the offer listed.
        append_rtcp_fb(out, c.pt, c.fb);
        if (!c.fmtp.empty()) {  // a=fmtp:<pt> <params>
            std::string v;
            append_uint(v, c.pt);
            v.push_back(' ');
            v.append(c.fmtp.data(), c.fmtp.size());
            append_attr(out, "fmtp", v);
        }
        // #37 — the paired RTX codec: a=rtpmap:<rtx> rtx/<clock> + a=fmtp apt=<pt>.
        if (c.rtx_pt != 0) {
            std::string v;
            append_uint(v, c.rtx_pt);
            v.push_back(' ');
            v.append(c.rtx_rtpmap.data(), c.rtx_rtpmap.size());
            append_attr(out, "rtpmap", v);
            std::string f;
            append_uint(f, c.rtx_pt);
            f.append(" apt=", 5);
            append_uint(f, c.pt);
            append_attr(out, "fmtp", f);
        }
    }

    // WA — simulcast answer (RFC 8851/8852): one a=rid:<id> recv line per offered
    // layer, then a=simulcast:recv <list>. (The RID a=extmap is emitted above as
    // part of the #37 extmap set.)
    assert(nm.rid_count <= kMaxRids && "append_media_section: rid overflow");
    if (nm.rid_count > 0) {
        for (std::size_t r = 0; r < nm.rid_count; ++r) {  // a=rid:<id> recv
            std::string v;
            v.append(nm.rids[r].data(), nm.rids[r].size());
            v.append(" recv", 5);
            append_attr(out, "rid", v);
        }
        std::string sc("recv ");  // a=simulcast:recv q;h;f
        for (std::size_t r = 0; r < nm.rid_count; ++r) {
            if (r != 0) sc.push_back(';');
            sc.append(nm.rids[r].data(), nm.rids[r].size());
        }
        append_attr(out, "simulcast", sc);
    }
}

SdpError build_media_answer(const MediaAnswerParams& p, std::string& out) {
    if (p.ice_ufrag.empty() || p.ice_pwd.empty() ||
        p.fingerprint_sha256.empty() || p.negotiation == nullptr) {
        return SdpError::MalformedLine;
    }
    if (p.negotiation->media_count == 0) return SdpError::MalformedLine;
    assert(p.negotiation->media_count <= kMaxMediaSections && "answer: overflow");
    assert(!p.setup.empty() && "answer: empty setup");

    out.clear();
    append_line(out, 'v', "0");
    out.append("o=- ", 4);
    out.append(p.origin_session_id.data(), p.origin_session_id.size());
    out.append(" 2 IN IP4 127.0.0.1\r\n");
    append_line(out, 's', "-");
    append_line(out, 't', "0 0");

    // a=group:BUNDLE <mid> <mid> ... — all m-lines on one transport.
    out.append("a=group:BUNDLE", 14);
    for (std::size_t i = 0; i < p.negotiation->media_count; ++i) {
        const std::string_view mid = p.negotiation->media[i].mid;
        out.push_back(' ');
        out.append(mid.data(), mid.size());
    }
    out.append("\r\n", 2);
    append_attr(out, "msid-semantic", " WMS");
    if (p.ice_lite) append_attr(out, "ice-lite", std::string_view{});

    // Build the fingerprint value once (shared by every m-line via BUNDLE).
    std::string fp;
    fp.reserve(8 + p.fingerprint_sha256.size());
    fp.append("sha-256 ");
    fp.append(p.fingerprint_sha256.data(), p.fingerprint_sha256.size());

    for (std::size_t i = 0; i < p.negotiation->media_count; ++i) {
        append_media_section(out, p.negotiation->media[i]);
        // Transport attrs repeat per m-line (BUNDLE-able, identical creds).
        append_attr(out, "ice-ufrag", p.ice_ufrag);
        append_attr(out, "ice-pwd", p.ice_pwd);
        append_attr(out, "fingerprint", fp);
        append_attr(out, "setup", p.setup);
    }
    return SdpError::Ok;
}

// ===========================================================================
// WM6 — combined media + data-channel answer (the aiortc `server` shape).
// ===========================================================================
namespace {

// Emit the shared per-m-line transport attrs (BUNDLE: identical on every line).
void append_transport_attrs(std::string& out, std::string_view ufrag,
                            std::string_view pwd, std::string_view fp,
                            std::string_view setup) {
    assert(!ufrag.empty() && "transport attrs: ufrag");
    assert(!setup.empty() && "transport attrs: setup");
    append_attr(out, "ice-ufrag", ufrag);
    append_attr(out, "ice-pwd", pwd);
    append_attr(out, "fingerprint", fp);
    append_attr(out, "setup", setup);
}

// Emit a=candidate:... lines (verbatim, with the leading "a=") + end-of-cands.
void append_candidates(std::string& out, const std::string_view* cands,
                       std::size_t n) {
    assert(cands != nullptr || n == 0);
    assert(n <= 64 && "append_candidates: bound");
    if (cands == nullptr || n == 0) return;
    for (std::size_t i = 0; i < n; ++i) {
        if (cands[i].empty()) continue;
        out.append("a=", 2);
        out.append(cands[i].data(), cands[i].size());
        out.append("\r\n", 2);
    }
    append_attr(out, "end-of-candidates", std::string_view{});
}

}  // namespace

SdpError build_echo_answer(const EchoAnswerParams& p, std::string& out) {
    if (p.ice_ufrag.empty() || p.ice_pwd.empty() ||
        p.fingerprint_sha256.empty() || p.negotiation == nullptr ||
        p.negotiation->media_count == 0) {
        return SdpError::MalformedLine;
    }
    assert(p.negotiation->media_count <= kMaxMediaSections && "echo: overflow");
    assert(!p.setup.empty() && "echo: empty setup");

    out.clear();
    append_line(out, 'v', "0");
    out.append("o=- ", 4);
    out.append(p.origin_session_id.data(), p.origin_session_id.size());
    out.append(" 2 IN IP4 127.0.0.1\r\n");
    append_line(out, 's', "-");
    append_line(out, 't', "0 0");

    // a=group:BUNDLE <media mids...> [<data mid>] — all on one transport.
    out.append("a=group:BUNDLE", 14);
    for (std::size_t i = 0; i < p.negotiation->media_count; ++i) {
        out.push_back(' ');
        const std::string_view mid = p.negotiation->media[i].mid;
        out.append(mid.data(), mid.size());
    }
    if (!p.data_mid.empty()) {
        out.push_back(' ');
        out.append(p.data_mid.data(), p.data_mid.size());
    }
    out.append("\r\n", 2);
    append_attr(out, "msid-semantic", " WMS");
    if (p.ice_lite) append_attr(out, "ice-lite", std::string_view{});

    std::string fp;
    fp.reserve(8 + p.fingerprint_sha256.size());
    fp.append("sha-256 ");
    fp.append(p.fingerprint_sha256.data(), p.fingerprint_sha256.size());

    // Media m-lines first; candidates on the FIRST m-line only.
    for (std::size_t i = 0; i < p.negotiation->media_count; ++i) {
        append_media_section(out, p.negotiation->media[i]);
        append_transport_attrs(out, p.ice_ufrag, p.ice_pwd, fp, p.setup);
        if (i == 0) append_candidates(out, p.candidates, p.candidate_count);
    }

    // Data m-line (when the offer had m=application), under the same BUNDLE.
    if (!p.data_mid.empty()) {
        out.append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
        append_line(out, 'c', "IN IP4 0.0.0.0");
        append_attr(out, "mid", p.data_mid);
        append_transport_attrs(out, p.ice_ufrag, p.ice_pwd, fp, p.setup);
        append_attr(out, "sctp-port",
                    [&] { std::string s; append_uint(s, p.sctp_port); return s; }());
        append_attr(out, "max-message-size",
                    [&] { std::string s; append_uint(s, p.max_message_size);
                          return s; }());
    }
    return SdpError::Ok;
}

// ===========================================================================
// WI — Trickle ICE (RFC 8838)
// ===========================================================================
namespace {

// Skip ASCII whitespace from `i` in `s`.
void skip_ws(std::string_view s, std::size_t& i) noexcept {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' ||
                            s[i] == '\n')) {
        ++i;
    }
}

// Extract a JSON string value for `key` from a flat object `body` (no nesting,
// no escapes beyond the bounded keys we use). Returns the value view + found.
// Bounded scan, noexcept, no allocation.
bool json_string_field(std::string_view body, std::string_view key,
                       std::string_view& out) noexcept {
    // Look for "<key>" then ':' then a quoted string.
    char pat[40];
    if (key.size() + 2 >= sizeof(pat)) return false;
    pat[0] = '"';
    std::memcpy(pat + 1, key.data(), key.size());
    pat[key.size() + 1] = '"';
    const std::string_view needle(pat, key.size() + 2);
    const std::size_t k = body.find(needle);
    if (k == std::string_view::npos) return false;
    std::size_t i = k + needle.size();
    skip_ws(body, i);
    if (i >= body.size() || body[i] != ':') return false;
    ++i;
    skip_ws(body, i);
    if (i >= body.size() || body[i] != '"') return false;
    ++i;
    const std::size_t start = i;
    while (i < body.size() && body[i] != '"') ++i;
    if (i >= body.size()) return false;
    out = body.substr(start, i - start);
    return true;
}

// Extract an unsigned integer field (e.g. "sdpMLineIndex": 0). Best-effort.
bool json_uint_field(std::string_view body, std::string_view key,
                     std::uint16_t& out) noexcept {
    char pat[40];
    if (key.size() + 2 >= sizeof(pat)) return false;
    pat[0] = '"';
    std::memcpy(pat + 1, key.data(), key.size());
    pat[key.size() + 1] = '"';
    const std::string_view needle(pat, key.size() + 2);
    const std::size_t k = body.find(needle);
    if (k == std::string_view::npos) return false;
    std::size_t i = k + needle.size();
    skip_ws(body, i);
    if (i >= body.size() || body[i] != ':') return false;
    ++i;
    skip_ws(body, i);
    const std::size_t start = i;
    while (i < body.size() && body[i] >= '0' && body[i] <= '9') ++i;
    if (i == start) return false;
    return parse_uint(body.substr(start, i - start), &out);
}

}  // namespace

SdpError parse_trickle(std::string_view body, TrickleCandidate& out) noexcept {
    out = TrickleCandidate{};
    std::size_t i = 0;
    skip_ws(body, i);
    if (i >= body.size()) return SdpError::Empty;

    // JSON envelope?
    if (body[i] == '{') {
        std::string_view cand;
        const bool has_cand = json_string_field(body, "candidate", cand);
        json_string_field(body, "sdpMid", out.sdp_mid);
        json_uint_field(body, "sdpMLineIndex", out.sdp_mline_index);
        if (!has_cand || cand.empty()) {
            out.end_of_candidates = true;
            return SdpError::Ok;  // {"candidate":""} == end-of-candidates
        }
        out.candidate = cand;
        return SdpError::Ok;
    }

    // Bare line: "end-of-candidates" or "candidate:...".
    std::string_view line = body.substr(i);
    // strip a trailing CRLF
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                            line.back() == ' ')) {
        line.remove_suffix(1);
    }
    if (line == "end-of-candidates" || line == "a=end-of-candidates") {
        out.end_of_candidates = true;
        return SdpError::Ok;
    }
    constexpr std::string_view kA = "a=";
    if (line.substr(0, kA.size()) == kA) line.remove_prefix(kA.size());
    constexpr std::string_view kC = "candidate:";
    if (line.substr(0, kC.size()) != kC) return SdpError::MalformedLine;
    out.candidate = line;
    return SdpError::Ok;
}

SdpError generate_trickle(const TrickleCandidate& c, std::string& out) {
    out.append("{\"candidate\":\"");
    if (!c.end_of_candidates) out.append(c.candidate.data(), c.candidate.size());
    out.append("\",\"sdpMid\":\"");
    out.append(c.sdp_mid.data(), c.sdp_mid.size());
    out.append("\",\"sdpMLineIndex\":");
    char buf[8];
    auto r = std::to_chars(buf, buf + sizeof(buf), c.sdp_mline_index);
    out.append(buf, static_cast<std::size_t>(r.ptr - buf));
    out.push_back('}');
    return SdpError::Ok;
}

}  // namespace webrtc
}  // namespace bolt::api
