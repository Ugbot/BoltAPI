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
                    if (out.media_count >= kSdpMaxMediaSections)
                        return SdpError::Overflow;
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
                            if (!tok.empty()) {
                                if (m.format_count >= kSdpMaxFormatsPerMedia)
                                    return SdpError::Overflow;
                                m.formats[m.format_count++] = tok;
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
                    if (current) {
                        if (current->attr_count >= kSdpMaxAttrsPerSection)
                            return SdpError::Overflow;
                        current->attrs[current->attr_count++] = a;
                    } else {
                        if (out.session_attr_count >= kSdpMaxAttrsPerSection)
                            return SdpError::Overflow;
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
        }
        // Keep the section even if empty so the answer can mark it inactive; but
        // only count sections that had at least one common codec.
        if (nm.codec_count > 0) ++out.media_count;
    }
    return SdpError::Ok;
}

// Emit one m= media section into `out` for a negotiated audio/video line.
static void append_media_section(std::string& out, const NegotiatedMedia& nm) {
    assert(nm.codec_count > 0 && "append_media_section: empty");
    assert(nm.codec_count <= kMaxCodecsPerSection && "append_media_section: overflow");

    // m=<kind> 9 UDP/TLS/RTP/SAVPF <pt>...
    out.append("m=", 2);
    out.append(nm.kind == MediaKind::kAudio ? "audio" : "video");
    out.append(" 9 UDP/TLS/RTP/SAVPF", 20);
    for (std::size_t i = 0; i < nm.codec_count; ++i) {
        out.push_back(' ');
        append_uint(out, nm.codecs[i].pt);
    }
    out.append("\r\n", 2);
    append_line(out, 'c', "IN IP4 0.0.0.0");
    append_attr(out, "rtcp-mux", std::string_view{});
    if (!nm.mid.empty()) append_attr(out, "mid", nm.mid);
    append_attr(out, nm.direction, std::string_view{});

    for (std::size_t i = 0; i < nm.codec_count; ++i) {
        const NegotiatedCodec& c = nm.codecs[i];
        {  // a=rtpmap:<pt> <encoding>
            std::string v;
            append_uint(v, c.pt);
            v.push_back(' ');
            v.append(c.rtpmap.data(), c.rtpmap.size());
            append_attr(out, "rtpmap", v);
        }
        if (!c.fmtp.empty()) {  // a=fmtp:<pt> <params>
            std::string v;
            append_uint(v, c.pt);
            v.push_back(' ');
            v.append(c.fmtp.data(), c.fmtp.size());
            append_attr(out, "fmtp", v);
        }
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

}  // namespace webrtc
}  // namespace bolt::api
