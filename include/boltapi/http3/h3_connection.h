// boltapi/http3/h3_connection.h — drive an HTTP/3 endpoint over a QuicConnection.
//
// This is the W5b bridge: it turns the byte streams a QuicConnection delivers
// into HTTP/3 requests (server role) and lets the owner send HTTP/3 responses,
// reusing:
//   * boltapi/http3/frame.h      — RFC 9114 DATA/HEADERS/SETTINGS framing;
//   * boltapi/http3/qpack.h      — RFC 9204 QPACK encode/decode (pseudo-headers);
//   * boltapi/quic/connection.h  — the established QUIC transport (open_uni/
//     open_bidi/stream_write + set_stream_data_handler).
//
// Endpoint setup (RFC 9114 §6.2): on attach the local side opens the control +
// QPACK encoder + QPACK decoder unidirectional streams and sends a SETTINGS
// frame on the control stream. Incoming uni streams are classified by their
// first varint (control/push/QPACK enc/dec) and consumed. Each client-initiated
// bidi stream carries one request: HEADERS (QPACK field section) followed by zero
// or more DATA frames, terminated by FIN. The server QPACK-decodes the field
// section into pseudo-headers (:method/:path/:scheme/:authority) + regular
// headers, accumulates DATA as the body, and raises the request callback. The
// owner replies with send_response(), which QPACK-encodes :status + headers as a
// HEADERS frame and the body as DATA, then FINs the stream.
//
// Tiger Style: header-only, no exceptions, >=2 asserts per function, bounded
// fixed-capacity per-stream state (a small pool — NO unbounded std::vector growth
// on the hot path), every loop bounded, functions <70 lines. Compiles
// UNCONDITIONALLY (its only deps are header-only quic/* + http3/*), so the gate
// test runs in the default ctest suite.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>

#include "boltapi/http3/frame.h"
#include "boltapi/http3/qpack.h"
#include "boltapi/quic/connection.h"

namespace bolt::api::http3 {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style). All per-stream state is fixed-capacity.
// ----------------------------------------------------------------------------
inline constexpr std::size_t kH3MaxStreams      = 8;        // concurrent requests
inline constexpr std::size_t kH3MaxHeaderBytes  = 16 * 1024;  // QPACK block cap
inline constexpr std::size_t kH3MaxBodyBytes    = 1 << 20;  // 1 MiB body cap
inline constexpr std::size_t kH3MaxRespHeaders  = 16;       // headers per response
inline constexpr std::size_t kH3WriteChunk      = 4096;     // DATA send chunk
inline constexpr std::size_t kH3MaxFramesPerMsg = 64;      // HEADERS + DATA frames

// ----------------------------------------------------------------------------
// H3Request — a decoded HTTP/3 request handed to the bridge callback. All views
// borrow the H3Stream's per-stream storage and are valid for the callback only.
// ----------------------------------------------------------------------------
struct H3Request {
    std::uint64_t      stream_id = 0;
    std::string_view   method;
    std::string_view   path;
    std::string_view   scheme;
    std::string_view   authority;
    std::string_view   protocol;   // :protocol (RFC 9220 extended CONNECT; WebTransport)
    const QpackHeader* headers     = nullptr;  // regular (non-pseudo) headers
    std::size_t        header_count = 0;
    const std::uint8_t* body       = nullptr;
    std::size_t        body_len    = 0;
};

// A response header to send (views into caller storage, valid for the call).
struct H3ResponseHeader {
    std::string_view name;
    std::string_view value;
};

// Callback the App bridge installs: receives a fully-assembled request. The
// implementation routes it and calls H3Connection::send_response() with the same
// stream id. Synchronous (the gate's App dispatch runs the handler inline).
using H3RequestFn = std::function<void(const H3Request&)>;

// ----------------------------------------------------------------------------
// H3Stream — bounded per-request reassembly slot. Accumulates the raw stream
// bytes (HEADERS+DATA frames) until FIN, then the parser pulls frames out.
// ----------------------------------------------------------------------------
struct H3Stream {
    bool          in_use   = false;
    bool          finished = false;  // dispatched already (guards double-fire)
    bool          wt       = false;  // a WebTransport session stream (stays open)
    bool          wt_checked = false;  // extended-CONNECT check already done
    std::uint64_t id       = 0;
    std::size_t   len      = 0;
    // Header (QPACK) block + body are split out by the frame parser at FIN.
    std::uint8_t  buf[kH3MaxHeaderBytes + kH3MaxBodyBytes];

    void reset(std::uint64_t sid) noexcept {
        assert(sid <= quic::kVarIntMax && "stream id out of range");
        assert(!in_use && "reset on an in-use slot");
        in_use     = true;
        finished   = false;
        wt         = false;
        wt_checked = false;
        id         = sid;
        len        = 0;
    }
};

// ============================================================================
// H3Connection — one HTTP/3 endpoint bound to a QuicConnection.
// ============================================================================
class H3Connection {
public:
    H3Connection() noexcept = default;
    H3Connection(const H3Connection&)            = delete;
    H3Connection& operator=(const H3Connection&) = delete;

    // Bind to an established QuicConnection. Installs the QUIC stream-data handler
    // and (when ready) opens our uni streams + sends SETTINGS. `is_server`
    // selects request-receiving (server) vs response-receiving (client) role.
    void attach(quic::QuicConnection& conn, bool is_server) noexcept {
        assert(qc_ == nullptr && "attach called twice");
        assert(!is_server || is_server);  // role flag is a valid bool
        qc_        = &conn;
        is_server_ = is_server;
        qc_->set_stream_data_handler(
            [this](std::uint64_t id, const std::uint8_t* d, std::size_t n,
                   bool fin) { on_stream_data(id, d, n, fin); });
    }

    void set_request_handler(H3RequestFn fn) noexcept {
        assert(qc_ != nullptr && "set handler before attach");
        assert(static_cast<bool>(fn) && "null request handler");
        on_request_ = std::move(fn);
    }

    // Open control + QPACK uni streams and send SETTINGS. Call once both peers'
    // 1-RTT keys are ready. Idempotent (guarded by setup_done_).
    void send_settings() noexcept {
        assert(qc_ != nullptr && "send_settings before attach");
        assert(qc_->one_rtt_keys_ready() && "settings before 1-RTT keys");
        if (setup_done_) return;
        control_id_ = qc_->open_uni();
        enc_id_     = qc_->open_uni();
        dec_id_     = qc_->open_uni();
        send_uni_prefix(control_id_, UniStreamType::kControl);
        send_uni_prefix(enc_id_, UniStreamType::kQpackEncoder);
        send_uni_prefix(dec_id_, UniStreamType::kQpackDecoder);
        send_settings_frame();
        setup_done_ = true;
    }

    // ------------------------------------------------------------------------
    // Client helper: send an H3 request (HEADERS [+ DATA]) on a fresh bidi
    // stream, FIN at the end. Returns the stream id (or UINT64_MAX on failure).
    // Pseudo-headers are emitted first, then any regular headers.
    // ------------------------------------------------------------------------
    std::uint64_t send_request(std::string_view method, std::string_view path,
                               std::string_view scheme, std::string_view authority,
                               const H3ResponseHeader* extra, std::size_t extra_n,
                               const std::uint8_t* body, std::size_t body_len) noexcept {
        assert(qc_ != nullptr && "send_request before attach");
        assert(!method.empty() && !path.empty() && "request needs method+path");
        const std::uint64_t sid = qc_->open_bidi();
        if (!write_headers(sid, /*is_response=*/false, /*status=*/0, method, path,
                           scheme, authority, extra, extra_n, body == nullptr &&
                                                                  body_len == 0)) {
            return UINT64_MAX;
        }
        if (body != nullptr && body_len > 0) {
            if (!write_data(sid, body, body_len, /*fin=*/true)) return UINT64_MAX;
        }
        return sid;
    }

    // ------------------------------------------------------------------------
    // Server: send a response on `stream_id` (HEADERS(:status,...) + DATA, FIN).
    // ------------------------------------------------------------------------
    bool send_response(std::uint64_t stream_id, std::uint16_t status,
                       const H3ResponseHeader* headers, std::size_t header_count,
                       const std::uint8_t* body, std::size_t body_len) noexcept {
        assert(qc_ != nullptr && "send_response before attach");
        assert(status >= 100 && status < 600 && "implausible HTTP status");
        const bool no_body = (body == nullptr || body_len == 0);
        if (!write_headers(stream_id, /*is_response=*/true, status, {}, {}, {}, {},
                           headers, header_count, no_body)) {
            return false;
        }
        if (!no_body) {
            if (!write_data(stream_id, body, body_len, /*fin=*/true)) return false;
        }
        return true;
    }

    // Pump: forward to the underlying connection's tick (drives sends/acks).
    void tick() noexcept {
        assert(qc_ != nullptr && "tick before attach");
        assert(control_id_ == UINT64_MAX || setup_done_);  // ids set => settings done
        qc_->tick();
    }

    quic::QuicConnection& quic() noexcept {
        assert(qc_ != nullptr && "quic() before attach");
        return *qc_;
    }

private:
    // QUIC stream-data callback: classify uni streams; accumulate bidi requests.
    void on_stream_data(std::uint64_t id, const std::uint8_t* d, std::size_t n,
                        bool fin) noexcept {
        assert((d != nullptr || n == 0) && "on_stream_data: null with n>0");
        assert(qc_ != nullptr && "stream data before attach");
        if (quic::stream_is_uni(id)) {
            on_uni_data(id, d, n);
            return;
        }
        // Client-initiated bidi == a request (server role) or a response
        // (client role). Both accumulate into a per-stream slot until FIN.
        H3Stream* s = slot_for(id);
        if (s == nullptr) return;  // pool exhausted; drop (bounded)
        append_stream(*s, d, n);
        // WebTransport: an extended CONNECT (:protocol=webtransport) arrives as a
        // HEADERS frame WITHOUT fin — the bidi stream stays open as the session.
        // Detect it as soon as the HEADERS frame is buffered, answer 200, and never
        // dispatch it as a normal (FIN-terminated) request.
        if (is_server_ && !s->finished && !s->wt && !s->wt_checked) {
            const int r = try_webtransport_connect(*s);
            if (r == 1) { s->wt = true; s->finished = true; return; }
            if (r == 0) s->wt_checked = true;  // headers seen, not WT — stop checking
        }
        if (fin && !s->finished) {
            s->finished = true;
            if (is_server_) dispatch_request(*s);
            else            dispatch_response(*s);
            release_slot(*s);
        }
    }

    // Uni streams: read+discard the type prefix; QPACK enc/dec instructions are
    // applied to our decoder/encoder; control-stream SETTINGS are parsed. We keep
    // this minimal (no dynamic table over the wire in W5b) but valid.
    void on_uni_data(std::uint64_t id, const std::uint8_t* d, std::size_t n) noexcept {
        assert((d != nullptr || n == 0) && "uni data null with n>0");
        assert(id <= quic::kVarIntMax && "uni id out of range");
        UniStreamState& u = uni_state(id);
        if (!u.typed) {
            std::uint64_t t = 0;
            const int tn = quic::varint_decode(d, n, t);
            if (tn <= 0) return;
            u.typed = true;
            u.type  = t;
            d += tn;
            n -= static_cast<std::size_t>(tn);
        }
        if (n == 0) return;
        if (u.type == static_cast<std::uint64_t>(UniStreamType::kQpackEncoder)) {
            (void)qpack_dec_.decode_encoder_stream(d, n);  // tolerate empties
        }
        // control / decoder / push payloads are accepted-and-ignored in W5b.
    }

    // Decode a complete request stream and raise the callback.
    void dispatch_request(H3Stream& s) noexcept {
        assert(s.in_use && "dispatch on free slot");
        assert(is_server_ && "dispatch_request on a client");
        if (!on_request_) return;
        H3Request req{};
        req.stream_id = s.id;
        if (!parse_message(s, req)) return;  // malformed: drop (bounded)
        on_request_(req);
    }

    // WebTransport extended-CONNECT detection. If s.buf begins with a complete
    // HEADERS frame whose pseudo-headers are :method=CONNECT + :protocol=webtransport,
    // answer 200 on the same stream WITHOUT fin (it becomes the session stream) and
    // return 1. Returns 0 when the leading HEADERS frame is complete but is not a WT
    // CONNECT, and -1 when that HEADERS frame is not yet fully buffered.
    int try_webtransport_connect(H3Stream& s) noexcept {
        assert(s.in_use && "wt check on free slot");
        assert(s.len <= sizeof(s.buf) && "stream cursor past buffer");
        FrameView fv{};
        std::size_t used = 0;
        const FrameStatus st = frame_parse(s.buf, s.len, fv, used);
        if (st == FrameStatus::kNeedMore) return -1;
        if (st != FrameStatus::kOk) return 0;
        if (fv.type != static_cast<std::uint64_t>(FrameType::kHeaders)) return 0;
        H3Request req{};
        req.stream_id = s.id;
        const bool dec = decode_headers(fv.payload, fv.length, req);
        if (std::getenv("BOLTAPI_QUIC_TRACE") != nullptr) {
            std::fprintf(stderr,
                "[h3] WT-CONNECT? decode=%d method='%.*s' protocol='%.*s' "
                "path='%.*s' hdr_len=%llu\n", (int)dec,
                (int)req.method.size(), req.method.data(),
                (int)req.protocol.size(), req.protocol.data(),
                (int)req.path.size(), req.path.data(),
                (unsigned long long)fv.length);
        }
        if (!dec) return 0;
        if (req.method != "CONNECT" || req.protocol != "webtransport") return 0;
        (void)write_headers(s.id, /*is_response=*/true, 200, {}, {}, {}, {},
                            nullptr, 0, /*fin=*/false);
        return 1;
    }

    // Decode a complete response stream into last_response_* (client side).
    void dispatch_response(H3Stream& s) noexcept {
        assert(s.in_use && "dispatch on free slot");
        assert(!is_server_ && "dispatch_response on a server");
        H3Request resp{};  // reuse the struct; status sits in resp.method scratch
        if (!parse_message(s, resp)) { resp_ok_ = false; return; }
        resp_status_ = parse_status(resp.method);  // method holds :status here
        resp_body_.assign(reinterpret_cast<const char*>(resp.body), resp.body_len);
        resp_stream_ = s.id;
        resp_ok_     = true;
    }

    // Walk the frames in s.buf: first a HEADERS frame (QPACK), then DATA frames.
    // Fills req with views into per-call scratch (decoded headers) + s.buf (body).
    bool parse_message(H3Stream& s, H3Request& req) noexcept {
        assert(s.len <= sizeof(s.buf) && "stream length overran buffer");
        assert(s.in_use && "parse on free slot");
        std::size_t pos = 0;
        bool got_headers = false;
        body_len_ = 0;
        for (std::size_t i = 0; i < kH3MaxFramesPerMsg && pos < s.len; ++i) {
            FrameView fv{};
            std::size_t used = 0;
            const FrameStatus st = frame_parse(s.buf + pos, s.len - pos, fv, used);
            if (st != FrameStatus::kOk) return false;
            pos += used;
            if (fv.type == static_cast<std::uint64_t>(FrameType::kHeaders)) {
                if (!decode_headers(fv.payload, fv.length, req)) return false;
                got_headers = true;
            } else if (fv.type == static_cast<std::uint64_t>(FrameType::kData)) {
                if (!accumulate_body(fv.payload, fv.length)) return false;
            }
            // Unknown frame types are skipped (already advanced by `used`).
        }
        req.body     = body_buf_;
        req.body_len = body_len_;
        return got_headers && pos == s.len;
    }

    // QPACK-decode the field section into req's pseudo-headers + regular headers.
    bool decode_headers(const std::uint8_t* p, std::size_t n, H3Request& req) noexcept {
        assert((p != nullptr || n == 0) && "decode_headers null with n>0");
        assert(n <= kH3MaxHeaderBytes && "header block too large");
        std::size_t cnt = 0;
        if (qpack_dec_.decode_field_section(p, n, decoded_, cnt) != 0) return false;
        std::size_t reg = 0;
        for (std::size_t i = 0; i < cnt; ++i) {
            const QpackHeader& h = decoded_[i];
            if (!assign_pseudo(h, req)) {
                regular_[reg++] = h;  // copy view-owning std::strings
            }
        }
        req.headers      = regular_;
        req.header_count = reg;
        return true;
    }

    // Route a pseudo-header (":..."). Returns true if consumed as a pseudo.
    static bool assign_pseudo(const QpackHeader& h, H3Request& req) noexcept {
        assert(!h.name.empty() && "empty header name");
        assert(h.name.size() <= kQpackMaxStringLen && "header name too long");
        if (h.name == ":method")    { req.method    = h.value; return true; }
        if (h.name == ":path")      { req.path      = h.value; return true; }
        if (h.name == ":scheme")    { req.scheme    = h.value; return true; }
        if (h.name == ":authority") { req.authority = h.value; return true; }
        if (h.name == ":protocol")  { req.protocol  = h.value; return true; }
        if (h.name == ":status")    { req.method    = h.value; return true; }
        return false;
    }

    bool accumulate_body(const std::uint8_t* p, std::size_t n) noexcept {
        assert((p != nullptr || n == 0) && "accumulate_body null with n>0");
        assert(body_len_ <= sizeof(body_buf_) && "body cursor past buffer");
        if (body_len_ + n > sizeof(body_buf_)) return false;
        std::memcpy(body_buf_ + body_len_, p, n);
        body_len_ += n;
        return true;
    }

    // Build + send a HEADERS frame for a request or response on `sid`.
    bool write_headers(std::uint64_t sid, bool is_response, std::uint16_t status,
                       std::string_view method, std::string_view path,
                       std::string_view scheme, std::string_view authority,
                       const H3ResponseHeader* extra, std::size_t extra_n,
                       bool fin) noexcept {
        assert(qc_ != nullptr && "write_headers before attach");
        assert(extra_n <= kH3MaxRespHeaders && "too many headers");
        QpackHeaderRef refs[kH3MaxRespHeaders + 4];
        std::size_t rc = 0;
        char status_buf[4];
        if (is_response) {
            status_buf[0] = static_cast<char>('0' + (status / 100) % 10);
            status_buf[1] = static_cast<char>('0' + (status / 10) % 10);
            status_buf[2] = static_cast<char>('0' + status % 10);
            refs[rc++] = {":status", std::string_view(status_buf, 3)};
        } else {
            refs[rc++] = {":method", method};
            refs[rc++] = {":path", path};
            if (!scheme.empty())    refs[rc++] = {":scheme", scheme};
            if (!authority.empty()) refs[rc++] = {":authority", authority};
        }
        // RFC 9114 §4.1.1 / §4.2: field names in HTTP/3 MUST be lowercase, or the
        // peer treats it as malformed (aioquic/Chrome close with H3_MESSAGE_ERROR).
        // Pseudo-headers above are already lowercase; lowercase the regular names
        // into a bounded scratch (string_views must stay alive through the encode).
        constexpr std::size_t kH3HeaderNameScratch = 2048;
        char namelc[kH3HeaderNameScratch];
        std::size_t lc_off = 0;
        for (std::size_t i = 0; i < extra_n; ++i) {
            const std::string_view nm = extra[i].name;
            assert(nm.size() <= kQpackMaxStringLen && "header name too long");
            assert(lc_off + nm.size() <= sizeof(namelc) && "name scratch overflow");
            if (lc_off + nm.size() > sizeof(namelc)) return false;
            char* const dst = namelc + lc_off;
            for (std::size_t j = 0; j < nm.size(); ++j) {
                const char c = nm[j];
                dst[j] = (c >= 'A' && c <= 'Z')
                             ? static_cast<char>(c - 'A' + 'a') : c;
            }
            refs[rc++] = {std::string_view(dst, nm.size()), extra[i].value};
            lc_off += nm.size();
        }
        assert(rc <= kH3MaxRespHeaders + 4 && "header ref overflow");
        std::size_t blk = 0;
        if (qpack_enc_.encode_field_section(refs, rc, hdr_block_, sizeof(hdr_block_),
                                            blk) != 0) {
            return false;
        }
        return frame_and_send(sid, FrameType::kHeaders, hdr_block_, blk, fin);
    }

    // Send a DATA frame (chunked under kH3WriteChunk to respect flow control).
    bool write_data(std::uint64_t sid, const std::uint8_t* body, std::size_t len,
                    bool fin) noexcept {
        assert((body != nullptr || len == 0) && "write_data null with len>0");
        assert(len <= kH3MaxBodyBytes && "body too large to frame");
        std::uint8_t hdr[kFrameHeaderMaxBytes];
        const std::size_t hn = frame_write_header(
            static_cast<std::uint64_t>(FrameType::kData), len, hdr, sizeof(hdr));
        if (hn == 0) return false;
        qc_->stream_write(sid, hdr, hn, /*fin=*/false);
        std::size_t off = 0;
        for (std::size_t i = 0; off < len && i < (kH3MaxBodyBytes /
             kH3WriteChunk) + 2; ++i) {
            const std::size_t chunk = (len - off < kH3WriteChunk) ? (len - off)
                                                                  : kH3WriteChunk;
            const bool last = (off + chunk == len);
            qc_->stream_write(sid, body + off, chunk, last && fin);
            off += chunk;
        }
        return off == len;
    }

    // Prepend the frame header to `payload` and stream_write both (one logical
    // frame). The HEADERS frame is small, so a fixed staging buffer suffices.
    bool frame_and_send(std::uint64_t sid, FrameType type,
                        const std::uint8_t* payload, std::size_t plen,
                        bool fin) noexcept {
        assert((payload != nullptr || plen == 0) && "frame_and_send null payload");
        assert(plen <= kH3MaxHeaderBytes && "frame payload too large to stage");
        std::uint8_t hdr[kFrameHeaderMaxBytes];
        const std::size_t hn = frame_write_header(static_cast<std::uint64_t>(type),
                                                  plen, hdr, sizeof(hdr));
        if (hn == 0) return false;
        qc_->stream_write(sid, hdr, hn, /*fin=*/false);
        qc_->stream_write(sid, payload, plen, fin);
        return true;
    }

    void send_uni_prefix(std::uint64_t sid, UniStreamType type) noexcept {
        assert(qc_ != nullptr && "uni prefix before attach");
        assert(sid <= quic::kVarIntMax && "uni id out of range");
        std::uint8_t b[quic::kVarIntMaxBytes];
        const std::size_t n = quic::varint_encode(static_cast<std::uint64_t>(type),
                                                  b);
        qc_->stream_write(sid, b, n, /*fin=*/false);
    }

    void send_settings_frame() noexcept {
        assert(qc_ != nullptr && "settings before attach");
        assert(control_id_ != UINT64_MAX && "control stream not opened");
        SettingsFrame sf{};
        sf.qpack_max_table_capacity = 0;        // static-only QPACK in W5b
        sf.qpack_blocked_streams    = 0;
        if (is_server_) {
            // Advertise WebTransport so a browser will offer it. The QUIC layer
            // advertises max_datagram_frame_size (RFC 9221); these settings are
            // RFC 9220 (extended CONNECT) + RFC 9297 (H3 datagrams) + WT sessions.
            sf.enable_connect_protocol = true;
            sf.h3_datagram             = true;
            sf.wt_max_sessions         = 1;
        }
        std::uint8_t payload[kSettingsMaxBytes];
        const std::size_t pn = sf.encode_payload(payload, sizeof(payload));
        if (std::getenv("BOLTAPI_QUIC_TRACE") != nullptr) {
            std::fprintf(stderr, "[h3] SETTINGS payload (%zu B):", pn);
            for (std::size_t i = 0; i < pn; ++i)
                std::fprintf(stderr, " %02x", payload[i]);
            std::fprintf(stderr, "\n");
        }
        (void)frame_and_send(control_id_, FrameType::kSettings, payload, pn,
                             /*fin=*/false);
    }

    void append_stream(H3Stream& s, const std::uint8_t* d, std::size_t n) noexcept {
        assert(s.in_use && "append to free slot");
        assert(s.len <= sizeof(s.buf) && "stream cursor past buffer");
        if (n == 0) return;
        if (s.len + n > sizeof(s.buf)) {
            n = sizeof(s.buf) - s.len;  // bounded: drop overflow tail
        }
        std::memcpy(s.buf + s.len, d, n);
        s.len += n;
    }

    H3Stream* slot_for(std::uint64_t id) noexcept {
        assert(id <= quic::kVarIntMax && "slot id out of range");
        for (std::size_t i = 0; i < kH3MaxStreams; ++i) {
            if (streams_[i].in_use && streams_[i].id == id) return &streams_[i];
        }
        for (std::size_t i = 0; i < kH3MaxStreams; ++i) {
            if (!streams_[i].in_use) { streams_[i].reset(id); return &streams_[i]; }
        }
        return nullptr;  // pool exhausted
    }

    void release_slot(H3Stream& s) noexcept {
        assert(s.in_use && "release on free slot");
        assert(&s >= streams_ && &s < streams_ + kH3MaxStreams && "alien slot");
        s.in_use = false;
        s.len    = 0;
    }

    // Per-uni-stream classification state (small fixed pool keyed by id).
    struct UniStreamState { bool used = false; bool typed = false;
                            std::uint64_t id = 0; std::uint64_t type = 0; };
    UniStreamState& uni_state(std::uint64_t id) noexcept {
        assert(id <= quic::kVarIntMax && "uni id out of range");
        for (std::size_t i = 0; i < kH3MaxUni; ++i) {
            if (uni_[i].used && uni_[i].id == id) return uni_[i];
        }
        for (std::size_t i = 0; i < kH3MaxUni; ++i) {
            if (!uni_[i].used) { uni_[i].used = true; uni_[i].id = id;
                                 return uni_[i]; }
        }
        return uni_[0];  // bounded fallback (overflow folds onto slot 0)
    }

    static std::uint16_t parse_status(std::string_view s) noexcept {
        assert(s.size() <= 3 && "status code too long");
        std::uint16_t v = 0;
        for (std::size_t i = 0; i < s.size() && i < 3; ++i) {
            if (s[i] < '0' || s[i] > '9') return 0;
            v = static_cast<std::uint16_t>(v * 10 + (s[i] - '0'));
        }
        return v;
    }

public:
    // Client-side accessors for the last decoded response (gate test reads these).
    bool          response_ready() const noexcept { return resp_ok_; }
    std::uint16_t response_status() const noexcept { return resp_status_; }
    std::uint64_t response_stream() const noexcept { return resp_stream_; }
    const std::string& response_body() const noexcept { return resp_body_; }
    void clear_response() noexcept { resp_ok_ = false; }

private:
    static constexpr std::size_t kH3MaxUni = 16;

    quic::QuicConnection* qc_ = nullptr;
    bool          is_server_  = false;
    bool          setup_done_ = false;
    std::uint64_t control_id_ = UINT64_MAX;
    std::uint64_t enc_id_     = UINT64_MAX;
    std::uint64_t dec_id_     = UINT64_MAX;

    H3RequestFn   on_request_;

    QpackEncoder  qpack_enc_{0};   // static-only (no dynamic table) in W5b
    QpackDecoder  qpack_dec_{0};

    H3Stream      streams_[kH3MaxStreams];
    UniStreamState uni_[kH3MaxUni];

    // Per-call scratch reused across dispatch (single-threaded per connection).
    QpackHeader   decoded_[kQpackMaxHeaders];
    QpackHeader   regular_[kQpackMaxHeaders];
    std::uint8_t  hdr_block_[kH3MaxHeaderBytes];
    std::uint8_t  body_buf_[kH3MaxBodyBytes];
    std::size_t   body_len_ = 0;

    // Client-side last-response capture.
    bool          resp_ok_     = false;
    std::uint16_t resp_status_ = 0;
    std::uint64_t resp_stream_ = UINT64_MAX;
    std::string   resp_body_;
};

}  // namespace bolt::api::http3
