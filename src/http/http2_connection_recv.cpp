// http2_connection_recv.cpp — Http2Connection receive path: frame reassembly,
// per-frame validation (RFC 9113 4-6), header block assembly, request field
// validation (8.2-8.3) and receive-side flow control.

#include "boltapi/http/http2_connection.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace bolt::api {
namespace http2 {

using core::err;
using core::error_code;
using core::ok;
using core::result;

namespace {

uint32_t get_u32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

constexpr int64_t kMaxWindow = 0x7FFFFFFF;

// Lowercase tchar (RFC 9110 5.6.2); uppercase is malformed in HTTP/2 (8.2.1).
bool is_lower_tchar(char c) noexcept {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return true;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
    case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default:
        return false;
    }
}

bool valid_name(std::string_view n) noexcept {
    if (n.empty()) return false;
    const size_t start = n[0] == ':' ? 1 : 0;
    if (start == n.size()) return false;
    for (size_t i = start; i < n.size(); ++i) {
        if (!is_lower_tchar(n[i])) return false;
    }
    return true;
}

bool valid_value(std::string_view v) noexcept {
    for (char c : v) {
        if (c == '\0' || c == '\r' || c == '\n') return false;
    }
    return true;
}

bool parse_digits(std::string_view v, uint64_t* out) noexcept {
    if (v.empty() || v.size() > 16) return false;
    uint64_t n = 0;
    for (char c : v) {
        if (c < '0' || c > '9') return false;
        n = n * 10 + static_cast<uint64_t>(c - '0');
    }
    *out = n;
    return true;
}

struct RequestFacts {
    bool has_cl{false};
    uint64_t cl{0};
    bool is_head{false};
};

// RFC 9113 8.2 / 8.3.1. Trailers carry no pseudo-header fields.
bool validate_fields(const std::vector<http::HPACKHeader>& fields, bool trailers,
                     RequestFacts* f) noexcept {
    assert(f != nullptr);
    bool regular_seen = false;
    bool method = false, scheme = false, path = false, authority = false;
    std::string_view method_v;
    size_t list_size = 0;
    for (const auto& h : fields) {
        list_size += h.name.size() + h.value.size() + 32;
        if (!valid_name(h.name) || !valid_value(h.value)) return false;
        if (h.name[0] == ':') {
            if (trailers || regular_seen) return false;
            bool* seen = nullptr;
            if (h.name == ":method") seen = &method, method_v = h.value;
            else if (h.name == ":scheme") seen = &scheme;
            else if (h.name == ":path") seen = &path;
            else if (h.name == ":authority") seen = &authority;
            if (seen == nullptr || *seen) return false;  // unknown/response pseudo, or repeated
            *seen = true;
            if (h.name == ":path" && h.value.empty()) return false;
            continue;
        }
        regular_seen = true;
        if (h.name == "connection" || h.name == "keep-alive" || h.name == "proxy-connection" ||
            h.name == "transfer-encoding" || h.name == "upgrade") {
            return false;
        }
        if (h.name == "te" && h.value != "trailers") return false;
        if (h.name == "content-length") {
            uint64_t n = 0;
            if (!parse_digits(h.value, &n)) return false;
            if (f->has_cl && n != f->cl) return false;
            f->has_cl = true;
            f->cl = n;
        }
    }
    if (list_size > Http2Connection::kMaxHeaderListSize) return false;
    if (trailers) return true;
    if (method_v == "CONNECT") return method && authority && !scheme && !path;
    f->is_head = method_v == "HEAD";
    return method && scheme && path;
}

}  // namespace

bool Http2Connection::is_idle(uint32_t id) const noexcept {
    // Clients open odd streams; we never push, so even ids stay idle.
    return (id % 2) == 0 || id > last_stream_id_;
}

result<size_t> Http2Connection::process_input(const uint8_t* data, size_t len) noexcept {
    assert(data != nullptr || len == 0);
    if (state_ == ConnectionState::CLOSED) return err<size_t>(error_code::invalid_state);
    size_t off = 0;
    if (is_server_ && state_ == ConnectionState::PREFACE_PENDING) {
        const size_t n = std::min(CONNECTION_PREFACE_LEN - preface_bytes_validated_, len);
        if (std::memcmp(CONNECTION_PREFACE + preface_bytes_validated_, data, n) != 0) {
            (void)connection_error(ErrorCode::PROTOCOL_ERROR);
            return err<size_t>(error_code::http_error);
        }
        preface_bytes_validated_ += n;
        off = n;
        if (preface_bytes_validated_ < CONNECTION_PREFACE_LEN) return ok(off);
        state_ = ConnectionState::ACTIVE;
    }
    // Every pass consumes at least one byte.
    for (size_t guard = 0; off < len && guard <= len; ++guard) {
        FrameHeader h;
        const uint8_t* payload = nullptr;
        if (input_buffer_len_ == 0 && len - off >= 9) {  // whole frame in hand: no copy
            h = parse_frame_header(data + off).value();
            if (h.length > kLocalMaxFrameSize) {
                (void)connection_error(ErrorCode::FRAME_SIZE_ERROR);
                return err<size_t>(error_code::http_error);
            }
            if (len - off >= 9 + static_cast<size_t>(h.length)) {
                payload = data + off + 9;
                off += 9 + h.length;
            }
        }
        if (payload == nullptr) {  // reassemble across reads
            if (input_buffer_len_ < 9) {
                const size_t n = std::min(9 - input_buffer_len_, len - off);
                std::memcpy(input_buffer_.data() + input_buffer_len_, data + off, n);
                input_buffer_len_ += n;
                off += n;
                if (input_buffer_len_ < 9) break;
            }
            h = parse_frame_header(input_buffer_.data()).value();
            if (h.length > kLocalMaxFrameSize) {
                (void)connection_error(ErrorCode::FRAME_SIZE_ERROR);
                return err<size_t>(error_code::http_error);
            }
            const size_t need = 9 + static_cast<size_t>(h.length);
            assert(need <= input_buffer_.size());
            const size_t n = std::min(need - input_buffer_len_, len - off);
            std::memcpy(input_buffer_.data() + input_buffer_len_, data + off, n);
            input_buffer_len_ += n;
            off += n;
            if (input_buffer_len_ < need) break;
            input_buffer_len_ = 0;
            payload = input_buffer_.data() + 9;
        }
        if (handle_frame(h, payload).is_err() || state_ == ConnectionState::CLOSED) {
            return err<size_t>(error_code::http_error);
        }
    }
    assert(off == len);
    return ok(len);
}

result<void> Http2Connection::handle_frame(const FrameHeader& h, const uint8_t* payload) noexcept {
    assert(h.length <= kLocalMaxFrameSize);
    if (is_server_ && !first_frame_seen_) {  // 3.4: the preface continues with SETTINGS
        first_frame_seen_ = true;
        if (h.type != FrameType::SETTINGS || (h.flags & FrameFlags::SETTINGS_ACK) != 0) {
            return connection_error(ErrorCode::PROTOCOL_ERROR);
        }
    }
    if (block_.stream_id != 0 && h.type != FrameType::CONTINUATION) {
        return connection_error(ErrorCode::PROTOCOL_ERROR);  // 6.2: nothing interleaves a block
    }
    switch (h.type) {
    case FrameType::DATA: return handle_data_frame(h, payload);
    case FrameType::HEADERS: return handle_headers_frame(h, payload);
    case FrameType::PRIORITY: return handle_priority_frame(h, payload);
    case FrameType::RST_STREAM: return handle_rst_stream_frame(h, payload);
    case FrameType::SETTINGS: return handle_settings_frame(h, payload);
    case FrameType::PUSH_PROMISE: return connection_error(ErrorCode::PROTOCOL_ERROR);  // 8.4
    case FrameType::PING: return handle_ping_frame(h, payload);
    case FrameType::GOAWAY: return handle_goaway_frame(h, payload);
    case FrameType::WINDOW_UPDATE: return handle_window_update_frame(h, payload);
    case FrameType::CONTINUATION: return handle_continuation_frame(h, payload);
    default: return ok();  // 5.5: unknown types are ignored
    }
}

result<void> Http2Connection::handle_settings_frame(const FrameHeader& h,
                                                    const uint8_t* payload) noexcept {
    if (h.stream_id != 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    if (h.flags & FrameFlags::SETTINGS_ACK) {
        if (h.length != 0) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
        settings_ack_pending_ = false;
        return ok();
    }
    if (h.length % 6 != 0) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
    auto r = apply_settings(payload, h.length);
    if (r.is_err()) return r;
    if (output_backlog() > kMaxControlBacklog) {
        return connection_error(ErrorCode::ENHANCE_YOUR_CALM);
    }
    queue_frame(FrameType::SETTINGS, FrameFlags::SETTINGS_ACK, 0, nullptr, 0);
    pump_data();  // a larger initial window may release queued DATA
    return ok();
}

result<void> Http2Connection::apply_settings(const uint8_t* payload, size_t len) noexcept {
    assert(len % 6 == 0);
    assert(payload != nullptr || len == 0);
    for (size_t off = 0; off < len; off += 6) {
        const uint16_t id = static_cast<uint16_t>((payload[off] << 8) | payload[off + 1]);
        const uint32_t v = get_u32(payload + off + 2);
        switch (static_cast<SettingsId>(id)) {
        case SettingsId::HEADER_TABLE_SIZE:
            remote_settings_.header_table_size = v;
            hpack_encoder_.set_max_table_size(v);
            break;
        case SettingsId::ENABLE_PUSH:
            if (v > 1) return connection_error(ErrorCode::PROTOCOL_ERROR);
            remote_settings_.enable_push = v == 1;
            break;
        case SettingsId::MAX_CONCURRENT_STREAMS:
            remote_settings_.max_concurrent_streams = v;
            break;
        case SettingsId::INITIAL_WINDOW_SIZE: {
            if (v > kMaxWindow) return connection_error(ErrorCode::FLOW_CONTROL_ERROR);
            const int64_t delta = static_cast<int64_t>(v) - remote_settings_.initial_window_size;
            for (size_t i = 0; i < open_count_; ++i) {  // 6.9.2: adjust open streams
                Http2Stream* s = stream_manager_.get_stream(open_ids_[i]);
                if (s == nullptr) continue;
                const int64_t w = static_cast<int64_t>(s->send_window_) + delta;
                if (w > kMaxWindow) return connection_error(ErrorCode::FLOW_CONTROL_ERROR);
                s->send_window_ = static_cast<int32_t>(w);
            }
            remote_settings_.initial_window_size = v;
            break;
        }
        case SettingsId::MAX_FRAME_SIZE:
            if (v < 16384 || v > 16777215) return connection_error(ErrorCode::PROTOCOL_ERROR);
            remote_settings_.max_frame_size = v;
            break;
        case SettingsId::MAX_HEADER_LIST_SIZE:
            remote_settings_.max_header_list_size = v;
            break;
        default:
            break;  // 6.5.2: unknown settings are ignored
        }
    }
    return ok();
}

result<void> Http2Connection::handle_ping_frame(const FrameHeader& h, const uint8_t* payload) noexcept {
    if (h.stream_id != 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    if (h.length != 8) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
    if (h.flags & FrameFlags::PING_ACK) return ok();
    if (output_backlog() > kMaxControlBacklog) {
        return connection_error(ErrorCode::ENHANCE_YOUR_CALM);  // ping flood, peer not reading
    }
    queue_frame(FrameType::PING, FrameFlags::PING_ACK, 0, payload, 8);
    return ok();
}

result<void> Http2Connection::handle_goaway_frame(const FrameHeader& h, const uint8_t* payload) noexcept {
    (void)payload;
    if (h.stream_id != 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    if (h.length < 8) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
    if (state_ == ConnectionState::ACTIVE) state_ = ConnectionState::GOAWAY_RECEIVED;
    return ok();
}

result<void> Http2Connection::handle_rst_stream_frame(const FrameHeader& h,
                                                      const uint8_t* payload) noexcept {
    if (h.stream_id == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    if (h.length != 4) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
    if (is_idle(h.stream_id)) return connection_error(ErrorCode::PROTOCOL_ERROR);
    Http2Stream* s = stream_manager_.get_stream(h.stream_id);
    if (s != nullptr) {
        s->set_error_code(static_cast<ErrorCode>(get_u32(payload)));
        s->on_rst_stream();
        close_stream(h.stream_id);
    }
    return ok();
}

result<void> Http2Connection::handle_priority_frame(const FrameHeader& h,
                                                    const uint8_t* payload) noexcept {
    if (h.stream_id == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    if (h.length != 5) return stream_error(h.stream_id, ErrorCode::FRAME_SIZE_ERROR);
    if ((get_u32(payload) & 0x7FFFFFFFu) == h.stream_id) {
        return stream_error(h.stream_id, ErrorCode::PROTOCOL_ERROR);  // 5.3.1
    }
    return ok();  // prioritisation is advisory; we serve in arrival order
}

result<void> Http2Connection::handle_window_update_frame(const FrameHeader& h,
                                                         const uint8_t* payload) noexcept {
    if (h.length != 4) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
    const uint32_t inc = get_u32(payload) & 0x7FFFFFFFu;
    if (h.stream_id == 0) {
        if (inc == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
        if (static_cast<int64_t>(connection_send_window_) + inc > kMaxWindow) {
            return connection_error(ErrorCode::FLOW_CONTROL_ERROR);
        }
        connection_send_window_ += static_cast<int32_t>(inc);
        pump_data();
        return ok();
    }
    if (is_idle(h.stream_id)) return connection_error(ErrorCode::PROTOCOL_ERROR);
    Http2Stream* s = stream_manager_.get_stream(h.stream_id);
    if (s == nullptr) return ok();  // closed: may still be in flight (6.9)
    if (inc == 0) return stream_error(h.stream_id, ErrorCode::PROTOCOL_ERROR);
    if (static_cast<int64_t>(s->send_window_) + inc > kMaxWindow) {
        return stream_error(h.stream_id, ErrorCode::FLOW_CONTROL_ERROR);
    }
    s->send_window_ += static_cast<int32_t>(inc);
    pump_data();
    return ok();
}

result<void> Http2Connection::handle_headers_frame(const FrameHeader& h,
                                                   const uint8_t* payload) noexcept {
    if (h.stream_id == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    size_t off = 0;
    size_t pad = 0;
    HeaderBlockState st;
    st.stream_id = h.stream_id;
    st.end_stream = (h.flags & FrameFlags::HEADERS_END_STREAM) != 0;
    if (h.flags & FrameFlags::HEADERS_PADDED) {
        if (h.length < 1) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
        pad = payload[0];
        off = 1;
    }
    if (h.flags & FrameFlags::HEADERS_PRIORITY) {
        if (h.length < off + 5) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
        st.self_dependent = (get_u32(payload + off) & 0x7FFFFFFFu) == h.stream_id;
        off += 5;
    }
    if (off + pad > h.length) return connection_error(ErrorCode::PROTOCOL_ERROR);  // 6.2
    const uint8_t* frag = payload + off;
    const size_t frag_len = h.length - off - pad;
    if (h.flags & FrameFlags::HEADERS_END_HEADERS) return finish_header_block(st, frag, frag_len);
    header_block_.assign(frag, frag + frag_len);
    block_ = st;
    return ok();
}

result<void> Http2Connection::handle_continuation_frame(const FrameHeader& h,
                                                        const uint8_t* payload) noexcept {
    if (block_.stream_id == 0 || h.stream_id != block_.stream_id) {
        return connection_error(ErrorCode::PROTOCOL_ERROR);  // 6.10
    }
    if (header_block_.size() + h.length > kMaxHeaderBlock) {
        return connection_error(ErrorCode::ENHANCE_YOUR_CALM);
    }
    header_block_.insert(header_block_.end(), payload, payload + h.length);
    if ((h.flags & FrameFlags::CONTINUATION_END_HEADERS) == 0) return ok();
    const HeaderBlockState st = block_;
    block_ = HeaderBlockState{};
    auto r = finish_header_block(st, header_block_.data(), header_block_.size());
    header_block_.clear();
    return r;
}

result<void> Http2Connection::finish_header_block(const HeaderBlockState& st, const uint8_t* block,
                                                  size_t len) noexcept {
    assert(st.stream_id != 0);
    assert(block_.stream_id == 0);
    decoded_.clear();
    // Decode first, always: the HPACK table must see every block (4.3).
    const int rc = hpack_decoder_.decode(block, len, decoded_, kMaxRequestHeaders);
    if (rc == http::HPACKDecoder::kCompressionError) {
        return connection_error(ErrorCode::COMPRESSION_ERROR);
    }
    const uint32_t id = st.stream_id;
    Http2Stream* s = stream_manager_.get_stream(id);
    if (s == nullptr) {
        if (id % 2 == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);  // 5.1.1
        if (id <= last_stream_id_) {
            return connection_error(recently_closed(id) ? ErrorCode::STREAM_CLOSED
                                                        : ErrorCode::PROTOCOL_ERROR);
        }
        last_stream_id_ = id;
        if (state_ != ConnectionState::ACTIVE) return stream_error(id, ErrorCode::REFUSED_STREAM);
        if (st.self_dependent) return stream_error(id, ErrorCode::PROTOCOL_ERROR);
        if (rc == http::HPACKDecoder::kTooManyHeaders) return stream_error(id, ErrorCode::REFUSED_STREAM);
        if (open_count_ >= kMaxConcurrentStreams) return stream_error(id, ErrorCode::REFUSED_STREAM);
        return open_stream(id, st.end_stream);
    }
    // A second block on an open stream is a trailer section (8.1).
    if (st.self_dependent) return stream_error(id, ErrorCode::PROTOCOL_ERROR);
    if (s->state() != StreamState::OPEN && s->state() != StreamState::HALF_CLOSED_LOCAL) {
        return stream_error(id, ErrorCode::STREAM_CLOSED);
    }
    RequestFacts facts;
    if (!st.end_stream || rc != http::HPACKDecoder::kOk || !validate_fields(decoded_, true, &facts)) {
        return stream_error(id, ErrorCode::PROTOCOL_ERROR);
    }
    s->on_headers_received(true);
    return complete_request(s);
}

result<void> Http2Connection::open_stream(uint32_t id, bool end_stream) noexcept {
    RequestFacts facts;
    if (!validate_fields(decoded_, false, &facts)) return stream_error(id, ErrorCode::PROTOCOL_ERROR);
    auto created = stream_manager_.create_stream(id);
    if (created.is_err()) return connection_error(ErrorCode::INTERNAL_ERROR);
    Http2Stream* s = created.value();
    s->send_window_ = static_cast<int32_t>(remote_settings_.initial_window_size);
    s->recv_window_ = kLocalWindow;
    s->io.has_content_length = facts.has_cl;
    s->io.content_length = facts.cl;
    s->io.is_head = facts.is_head;
    for (const auto& f : decoded_) {  // repeats join (8.2.3 cookie, RFC 9110 5.3)
        auto [it, inserted] = s->request_headers_.try_emplace(std::string(f.name), std::string(f.value));
        if (inserted) continue;
        it->second.append(f.name == "cookie" ? "; " : ", ");
        it->second.append(f.value.data(), f.value.size());
    }
    assert(open_count_ < kMaxConcurrentStreams);
    open_ids_[open_count_++] = id;
    s->on_headers_received(end_stream);
    if (!end_stream) return ok();
    return complete_request(s);
}

result<void> Http2Connection::complete_request(Http2Stream* s) noexcept {
    assert(s != nullptr);
    assert(!s->io.request_complete);
    if (s->io.has_content_length && s->io.body_received != s->io.content_length) {
        return stream_error(s->id(), ErrorCode::PROTOCOL_ERROR);  // 8.1.1
    }
    s->io.request_complete = true;
    if (request_callback_) request_callback_(s);
    return ok();
}

result<void> Http2Connection::handle_data_frame(const FrameHeader& h, const uint8_t* payload) noexcept {
    if (h.stream_id == 0) return connection_error(ErrorCode::PROTOCOL_ERROR);
    // The whole payload, padding included, is flow controlled (6.9.1), and it
    // counts against the connection even when the stream is gone.
    if (static_cast<int32_t>(h.length) > connection_recv_window_) {
        return connection_error(ErrorCode::FLOW_CONTROL_ERROR);
    }
    connection_recv_window_ -= static_cast<int32_t>(h.length);
    if (auto r = replenish(nullptr, h.length); r.is_err()) return r;
    size_t off = 0;
    size_t pad = 0;
    if (h.flags & FrameFlags::DATA_PADDED) {
        if (h.length < 1) return connection_error(ErrorCode::FRAME_SIZE_ERROR);
        pad = payload[0];
        off = 1;
        if (pad >= h.length) return connection_error(ErrorCode::PROTOCOL_ERROR);
    }
    if (is_idle(h.stream_id)) return connection_error(ErrorCode::PROTOCOL_ERROR);
    Http2Stream* s = stream_manager_.get_stream(h.stream_id);
    if (s == nullptr || (s->state() != StreamState::OPEN &&
                         s->state() != StreamState::HALF_CLOSED_LOCAL)) {
        return stream_error(h.stream_id, ErrorCode::STREAM_CLOSED);
    }
    if (static_cast<int32_t>(h.length) > s->recv_window_) {
        return stream_error(h.stream_id, ErrorCode::FLOW_CONTROL_ERROR);
    }
    s->recv_window_ -= static_cast<int32_t>(h.length);
    const size_t n = h.length - off - pad;
    s->io.body_received += n;
    if (s->io.has_content_length && s->io.body_received > s->io.content_length) {
        return stream_error(h.stream_id, ErrorCode::PROTOCOL_ERROR);
    }
    if (s->io.body_received > max_request_body_) {
        return stream_error(h.stream_id, ErrorCode::ENHANCE_YOUR_CALM);
    }
    if (n > 0) s->append_request_body(payload + off, n);
    const bool end = (h.flags & FrameFlags::DATA_END_STREAM) != 0;
    s->on_data_received(end);
    if (end) return complete_request(s);
    return replenish(s, h.length);
}

result<void> Http2Connection::replenish(Http2Stream* stream, uint32_t consumed) noexcept {
    (void)consumed;
    uint8_t inc[4];
    if (connection_recv_window_ <= kLocalWindow / 2) {
        const uint32_t add = static_cast<uint32_t>(kLocalWindow - connection_recv_window_);
        inc[0] = static_cast<uint8_t>(add >> 24);
        inc[1] = static_cast<uint8_t>(add >> 16);
        inc[2] = static_cast<uint8_t>(add >> 8);
        inc[3] = static_cast<uint8_t>(add);
        queue_frame(FrameType::WINDOW_UPDATE, 0, 0, inc, 4);
        connection_recv_window_ = kLocalWindow;
    }
    if (stream != nullptr && stream->recv_window_ <= kLocalWindow / 2) {
        const uint32_t add = static_cast<uint32_t>(kLocalWindow - stream->recv_window_);
        inc[0] = static_cast<uint8_t>(add >> 24);
        inc[1] = static_cast<uint8_t>(add >> 16);
        inc[2] = static_cast<uint8_t>(add >> 8);
        inc[3] = static_cast<uint8_t>(add);
        queue_frame(FrameType::WINDOW_UPDATE, 0, stream->id(), inc, 4);
        stream->recv_window_ = kLocalWindow;
    }
    assert(connection_recv_window_ > kLocalWindow / 2);
    assert(stream == nullptr || stream->recv_window_ > kLocalWindow / 2);
    return ok();
}

} // namespace http2
} // namespace bolt::api
