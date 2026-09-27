#include "boltapi/http/http2_connection.h"
#include "boltapi/core/logger.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <new>
#include <type_traits>
#include <algorithm>
#include <iostream>
#include <cstdio>

namespace bolt::api {
namespace http2 {

namespace {

// glibc carves static TLS out of every thread's stack; 640 KiB of pools in
// static TLS was stack every gestaltd thread gave up. Pools are over-aligned
// (64), so this can't use bolt::tls_scratch.
template <class Pool>
struct TlsPoolHolder {
    static_assert(std::is_trivially_destructible_v<Pool>,
                  "pool is freed without running its destructor");
    Pool* p = nullptr;
    ~TlsPoolHolder() {
        if (p != nullptr) ::operator delete(p, std::align_val_t{alignof(Pool)});
    }
};

template <class Pool>
Pool* tls_pool(TlsPoolHolder<Pool>* h) noexcept {
    assert(h != nullptr);
    if (h->p != nullptr) return h->p;
    void* mem = ::operator new(sizeof(Pool), std::align_val_t{alignof(Pool)},
                               std::nothrow);
    if (mem == nullptr) return nullptr;
    h->p = ::new (mem) Pool;
    assert(!h->p->initialized);
    assert(reinterpret_cast<std::uintptr_t>(h->p) % alignof(Pool) == 0u);
    return h->p;
}

}  // namespace

H2FramePool* h2_frame_pool() noexcept {
    thread_local TlsPoolHolder<H2FramePool> h;
    return tls_pool(&h);
}

H2HeaderPool* h2_header_pool() noexcept {
    thread_local TlsPoolHolder<H2HeaderPool> h;
    return tls_pool(&h);
}

// ============================================================================
// CachedHpackHeaders Implementation
// ============================================================================

bool CachedHpackHeaders::initialized_ = false;

// Helper to build literal header with indexed name
// Format: 0x40 | index (6-bit) for incremental indexing, OR
//         0x00 | index (4-bit) for without indexing
// Using never indexed (0x10) for headers that shouldn't be indexed
static size_t build_literal_indexed_name(uint8_t index_prefix, uint8_t name_index,
                                         const char* value, size_t value_len,
                                         uint8_t* out, size_t capacity) {
    if (capacity < 2 + value_len) return 0;
    
    size_t pos = 0;
    
    // Header byte with indexed name
    out[pos++] = index_prefix | name_index;
    
    // Value length (no Huffman for simplicity, values are short)
    out[pos++] = static_cast<uint8_t>(value_len);
    
    // Value
    std::memcpy(out + pos, value, value_len);
    pos += value_len;
    
    return pos;
}

// Pre-computed content-type headers
// content-type is index 31 in static table
// Using literal without indexing (0x0f for 4-bit prefix)
const CachedHpackHeaders::ContentTypeHeader CachedHpackHeaders::CT_JSON = []() {
    ContentTypeHeader h{};
    const char* value = "application/json";
    size_t vlen = strlen(value);
    // 0x5f = 0x40 (literal with indexing) | 31 (index)
    // But 31 needs extension: 0x4f + 0x10 (31-15=16 in next byte)
    // Simpler: use 0x0f (literal without indexing, 4-bit index) + continuation
    h.data[0] = 0x0f;  // Literal without indexing, index follows
    h.data[1] = 0x10;  // 31 - 15 = 16
    h.data[2] = static_cast<uint8_t>(vlen);
    std::memcpy(h.data + 3, value, vlen);
    h.len = static_cast<uint8_t>(3 + vlen);
    return h;
}();

const CachedHpackHeaders::ContentTypeHeader CachedHpackHeaders::CT_TEXT_PLAIN = []() {
    ContentTypeHeader h{};
    const char* value = "text/plain";
    size_t vlen = strlen(value);
    h.data[0] = 0x0f;
    h.data[1] = 0x10;  // content-type index 31
    h.data[2] = static_cast<uint8_t>(vlen);
    std::memcpy(h.data + 3, value, vlen);
    h.len = static_cast<uint8_t>(3 + vlen);
    return h;
}();

const CachedHpackHeaders::ContentTypeHeader CachedHpackHeaders::CT_TEXT_HTML = []() {
    ContentTypeHeader h{};
    const char* value = "text/html";
    size_t vlen = strlen(value);
    h.data[0] = 0x0f;
    h.data[1] = 0x10;  // content-type index 31
    h.data[2] = static_cast<uint8_t>(vlen);
    std::memcpy(h.data + 3, value, vlen);
    h.len = static_cast<uint8_t>(3 + vlen);
    return h;
}();

const CachedHpackHeaders::ContentTypeHeader CachedHpackHeaders::CT_OCTET_STREAM = []() {
    ContentTypeHeader h{};
    const char* value = "application/octet-stream";
    size_t vlen = strlen(value);
    h.data[0] = 0x0f;
    h.data[1] = 0x10;  // content-type index 31
    h.data[2] = static_cast<uint8_t>(vlen);
    std::memcpy(h.data + 3, value, vlen);
    h.len = static_cast<uint8_t>(3 + vlen);
    return h;
}();

// Pre-computed content-length: 0
// content-length is index 28 in static table
const CachedHpackHeaders::ContentLengthHeader CachedHpackHeaders::CL_0 = []() {
    ContentLengthHeader h{};
    const char* value = "0";
    h.data[0] = 0x0f;  // Literal without indexing
    h.data[1] = 0x0d;  // 28 - 15 = 13
    h.data[2] = 1;     // Length 1
    h.data[3] = '0';
    h.len = 4;
    return h;
}();

// Combined response headers for common cases
// :status 200 + content-type: application/json
const uint8_t CachedHpackHeaders::RESP_200_JSON[] = {
    0x88,              // :status 200 (index 8)
    0x0f, 0x10,        // content-type (index 31)
    16,                // value length
    'a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n'
};
const size_t CachedHpackHeaders::RESP_200_JSON_LEN = sizeof(RESP_200_JSON);

// :status 200 + content-type: text/plain
const uint8_t CachedHpackHeaders::RESP_200_TEXT[] = {
    0x88,              // :status 200 (index 8)
    0x0f, 0x10,        // content-type (index 31)
    10,                // value length
    't','e','x','t','/','p','l','a','i','n'
};
const size_t CachedHpackHeaders::RESP_200_TEXT_LEN = sizeof(RESP_200_TEXT);

// :status 404 + content-type: text/plain
const uint8_t CachedHpackHeaders::RESP_404_TEXT[] = {
    0x8d,              // :status 404 (index 13)
    0x0f, 0x10,        // content-type (index 31)
    10,                // value length
    't','e','x','t','/','p','l','a','i','n'
};
const size_t CachedHpackHeaders::RESP_404_TEXT_LEN = sizeof(RESP_404_TEXT);

// :status 500 + content-type: text/plain
const uint8_t CachedHpackHeaders::RESP_500_TEXT[] = {
    0x8e,              // :status 500 (index 14)
    0x0f, 0x10,        // content-type (index 31)
    10,                // value length
    't','e','x','t','/','p','l','a','i','n'
};
const size_t CachedHpackHeaders::RESP_500_TEXT_LEN = sizeof(RESP_500_TEXT);

size_t CachedHpackHeaders::get_status(uint16_t status_code, uint8_t* buf, size_t capacity) noexcept {
    if (capacity < 1) return 0;
    
    // Check for indexed status codes (single byte)
    switch (status_code) {
        case 200: buf[0] = STATUS_200; return 1;
        case 204: buf[0] = STATUS_204; return 1;
        case 206: buf[0] = STATUS_206; return 1;
        case 304: buf[0] = STATUS_304; return 1;
        case 400: buf[0] = STATUS_400; return 1;
        case 404: buf[0] = STATUS_404; return 1;
        case 500: buf[0] = STATUS_500; return 1;
        default: break;
    }
    
    // Non-indexed status: literal with indexed name
    // :status is index 8, but we need literal value
    // Format: 0x08 (literal without indexing, index 8) + length + value
    if (capacity < 6) return 0;
    
    char status_str[4];
    int len = snprintf(status_str, sizeof(status_str), "%u", status_code);
    if (len < 0 || len > 3) return 0;
    
    buf[0] = 0x08;  // Literal without indexing, indexed name :status (index 8)
    buf[1] = static_cast<uint8_t>(len);
    std::memcpy(buf + 2, status_str, static_cast<size_t>(len));
    
    return 2 + static_cast<size_t>(len);
}

size_t CachedHpackHeaders::encode_content_length(size_t length, uint8_t* buf, size_t capacity) noexcept {
    // Special case: content-length 0
    if (length == 0 && capacity >= CL_0.len) {
        std::memcpy(buf, CL_0.data, CL_0.len);
        return CL_0.len;
    }
    
    // Encode dynamically
    char len_str[24];
    int str_len = snprintf(len_str, sizeof(len_str), "%zu", length);
    if (str_len < 0 || capacity < static_cast<size_t>(3 + str_len)) return 0;
    
    buf[0] = 0x0f;  // Literal without indexing
    buf[1] = 0x0d;  // content-length index 28 - 15 = 13
    buf[2] = static_cast<uint8_t>(str_len);
    std::memcpy(buf + 3, len_str, static_cast<size_t>(str_len));
    
    return 3 + static_cast<size_t>(str_len);
}

void CachedHpackHeaders::initialize() noexcept {
    if (initialized_) return;
    // All static initialization done via lambdas above
    initialized_ = true;
}

using core::result;
using core::error_code;
using core::ok;
using core::err;

namespace {

void put_u32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Connection-specific fields are illegal in HTTP/2 (RFC 9113 8.2.2).
bool is_hop_by_hop(std::string_view lower) noexcept {
    return lower == "connection" || lower == "keep-alive" || lower == "proxy-connection" ||
           lower == "transfer-encoding" || lower == "upgrade";
}

}  // namespace

Http2Connection::Http2Connection(bool is_server)
    : is_server_(is_server),
      stream_manager_(static_cast<uint32_t>(kLocalWindow)),
      hpack_encoder_(http::HPACKDynamicTable::DEFAULT_MAX_SIZE),
      hpack_decoder_(http::HPACKDynamicTable::DEFAULT_MAX_SIZE) {
    local_settings_.header_table_size = http::HPACKDynamicTable::DEFAULT_MAX_SIZE;
    local_settings_.enable_push = false;
    local_settings_.max_concurrent_streams = kMaxConcurrentStreams;
    local_settings_.initial_window_size = static_cast<uint32_t>(kLocalWindow);
    local_settings_.max_frame_size = kLocalMaxFrameSize;
    local_settings_.max_header_list_size = kMaxHeaderListSize;
    // RFC 9113 6.5.2 initial values until the peer's SETTINGS arrive.
    remote_settings_.enable_push = true;
    remote_settings_.max_concurrent_streams = UINT32_MAX;
    remote_settings_.max_header_list_size = UINT32_MAX;
    decoded_.reserve(kMaxRequestHeaders);
    output_buffer_.reserve(4096);
    if (is_server) {
        state_ = ConnectionState::PREFACE_PENDING;
        (void)send_settings();  // server preface (3.4)
    } else {
        state_ = ConnectionState::ACTIVE;
    }
    assert(remote_settings_.max_frame_size == kLocalMaxFrameSize);
    assert(!is_server || output_backlog() > 0);
}

bool Http2Connection::get_output(const uint8_t** out_data, size_t* out_len) noexcept {
    assert(out_data != nullptr && out_len != nullptr);
    if (output_offset_ >= output_buffer_.size()) return false;
    *out_data = output_buffer_.data() + output_offset_;
    *out_len = output_buffer_.size() - output_offset_;
    return true;
}

void Http2Connection::commit_output(size_t len) noexcept {
    assert(len <= output_backlog());
    output_offset_ += std::min(len, output_backlog());
    if (output_offset_ >= output_buffer_.size()) {
        output_buffer_.clear();
        output_offset_ = 0;
    }
}

bool Http2Connection::wants_close() const noexcept {
    if (state_ == ConnectionState::CLOSED) return true;
    const bool draining = state_ == ConnectionState::GOAWAY_RECEIVED ||
                          state_ == ConnectionState::GOAWAY_SENT;
    return draining && open_count_ == 0;
}

void Http2Connection::queue_frame(FrameType type, uint8_t flags, uint32_t stream_id,
                                  const uint8_t* payload, size_t len) noexcept {
    assert(len <= 0xFFFFFFu);
    assert(payload != nullptr || len == 0);
    uint8_t hdr[9];
    hdr[0] = static_cast<uint8_t>(len >> 16);
    hdr[1] = static_cast<uint8_t>(len >> 8);
    hdr[2] = static_cast<uint8_t>(len);
    hdr[3] = static_cast<uint8_t>(type);
    hdr[4] = flags;
    put_u32(hdr + 5, stream_id & 0x7FFFFFFFu);
    output_buffer_.insert(output_buffer_.end(), hdr, hdr + 9);
    if (len > 0) output_buffer_.insert(output_buffer_.end(), payload, payload + len);
}

void Http2Connection::queue_header_block(uint32_t stream_id, const uint8_t* block, size_t len,
                                         bool end_stream) noexcept {
    assert(stream_id != 0);
    const size_t max = remote_settings_.max_frame_size;
    assert(max >= kLocalMaxFrameSize);
    size_t off = 0;
    bool first = true;
    for (size_t guard = 0; guard <= len; ++guard) {  // >= 1 byte per frame, or the last
        const size_t n = std::min(max, len - off);
        const bool last = off + n == len;
        uint8_t flags = last ? FrameFlags::HEADERS_END_HEADERS : 0;
        if (first && end_stream) flags |= FrameFlags::HEADERS_END_STREAM;
        queue_frame(first ? FrameType::HEADERS : FrameType::CONTINUATION, flags, stream_id,
                    block + off, n);
        off += n;
        first = false;
        if (last) break;
    }
    assert(off == len);
}

result<void> Http2Connection::send_settings() noexcept {
    const std::pair<SettingsId, uint32_t> params[] = {
        {SettingsId::HEADER_TABLE_SIZE, local_settings_.header_table_size},
        {SettingsId::MAX_CONCURRENT_STREAMS, local_settings_.max_concurrent_streams},
        {SettingsId::INITIAL_WINDOW_SIZE, local_settings_.initial_window_size},
        {SettingsId::MAX_FRAME_SIZE, local_settings_.max_frame_size},
        {SettingsId::MAX_HEADER_LIST_SIZE, local_settings_.max_header_list_size},
    };
    uint8_t payload[sizeof(params) / sizeof(params[0]) * 6];
    size_t n = 0;
    for (const auto& [id, v] : params) {
        payload[n] = static_cast<uint8_t>(static_cast<uint16_t>(id) >> 8);
        payload[n + 1] = static_cast<uint8_t>(static_cast<uint16_t>(id));
        put_u32(payload + n + 2, v);
        n += 6;
    }
    assert(n == sizeof(payload));
    queue_frame(FrameType::SETTINGS, 0, 0, payload, n);
    settings_ack_pending_ = true;
    return ok();
}

result<void> Http2Connection::send_response(uint32_t stream_id, uint16_t status,
                                            const http::CoroResponseHeaders& headers,
                                            const std::string& body) noexcept {
    Http2Stream* stream = stream_manager_.get_stream(stream_id);
    if (stream == nullptr || state_ == ConnectionState::CLOSED) {
        return err<void>(error_code::invalid_state);  // reset meanwhile
    }
    if (!stream->can_send() || stream->io.send_pending) {
        return err<void>(error_code::invalid_state);
    }
    if (status < 100 || status > 999) status = 500;
    char status_buf[4];
    std::snprintf(status_buf, sizeof(status_buf), "%u", static_cast<unsigned>(status));

    std::vector<http::HPACKHeader> fields;
    std::vector<std::string> names;  // lowercased names outlive the encode
    fields.reserve(headers.size() + 1);
    names.reserve(headers.size());
    fields.push_back({":status", status_buf, false});
    for (const auto& [name, value] : headers) {
        std::string& lower = names.emplace_back(name);
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; });
        if (lower.empty() || is_hop_by_hop(lower)) continue;
        fields.push_back({lower, value, false});
    }
    if (encode_buf_.size() < kMaxResponseHeaderBlock) encode_buf_.resize(kMaxResponseHeaderBlock);
    size_t block_len = 0;
    if (hpack_encoder_.encode(fields.data(), fields.size(), encode_buf_.data(),
                              encode_buf_.size(), block_len) != 0) {
        (void)stream_error(stream_id, ErrorCode::INTERNAL_ERROR);  // headers too large
        return err<void>(error_code::internal_error);
    }
    const bool has_body = !body.empty() && !stream->io.is_head && status != 204 && status != 304;
    queue_header_block(stream_id, encode_buf_.data(), block_len, !has_body);
    stream->on_headers_sent(!has_body);
    if (!has_body) {
        maybe_close(stream);
        return ok();
    }
    stream->io.send_buf = body;
    stream->io.send_off = 0;
    stream->io.send_pending = true;
    pump_data();
    return ok();
}

bool Http2Connection::pump_stream(Http2Stream* stream) noexcept {
    assert(stream != nullptr);
    Http2Stream::Io& io = stream->io;
    if (!io.send_pending) return false;
    assert(io.send_off < io.send_buf.size());
    const int32_t window = std::min(connection_send_window_, stream->send_window_);
    if (window <= 0) return false;
    const size_t remaining = io.send_buf.size() - io.send_off;
    const size_t n = std::min({remaining, static_cast<size_t>(remote_settings_.max_frame_size),
                               static_cast<size_t>(window)});
    const bool last = n == remaining;
    queue_frame(FrameType::DATA, last ? FrameFlags::DATA_END_STREAM : 0, stream->id(),
                reinterpret_cast<const uint8_t*>(io.send_buf.data()) + io.send_off, n);
    io.send_off += n;
    connection_send_window_ -= static_cast<int32_t>(n);
    stream->send_window_ -= static_cast<int32_t>(n);
    if (last) {
        io.send_pending = false;
        std::string().swap(io.send_buf);
        stream->on_data_sent(true);
        maybe_close(stream);
    }
    return true;
}

void Http2Connection::pump_data() noexcept {
    // Round-robin one frame per stream per pass; every pass that makes
    // progress sends at least one byte, so windows bound the passes.
    constexpr size_t kMaxPasses = 1u << 20;
    for (size_t pass = 0; pass < kMaxPasses; ++pass) {
        if (connection_send_window_ <= 0) return;
        std::array<uint32_t, kMaxConcurrentStreams> ids;
        const size_t n = open_count_;
        std::copy(open_ids_.begin(), open_ids_.begin() + static_cast<std::ptrdiff_t>(n), ids.begin());
        bool progress = false;
        for (size_t i = 0; i < n; ++i) {
            Http2Stream* s = stream_manager_.get_stream(ids[i]);
            if (s != nullptr && pump_stream(s)) progress = true;
        }
        if (!progress) return;
    }
}

void Http2Connection::maybe_close(Http2Stream* stream) noexcept {
    assert(stream != nullptr);
    if (stream->state() == StreamState::CLOSED && !stream->io.send_pending) {
        close_stream(stream->id());
    }
}

void Http2Connection::close_stream(uint32_t id) noexcept {
    for (size_t i = 0; i < open_count_; ++i) {
        if (open_ids_[i] != id) continue;
        open_ids_[i] = open_ids_[open_count_ - 1];
        --open_count_;
        break;
    }
    stream_manager_.remove_stream(id);
    closed_ids_[closed_next_ % kClosedRing] = id;
    ++closed_next_;
    assert(open_count_ <= kMaxConcurrentStreams);
    assert(stream_manager_.get_stream(id) == nullptr);
}

bool Http2Connection::recently_closed(uint32_t id) const noexcept {
    const size_t n = std::min(closed_next_, kClosedRing);
    for (size_t i = 0; i < n; ++i) {
        if (closed_ids_[i] == id) return true;
    }
    return false;
}

result<void> Http2Connection::connection_error(ErrorCode code) noexcept {
    assert(code != ErrorCode::NO_ERROR);
    if (state_ != ConnectionState::CLOSED) {
        uint8_t payload[8];
        put_u32(payload, last_stream_id_);
        put_u32(payload + 4, static_cast<uint32_t>(code));
        queue_frame(FrameType::GOAWAY, 0, 0, payload, sizeof(payload));
        last_error_ = code;
        state_ = ConnectionState::CLOSED;
    }
    assert(state_ == ConnectionState::CLOSED);
    return err<void>(error_code::http_error);
}

result<void> Http2Connection::stream_error(uint32_t stream_id, ErrorCode code) noexcept {
    assert(stream_id != 0);
    if (output_backlog() > kMaxControlBacklog) {
        return connection_error(ErrorCode::ENHANCE_YOUR_CALM);  // peer is not reading
    }
    uint8_t payload[4];
    put_u32(payload, static_cast<uint32_t>(code));
    queue_frame(FrameType::RST_STREAM, 0, stream_id, payload, sizeof(payload));
    if (stream_manager_.get_stream(stream_id) != nullptr) {
        close_stream(stream_id);
    } else if (!recently_closed(stream_id)) {
        closed_ids_[closed_next_ % kClosedRing] = stream_id;
        ++closed_next_;
    }
    return ok();
}

result<void> Http2Connection::send_rst_stream(uint32_t stream_id, ErrorCode error) noexcept {
    if (stream_id == 0) return err<void>(error_code::invalid_state);
    return stream_error(stream_id, error);
}

result<void> Http2Connection::send_goaway(ErrorCode error, const std::string& debug_data) noexcept {
    if (state_ == ConnectionState::CLOSED) return err<void>(error_code::invalid_state);
    const size_t dbg = std::min(debug_data.size(), static_cast<size_t>(kLocalMaxFrameSize - 8));
    std::vector<uint8_t> payload(8 + dbg);
    put_u32(payload.data(), last_stream_id_);
    put_u32(payload.data() + 4, static_cast<uint32_t>(error));
    if (dbg > 0) std::memcpy(payload.data() + 8, debug_data.data(), dbg);
    queue_frame(FrameType::GOAWAY, 0, 0, payload.data(), payload.size());
    if (error != ErrorCode::NO_ERROR) {
        last_error_ = error;
        state_ = ConnectionState::CLOSED;
    } else if (state_ == ConnectionState::ACTIVE) {
        state_ = ConnectionState::GOAWAY_SENT;
    }
    return ok();
}

Http2Stream* Http2Connection::get_stream(uint32_t stream_id) noexcept {
    return stream_manager_.get_stream(stream_id);
}

} // namespace http2
} // namespace bolt::api
