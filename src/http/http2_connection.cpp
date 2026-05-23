#include "boltapi/http/http2_connection.h"
#include "boltapi/core/logger.h"
#include <cstring>
#include <algorithm>
#include <iostream>
#include <cstdio>

namespace bolt::api {
namespace http2 {

// Thread-local buffer pools for HTTP/2 (cache-line aligned, lock-free)
thread_local Http2BufferPool<H2_FRAME_BUFFER_SIZE, H2_FRAME_BUFFER_COUNT> t_h2_frame_pool;
thread_local Http2BufferPool<H2_HEADER_BUFFER_SIZE, H2_HEADER_BUFFER_COUNT> t_h2_header_pool;

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

// Http2Connection implementation

Http2Connection::Http2Connection(bool is_server)
    : is_server_(is_server),
      stream_manager_(local_settings_.initial_window_size),
      hpack_encoder_(local_settings_.header_table_size),
      hpack_decoder_(local_settings_.header_table_size) {

    if (is_server) {
        state_ = ConnectionState::PREFACE_PENDING;
        // Queue initial SETTINGS frame (server connection preface per RFC 7540 Section 3.5)
        // This must be sent before processing any client data
        send_settings();
    } else {
        state_ = ConnectionState::ACTIVE;
    }
}

core::result<size_t> Http2Connection::process_input(const uint8_t* data, size_t len) noexcept {
    if (state_ == ConnectionState::CLOSED) {
        return err<size_t>(error_code::invalid_state);
    }

    size_t consumed = 0;

    // Check for client preface if server and not yet received
    // Validate preface incrementally to handle partial reads correctly
    if (is_server_ && state_ == ConnectionState::PREFACE_PENDING) {
        size_t bytes_needed = CONNECTION_PREFACE_LEN - preface_bytes_validated_;
        size_t bytes_available = std::min(bytes_needed, len);

        // Debug: Log received bytes
        DEBUG_LOG_H2("Validating preface: offset=%zu bytes_available=%zu len=%zu",
                     preface_bytes_validated_, bytes_available, len);
        DEBUG_LOG_H2("Expected: %s",
                     bolt::api::core::hex_dump(
                         reinterpret_cast<const uint8_t*>(CONNECTION_PREFACE + preface_bytes_validated_),
                         bytes_available).c_str());
        DEBUG_LOG_H2("Received: %s",
                     bolt::api::core::hex_dump(data, bytes_available).c_str());

        // Validate the bytes we can against the correct position in preface
        if (std::memcmp(
            CONNECTION_PREFACE + preface_bytes_validated_,
            data,
            bytes_available
        ) != 0) {
            // Preface mismatch - protocol error
            DEBUG_LOG_H2("Preface mismatch!");
            return err<size_t>(error_code::internal_error);
        }

        DEBUG_LOG_H2("Preface bytes validated OK");

        // Update validated byte count and consumed count
        preface_bytes_validated_ += bytes_available;
        consumed = bytes_available;

        // Check if we've received the complete preface
        if (preface_bytes_validated_ == CONNECTION_PREFACE_LEN) {
            // Complete preface received and validated
            DEBUG_LOG_H2("Complete preface validated, transitioning to ACTIVE state");
            state_ = ConnectionState::ACTIVE;
            // Note: Initial SETTINGS already queued in constructor
        } else {
            // Need more data to complete preface validation
            return ok(consumed);
        }
    }

    DEBUG_LOG_H2("Processing frames, consumed=%zu len=%zu", consumed, len);

    // Process frames
    while (consumed < len) {
        size_t remaining = len - consumed;

        // Need at least 9 bytes for frame header
        if (remaining < 9) {
            // Buffer partial frame header
            std::memcpy(input_buffer_.data() + input_buffer_len_,
                       data + consumed, remaining);
            input_buffer_len_ += remaining;
            consumed += remaining;
            break;
        }

        // Parse frame header
        auto header_result = parse_frame_header(data + consumed);
        if (header_result.is_err()) {
            DEBUG_LOG_H2("Frame header parse error!");
            return err<size_t>(header_result.error());
        }

        FrameHeader header = header_result.value();
        DEBUG_LOG_H2("Parsed frame: type=%d flags=%d stream_id=%u length=%u",
                     (int)header.type, (int)header.flags, header.stream_id, header.length);

        // Check if we have complete frame
        size_t frame_size = 9 + header.length;
        if (remaining < frame_size) {
            // Buffer partial frame
            std::memcpy(input_buffer_.data() + input_buffer_len_,
                       data + consumed, remaining);
            input_buffer_len_ += remaining;
            consumed += remaining;
            break;
        }

        // Process complete frame
        const uint8_t* payload = data + consumed + 9;

        // Dispatch to appropriate handler
        result<void> handle_result = ok();

        switch (header.type) {
        case FrameType::SETTINGS:
            handle_result = handle_settings_frame(header, payload);
            break;
        case FrameType::HEADERS:
            handle_result = handle_headers_frame(header, payload, header.length);
            break;
        case FrameType::DATA:
            handle_result = handle_data_frame(header, payload, header.length);
            break;
        case FrameType::WINDOW_UPDATE:
            handle_result = handle_window_update_frame(header, payload);
            break;
        case FrameType::PING:
            handle_result = handle_ping_frame(header, payload);
            break;
        case FrameType::RST_STREAM:
            handle_result = handle_rst_stream_frame(header, payload);
            break;
        case FrameType::GOAWAY:
            handle_result = handle_goaway_frame(payload, header.length);
            break;
        default:
            // Unknown frame type - ignore per spec
            break;
        }

        if (handle_result.is_err()) {
            return err<size_t>(handle_result.error());
        }

        consumed += frame_size;
    }

    return ok(consumed);
}

bool Http2Connection::get_output(const uint8_t** out_data, size_t* out_len) noexcept {
    if (output_offset_ >= output_buffer_.size()) {
        return false;  // No data available
    }

    *out_data = output_buffer_.data() + output_offset_;
    *out_len = output_buffer_.size() - output_offset_;
    return true;
}

void Http2Connection::commit_output(size_t len) noexcept {
    output_offset_ += len;

    // Clear buffer if fully consumed
    if (output_offset_ >= output_buffer_.size()) {
        output_buffer_.clear();
        output_offset_ = 0;
    }
}

core::result<void> Http2Connection::send_response(
    uint32_t stream_id,
    uint16_t status,
    const http::CoroResponseHeaders& headers,
    const std::string& body
) noexcept {
    Http2Stream* stream = stream_manager_.get_stream(stream_id);
    if (!stream) {
        return err<void>(error_code::invalid_state);
    }

    // Build headers vector for HPACK encoding
    std::vector<http::HPACKHeader> hpack_headers;
    hpack_headers.reserve(headers.size() + 1);

    // Storage for lowercase header names (HPACKHeader uses string_view, so we need
    // to keep the strings alive until encoding is complete)
    std::vector<std::string> lowercase_names;
    lowercase_names.reserve(headers.size());

    // Add :status pseudo-header
    char status_buf[4];
    snprintf(status_buf, sizeof(status_buf), "%u", status);
    hpack_headers.push_back({":status", status_buf, false});

    // Add response headers (convert names to lowercase for HTTP/2 compliance)
    for (const auto& [name, value] : headers) {
        // HTTP/2 requires lowercase header names (RFC 7540 Section 8.1.2)
        lowercase_names.emplace_back(name);
        std::transform(lowercase_names.back().begin(), lowercase_names.back().end(),
                       lowercase_names.back().begin(), ::tolower);
        hpack_headers.push_back({lowercase_names.back(), value, false});
    }

    // Encode headers with HPACK
    uint8_t encoded_buffer[4096];  // Stack buffer for encoded headers
    size_t encoded_len = 0;

    int encode_result = hpack_encoder_.encode(
        hpack_headers.data(),
        hpack_headers.size(),
        encoded_buffer,
        sizeof(encoded_buffer),
        encoded_len
    );
    if (encode_result != 0) {
        return err<void>(error_code::internal_error);
    }

    std::vector<uint8_t> encoded_headers(encoded_buffer, encoded_buffer + encoded_len);

    // Create HEADERS frame
    bool end_stream = body.empty();
    auto headers_frame = write_headers_frame(stream_id, encoded_headers, end_stream, true);

    auto queue_result = queue_frame(headers_frame);
    if (queue_result.is_err()) {
        return queue_result;
    }

    // Send DATA frame if body present
    if (!body.empty()) {
        auto data_frame = write_data_frame(stream_id, body, true);
        queue_result = queue_frame(data_frame);
        if (queue_result.is_err()) {
            return queue_result;
        }
    }

    // Update stream state
    stream->on_headers_sent(end_stream);
    if (!body.empty()) {
        stream->on_data_sent(true);
    }

    return ok();
}

core::result<void> Http2Connection::send_rst_stream(uint32_t stream_id, ErrorCode error) noexcept {
    auto frame = write_rst_stream_frame(stream_id, error);
    return queue_frame(frame);
}

core::result<void> Http2Connection::send_goaway(ErrorCode error, const std::string& debug_data) noexcept {
    auto frame = write_goaway_frame(last_stream_id_, error, debug_data);
    state_ = ConnectionState::GOAWAY_SENT;
    return queue_frame(frame);
}

Http2Stream* Http2Connection::get_stream(uint32_t stream_id) noexcept {
    return stream_manager_.get_stream(stream_id);
}

// Frame handlers

core::result<void> Http2Connection::handle_settings_frame(
    const FrameHeader& header,
    const uint8_t* payload
) noexcept {
    // SETTINGS ACK
    if (header.flags & FrameFlags::SETTINGS_ACK) {
        settings_ack_pending_ = false;
        return ok();
    }

    // Parse SETTINGS parameters
    auto params_result = parse_settings_frame(header, payload, header.length);
    if (params_result.is_err()) {
        return err<void>(params_result.error());
    }

    // Apply settings
    auto apply_result = apply_settings(params_result.value());
    if (apply_result.is_err()) {
        return apply_result;
    }

    // Send SETTINGS ACK
    return send_settings_ack();
}

core::result<void> Http2Connection::handle_headers_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
) noexcept {
    DEBUG_LOG_H2("handle_headers_frame: stream_id=%u payload_len=%zu",
                 header.stream_id, payload_len);

    // Get or create stream
    Http2Stream* stream = stream_manager_.get_stream(header.stream_id);
    if (!stream) {
        DEBUG_LOG_H2("Creating new stream %u", header.stream_id);
        auto create_result = stream_manager_.create_stream(header.stream_id);
        if (create_result.is_err()) {
            DEBUG_LOG_H2("Failed to create stream!");
            return err<void>(create_result.error());
        }
        stream = create_result.value();
        last_stream_id_ = header.stream_id;
    }

    // Parse HEADERS frame to extract header block
    PrioritySpec priority;
    std::vector<uint8_t> header_block;

    DEBUG_LOG_H2("Parsing HEADERS frame...");
    auto parse_result = parse_headers_frame(header, payload, payload_len,
                                           &priority, header_block);
    if (parse_result.is_err()) {
        DEBUG_LOG_H2("Failed to parse HEADERS frame!");
        return err<void>(parse_result.error());
    }
    DEBUG_LOG_H2("Parsed HEADERS frame, header_block size=%zu", header_block.size());

    // Decode HPACK headers
    std::vector<http::HPACKHeader> decoded_headers;
    DEBUG_LOG_H2("Decoding HPACK headers...");
    int decode_result = hpack_decoder_.decode(header_block.data(),
                                             header_block.size(),
                                             decoded_headers);
    if (decode_result != 0) {
        DEBUG_LOG_H2("Failed to decode HPACK headers! decode_result=%d", decode_result);
        return err<void>(error_code::internal_error);
    }
    DEBUG_LOG_H2("Decoded %zu headers", decoded_headers.size());

    // Store headers in stream
    for (const auto& h : decoded_headers) {
        DEBUG_LOG_H2("Header: %s: %s",
                     bolt::api::core::safe_string(h.name, 50).c_str(),
                     bolt::api::core::safe_string(h.value, 100).c_str());
        stream->add_request_header(std::string(h.name), std::string(h.value));
    }

    // Update stream state
    bool end_stream = (header.flags & FrameFlags::HEADERS_END_STREAM) != 0;
    DEBUG_LOG_H2("end_stream=%d request_callback_=%s",
                 end_stream, request_callback_ ? "set" : "null");
    stream->on_headers_received(end_stream);

    // If request complete, invoke callback
    if (end_stream && request_callback_) {
        DEBUG_LOG_H2("Invoking request callback for stream %u", stream->id());
        request_callback_(stream);
        DEBUG_LOG_H2("Request callback completed");
    }

    return ok();
}

core::result<void> Http2Connection::handle_data_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
) noexcept {
    DEBUG_LOG_H2("handle_data_frame: stream_id=%u payload_len=%zu flags=%u",
                 header.stream_id, payload_len, header.flags);

    Http2Stream* stream = stream_manager_.get_stream(header.stream_id);
    if (!stream) {
        DEBUG_LOG_H2("Stream %u not found!", header.stream_id);
        return err<void>(error_code::invalid_state);
    }

    // Parse DATA frame
    auto data_result = parse_data_frame(header, payload, payload_len);
    if (data_result.is_err()) {
        DEBUG_LOG_H2("parse_data_frame failed!");
        return err<void>(data_result.error());
    }
    DEBUG_LOG_H2("Parsed DATA frame, body_len=%zu", data_result.value().size());

    // Check flow control
    auto consume_conn = consume_recv_window(static_cast<uint32_t>(data_result.value().size()));
    if (consume_conn.is_err()) {
        DEBUG_LOG_H2("consume_recv_window (connection) failed!");
        return consume_conn;
    }

    auto consume_stream = stream->consume_recv_window(static_cast<uint32_t>(data_result.value().size()));
    if (consume_stream.is_err()) {
        DEBUG_LOG_H2("consume_recv_window (stream) failed!");
        return consume_stream;
    }

    // Append to stream body
    stream->append_request_body(data_result.value());
    DEBUG_LOG_H2("Appended body, total_body_len=%zu", stream->request_body_size());

    // Update stream state
    bool end_stream = (header.flags & FrameFlags::DATA_END_STREAM) != 0;
    DEBUG_LOG_H2("end_stream=%d request_callback_=%s",
                 end_stream, request_callback_ ? "set" : "null");
    stream->on_data_received(end_stream);

    // If request complete, invoke callback
    if (end_stream && request_callback_) {
        DEBUG_LOG_H2("Invoking request callback for DATA frame on stream %u", stream->id());
        request_callback_(stream);
        DEBUG_LOG_H2("Request callback completed for DATA frame");
    }

    return ok();
}

core::result<void> Http2Connection::handle_window_update_frame(
    const FrameHeader& header,
    const uint8_t* payload
) noexcept {
    auto increment_result = parse_window_update_frame(payload);
    if (increment_result.is_err()) {
        return err<void>(increment_result.error());
    }

    uint32_t increment = increment_result.value();

    if (header.stream_id == 0) {
        // Connection-level window update
        if (connection_send_window_ > INT32_MAX - static_cast<int32_t>(increment)) {
            return err<void>(error_code::internal_error);
        }
        connection_send_window_ += static_cast<int32_t>(increment);
    } else {
        // Stream-level window update
        Http2Stream* stream = stream_manager_.get_stream(header.stream_id);
        if (!stream) {
            return err<void>(error_code::invalid_state);
        }
        return stream->update_send_window(static_cast<int32_t>(increment));
    }

    return ok();
}

core::result<void> Http2Connection::handle_ping_frame(
    const FrameHeader& header,
    const uint8_t* payload
) noexcept {
    auto opaque_result = parse_ping_frame(payload);
    if (opaque_result.is_err()) {
        return err<void>(opaque_result.error());
    }

    // If not ACK, send PING ACK with same data
    if (!(header.flags & FrameFlags::PING_ACK)) {
        auto frame = write_ping_frame(opaque_result.value(), true);
        return queue_frame(frame);
    }

    return ok();
}

core::result<void> Http2Connection::handle_rst_stream_frame(
    const FrameHeader& header,
    const uint8_t* payload
) noexcept {
    auto error_result = parse_rst_stream_frame(payload);
    if (error_result.is_err()) {
        return err<void>(error_result.error());
    }

    Http2Stream* stream = stream_manager_.get_stream(header.stream_id);
    if (stream) {
        stream->on_rst_stream();
        stream->set_error_code(error_result.value());
    }

    return ok();
}

core::result<void> Http2Connection::handle_goaway_frame(
    const uint8_t* payload,
    size_t payload_len
) noexcept {
    uint32_t last_stream_id;
    ErrorCode error_code_val;
    std::string debug_data;

    auto parse_result = parse_goaway_frame(payload, payload_len,
                                          last_stream_id, error_code_val, debug_data);
    if (parse_result.is_err()) {
        return err<void>(parse_result.error());
    }

    DEBUG_LOG_H2("GOAWAY received: last_stream_id=%u error_code=%u debug_data_len=%zu%s%s%s",
                 last_stream_id,
                 static_cast<uint32_t>(error_code_val),
                 debug_data.size(),
                 debug_data.empty() ? "" : " debug_data=\"",
                 debug_data.empty() ? "" : bolt::api::core::safe_string(debug_data, 64).c_str(),
                 debug_data.empty() ? "" : "\"");

    state_ = ConnectionState::GOAWAY_RECEIVED;
    return ok();
}

// Settings management

core::result<void> Http2Connection::apply_settings(
    const std::vector<SettingsParameter>& params
) noexcept {
    for (const auto& param : params) {
        switch (param.id) {
        case SettingsId::HEADER_TABLE_SIZE:
            remote_settings_.header_table_size = param.value;
            hpack_encoder_.set_max_table_size(param.value);
            break;
        case SettingsId::ENABLE_PUSH:
            remote_settings_.enable_push = (param.value != 0);
            break;
        case SettingsId::MAX_CONCURRENT_STREAMS:
            remote_settings_.max_concurrent_streams = param.value;
            break;
        case SettingsId::INITIAL_WINDOW_SIZE:
            remote_settings_.initial_window_size = param.value;
            stream_manager_.update_initial_window_size(param.value);
            break;
        case SettingsId::MAX_FRAME_SIZE:
            if (param.value < 16384 || param.value > 16777215) {
                return err<void>(error_code::internal_error);
            }
            remote_settings_.max_frame_size = param.value;
            break;
        case SettingsId::MAX_HEADER_LIST_SIZE:
            remote_settings_.max_header_list_size = param.value;
            break;
        }
    }

    settings_received_ = true;
    return ok();
}

core::result<void> Http2Connection::send_settings() noexcept {
    std::vector<SettingsParameter> params;
    params.push_back({SettingsId::HEADER_TABLE_SIZE, local_settings_.header_table_size});
    // Note: ENABLE_PUSH is a client-only setting per RFC 7540 Section 8.2
    // Servers indicate push capability by sending (or not) PUSH_PROMISE frames
    params.push_back({SettingsId::MAX_CONCURRENT_STREAMS, local_settings_.max_concurrent_streams});
    params.push_back({SettingsId::INITIAL_WINDOW_SIZE, local_settings_.initial_window_size});
    params.push_back({SettingsId::MAX_FRAME_SIZE, local_settings_.max_frame_size});

    auto frame = write_settings_frame(params);
    settings_ack_pending_ = true;
    return queue_frame(frame);
}

core::result<void> Http2Connection::send_settings_ack() noexcept {
    auto frame = write_settings_ack();
    return queue_frame(frame);
}

// Output helpers

core::result<void> Http2Connection::queue_frame(const std::vector<uint8_t>& frame) noexcept {
    return queue_data(frame.data(), frame.size());
}

core::result<void> Http2Connection::queue_data(const uint8_t* data, size_t len) noexcept {
    output_buffer_.insert(output_buffer_.end(), data, data + len);
    return ok();
}

// Preface handling (now handled inline in process_input for incremental validation)

// Flow control helpers (connection-level)

core::result<void> Http2Connection::consume_recv_window(uint32_t size) noexcept {
    if (static_cast<int32_t>(size) > connection_recv_window_) {
        return err<void>(error_code::internal_error);
    }
    connection_recv_window_ -= static_cast<int32_t>(size);
    return ok();
}

} // namespace http2
} // namespace bolt::api
