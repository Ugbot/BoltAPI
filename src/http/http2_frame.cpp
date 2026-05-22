#include "boltapi/http/http2_frame.h"
#include "boltapi/net/sys_compat.h"  // htons/ntohs (winsock on Windows, arpa/inet on POSIX)
#include <cstring>

namespace bolt::api {
namespace http2 {

// Import core error handling types
using core::result;
using core::error_code;
using core::ok;

// Helper functions for network byte order conversion

static uint16_t read_uint16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) |
           static_cast<uint16_t>(data[1]);
}

static uint32_t read_uint24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}

static uint32_t read_uint32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

static uint64_t read_uint64(const uint8_t* data) {
    return (static_cast<uint64_t>(data[0]) << 56) |
           (static_cast<uint64_t>(data[1]) << 48) |
           (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) |
           (static_cast<uint64_t>(data[4]) << 24) |
           (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) |
           static_cast<uint64_t>(data[7]);
}

static void write_uint16(uint8_t* out, uint16_t value) {
    out[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[1] = static_cast<uint8_t>(value & 0xff);
}

static void write_uint24(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[2] = static_cast<uint8_t>(value & 0xff);
}

static void write_uint32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xff);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[3] = static_cast<uint8_t>(value & 0xff);
}

static void write_uint64(uint8_t* out, uint64_t value) {
    out[0] = static_cast<uint8_t>((value >> 56) & 0xff);
    out[1] = static_cast<uint8_t>((value >> 48) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 40) & 0xff);
    out[3] = static_cast<uint8_t>((value >> 32) & 0xff);
    out[4] = static_cast<uint8_t>((value >> 24) & 0xff);
    out[5] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[6] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[7] = static_cast<uint8_t>(value & 0xff);
}

// Frame header parsing and serialization

result<FrameHeader> parse_frame_header(const uint8_t* data) {
    if (!data) {
        return result<FrameHeader>(error_code::internal_error);
    }

    FrameHeader header;

    // Read 24-bit length
    header.length = read_uint24(data);

    // Read frame type
    header.type = static_cast<FrameType>(data[3]);

    // Read flags
    header.flags = data[4];

    // Read 31-bit stream ID (mask off reserved bit)
    header.stream_id = read_uint32(data + 5) & 0x7FFFFFFF;

    return ok(header);
}

void write_frame_header(const FrameHeader& header, uint8_t* out) {
    // Write 24-bit length
    write_uint24(out, header.length);

    // Write frame type
    out[3] = static_cast<uint8_t>(header.type);

    // Write flags
    out[4] = header.flags;

    // Write 31-bit stream ID (reserved bit already 0)
    write_uint32(out + 5, header.stream_id & 0x7FFFFFFF);
}

// DATA frame (RFC 7540 Section 6.1)

result<std::string> parse_data_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
) {
    if (header.length != payload_len) {
        return result<std::string>(error_code::internal_error);
    }

    size_t offset = 0;
    uint8_t pad_length = 0;

    // If PADDED flag set, read pad length
    if (header.flags & FrameFlags::DATA_PADDED) {
        if (payload_len < 1) {
            return result<std::string>(error_code::internal_error);
        }
        pad_length = payload[0];
        offset = 1;

        // Validate padding
        if (pad_length >= payload_len) {
            return result<std::string>(error_code::internal_error);
        }
    }

    // Extract data (without padding)
    size_t data_len = payload_len - offset - pad_length;
    std::string data(reinterpret_cast<const char*>(payload + offset), data_len);

    return ok(std::move(data));
}

// HEADERS frame (RFC 7540 Section 6.2)

result<void> parse_headers_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len,
    PrioritySpec* out_priority,
    std::vector<uint8_t>& out_header_block
) {
    if (header.length != payload_len) {
        return result<void>(error_code::internal_error);
    }

    size_t offset = 0;
    uint8_t pad_length = 0;

    // If PADDED flag set, read pad length
    if (header.flags & FrameFlags::HEADERS_PADDED) {
        if (payload_len < 1) {
            return result<void>(error_code::internal_error);
        }
        pad_length = payload[0];
        offset = 1;
    }

    // If PRIORITY flag set, read priority spec (5 bytes)
    if (header.flags & FrameFlags::HEADERS_PRIORITY) {
        if (payload_len < offset + 5) {
            return result<void>(error_code::internal_error);
        }

        if (out_priority) {
            uint32_t stream_dep = read_uint32(payload + offset);
            out_priority->exclusive = (stream_dep >> 31) & 0x1;
            out_priority->stream_dependency = stream_dep & 0x7FFFFFFF;
            out_priority->weight = payload[offset + 4];
        }

        offset += 5;
    }

    // Validate padding
    if (offset + pad_length > payload_len) {
        return result<void>(error_code::internal_error);
    }

    // Extract header block (HPACK-encoded headers)
    size_t header_block_len = payload_len - offset - pad_length;
    out_header_block.assign(payload + offset, payload + offset + header_block_len);

    return ok();
}

// PRIORITY frame (RFC 7540 Section 6.3)

result<PrioritySpec> parse_priority_frame(const uint8_t* payload) {
    if (!payload) {
        return result<PrioritySpec>(error_code::internal_error);
    }

    PrioritySpec spec;

    uint32_t stream_dep = read_uint32(payload);
    spec.exclusive = (stream_dep >> 31) & 0x1;
    spec.stream_dependency = stream_dep & 0x7FFFFFFF;
    spec.weight = payload[4];

    return ok(spec);
}

// RST_STREAM frame (RFC 7540 Section 6.4)

result<ErrorCode> parse_rst_stream_frame(const uint8_t* payload) {
    if (!payload) {
        return result<ErrorCode>(error_code::internal_error);
    }

    uint32_t error_code_val = read_uint32(payload);
    ErrorCode error = static_cast<ErrorCode>(error_code_val);

    return ok(error);
}

// SETTINGS frame (RFC 7540 Section 6.5)

result<std::vector<SettingsParameter>> parse_settings_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
) {
    // SETTINGS ACK must have empty payload
    if (header.flags & FrameFlags::SETTINGS_ACK) {
        if (payload_len != 0) {
            return result<std::vector<SettingsParameter>>(error_code::internal_error);
        }
        return ok(std::vector<SettingsParameter>{});
    }

    // Payload must be multiple of 6 bytes (each setting is 6 bytes)
    if (payload_len % 6 != 0) {
        return result<std::vector<SettingsParameter>>(error_code::internal_error);
    }

    std::vector<SettingsParameter> params;
    size_t num_params = payload_len / 6;
    params.reserve(num_params);

    for (size_t i = 0; i < num_params; ++i) {
        const uint8_t* param_data = payload + (i * 6);

        SettingsParameter param;
        param.id = static_cast<SettingsId>(read_uint16(param_data));
        param.value = read_uint32(param_data + 2);

        params.push_back(param);
    }

    return ok(std::move(params));
}

// PING frame (RFC 7540 Section 6.7)

result<uint64_t> parse_ping_frame(const uint8_t* payload) {
    if (!payload) {
        return result<uint64_t>(error_code::internal_error);
    }

    uint64_t opaque_data = read_uint64(payload);
    return ok(opaque_data);
}

// GOAWAY frame (RFC 7540 Section 6.8)

result<void> parse_goaway_frame(
    const uint8_t* payload,
    size_t payload_len,
    uint32_t& out_last_stream_id,
    ErrorCode& out_error_code,
    std::string& out_debug_data
) {
    if (payload_len < 8) {
        return result<void>(error_code::internal_error);
    }

    // Read last stream ID (31 bits)
    out_last_stream_id = read_uint32(payload) & 0x7FFFFFFF;

    // Read error code
    out_error_code = static_cast<ErrorCode>(read_uint32(payload + 4));

    // Read debug data (rest of payload)
    if (payload_len > 8) {
        out_debug_data.assign(
            reinterpret_cast<const char*>(payload + 8),
            payload_len - 8
        );
    }

    return ok();
}

// WINDOW_UPDATE frame (RFC 7540 Section 6.9)

result<uint32_t> parse_window_update_frame(const uint8_t* payload) {
    if (!payload) {
        return result<uint32_t>(error_code::internal_error);
    }

    // Read 31-bit window size increment (reserved bit must be 0)
    uint32_t increment = read_uint32(payload) & 0x7FFFFFFF;

    // Increment must be non-zero
    if (increment == 0) {
        return result<uint32_t>(error_code::internal_error);
    }

    return ok(increment);
}

// PUSH_PROMISE frame (RFC 7540 Section 6.6)

result<void> parse_push_promise_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len,
    uint32_t& out_promised_stream_id,
    std::vector<uint8_t>& out_header_block
) {
    if (header.length != payload_len) {
        return result<void>(error_code::internal_error);
    }

    size_t offset = 0;
    uint8_t pad_length = 0;

    // If PADDED flag set, read pad length
    if (header.flags & FrameFlags::PUSH_PROMISE_PADDED) {
        if (payload_len < 1) {
            return result<void>(error_code::internal_error);
        }
        pad_length = payload[0];
        offset = 1;
    }

    // Read promised stream ID (4 bytes)
    if (payload_len < offset + 4) {
        return result<void>(error_code::internal_error);
    }

    out_promised_stream_id = read_uint32(payload + offset) & 0x7FFFFFFF;
    offset += 4;

    // Validate padding
    if (offset + pad_length > payload_len) {
        return result<void>(error_code::internal_error);
    }

    // Extract header block
    size_t header_block_len = payload_len - offset - pad_length;
    out_header_block.assign(payload + offset, payload + offset + header_block_len);

    return ok();
}

// Frame serialization functions

std::vector<uint8_t> write_data_frame(
    uint32_t stream_id,
    const std::string& data,
    bool end_stream
) {
    // No padding for simplicity
    uint32_t length = static_cast<uint32_t>(data.size());
    uint8_t flags = end_stream ? FrameFlags::DATA_END_STREAM : 0;

    std::vector<uint8_t> frame(9 + length);

    // Write frame header
    FrameHeader header(length, FrameType::DATA, flags, stream_id);
    write_frame_header(header, frame.data());

    // Write data payload
    std::memcpy(frame.data() + 9, data.data(), data.size());

    return frame;
}

std::vector<uint8_t> write_headers_frame(
    uint32_t stream_id,
    const std::vector<uint8_t>& header_block,
    bool end_stream,
    bool end_headers,
    const PrioritySpec* priority
) {
    // Calculate payload size
    size_t priority_size = priority ? 5 : 0;
    uint32_t length = static_cast<uint32_t>(priority_size + header_block.size());

    // Set flags
    uint8_t flags = 0;
    if (end_stream) flags |= FrameFlags::HEADERS_END_STREAM;
    if (end_headers) flags |= FrameFlags::HEADERS_END_HEADERS;
    if (priority) flags |= FrameFlags::HEADERS_PRIORITY;

    std::vector<uint8_t> frame(9 + length);

    // Write frame header
    FrameHeader header(length, FrameType::HEADERS, flags, stream_id);
    write_frame_header(header, frame.data());

    size_t offset = 9;

    // Write priority spec if present
    if (priority) {
        uint32_t stream_dep = priority->stream_dependency;
        if (priority->exclusive) {
            stream_dep |= 0x80000000;  // Set exclusive bit
        }
        write_uint32(frame.data() + offset, stream_dep);
        frame[offset + 4] = priority->weight;
        offset += 5;
    }

    // Write header block
    std::memcpy(frame.data() + offset, header_block.data(), header_block.size());

    return frame;
}

std::vector<uint8_t> write_settings_frame(
    const std::vector<SettingsParameter>& params,
    bool ack
) {
    if (ack) {
        // SETTINGS ACK has no payload
        std::vector<uint8_t> frame(9);
        FrameHeader header(0, FrameType::SETTINGS, FrameFlags::SETTINGS_ACK, 0);
        write_frame_header(header, frame.data());
        return frame;
    }

    // Each parameter is 6 bytes
    uint32_t length = static_cast<uint32_t>(params.size() * 6);
    std::vector<uint8_t> frame(9 + length);

    // Write frame header
    FrameHeader header(length, FrameType::SETTINGS, 0, 0);
    write_frame_header(header, frame.data());

    // Write settings parameters
    for (size_t i = 0; i < params.size(); ++i) {
        uint8_t* param_data = frame.data() + 9 + (i * 6);
        write_uint16(param_data, static_cast<uint16_t>(params[i].id));
        write_uint32(param_data + 2, params[i].value);
    }

    return frame;
}

std::vector<uint8_t> write_settings_ack() {
    return write_settings_frame({}, true);
}

std::vector<uint8_t> write_window_update_frame(
    uint32_t stream_id,
    uint32_t increment
) {
    std::vector<uint8_t> frame(9 + 4);

    // Write frame header
    FrameHeader header(4, FrameType::WINDOW_UPDATE, 0, stream_id);
    write_frame_header(header, frame.data());

    // Write window size increment (31 bits)
    write_uint32(frame.data() + 9, increment & 0x7FFFFFFF);

    return frame;
}

std::vector<uint8_t> write_ping_frame(
    uint64_t opaque_data,
    bool ack
) {
    std::vector<uint8_t> frame(9 + 8);

    uint8_t flags = ack ? FrameFlags::PING_ACK : 0;

    // Write frame header
    FrameHeader header(8, FrameType::PING, flags, 0);
    write_frame_header(header, frame.data());

    // Write opaque data
    write_uint64(frame.data() + 9, opaque_data);

    return frame;
}

std::vector<uint8_t> write_goaway_frame(
    uint32_t last_stream_id,
    ErrorCode error_code,
    const std::string& debug_data
) {
    uint32_t length = 8 + static_cast<uint32_t>(debug_data.size());
    std::vector<uint8_t> frame(9 + length);

    // Write frame header
    FrameHeader header(length, FrameType::GOAWAY, 0, 0);
    write_frame_header(header, frame.data());

    // Write last stream ID (31 bits)
    write_uint32(frame.data() + 9, last_stream_id & 0x7FFFFFFF);

    // Write error code
    write_uint32(frame.data() + 13, static_cast<uint32_t>(error_code));

    // Write debug data
    if (!debug_data.empty()) {
        std::memcpy(frame.data() + 17, debug_data.data(), debug_data.size());
    }

    return frame;
}

std::vector<uint8_t> write_rst_stream_frame(
    uint32_t stream_id,
    ErrorCode error_code
) {
    std::vector<uint8_t> frame(9 + 4);

    // Write frame header
    FrameHeader header(4, FrameType::RST_STREAM, 0, stream_id);
    write_frame_header(header, frame.data());

    // Write error code
    write_uint32(frame.data() + 9, static_cast<uint32_t>(error_code));

    return frame;
}

// ============================================================================
// Zero-allocation frame serialization (_to variants)
// ============================================================================

size_t write_data_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* data,
    size_t data_len,
    bool end_stream
) noexcept {
    const size_t frame_size = 9 + data_len;
    if (capacity < frame_size) {
        return 0;
    }

    uint8_t flags = end_stream ? FrameFlags::DATA_END_STREAM : 0;
    FrameHeader header(static_cast<uint32_t>(data_len), FrameType::DATA, flags, stream_id);
    write_frame_header(header, buf);

    if (data_len > 0 && data) {
        std::memcpy(buf + 9, data, data_len);
    }

    return frame_size;
}

size_t write_headers_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_stream,
    bool end_headers,
    const PrioritySpec* priority
) noexcept {
    const size_t priority_size = priority ? 5 : 0;
    const size_t payload_len = priority_size + header_block_len;
    const size_t frame_size = 9 + payload_len;

    if (capacity < frame_size) {
        return 0;
    }

    uint8_t flags = 0;
    if (end_stream) flags |= FrameFlags::HEADERS_END_STREAM;
    if (end_headers) flags |= FrameFlags::HEADERS_END_HEADERS;
    if (priority) flags |= FrameFlags::HEADERS_PRIORITY;

    FrameHeader header(static_cast<uint32_t>(payload_len), FrameType::HEADERS, flags, stream_id);
    write_frame_header(header, buf);

    size_t offset = 9;

    if (priority) {
        uint32_t stream_dep = priority->stream_dependency;
        if (priority->exclusive) {
            stream_dep |= 0x80000000;
        }
        write_uint32(buf + offset, stream_dep);
        buf[offset + 4] = priority->weight;
        offset += 5;
    }

    if (header_block_len > 0 && header_block) {
        std::memcpy(buf + offset, header_block, header_block_len);
    }

    return frame_size;
}

size_t write_settings_frame_to(
    uint8_t* buf,
    size_t capacity,
    const SettingsParameter* params,
    size_t param_count,
    bool ack
) noexcept {
    if (ack) {
        if (capacity < 9) {
            return 0;
        }
        FrameHeader header(0, FrameType::SETTINGS, FrameFlags::SETTINGS_ACK, 0);
        write_frame_header(header, buf);
        return 9;
    }

    const size_t payload_len = param_count * 6;
    const size_t frame_size = 9 + payload_len;

    if (capacity < frame_size) {
        return 0;
    }

    FrameHeader header(static_cast<uint32_t>(payload_len), FrameType::SETTINGS, 0, 0);
    write_frame_header(header, buf);

    for (size_t i = 0; i < param_count; ++i) {
        uint8_t* param_data = buf + 9 + (i * 6);
        write_uint16(param_data, static_cast<uint16_t>(params[i].id));
        write_uint32(param_data + 2, params[i].value);
    }

    return frame_size;
}

size_t write_settings_ack_to(uint8_t* buf, size_t capacity) noexcept {
    return write_settings_frame_to(buf, capacity, nullptr, 0, true);
}

size_t write_window_update_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    uint32_t increment
) noexcept {
    constexpr size_t frame_size = 9 + 4;
    if (capacity < frame_size) {
        return 0;
    }

    FrameHeader header(4, FrameType::WINDOW_UPDATE, 0, stream_id);
    write_frame_header(header, buf);
    write_uint32(buf + 9, increment & 0x7FFFFFFF);

    return frame_size;
}

size_t write_ping_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint64_t opaque_data,
    bool ack
) noexcept {
    constexpr size_t frame_size = 9 + 8;
    if (capacity < frame_size) {
        return 0;
    }

    uint8_t flags = ack ? FrameFlags::PING_ACK : 0;
    FrameHeader header(8, FrameType::PING, flags, 0);
    write_frame_header(header, buf);
    write_uint64(buf + 9, opaque_data);

    return frame_size;
}

size_t write_goaway_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t last_stream_id,
    ErrorCode error_code,
    const uint8_t* debug_data,
    size_t debug_data_len
) noexcept {
    const size_t payload_len = 8 + debug_data_len;
    const size_t frame_size = 9 + payload_len;

    if (capacity < frame_size) {
        return 0;
    }

    FrameHeader header(static_cast<uint32_t>(payload_len), FrameType::GOAWAY, 0, 0);
    write_frame_header(header, buf);
    write_uint32(buf + 9, last_stream_id & 0x7FFFFFFF);
    write_uint32(buf + 13, static_cast<uint32_t>(error_code));

    if (debug_data_len > 0 && debug_data) {
        std::memcpy(buf + 17, debug_data, debug_data_len);
    }

    return frame_size;
}

size_t write_rst_stream_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    ErrorCode error_code
) noexcept {
    constexpr size_t frame_size = 9 + 4;
    if (capacity < frame_size) {
        return 0;
    }

    FrameHeader header(4, FrameType::RST_STREAM, 0, stream_id);
    write_frame_header(header, buf);
    write_uint32(buf + 9, static_cast<uint32_t>(error_code));

    return frame_size;
}

size_t write_push_promise_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    uint32_t promised_stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_headers
) noexcept {
    const size_t payload_len = 4 + header_block_len;  // 4 bytes for promised stream ID
    const size_t frame_size = 9 + payload_len;

    if (capacity < frame_size) {
        return 0;
    }

    uint8_t flags = end_headers ? FrameFlags::PUSH_PROMISE_END_HEADERS : 0;
    FrameHeader header(static_cast<uint32_t>(payload_len), FrameType::PUSH_PROMISE, flags, stream_id);
    write_frame_header(header, buf);

    // Write promised stream ID (31 bits)
    write_uint32(buf + 9, promised_stream_id & 0x7FFFFFFF);

    if (header_block_len > 0 && header_block) {
        std::memcpy(buf + 13, header_block, header_block_len);
    }

    return frame_size;
}

size_t write_continuation_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_headers
) noexcept {
    const size_t frame_size = 9 + header_block_len;

    if (capacity < frame_size) {
        return 0;
    }

    uint8_t flags = end_headers ? FrameFlags::CONTINUATION_END_HEADERS : 0;
    FrameHeader header(static_cast<uint32_t>(header_block_len), FrameType::CONTINUATION, flags, stream_id);
    write_frame_header(header, buf);

    if (header_block_len > 0 && header_block) {
        std::memcpy(buf + 9, header_block, header_block_len);
    }

    return frame_size;
}

} // namespace http2
} // namespace bolt::api
