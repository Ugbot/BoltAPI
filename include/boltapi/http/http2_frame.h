#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include "boltapi/core/result.h"

namespace bolt::api {
namespace http2 {

/**
 * HTTP/2 Frame Types (RFC 7540 Section 6)
 *
 * All 10 frame types defined in the HTTP/2 specification.
 */
enum class FrameType : uint8_t {
    DATA          = 0x0,  // Section 6.1: Request/response body
    HEADERS       = 0x1,  // Section 6.2: Request/response headers
    PRIORITY      = 0x2,  // Section 6.3: Stream priority
    RST_STREAM    = 0x3,  // Section 6.4: Stream error/cancellation
    SETTINGS      = 0x4,  // Section 6.5: Connection configuration
    PUSH_PROMISE  = 0x5,  // Section 6.6: Server push
    PING          = 0x6,  // Section 6.7: Keepalive/RTT measurement
    GOAWAY        = 0x7,  // Section 6.8: Graceful shutdown
    WINDOW_UPDATE = 0x8,  // Section 6.9: Flow control
    CONTINUATION  = 0x9   // Section 6.10: Header continuation
};

/**
 * Frame Flags (RFC 7540 Section 6)
 *
 * Different frame types use different flags.
 */
namespace FrameFlags {
    // DATA frame flags
    constexpr uint8_t DATA_END_STREAM = 0x1;
    constexpr uint8_t DATA_PADDED     = 0x8;

    // HEADERS frame flags
    constexpr uint8_t HEADERS_END_STREAM  = 0x1;
    constexpr uint8_t HEADERS_END_HEADERS = 0x4;
    constexpr uint8_t HEADERS_PADDED      = 0x8;
    constexpr uint8_t HEADERS_PRIORITY    = 0x20;

    // SETTINGS frame flags
    constexpr uint8_t SETTINGS_ACK = 0x1;

    // PING frame flags
    constexpr uint8_t PING_ACK = 0x1;

    // PUSH_PROMISE frame flags
    constexpr uint8_t PUSH_PROMISE_END_HEADERS = 0x4;
    constexpr uint8_t PUSH_PROMISE_PADDED      = 0x8;

    // CONTINUATION frame flags
    constexpr uint8_t CONTINUATION_END_HEADERS = 0x4;
}

/**
 * HTTP/2 Error Codes (RFC 7540 Section 7)
 */
enum class ErrorCode : uint32_t {
    NO_ERROR            = 0x0,  // Graceful shutdown
    PROTOCOL_ERROR      = 0x1,  // Protocol violation
    INTERNAL_ERROR      = 0x2,  // Implementation error
    FLOW_CONTROL_ERROR  = 0x3,  // Flow control violation
    SETTINGS_TIMEOUT    = 0x4,  // Settings ACK not received
    STREAM_CLOSED       = 0x5,  // Frame on closed stream
    FRAME_SIZE_ERROR    = 0x6,  // Invalid frame size
    REFUSED_STREAM      = 0x7,  // Stream not processed
    CANCEL              = 0x8,  // Stream cancelled
    COMPRESSION_ERROR   = 0x9,  // HPACK compression error
    CONNECT_ERROR       = 0xa,  // TCP connection error
    ENHANCE_YOUR_CALM   = 0xb,  // Excessive resource usage
    INADEQUATE_SECURITY = 0xc,  // TLS requirements not met
    HTTP_1_1_REQUIRED   = 0xd   // Fallback to HTTP/1.1
};

/**
 * SETTINGS Parameters (RFC 7540 Section 6.5.2)
 */
enum class SettingsId : uint16_t {
    HEADER_TABLE_SIZE      = 0x1,  // HPACK dynamic table size
    ENABLE_PUSH            = 0x2,  // Server push enabled
    MAX_CONCURRENT_STREAMS = 0x3,  // Max parallel streams
    INITIAL_WINDOW_SIZE    = 0x4,  // Initial flow control window
    MAX_FRAME_SIZE         = 0x5,  // Max frame payload size
    MAX_HEADER_LIST_SIZE   = 0x6   // Max header list size
};

/**
 * HTTP/2 Frame Header (RFC 7540 Section 4.1)
 *
 * All frames begin with a fixed 9-octet header:
 * +-----------------------------------------------+
 * |                 Length (24)                   |
 * +---------------+---------------+---------------+
 * |   Type (8)    |   Flags (8)   |
 * +-+-------------+---------------+-------------------------------+
 * |R|                 Stream Identifier (31)                      |
 * +=+=============================================================+
 */
struct FrameHeader {
    uint32_t length;      // 24-bit payload length (max 16,777,215)
    FrameType type;       // Frame type
    uint8_t flags;        // Frame-specific flags
    uint32_t stream_id;   // 31-bit stream identifier (R bit reserved)

    FrameHeader()
        : length(0), type(FrameType::DATA), flags(0), stream_id(0) {}

    FrameHeader(uint32_t len, FrameType t, uint8_t f, uint32_t sid)
        : length(len), type(t), flags(f), stream_id(sid) {}
};

/**
 * Priority Information (RFC 7540 Section 6.3)
 *
 * Used in HEADERS and PRIORITY frames.
 */
struct PrioritySpec {
    bool exclusive;       // Exclusive dependency flag
    uint32_t stream_dependency;  // Stream this depends on
    uint8_t weight;       // Priority weight (1-256, encoded as 0-255)

    PrioritySpec() : exclusive(false), stream_dependency(0), weight(16) {}
};

/**
 * SETTINGS Frame Parameter
 */
struct SettingsParameter {
    SettingsId id;
    uint32_t value;
};

// Frame parsing results
using core::result;
using core::error_code;

/**
 * Parse 9-byte frame header from buffer.
 *
 * @param data Pointer to 9 bytes of frame header
 * @return Parsed frame header or error
 */
result<FrameHeader> parse_frame_header(const uint8_t* data);

/**
 * Serialize frame header to 9 bytes.
 *
 * @param header Frame header to serialize
 * @param out Output buffer (must be at least 9 bytes)
 */
void write_frame_header(const FrameHeader& header, uint8_t* out);

/**
 * Parse DATA frame payload (RFC 7540 Section 6.1)
 *
 * @param header Frame header
 * @param payload Frame payload
 * @param payload_len Payload length
 * @param out_data Output data (after removing padding)
 * @return Success or error
 */
result<std::string> parse_data_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
);

/**
 * Parse HEADERS frame payload (RFC 7540 Section 6.2)
 *
 * @param header Frame header
 * @param payload Frame payload
 * @param payload_len Payload length
 * @param out_priority Priority spec (if PRIORITY flag set)
 * @param out_header_block HPACK-encoded header block
 * @return Success or error
 */
result<void> parse_headers_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len,
    PrioritySpec* out_priority,
    std::vector<uint8_t>& out_header_block
);

/**
 * Parse PRIORITY frame payload (RFC 7540 Section 6.3)
 *
 * @param payload Frame payload (must be 5 bytes)
 * @return Priority spec or error
 */
result<PrioritySpec> parse_priority_frame(const uint8_t* payload);

/**
 * Parse RST_STREAM frame payload (RFC 7540 Section 6.4)
 *
 * @param payload Frame payload (must be 4 bytes)
 * @return Error code or error
 */
result<ErrorCode> parse_rst_stream_frame(const uint8_t* payload);

/**
 * Parse SETTINGS frame payload (RFC 7540 Section 6.5)
 *
 * @param header Frame header
 * @param payload Frame payload
 * @param payload_len Payload length (must be multiple of 6)
 * @return Settings parameters or error
 */
result<std::vector<SettingsParameter>> parse_settings_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len
);

/**
 * Parse PING frame payload (RFC 7540 Section 6.7)
 *
 * @param payload Frame payload (must be 8 bytes)
 * @return 8-byte opaque data or error
 */
result<uint64_t> parse_ping_frame(const uint8_t* payload);

/**
 * Parse GOAWAY frame payload (RFC 7540 Section 6.8)
 *
 * @param payload Frame payload
 * @param payload_len Payload length (must be >= 8)
 * @param out_last_stream_id Last stream ID processed
 * @param out_error_code Error code
 * @param out_debug_data Additional debug data
 * @return Success or error
 */
result<void> parse_goaway_frame(
    const uint8_t* payload,
    size_t payload_len,
    uint32_t& out_last_stream_id,
    ErrorCode& out_error_code,
    std::string& out_debug_data
);

/**
 * Parse WINDOW_UPDATE frame payload (RFC 7540 Section 6.9)
 *
 * @param payload Frame payload (must be 4 bytes)
 * @return Window size increment or error
 */
result<uint32_t> parse_window_update_frame(const uint8_t* payload);

/**
 * Parse PUSH_PROMISE frame payload (RFC 7540 Section 6.6)
 *
 * @param header Frame header
 * @param payload Frame payload
 * @param payload_len Payload length
 * @param out_promised_stream_id Promised stream ID
 * @param out_header_block HPACK-encoded header block
 * @return Success or error
 */
result<void> parse_push_promise_frame(
    const FrameHeader& header,
    const uint8_t* payload,
    size_t payload_len,
    uint32_t& out_promised_stream_id,
    std::vector<uint8_t>& out_header_block
);

// Frame serialization functions (for sending responses)
// Legacy allocating versions - prefer the _to variants for zero-allocation

/**
 * Serialize DATA frame.
 */
std::vector<uint8_t> write_data_frame(
    uint32_t stream_id,
    const std::string& data,
    bool end_stream = false
);

/**
 * Serialize HEADERS frame.
 */
std::vector<uint8_t> write_headers_frame(
    uint32_t stream_id,
    const std::vector<uint8_t>& header_block,
    bool end_stream = false,
    bool end_headers = true,
    const PrioritySpec* priority = nullptr
);

/**
 * Serialize SETTINGS frame.
 */
std::vector<uint8_t> write_settings_frame(
    const std::vector<SettingsParameter>& params,
    bool ack = false
);

/**
 * Serialize SETTINGS ACK frame.
 */
std::vector<uint8_t> write_settings_ack();

/**
 * Serialize WINDOW_UPDATE frame.
 */
std::vector<uint8_t> write_window_update_frame(
    uint32_t stream_id,
    uint32_t increment
);

/**
 * Serialize PING frame.
 */
std::vector<uint8_t> write_ping_frame(
    uint64_t opaque_data,
    bool ack = false
);

/**
 * Serialize GOAWAY frame.
 */
std::vector<uint8_t> write_goaway_frame(
    uint32_t last_stream_id,
    ErrorCode error_code,
    const std::string& debug_data = ""
);

/**
 * Serialize RST_STREAM frame.
 */
std::vector<uint8_t> write_rst_stream_frame(
    uint32_t stream_id,
    ErrorCode error_code
);

// ============================================================================
// Zero-allocation frame serialization (_to variants)
// These write directly to a provided buffer, returning bytes written.
// All return 0 on insufficient capacity.
// ============================================================================

/**
 * Serialize DATA frame to buffer (zero-allocation).
 * @param buf Output buffer
 * @param capacity Buffer capacity
 * @param stream_id Stream identifier
 * @param data Data payload
 * @param data_len Data length
 * @param end_stream END_STREAM flag
 * @return Bytes written, or 0 if insufficient capacity
 */
size_t write_data_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* data,
    size_t data_len,
    bool end_stream = false
) noexcept;

/**
 * Serialize HEADERS frame to buffer (zero-allocation).
 * @param buf Output buffer
 * @param capacity Buffer capacity
 * @param stream_id Stream identifier
 * @param header_block HPACK-encoded header block
 * @param header_block_len Header block length
 * @param end_stream END_STREAM flag
 * @param end_headers END_HEADERS flag
 * @param priority Optional priority spec
 * @return Bytes written, or 0 if insufficient capacity
 */
size_t write_headers_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_stream = false,
    bool end_headers = true,
    const PrioritySpec* priority = nullptr
) noexcept;

/**
 * Serialize SETTINGS frame to buffer (zero-allocation).
 * @param buf Output buffer
 * @param capacity Buffer capacity
 * @param params Settings parameters array
 * @param param_count Number of parameters
 * @param ack ACK flag
 * @return Bytes written, or 0 if insufficient capacity
 */
size_t write_settings_frame_to(
    uint8_t* buf,
    size_t capacity,
    const SettingsParameter* params,
    size_t param_count,
    bool ack = false
) noexcept;

/**
 * Serialize SETTINGS ACK frame to buffer (zero-allocation).
 * Always 9 bytes (header only, no payload).
 */
size_t write_settings_ack_to(uint8_t* buf, size_t capacity) noexcept;

/**
 * Serialize WINDOW_UPDATE frame to buffer (zero-allocation).
 * Always 13 bytes (9 header + 4 payload).
 */
size_t write_window_update_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    uint32_t increment
) noexcept;

/**
 * Serialize PING frame to buffer (zero-allocation).
 * Always 17 bytes (9 header + 8 payload).
 */
size_t write_ping_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint64_t opaque_data,
    bool ack = false
) noexcept;

/**
 * Serialize GOAWAY frame to buffer (zero-allocation).
 */
size_t write_goaway_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t last_stream_id,
    ErrorCode error_code,
    const uint8_t* debug_data = nullptr,
    size_t debug_data_len = 0
) noexcept;

/**
 * Serialize RST_STREAM frame to buffer (zero-allocation).
 * Always 13 bytes (9 header + 4 payload).
 */
size_t write_rst_stream_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    ErrorCode error_code
) noexcept;

/**
 * Serialize PUSH_PROMISE frame to buffer (zero-allocation).
 */
size_t write_push_promise_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    uint32_t promised_stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_headers = true
) noexcept;

/**
 * Serialize CONTINUATION frame to buffer (zero-allocation).
 */
size_t write_continuation_frame_to(
    uint8_t* buf,
    size_t capacity,
    uint32_t stream_id,
    const uint8_t* header_block,
    size_t header_block_len,
    bool end_headers = true
) noexcept;

/**
 * HTTP/2 Connection Preface (RFC 7540 Section 3.5)
 *
 * Client must send this as first bytes: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
 */
constexpr const char* CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t CONNECTION_PREFACE_LEN = 24;

} // namespace http2
} // namespace bolt::api
