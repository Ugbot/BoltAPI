#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

/**
 * WebSocket protocol implementation for Bolt API.
 * 
 * Frame parsing algorithms inspired by uWebSockets' high-performance approach.
 * Written from scratch for Bolt API with optimizations for our use case.
 */

namespace bolt::api {
namespace websocket {

/**
 * WebSocket frame opcodes (RFC 6455)
 */
enum class OpCode : uint8_t {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA
};

/**
 * WebSocket close codes (RFC 6455)
 */
enum class CloseCode : uint16_t {
    NORMAL = 1000,
    GOING_AWAY = 1001,
    PROTOCOL_ERROR = 1002,
    UNSUPPORTED_DATA = 1003,
    NO_STATUS = 1005,
    ABNORMAL = 1006,
    INVALID_PAYLOAD = 1007,
    POLICY_VIOLATION = 1008,
    MESSAGE_TOO_BIG = 1009,
    MANDATORY_EXTENSION = 1010,
    INTERNAL_ERROR = 1011,
    TLS_HANDSHAKE = 1015
};

/**
 * WebSocket frame header
 */
struct FrameHeader {
    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;
    OpCode opcode;
    bool mask;
    uint64_t payload_length;
    uint8_t masking_key[4];
    
    FrameHeader()
        : fin(false), rsv1(false), rsv2(false), rsv3(false),
          opcode(OpCode::CONTINUATION), mask(false), payload_length(0) {
        masking_key[0] = masking_key[1] = masking_key[2] = masking_key[3] = 0;
    }
};

/**
 * WebSocket frame parser
 * 
 * High-performance frame parsing inspired by uWebSockets algorithms.
 * Features:
 * - Zero-copy parsing where possible
 * - Minimal allocations
 * - Streaming support for large payloads
 */
class FrameParser {
public:
    FrameParser();
    ~FrameParser();
    
    /**
     * Parse WebSocket frame data.
     * 
     * @param data Input buffer
     * @param length Buffer length
     * @param consumed Number of bytes consumed (output)
     * @param header Frame header (output)
     * @param payload_start Pointer to payload start (output)
     * @param payload_length Payload length (output)
     * @return 0 on success, -1 if more data needed, error code otherwise
     */
    int parse_frame(
        const uint8_t* data,
        size_t length,
        size_t& consumed,
        FrameHeader& header,
        const uint8_t*& payload_start,
        size_t& payload_length
    );
    
    /**
     * Unmask payload data in-place.
     * Uses optimized 8-byte chunk processing.
     * 
     * @param data Payload data (will be modified)
     * @param length Payload length
     * @param masking_key 4-byte masking key
     * @param offset Offset for fragmented messages
     */
    static void unmask(
        uint8_t* data,
        size_t length,
        const uint8_t* masking_key,
        size_t offset = 0
    );
    
    /**
     * Build WebSocket frame.
     * 
     * @param opcode Frame opcode
     * @param payload Payload data
     * @param length Payload length
     * @param fin FIN bit
     * @param rsv1 RSV1 bit (used for compression)
     * @param output Output buffer (will be appended to)
     * @return 0 on success, error code otherwise
     */
    static int build_frame(
        OpCode opcode,
        const uint8_t* payload,
        size_t length,
        bool fin,
        bool rsv1,
        std::string& output
    );
    
    /**
     * Build close frame.
     * 
     * @param code Close code
     * @param reason Close reason (optional)
     * @param output Output buffer
     * @return 0 on success, error code otherwise
     */
    static int build_close_frame(
        CloseCode code,
        const char* reason,
        std::string& output
    );
    
    /**
     * Parse close frame payload.
     * 
     * @param payload Close payload
     * @param length Payload length
     * @param code Close code (output)
     * @param reason Close reason (output)
     * @return 0 on success, error code otherwise
     */
    static int parse_close_payload(
        const uint8_t* payload,
        size_t length,
        CloseCode& code,
        std::string& reason
    );
    
    /**
     * Validate UTF-8 text payload.
     * 
     * @param data UTF-8 data
     * @param length Data length
     * @return true if valid UTF-8, false otherwise
     */
    static bool validate_utf8(const uint8_t* data, size_t length);
    
    /**
     * Reset parser state.
     */
    void reset();
    
private:
    enum class State {
        READING_HEADER,
        READING_PAYLOAD_LENGTH_16,
        READING_PAYLOAD_LENGTH_64,
        READING_MASKING_KEY,
        READING_PAYLOAD,
        COMPLETE,
        // Renamed from ERROR — Windows headers (`wingdi.h`) `#define ERROR 0`,
        // which corrupts this enum the moment any user transitively pulls
        // <windows.h> before this header. Using `kError` keeps the enum
        // Windows-clean.
        kError
    };
    
    State state_;
    FrameHeader current_header_;
    size_t bytes_needed_;
    size_t bytes_read_;
    uint8_t temp_buffer_[14];  // Max header size
    size_t temp_buffer_pos_;
};

/**
 * WebSocket handshake utilities
 */
class HandshakeUtils {
public:
    /**
     * Compute Sec-WebSocket-Accept value.
     * 
     * @param key Sec-WebSocket-Key from client
     * @return Sec-WebSocket-Accept value
     */
    static std::string compute_accept_key(const std::string& key);
    
    /**
     * Validate WebSocket upgrade request.
     * 
     * @param method HTTP method
     * @param upgrade Upgrade header value
     * @param connection Connection header value
     * @param ws_version Sec-WebSocket-Version header value
     * @param ws_key Sec-WebSocket-Key header value
     * @return true if valid, false otherwise
     */
    static bool validate_upgrade_request(
        const std::string& method,
        const std::string& upgrade,
        const std::string& connection,
        const std::string& ws_version,
        const std::string& ws_key
    );
};

} // namespace websocket
} // namespace bolt::api





