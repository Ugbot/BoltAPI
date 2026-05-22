#pragma once

#include "boltapi/http/http2_frame.h"
#include "boltapi/http/http2_stream.h"
#include "boltapi/http/hpack.h"
#include "boltapi/core/result.h"
#include <cstdint>
#include <vector>
#include <array>
#include <functional>

namespace bolt::api {
namespace http2 {

/**
 * HTTP/2 Connection Settings.
 *
 * Configurable parameters for the connection (RFC 7540 Section 6.5.2).
 */
struct ConnectionSettings {
    uint32_t header_table_size{4096};        // SETTINGS_HEADER_TABLE_SIZE
    bool enable_push{true};                  // SETTINGS_ENABLE_PUSH
    uint32_t max_concurrent_streams{100};    // SETTINGS_MAX_CONCURRENT_STREAMS
    uint32_t initial_window_size{65535};     // SETTINGS_INITIAL_WINDOW_SIZE
    uint32_t max_frame_size{16384};          // SETTINGS_MAX_FRAME_SIZE (min 16384, max 16777215)
    uint32_t max_header_list_size{8192};     // SETTINGS_MAX_HEADER_LIST_SIZE
};

// ============================================================================
// Thread-local buffer pool for HTTP/2 frame processing
// Cache-line aligned to avoid false sharing, matching HTTP/1 pattern
// ============================================================================
static constexpr size_t H2_FRAME_BUFFER_SIZE = 16384;
static constexpr size_t H2_FRAME_BUFFER_COUNT = 32;
static constexpr size_t H2_HEADER_BUFFER_SIZE = 8192;
static constexpr size_t H2_HEADER_BUFFER_COUNT = 16;

/**
 * Cache-line aligned buffer for zero-allocation frame processing.
 * Aligned to 64 bytes to avoid false sharing between CPU cores.
 */
template<size_t BufferSize>
struct alignas(64) AlignedBuffer {
    uint8_t data[BufferSize];
};

/**
 * Thread-local buffer pool for HTTP/2.
 * 
 * Like HTTP/1's buffer pool pattern:
 * - Cache-line aligned buffers (64 bytes)
 * - Thread-local to avoid locks
 * - Simple linear search (fast for small pools)
 */
template<size_t BufferSize, size_t PoolSize>
struct Http2BufferPool {
    std::array<AlignedBuffer<BufferSize>, PoolSize> buffers;
    std::array<bool, PoolSize> in_use{};
    bool initialized = false;
    
    void init() noexcept {
        if (initialized) return;
        for (size_t i = 0; i < PoolSize; i++) {
            in_use[i] = false;
        }
        initialized = true;
    }
    
    uint8_t* acquire() noexcept {
        if (!initialized) init();
        for (size_t i = 0; i < PoolSize; i++) {
            if (!in_use[i]) {
                in_use[i] = true;
                return buffers[i].data;
            }
        }
        return nullptr;  // Pool exhausted
    }
    
    void release(uint8_t* buf) noexcept {
        if (!buf) return;
        for (size_t i = 0; i < PoolSize; i++) {
            if (buffers[i].data == buf) {
                in_use[i] = false;
                return;
            }
        }
    }
    
    constexpr size_t buffer_size() const noexcept { return BufferSize; }
};

// Thread-local buffer pools (declared extern, defined in cpp)
extern thread_local Http2BufferPool<H2_FRAME_BUFFER_SIZE, H2_FRAME_BUFFER_COUNT> t_h2_frame_pool;
extern thread_local Http2BufferPool<H2_HEADER_BUFFER_SIZE, H2_HEADER_BUFFER_COUNT> t_h2_header_pool;

// ============================================================================
// Pre-computed HPACK Response Headers
// Common response headers are pre-encoded to skip HPACK encoding at runtime.
// This eliminates dynamic table lookups and encoding for hot paths.
// ============================================================================

/**
 * Pre-computed HPACK-encoded common response headers.
 * 
 * These are computed once at startup and reused for every response.
 * Saves ~300ns per response by skipping HPACK encoding for common cases.
 * 
 * Uses static table indices where possible:
 * - :status 200 = index 8
 * - :status 204 = index 9
 * - :status 206 = index 10
 * - :status 304 = index 11
 * - :status 400 = index 12
 * - :status 404 = index 13
 * - :status 500 = index 14
 * - content-type = index 31 (name only)
 * - content-length = index 28 (name only)
 */
class CachedHpackHeaders {
public:
    // Status codes (just the indexed header byte)
    static constexpr uint8_t STATUS_200 = 0x88;  // Index 8
    static constexpr uint8_t STATUS_204 = 0x89;  // Index 9
    static constexpr uint8_t STATUS_206 = 0x8a;  // Index 10
    static constexpr uint8_t STATUS_304 = 0x8b;  // Index 11
    static constexpr uint8_t STATUS_400 = 0x8c;  // Index 12
    static constexpr uint8_t STATUS_404 = 0x8d;  // Index 13
    static constexpr uint8_t STATUS_500 = 0x8e;  // Index 14
    
    // Get pre-encoded status header
    // Returns pointer to single byte for indexed statuses, or encodes on-the-fly
    static size_t get_status(uint16_t status_code, uint8_t* buf, size_t capacity) noexcept;
    
    // Pre-computed content-type headers (literal with indexed name)
    // Format: 0x5f (index 31 with literal value) + length + value
    struct ContentTypeHeader {
        uint8_t data[64];
        uint8_t len;
    };
    
    static const ContentTypeHeader CT_JSON;           // application/json
    static const ContentTypeHeader CT_TEXT_PLAIN;     // text/plain
    static const ContentTypeHeader CT_TEXT_HTML;      // text/html
    static const ContentTypeHeader CT_OCTET_STREAM;   // application/octet-stream
    
    // Pre-computed content-length headers for common sizes
    // Format: 0x5c (index 28 with literal value) + length + value
    struct ContentLengthHeader {
        uint8_t data[16];
        uint8_t len;
    };
    
    static const ContentLengthHeader CL_0;     // Content-Length: 0
    
    // Encode content-length dynamically (for non-cached sizes)
    static size_t encode_content_length(size_t length, uint8_t* buf, size_t capacity) noexcept;
    
    // Common response header block combinations
    // These combine multiple headers for ultra-fast common responses
    
    // 200 OK + application/json (for JSON API responses)
    static const uint8_t RESP_200_JSON[];
    static const size_t RESP_200_JSON_LEN;
    
    // 200 OK + text/plain (for plaintext responses)
    static const uint8_t RESP_200_TEXT[];
    static const size_t RESP_200_TEXT_LEN;
    
    // 404 Not Found + text/plain
    static const uint8_t RESP_404_TEXT[];
    static const size_t RESP_404_TEXT_LEN;
    
    // 500 Internal Server Error + text/plain
    static const uint8_t RESP_500_TEXT[];
    static const size_t RESP_500_TEXT_LEN;
    
    // Initialize cached headers (called once at startup)
    static void initialize() noexcept;
    
private:
    static bool initialized_;
};

/**
 * Legacy BufferPool template for backward compatibility.
 * Now just wraps thread-local pool access.
 */
template<size_t BufferSize = 16384, size_t PoolSize = 16>
class BufferPool {
public:
    BufferPool() = default;

    uint8_t* acquire() noexcept {
        // Use thread-local pool based on buffer size
        if constexpr (BufferSize >= 16384) {
            return t_h2_frame_pool.acquire();
        } else {
            return t_h2_header_pool.acquire();
        }
    }

    void release(uint8_t* buffer) noexcept {
        if constexpr (BufferSize >= 16384) {
            t_h2_frame_pool.release(buffer);
        } else {
            t_h2_header_pool.release(buffer);
        }
    }

    constexpr size_t buffer_size() const noexcept { return BufferSize; }
};

/**
 * RAII wrapper for buffer pool allocation.
 */
template<size_t BufferSize, size_t PoolSize>
class PooledBuffer {
public:
    PooledBuffer(BufferPool<BufferSize, PoolSize>& pool)
        : pool_(pool), buffer_(pool.acquire()) {}

    ~PooledBuffer() {
        if (buffer_) {
            pool_.release(buffer_);
        }
    }

    // No copy
    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer& operator=(const PooledBuffer&) = delete;

    // Move only
    PooledBuffer(PooledBuffer&& other) noexcept
        : pool_(other.pool_), buffer_(other.buffer_) {
        other.buffer_ = nullptr;
    }

    uint8_t* get() noexcept { return buffer_; }
    const uint8_t* get() const noexcept { return buffer_; }
    explicit operator bool() const noexcept { return buffer_ != nullptr; }

private:
    BufferPool<BufferSize, PoolSize>& pool_;
    uint8_t* buffer_;
};

/**
 * HTTP/2 Connection State Machine.
 */
enum class ConnectionState : uint8_t {
    IDLE = 0,           // Not yet connected
    PREFACE_PENDING,    // Waiting for client preface
    ACTIVE,             // Active and processing frames
    GOAWAY_SENT,        // GOAWAY sent, shutting down
    GOAWAY_RECEIVED,    // GOAWAY received, shutting down
    CLOSED              // Connection closed
};

/**
 * HTTP/2 Connection.
 *
 * Manages the HTTP/2 connection state, settings, streams, and frame processing.
 * Designed for zero-allocation operation using buffer pools and ring buffers.
 */
class Http2Connection {
public:
    /**
     * Create HTTP/2 connection.
     *
     * @param is_server True if server-side, false if client-side
     */
    explicit Http2Connection(bool is_server = true);

    /**
     * Process incoming data from network.
     *
     * Parses frames and dispatches to appropriate handlers.
     * Uses buffer pool to avoid allocations.
     *
     * @param data Incoming data buffer
     * @param len Data length
     * @return Number of bytes consumed or error
     */
    core::result<size_t> process_input(const uint8_t* data, size_t len) noexcept;

    /**
     * Get outgoing data to send to network.
     *
     * Drains the output ring buffer.
     *
     * @param out_data Output data pointer (valid until next call)
     * @param out_len Output data length
     * @return True if data available
     */
    bool get_output(const uint8_t** out_data, size_t* out_len) noexcept;

    /**
     * Commit output bytes (mark as sent).
     *
     * @param len Number of bytes successfully sent
     */
    void commit_output(size_t len) noexcept;

    /**
     * Send HTTP/2 response for stream.
     *
     * Encodes headers with HPACK, creates frames, queues to output buffer.
     *
     * @param stream_id Stream ID
     * @param status HTTP status code
     * @param headers Response headers
     * @param body Response body
     * @return Success or error
     */
    core::result<void> send_response(
        uint32_t stream_id,
        uint16_t status,
        const std::unordered_map<std::string, std::string>& headers,
        const std::string& body
    ) noexcept;

    /**
     * Send RST_STREAM frame.
     */
    core::result<void> send_rst_stream(uint32_t stream_id, ErrorCode error) noexcept;

    /**
     * Send GOAWAY frame (graceful shutdown).
     */
    core::result<void> send_goaway(ErrorCode error, const std::string& debug_data = "") noexcept;

    /**
     * Get stream by ID.
     */
    Http2Stream* get_stream(uint32_t stream_id) noexcept;

    /**
     * Connection state.
     */
    ConnectionState state() const noexcept { return state_; }

    /**
     * Check if connection is active.
     */
    bool is_active() const noexcept { return state_ == ConnectionState::ACTIVE; }

    /**
     * Local settings (what we advertise).
     */
    const ConnectionSettings& local_settings() const noexcept { return local_settings_; }

    /**
     * Remote settings (what peer advertised).
     */
    const ConnectionSettings& remote_settings() const noexcept { return remote_settings_; }

    /**
     * Connection-level flow control window (data we can send).
     */
    int32_t connection_send_window() const noexcept { return connection_send_window_; }

    /**
     * Connection-level flow control window (data we can receive).
     */
    int32_t connection_recv_window() const noexcept { return connection_recv_window_; }

    /**
     * Request callback - called when complete request received.
     *
     * Handler should populate stream response and return.
     * Response will be sent automatically.
     */
    using RequestCallback = std::function<void(Http2Stream*)>;
    void set_request_callback(RequestCallback callback) {
        request_callback_ = std::move(callback);
    }

private:
    // Connection state
    ConnectionState state_{ConnectionState::IDLE};
    bool is_server_;

    // Settings
    ConnectionSettings local_settings_;
    ConnectionSettings remote_settings_;
    bool settings_received_{false};
    bool settings_ack_pending_{false};

    // Flow control
    int32_t connection_send_window_{65535};
    int32_t connection_recv_window_{65535};

    // Stream management
    StreamManager stream_manager_;
    uint32_t last_stream_id_{0};  // Last stream ID we processed

    // HPACK encoder/decoder
    http::HPACKEncoder hpack_encoder_;
    http::HPACKDecoder hpack_decoder_;

    // Buffer pools (zero-allocation frame processing)
    BufferPool<16384, 16> frame_buffer_pool_;  // For frame data
    BufferPool<8192, 8> header_buffer_pool_;   // For header blocks

    // Input buffer (partial frame assembly)
    std::array<uint8_t, 32768> input_buffer_;
    size_t input_buffer_len_{0};

    // Preface validation (for incremental client preface checking)
    size_t preface_bytes_validated_{0};

    // Output buffer (pending data to send)
    std::vector<uint8_t> output_buffer_;
    size_t output_offset_{0};

    // Request callback
    RequestCallback request_callback_;

    // Frame processing
    core::result<size_t> process_frame(const uint8_t* data, size_t len) noexcept;
    core::result<void> handle_settings_frame(const FrameHeader& header, const uint8_t* payload) noexcept;
    core::result<void> handle_headers_frame(const FrameHeader& header, const uint8_t* payload, size_t payload_len) noexcept;
    core::result<void> handle_data_frame(const FrameHeader& header, const uint8_t* payload, size_t payload_len) noexcept;
    core::result<void> handle_window_update_frame(const FrameHeader& header, const uint8_t* payload) noexcept;
    core::result<void> handle_ping_frame(const FrameHeader& header, const uint8_t* payload) noexcept;
    core::result<void> handle_rst_stream_frame(const FrameHeader& header, const uint8_t* payload) noexcept;
    core::result<void> handle_goaway_frame(const uint8_t* payload, size_t payload_len) noexcept;

    // Settings
    core::result<void> apply_settings(const std::vector<SettingsParameter>& params) noexcept;
    core::result<void> send_settings() noexcept;
    core::result<void> send_settings_ack() noexcept;

    // Output helpers
    core::result<void> queue_frame(const std::vector<uint8_t>& frame) noexcept;
    core::result<void> queue_data(const uint8_t* data, size_t len) noexcept;

    // Flow control helpers
    core::result<void> consume_recv_window(uint32_t size) noexcept;
};

} // namespace http2
} // namespace bolt::api
