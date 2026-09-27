#pragma once

#include "boltapi/http/http2_frame.h"
#include "boltapi/http/http2_stream.h"
#include "boltapi/http/hpack.h"
#include "boltapi/http/response_headers.h"
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

using H2FramePool  = Http2BufferPool<H2_FRAME_BUFFER_SIZE, H2_FRAME_BUFFER_COUNT>;
using H2HeaderPool = Http2BufferPool<H2_HEADER_BUFFER_SIZE, H2_HEADER_BUFFER_COUNT>;

// Calling thread's pools, heap-allocated on first use and freed at thread
// exit; only a pointer lives in static TLS (G2CHK-172). nullptr if that one
// allocation fails.
H2FramePool*  h2_frame_pool() noexcept;
H2HeaderPool* h2_header_pool() noexcept;

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
        if constexpr (BufferSize >= 16384) {
            H2FramePool* p = h2_frame_pool();
            return p != nullptr ? p->acquire() : nullptr;
        } else {
            H2HeaderPool* p = h2_header_pool();
            return p != nullptr ? p->acquire() : nullptr;
        }
    }

    void release(uint8_t* buffer) noexcept {
        if (buffer == nullptr) return;
        if constexpr (BufferSize >= 16384) {
            if (H2FramePool* p = h2_frame_pool()) p->release(buffer);
        } else {
            if (H2HeaderPool* p = h2_header_pool()) p->release(buffer);
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
    GOAWAY_RECEIVED,    // GOAWAY received, finishing in-flight streams
    CLOSED              // Connection error sent (or fatal); nothing more is read
};

/**
 * HTTP/2 connection (RFC 9113), server side.
 *
 * process_input() reassembles frames across reads, validates every frame and
 * header block, and answers violations as the RFC prescribes: a connection
 * error queues GOAWAY and returns an error (the caller flushes output and
 * closes); a stream error queues RST_STREAM and the connection carries on.
 * Responses are framed to the peer's SETTINGS_MAX_FRAME_SIZE and paced by
 * both flow-control windows; bodies wait in the stream until WINDOW_UPDATE.
 */
class Http2Connection {
public:
    static constexpr uint32_t kLocalMaxFrameSize = 16384;
    static constexpr uint32_t kMaxConcurrentStreams = 100;
    static constexpr uint32_t kMaxHeaderListSize = 64 * 1024;
    static constexpr size_t kMaxHeaderBlock = 64 * 1024;      // HEADERS + CONTINUATION
    static constexpr size_t kMaxRequestHeaders = 128;
    static constexpr size_t kMaxResponseHeaderBlock = 64 * 1024;
    static constexpr size_t kDefaultMaxRequestBody = 16u * 1024 * 1024;
    static constexpr int32_t kLocalWindow = 65535;            // stream + connection
    static constexpr size_t kMaxControlBacklog = 1u << 20;    // unread control frames
    static constexpr size_t kClosedRing = 256;                // recently closed ids
    static constexpr size_t kMaxFramesPerInput = 1u << 20;

    explicit Http2Connection(bool is_server = true);

    /**
     * Feed bytes read from the peer. Consumes all of them (partial frames
     * are kept for the next call). An error means a connection error was
     * queued as GOAWAY (or the peer is unusable): flush output, then close.
     */
    core::result<size_t> process_input(const uint8_t* data, size_t len) noexcept;

    /** Pending output; valid until the next call into the connection. */
    bool get_output(const uint8_t** out_data, size_t* out_len) noexcept;
    void commit_output(size_t len) noexcept;

    /**
     * Respond on a stream whose request completed. Headers go out at once;
     * the body is framed as the windows allow. Hop-by-hop fields are dropped.
     */
    core::result<void> send_response(
        uint32_t stream_id,
        uint16_t status,
        const http::CoroResponseHeaders& headers,
        const std::string& body
    ) noexcept;

    core::result<void> send_rst_stream(uint32_t stream_id, ErrorCode error) noexcept;
    core::result<void> send_goaway(ErrorCode error, const std::string& debug_data = "") noexcept;

    Http2Stream* get_stream(uint32_t stream_id) noexcept;

    ConnectionState state() const noexcept { return state_; }
    bool is_active() const noexcept { return state_ == ConnectionState::ACTIVE; }

    /** True once nothing more will happen: a connection error was queued, or
     *  the peer's GOAWAY left no stream with work outstanding. */
    bool wants_close() const noexcept;

    /** The code of the connection error we sent, NO_ERROR if none. */
    ErrorCode last_error() const noexcept { return last_error_; }

    void set_max_request_body(size_t bytes) noexcept { max_request_body_ = bytes; }

    const ConnectionSettings& local_settings() const noexcept { return local_settings_; }
    const ConnectionSettings& remote_settings() const noexcept { return remote_settings_; }
    int32_t connection_send_window() const noexcept { return connection_send_window_; }
    int32_t connection_recv_window() const noexcept { return connection_recv_window_; }
    size_t open_stream_count() const noexcept { return open_count_; }

    using RequestCallback = std::function<void(Http2Stream*)>;
    void set_request_callback(RequestCallback callback) {
        request_callback_ = std::move(callback);
    }

private:
    struct HeaderBlockState {
        uint32_t stream_id{0};   // non-zero while CONTINUATION is expected
        bool end_stream{false};
        bool self_dependent{false};
    };

    ConnectionState state_{ConnectionState::IDLE};
    bool is_server_;
    bool first_frame_seen_{false};
    ErrorCode last_error_{ErrorCode::NO_ERROR};

    ConnectionSettings local_settings_;
    ConnectionSettings remote_settings_;
    bool settings_ack_pending_{false};

    int32_t connection_send_window_{65535};
    int32_t connection_recv_window_{kLocalWindow};

    StreamManager stream_manager_;
    uint32_t last_stream_id_{0};  // highest client stream id seen
    std::array<uint32_t, kMaxConcurrentStreams> open_ids_{};
    size_t open_count_{0};
    std::array<uint32_t, kClosedRing> closed_ids_{};
    size_t closed_next_{0};
    size_t max_request_body_{kDefaultMaxRequestBody};

    http::HPACKEncoder hpack_encoder_;
    http::HPACKDecoder hpack_decoder_;
    std::vector<http::HPACKHeader> decoded_;
    std::vector<uint8_t> header_block_;
    HeaderBlockState block_;

    // Frame reassembly across reads: header, then payload.
    std::array<uint8_t, 9 + kLocalMaxFrameSize> input_buffer_{};
    size_t input_buffer_len_{0};
    size_t preface_bytes_validated_{0};

    std::vector<uint8_t> output_buffer_;
    size_t output_offset_{0};

    RequestCallback request_callback_;
    std::vector<uint8_t> encode_buf_;  // response header block scratch (lazy, bounded)

    // Receive path (http2_connection_recv.cpp).
    core::result<void> handle_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_settings_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_headers_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_continuation_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_data_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_window_update_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_ping_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_rst_stream_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_priority_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> handle_goaway_frame(const FrameHeader& h, const uint8_t* payload) noexcept;
    core::result<void> finish_header_block(const HeaderBlockState& st, const uint8_t* block,
                                           size_t len) noexcept;
    core::result<void> open_stream(uint32_t id, bool end_stream) noexcept;
    core::result<void> apply_settings(const uint8_t* payload, size_t len) noexcept;
    core::result<void> replenish(Http2Stream* stream, uint32_t consumed) noexcept;
    core::result<void> complete_request(Http2Stream* stream) noexcept;
    bool is_idle(uint32_t id) const noexcept;

    // Errors.
    core::result<void> connection_error(ErrorCode code) noexcept;
    core::result<void> stream_error(uint32_t stream_id, ErrorCode code) noexcept;
    bool recently_closed(uint32_t id) const noexcept;

    // Stream bookkeeping.
    void close_stream(uint32_t id) noexcept;
    void maybe_close(Http2Stream* stream) noexcept;

    // Send path (http2_connection.cpp).
    core::result<void> send_settings() noexcept;
    void queue_frame(FrameType type, uint8_t flags, uint32_t stream_id,
                     const uint8_t* payload, size_t len) noexcept;
    void queue_header_block(uint32_t stream_id, const uint8_t* block, size_t len,
                            bool end_stream) noexcept;
    void pump_data() noexcept;
    bool pump_stream(Http2Stream* stream) noexcept;
    size_t output_backlog() const noexcept { return output_buffer_.size() - output_offset_; }
};

} // namespace http2
} // namespace bolt::api
