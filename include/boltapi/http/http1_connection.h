/**
 * HTTP/1.1 Connection Handler
 *
 * Manages HTTP/1.0 and HTTP/1.1 connections with:
 * - Request parsing (HTTP1Parser)
 * - Response generation
 * - Keep-alive (persistent connections)
 * - Coroutine handler integration
 * - Event loop integration
 *
 * Supports both cleartext and TLS connections.
 */

#pragma once

#include "boltapi/http/http1_parser.h"
#include "boltapi/core/result.h"
#include <string>
#include <string_view>
#include <unordered_map>
#include <functional>
#include <vector>
#include <array>
#include <chrono>
#include <charconv>
#include <cstring>

namespace bolt::api {
namespace http {

/**
 * HTTP/1.1 Connection State
 */
enum class Http1State {
    READING_REQUEST,     // Parsing request headers
    READING_BODY,        // Reading request body
    PROCESSING,          // Calling the request handler
    WRITING_RESPONSE,    // Sending response
    KEEPALIVE,           // Connection kept alive, ready for next request
    CLOSING,             // Connection closing
    ERROR                // Error state
};

/**
 * Zero-copy HTTP request view (for fast callback path)
 * 
 * All string_views point into the connection's input buffer.
 * Valid only during the callback - do not store references.
 */
struct Http1RequestView {
    std::string_view method;
    std::string_view path;
    std::string_view query_string;  // Everything after '?' (empty if none)
    std::string_view body;
    
    // Headers as array of name/value pairs (zero-copy)
    static constexpr size_t MAX_HEADERS = 64;
    std::array<std::pair<std::string_view, std::string_view>, MAX_HEADERS> headers;
    size_t header_count = 0;
    
    // Get header value (case-insensitive search)
    std::string_view get_header(std::string_view name) const noexcept {
        for (size_t i = 0; i < header_count; ++i) {
            if (headers[i].first.size() == name.size()) {
                bool match = true;
                for (size_t j = 0; j < name.size(); ++j) {
                    char a = headers[i].first[j];
                    char b = name[j];
                    // Case-insensitive compare
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = false; break; }
                }
                if (match) return headers[i].second;
            }
        }
        return {};
    }
};

/**
 * HTTP/1.1 Pipelining Constants
 */
static constexpr size_t MAX_PIPELINE_DEPTH = 16;

/**
 * Pipelined request metadata
 * 
 * Tracks the location of a parsed request within the input buffer.
 * The actual request data lives in the connection's input_buffer_.
 */
struct PipelinedRequest {
    size_t buffer_start = 0;      // Offset in input_buffer_ where request starts
    size_t buffer_end = 0;        // Offset where request ends (exclusive)
    bool has_body = false;        // Request has a body
    size_t content_length = 0;    // Body length if present
    bool processed = false;       // Handler has been called
    
    // Cached parsed request view (avoids re-parsing)
    // These are offsets into input_buffer_, converted to string_views at process time
    size_t method_start = 0;
    size_t method_len = 0;
    size_t path_start = 0;
    size_t path_len = 0;
    size_t query_start = 0;       // 0 if no query string
    size_t query_len = 0;
    size_t body_start = 0;
    
    // Header offsets (name_start, name_len, value_start, value_len) packed
    static constexpr size_t MAX_CACHED_HEADERS = 32;
    struct HeaderOffset {
        uint16_t name_start;
        uint8_t name_len;
        uint16_t value_start;
        uint16_t value_len;
    };
    std::array<HeaderOffset, MAX_CACHED_HEADERS> header_offsets{};
    uint8_t header_count = 0;
};

/**
 * Pipelined response slot
 * 
 * Holds a serialized HTTP response waiting to be sent.
 * Responses must be sent in order (FIFO).
 * 
 * Uses a pointer to a pooled buffer to avoid per-response allocation.
 */
struct PipelinedResponse {
    uint8_t* data = nullptr;      // Pointer to pooled buffer
    size_t size = 0;              // Bytes written to buffer
    size_t capacity = 0;          // Buffer capacity
    bool ready = false;           // Response is complete and ready to send
    bool owns_buffer = false;     // True if we need to release to pool
    
    void clear() noexcept {
        // Note: buffer release handled by Http1Connection
        data = nullptr;
        size = 0;
        capacity = 0;
        ready = false;
        owns_buffer = false;
    }
};

/**
 * Ultra-fast response writer (zero allocation)
 * 
 * Writes HTTP response directly to a pre-allocated buffer.
 * Used by UltraFastCallback for maximum performance.
 */
struct FastResponseWriter {
    uint8_t* buffer;
    size_t capacity;
    size_t size = 0;
    
    FastResponseWriter(uint8_t* buf, size_t cap) : buffer(buf), capacity(cap) {}
    
    // Write raw bytes
    bool write(const char* data, size_t len) noexcept {
        if (size + len > capacity) return false;
        memcpy(buffer + size, data, len);
        size += len;
        return true;
    }
    
    // Write string_view
    bool write(std::string_view sv) noexcept {
        return write(sv.data(), sv.size());
    }
    
    // Write common status lines (pre-computed)
    bool write_status_200() noexcept {
        static constexpr char s[] = "HTTP/1.1 200 OK\r\n";
        return write(s, sizeof(s) - 1);
    }

    bool write_status_201() noexcept {
        static constexpr char s[] = "HTTP/1.1 201 Created\r\n";
        return write(s, sizeof(s) - 1);
    }

    bool write_status_400() noexcept {
        static constexpr char s[] = "HTTP/1.1 400 Bad Request\r\n";
        return write(s, sizeof(s) - 1);
    }
    
    // Write Content-Type: application/json
    bool write_content_type_json() noexcept {
        static constexpr char s[] = "Content-Type: application/json\r\n";
        return write(s, sizeof(s) - 1);
    }
    
    // Write Content-Type: text/plain
    bool write_content_type_text() noexcept {
        static constexpr char s[] = "Content-Type: text/plain\r\n";
        return write(s, sizeof(s) - 1);
    }
    
    // Write Connection: keep-alive
    bool write_connection_keepalive() noexcept {
        static constexpr char s[] = "Connection: keep-alive\r\n";
        return write(s, sizeof(s) - 1);
    }
    
    // Write Content-Length with value
    bool write_content_length(size_t len) noexcept {
        char buf[48];
        char* ptr = buf;
        memcpy(ptr, "Content-Length: ", 16);
        ptr += 16;
        auto [end, ec] = std::to_chars(ptr, ptr + 20, len);
        *end++ = '\r';
        *end++ = '\n';
        return write(buf, end - buf);
    }
    
    // Write end of headers
    bool write_headers_end() noexcept {
        return write("\r\n", 2);
    }
};

/**
 * HTTP/1.1 Response
 */
struct Http1Response {
    uint16_t status = 200;
    std::string status_message = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    // WebSocket upgrade flag
    bool websocket_upgrade = false;
    std::string websocket_path;  // Path for WebSocket handler lookup

    // Helper: Add header
    void add_header(const std::string& name, const std::string& value) {
        headers[name] = value;
    }

    // Helper: Set content type
    void set_content_type(const std::string& type) {
        headers["Content-Type"] = type;
    }

    // Helper: Mark as WebSocket upgrade response
    void mark_websocket_upgrade(const std::string& path) {
        websocket_upgrade = true;
        websocket_path = path;
    }
};

/**
 * HTTP/1.1 Connection Handler
 *
 * Manages a single HTTP/1.1 connection lifecycle.
 * Supports keep-alive for connection reuse.
 *
 * Usage:
 *   Http1Connection conn(socket_fd);
 *   conn.set_request_callback(my_handler);
 *
 *   // In event loop:
 *   conn.process_input(data, len);  // Parse request
 *   conn.process_output();           // Send response
 */
class Http1Connection {
public:
    /**
     * Request callback type
     *
     * Called when a complete HTTP request is received.
     * Handler should fill in the response and return.
     *
     * @param method HTTP method string
     * @param path URL path
     * @param headers Request headers
     * @param body Request body
     * @return Response to send to client
     */
    using RequestCallback = std::function<Http1Response(
        const std::string& method,
        const std::string& path,
        const std::unordered_map<std::string, std::string>& headers,
        const std::string& body
    )>;
    
    /**
     * Fast request callback type (zero-copy)
     * 
     * Uses string_view to avoid allocations. All views are valid only
     * during the callback invocation.
     */
    using FastRequestCallback = std::function<Http1Response(const Http1RequestView&)>;
    
    /**
     * Ultra-fast callback type (zero allocation)
     * 
     * Writes response directly to pre-allocated buffer.
     * Returns number of bytes written, or 0 on error.
     * 
     * This is the fastest path - no std::function, no allocations.
     */
    using UltraFastCallback = size_t(*)(const Http1RequestView&, FastResponseWriter&);

    /**
     * Create HTTP/1.1 connection
     *
     * @param socket_fd Socket file descriptor (ownership not transferred)
     */
    explicit Http1Connection(int socket_fd);

    /**
     * Destructor
     */
    ~Http1Connection();

    // Non-copyable, movable
    Http1Connection(const Http1Connection&) = delete;
    Http1Connection& operator=(const Http1Connection&) = delete;
    Http1Connection(Http1Connection&& other) noexcept;
    Http1Connection& operator=(Http1Connection&& other) noexcept;

    /**
     * Set request callback
     *
     * Called when a complete request is received.
     *
     * @param callback Handler function
     */
    void set_request_callback(RequestCallback callback) {
        request_callback_ = std::move(callback);
        fast_request_callback_ = nullptr;  // Clear fast callback
    }
    
    /**
     * Set fast request callback (zero-copy, preferred)
     * 
     * This callback avoids string allocations by using string_view.
     * Provides ~10-20% better throughput for simple handlers.
     */
    void set_fast_request_callback(FastRequestCallback callback) {
        fast_request_callback_ = std::move(callback);
        request_callback_ = nullptr;  // Clear legacy callback
        ultra_fast_callback_ = nullptr;
    }
    
    /**
     * Set ultra-fast callback (zero allocation, maximum performance)
     * 
     * Uses raw function pointer and writes directly to buffer.
     * Best for benchmarks and high-throughput scenarios.
     */
    void set_ultra_fast_callback(UltraFastCallback callback) {
        ultra_fast_callback_ = callback;
        fast_request_callback_ = nullptr;
        request_callback_ = nullptr;
    }

    /**
     * Process incoming data
     *
     * Parse HTTP request from incoming data.
     * May trigger request callback if request is complete.
     *
     * @param data Incoming data buffer
     * @param len Data length
     * @return Number of bytes consumed, or -1 on error
     */
    core::result<size_t> process_input(const uint8_t* data, size_t len) noexcept;

    /**
     * Get output data to send
     *
     * Returns pointer to response data that needs to be sent.
     *
     * @param out_data Output buffer pointer (output)
     * @param out_len Output buffer length (output)
     * @return true if data available, false if none
     */
    bool get_output(const uint8_t** out_data, size_t* out_len) noexcept;

    /**
     * Commit sent output
     *
     * Call after sending data returned by get_output().
     * Advances the output pointer.
     *
     * @param len Number of bytes sent
     */
    void commit_output(size_t len) noexcept;

    /**
     * Get connection state
     */
    Http1State get_state() const noexcept {
        return state_;
    }

    /**
     * Check if connection should be kept alive
     */
    bool should_keep_alive() const noexcept {
        return keep_alive_ && state_ != Http1State::ERROR && state_ != Http1State::CLOSING;
    }

    /**
     * Check if connection has data to send
     */
    bool has_pending_output() const noexcept {
        return output_offset_ < output_buffer_.size();
    }

    /**
     * Reset connection for next request (keep-alive)
     */
    void reset_for_next_request() noexcept;

    /**
     * Get error message (if in ERROR state)
     */
    const std::string& get_error() const noexcept {
        return error_message_;
    }

    /**
     * Mark request start time (for request timeout tracking)
     */
    void mark_request_start() noexcept {
        request_start_time_ = std::chrono::steady_clock::now();
    }

    /**
     * Update last activity time (for idle timeout tracking)
     */
    void mark_activity() noexcept {
        last_activity_time_ = std::chrono::steady_clock::now();
    }

    /**
     * Check if request has timed out
     *
     * @param timeout_ms Maximum request duration in milliseconds
     * @return true if request has exceeded timeout
     */
    bool is_request_timed_out(uint32_t timeout_ms) const noexcept {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - request_start_time_).count();
        return elapsed > timeout_ms;
    }

    /**
     * Check if connection is idle (for keep-alive timeout)
     *
     * @param timeout_ms Maximum idle time in milliseconds
     * @return true if connection has been idle longer than timeout
     */
    bool is_idle_timed_out(uint32_t timeout_ms) const noexcept {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_activity_time_).count();
        return elapsed > timeout_ms;
    }

    /**
     * Get milliseconds elapsed since request started
     */
    uint64_t get_request_elapsed_ms() const noexcept {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            now - request_start_time_).count();
    }

    /**
     * Get milliseconds since last activity
     */
    uint64_t get_idle_time_ms() const noexcept {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_activity_time_).count();
    }

    /**
     * Build and queue a 408 Request Timeout response
     */
    void send_timeout_response() noexcept;

    /**
     * Build and queue a 413 Payload Too Large response
     */
    void send_payload_too_large_response() noexcept;

    /**
     * Build and queue a 431 Request Header Fields Too Large response
     */
    void send_header_too_large_response() noexcept;

    /**
     * Check if Content-Length exceeds max body size
     *
     * @param max_body_size Maximum allowed body size in bytes
     * @return true if body too large (should reject), false if acceptable
     */
    bool is_body_too_large(size_t max_body_size) const noexcept;

    /**
     * Get Content-Length from current request (0 if not set)
     */
    size_t get_content_length() const noexcept;

    /**
     * Check if connection is pending WebSocket upgrade.
     * Returns true if the last response was a 101 Switching Protocols.
     */
    bool is_websocket_upgrade() const noexcept {
        return pending_websocket_upgrade_;
    }

    /**
     * Get WebSocket path (for handler lookup after upgrade).
     */
    const std::string& get_websocket_path() const noexcept {
        return pending_websocket_path_;
    }

private:
    /**
     * Parse request from input buffer
     */
    core::result<void> parse_request() noexcept;

    /**
     * Handle complete request (invoke callback)
     */
    core::result<void> handle_request() noexcept;

    /**
     * Build HTTP response
     */
    void build_response(const Http1Response& response) noexcept;

    /**
     * Build response status line
     */
    std::string build_status_line(uint16_t status, const std::string& message) const;

    /**
     * Should connection be kept alive based on request?
     */
    bool should_keep_alive_from_request(const HTTP1Request& request) const noexcept;

    /**
     * Process all pending pipelined requests
     */
    void process_pending_requests() noexcept;

    /**
     * Flush ready responses to output buffer (in order)
     */
    void flush_ready_responses() noexcept;

    /**
     * Build response into pipelined slot
     */
    void build_pipelined_response(const Http1Response& response, PipelinedResponse& out) noexcept;

    int socket_fd_;
    Http1State state_ = Http1State::READING_REQUEST;

    // Parsing
    HTTP1Parser parser_;
    std::vector<uint8_t> input_buffer_;  // Accumulates partial requests
    HTTP1Request current_request_;
    size_t body_bytes_read_ = 0;
    size_t bytes_consumed_ = 0;  // Bytes consumed by current request (for pipelining)

    // Response
    std::vector<uint8_t> output_buffer_;
    size_t output_offset_ = 0;

    // Keep-alive
    bool keep_alive_ = true;
    size_t requests_served_ = 0;

    // Callbacks
    RequestCallback request_callback_;
    FastRequestCallback fast_request_callback_;
    UltraFastCallback ultra_fast_callback_ = nullptr;

    // Error tracking
    std::string error_message_;

    // WebSocket upgrade tracking
    bool pending_websocket_upgrade_ = false;
    std::string pending_websocket_path_;

    // Timeout tracking
    std::chrono::steady_clock::time_point request_start_time_;
    std::chrono::steady_clock::time_point last_activity_time_;

    // HTTP/1.1 Pipelining support
    std::array<PipelinedRequest, MAX_PIPELINE_DEPTH> pipeline_requests_;
    std::array<PipelinedResponse, MAX_PIPELINE_DEPTH> pipeline_responses_;
    size_t pipeline_write_idx_ = 0;   // Next slot to parse into
    size_t pipeline_read_idx_ = 0;    // Next slot to send from
    size_t pipeline_count_ = 0;       // Number of requests currently in pipeline
    size_t pipeline_parse_pos_ = 0;   // Current parse position in input_buffer_
};

} // namespace http
} // namespace bolt::api
