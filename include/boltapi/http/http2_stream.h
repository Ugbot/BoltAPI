#pragma once

#include "boltapi/http/http2_frame.h"
#include "boltapi/http/request_body_buffer.h"
#include "boltapi/core/result.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>

namespace bolt::api {
namespace http2 {

// ============================================================================
// Common Header Value Constants
// Provides string_view to avoid allocations for common header values.
// ============================================================================
namespace common_headers {
    // Common content types
    inline constexpr std::string_view CT_JSON = "application/json";
    inline constexpr std::string_view CT_TEXT_PLAIN = "text/plain";
    inline constexpr std::string_view CT_TEXT_HTML = "text/html";
    inline constexpr std::string_view CT_OCTET_STREAM = "application/octet-stream";
    inline constexpr std::string_view CT_FORM_URLENCODED = "application/x-www-form-urlencoded";
    inline constexpr std::string_view CT_MULTIPART = "multipart/form-data";
    
    // Common HTTP methods
    inline constexpr std::string_view METHOD_GET = "GET";
    inline constexpr std::string_view METHOD_POST = "POST";
    inline constexpr std::string_view METHOD_PUT = "PUT";
    inline constexpr std::string_view METHOD_DELETE = "DELETE";
    inline constexpr std::string_view METHOD_PATCH = "PATCH";
    inline constexpr std::string_view METHOD_HEAD = "HEAD";
    inline constexpr std::string_view METHOD_OPTIONS = "OPTIONS";
    
    // Common header names (lowercase per HTTP/2 spec)
    inline constexpr std::string_view HDR_CONTENT_TYPE = "content-type";
    inline constexpr std::string_view HDR_CONTENT_LENGTH = "content-length";
    inline constexpr std::string_view HDR_ACCEPT = "accept";
    inline constexpr std::string_view HDR_AUTHORIZATION = "authorization";
    inline constexpr std::string_view HDR_CACHE_CONTROL = "cache-control";
    inline constexpr std::string_view HDR_USER_AGENT = "user-agent";
    inline constexpr std::string_view HDR_HOST = "host";
    
    // Pseudo-headers
    inline constexpr std::string_view HDR_METHOD = ":method";
    inline constexpr std::string_view HDR_PATH = ":path";
    inline constexpr std::string_view HDR_SCHEME = ":scheme";
    inline constexpr std::string_view HDR_AUTHORITY = ":authority";
    inline constexpr std::string_view HDR_STATUS = ":status";
    
    // Common cache-control values
    inline constexpr std::string_view CC_NO_CACHE = "no-cache";
    inline constexpr std::string_view CC_NO_STORE = "no-store";
    inline constexpr std::string_view CC_PRIVATE = "private";
    inline constexpr std::string_view CC_PUBLIC = "public";
}

/**
 * Optimized header storage using string_view where possible.
 * 
 * For common values (content-types, methods), uses constexpr string_view
 * to avoid allocations. Falls back to string storage for dynamic values.
 */
struct HeaderView {
    std::string_view name;
    std::string_view value;
    
    // Storage for dynamically-allocated values (when not using constexpr)
    std::string name_storage;
    std::string value_storage;
    
    // Track whether we own the storage (for proper move semantics)
    bool owns_name{false};
    bool owns_value{false};
    
    HeaderView() = default;
    
    // Construct with string_view (zero-copy, references external data)
    HeaderView(std::string_view n, std::string_view v)
        : name(n), value(v), owns_name(false), owns_value(false) {}
    
    // Construct with owned strings
    HeaderView(std::string n, std::string v)
        : name_storage(std::move(n)), value_storage(std::move(v)),
          owns_name(true), owns_value(true) {
        name = name_storage;
        value = value_storage;
    }
    
    // Copy constructor - must re-point string_views if owned
    HeaderView(const HeaderView& other)
        : name_storage(other.name_storage), value_storage(other.value_storage),
          owns_name(other.owns_name), owns_value(other.owns_value) {
        name = owns_name ? std::string_view(name_storage) : other.name;
        value = owns_value ? std::string_view(value_storage) : other.value;
    }
    
    // Move constructor - must re-point string_views after moving storage
    HeaderView(HeaderView&& other) noexcept
        : name_storage(std::move(other.name_storage)),
          value_storage(std::move(other.value_storage)),
          owns_name(other.owns_name), owns_value(other.owns_value) {
        name = owns_name ? std::string_view(name_storage) : other.name;
        value = owns_value ? std::string_view(value_storage) : other.value;
    }
    
    // Copy assignment
    HeaderView& operator=(const HeaderView& other) {
        if (this != &other) {
            name_storage = other.name_storage;
            value_storage = other.value_storage;
            owns_name = other.owns_name;
            owns_value = other.owns_value;
            name = owns_name ? std::string_view(name_storage) : other.name;
            value = owns_value ? std::string_view(value_storage) : other.value;
        }
        return *this;
    }
    
    // Move assignment
    HeaderView& operator=(HeaderView&& other) noexcept {
        if (this != &other) {
            name_storage = std::move(other.name_storage);
            value_storage = std::move(other.value_storage);
            owns_name = other.owns_name;
            owns_value = other.owns_value;
            name = owns_name ? std::string_view(name_storage) : other.name;
            value = owns_value ? std::string_view(value_storage) : other.value;
        }
        return *this;
    }
    
    // Set from string_view (caller must ensure lifetime)
    void set_view(std::string_view n, std::string_view v) {
        name = n;
        value = v;
        name_storage.clear();
        value_storage.clear();
        owns_name = false;
        owns_value = false;
    }
    
    // Set with owned copy
    void set_owned(std::string n, std::string v) {
        name_storage = std::move(n);
        value_storage = std::move(v);
        name = name_storage;
        value = value_storage;
        owns_name = true;
        owns_value = true;
    }
};

/**
 * Fast header lookup for common headers.
 * 
 * Uses a small fixed array for pseudo-headers and common headers,
 * with overflow to vector for rare/custom headers.
 */
class FastHeaders {
public:
    static constexpr size_t COMMON_HEADER_SLOTS = 16;
    
    FastHeaders() = default;
    
    // Add header (auto-detects if common value can use string_view)
    void add(std::string_view name, std::string_view value);
    void add(std::string name, std::string value);
    
    // Get header value by name (returns empty if not found)
    std::string_view get(std::string_view name) const noexcept;
    
    // Check if header exists
    bool has(std::string_view name) const noexcept;
    
    // Get pseudo-headers quickly (no string comparison)
    std::string_view method() const noexcept { return method_; }
    std::string_view path() const noexcept { return path_; }
    std::string_view scheme() const noexcept { return scheme_; }
    std::string_view authority() const noexcept { return authority_; }
    std::string_view status() const noexcept { return status_; }
    
    // Set pseudo-headers
    void set_method(std::string_view m) { method_ = m; }
    void set_path(std::string_view p);
    void set_scheme(std::string_view s) { scheme_ = s; }
    void set_authority(std::string_view a);
    void set_status(std::string_view s) { status_ = s; }
    
    // Iterate all headers
    template<typename Fn>
    void for_each(Fn&& fn) const {
        if (!method_.empty()) fn(common_headers::HDR_METHOD, method_);
        if (!path_.empty()) fn(common_headers::HDR_PATH, path_);
        if (!scheme_.empty()) fn(common_headers::HDR_SCHEME, scheme_);
        if (!authority_.empty()) fn(common_headers::HDR_AUTHORITY, authority_);
        if (!status_.empty()) fn(common_headers::HDR_STATUS, status_);
        
        for (size_t i = 0; i < common_count_; ++i) {
            fn(common_headers_[i].name, common_headers_[i].value);
        }
        for (const auto& h : overflow_headers_) {
            fn(h.name, h.value);
        }
    }
    
    // Get header count
    size_t size() const noexcept;
    
    // Clear all headers
    void clear() noexcept;
    
    // Convert to unordered_map for compatibility
    std::unordered_map<std::string, std::string> to_map() const;
    
private:
    // Pseudo-headers (direct access, no lookup)
    std::string_view method_;
    std::string_view path_;
    std::string_view scheme_;
    std::string_view authority_;
    std::string_view status_;
    
    // Storage for path/authority if they're dynamically set
    std::string path_storage_;
    std::string authority_storage_;
    
    // Common headers in fixed array (fast iteration)
    std::array<HeaderView, COMMON_HEADER_SLOTS> common_headers_;
    size_t common_count_{0};
    
    // Overflow for additional headers
    std::vector<HeaderView> overflow_headers_;
    
    // Try to use constexpr string_view for common values
    static std::string_view intern_content_type(std::string_view value) noexcept;
    static std::string_view intern_method(std::string_view value) noexcept;
};

/**
 * HTTP/2 Stream States (RFC 7540 Section 5.1)
 *
 * Stream state machine:
 *                          +--------+
 *                  send PP |        | recv PP
 *                 ,--------|  idle  |--------.
 *                /         |        |         \
 *               v          +--------+          v
 *        +----------+          |           +----------+
 *        |          |          | send H /  |          |
 * ,------| reserved |          | recv H    | reserved |------.
 * |      | (local)  |          |           | (remote) |      |
 * |      +----------+          v           +----------+      |
 * |          |             +--------+             |          |
 * |          |     recv ES |        | send ES     |          |
 * |   send H |     ,-------|  open  |-------.     | recv H   |
 * |          |    /        |        |        \    |          |
 * |          v   v         +--------+         v   v          |
 * |      +----------+          |           +----------+      |
 * |      |   half   |          |           |   half   |      |
 * |      |  closed  |          | send R /  |  closed  |      |
 * |      | (remote) |          | recv R    | (local)  |      |
 * |      +----------+          |           +----------+      |
 * |           |                |                 |           |
 * |           | send ES /      |       recv ES / |           |
 * |           | send R /       v        send R / |           |
 * |           | recv R     +--------+   recv R   |           |
 * | send R /  `----------->|        |<-----------'  send R / |
 * | recv R                 | closed |               recv R   |
 * `----------------------->|        |<----------------------'
 *                          +--------+
 *
 * send:   endpoint sends this frame
 * recv:   endpoint receives this frame
 * H:      HEADERS frame (with or without END_STREAM flag)
 * PP:     PUSH_PROMISE
 * ES:     END_STREAM flag
 * R:      RST_STREAM frame
 */
enum class StreamState : uint8_t {
    IDLE = 0,              // Not yet used
    RESERVED_LOCAL = 1,    // Reserved by local PUSH_PROMISE
    RESERVED_REMOTE = 2,   // Reserved by remote PUSH_PROMISE
    OPEN = 3,              // Open for both sides
    HALF_CLOSED_LOCAL = 4, // Local sent END_STREAM
    HALF_CLOSED_REMOTE = 5,// Remote sent END_STREAM
    CLOSED = 6             // Stream closed
};

/**
 * HTTP/2 Stream.
 *
 * Represents a single request-response exchange.
 * Handles state machine, flow control, and data buffering.
 */
class Http2Stream {
public:
    // Allow StreamManager to access private members
    friend class StreamManager;

    /**
     * Create stream.
     *
     * @param stream_id Stream ID (must be odd for client-initiated, even for server push)
     * @param initial_window_size Initial flow control window (default 65535)
     */
    explicit Http2Stream(uint32_t stream_id, uint32_t initial_window_size = 65535);

    // Stream ID
    uint32_t id() const noexcept { return stream_id_; }

    // Current state
    StreamState state() const noexcept { return state_; }

    /**
     * State transitions.
     */
    void on_headers_sent(bool end_stream) noexcept;
    void on_headers_received(bool end_stream) noexcept;
    void on_data_sent(bool end_stream) noexcept;
    void on_data_received(bool end_stream) noexcept;
    void on_rst_stream() noexcept;
    void on_push_promise_sent() noexcept;
    void on_push_promise_received() noexcept;

    /**
     * Check if stream is closed.
     */
    bool is_closed() const noexcept { return state_ == StreamState::CLOSED; }

    /**
     * Check if stream can send data.
     */
    bool can_send() const noexcept {
        return state_ == StreamState::OPEN || state_ == StreamState::HALF_CLOSED_REMOTE;
    }

    /**
     * Check if stream can receive data.
     */
    bool can_receive() const noexcept {
        return state_ == StreamState::OPEN || state_ == StreamState::HALF_CLOSED_LOCAL;
    }

    /**
     * Flow control - send window.
     *
     * Amount of data we're allowed to send before receiving WINDOW_UPDATE.
     */
    int32_t send_window() const noexcept { return send_window_; }

    /**
     * Flow control - receive window.
     *
     * Amount of data we can receive before sending WINDOW_UPDATE.
     */
    int32_t recv_window() const noexcept { return recv_window_; }

    /**
     * Update send window (when WINDOW_UPDATE received).
     *
     * @param increment Window increment (must be positive)
     * @return Success or error
     */
    core::result<void> update_send_window(int32_t increment) noexcept;

    /**
     * Update receive window (when we send WINDOW_UPDATE).
     *
     * @param increment Window increment (must be positive)
     * @return Success or error
     */
    core::result<void> update_recv_window(int32_t increment) noexcept;

    /**
     * Consume send window (when DATA frame sent).
     *
     * @param size Data size
     * @return Success or error if window would become negative
     */
    core::result<void> consume_send_window(uint32_t size) noexcept;

    /**
     * Consume receive window (when DATA frame received).
     *
     * @param size Data size
     * @return Success or error if window would become negative
     */
    core::result<void> consume_recv_window(uint32_t size) noexcept;

    /**
     * Priority information (RFC 7540 Section 5.3).
     */
    bool has_priority() const noexcept { return has_priority_; }
    const PrioritySpec& priority() const noexcept { return priority_; }
    void set_priority(const PrioritySpec& spec) noexcept {
        priority_ = spec;
        has_priority_ = true;
    }

    /**
     * Request headers (after HPACK decoding).
     */
    const std::unordered_map<std::string, std::string>& request_headers() const noexcept {
        return request_headers_;
    }

    void add_request_header(std::string name, std::string value) {
        request_headers_[std::move(name)] = std::move(value);
    }

    /**
     * Request body data — backed by thread-local arena pool.
     */
    std::string request_body() const { return body_buf_.to_string(); }
    std::string_view request_body_view() const noexcept { return body_buf_.view(); }
    size_t request_body_size() const noexcept { return body_buf_.size(); }

    void append_request_body(const uint8_t* data, size_t len) {
        body_buf_.append(data, len);
    }

    void append_request_body(const std::string& data) {
        body_buf_.append(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    /**
     * Response status code.
     */
    uint16_t response_status() const noexcept { return response_status_; }
    void set_response_status(uint16_t status) noexcept { response_status_ = status; }

    /**
     * Response headers.
     */
    const std::unordered_map<std::string, std::string>& response_headers() const noexcept {
        return response_headers_;
    }

    void add_response_header(std::string name, std::string value) {
        response_headers_[std::move(name)] = std::move(value);
    }

    /**
     * Response body data.
     */
    const std::string& response_body() const noexcept { return response_body_; }

    void set_response_body(std::string body) {
        response_body_ = std::move(body);
    }

    void append_response_body(std::string data) {
        response_body_.append(std::move(data));
    }

    /**
     * Error code (if RST_STREAM sent/received).
     */
    ErrorCode error_code() const noexcept { return error_code_; }
    void set_error_code(ErrorCode code) noexcept { error_code_ = code; }

private:
    uint32_t stream_id_;
    StreamState state_{StreamState::IDLE};

    // Flow control windows
    int32_t send_window_;  // Data we can send
    int32_t recv_window_;  // Data we can receive

    // Priority
    bool has_priority_{false};
    PrioritySpec priority_;

    // Request data
    std::unordered_map<std::string, std::string> request_headers_;
    http::RequestBodyBuffer body_buf_;

    // Response data
    uint16_t response_status_{200};
    std::unordered_map<std::string, std::string> response_headers_;
    std::string response_body_;

    // Error handling
    ErrorCode error_code_{ErrorCode::NO_ERROR};
};

/**
 * HTTP/2 Stream Manager.
 *
 * Manages all active streams for a connection.
 */
class StreamManager {
public:
    /**
     * Create stream manager.
     *
     * @param initial_window_size Initial flow control window for new streams
     */
    explicit StreamManager(uint32_t initial_window_size = 65535);

    /**
     * Create new stream.
     *
     * @param stream_id Stream ID
     * @return Stream pointer or error if stream already exists
     */
    core::result<Http2Stream*> create_stream(uint32_t stream_id) noexcept;

    /**
     * Get stream by ID.
     *
     * @param stream_id Stream ID
     * @return Stream pointer or nullptr if not found
     */
    Http2Stream* get_stream(uint32_t stream_id) noexcept;

    /**
     * Remove stream (when closed and processed).
     *
     * @param stream_id Stream ID
     */
    void remove_stream(uint32_t stream_id) noexcept;

    /**
     * Get number of active streams.
     */
    size_t stream_count() const noexcept { return streams_.size(); }

    /**
     * Update initial window size for all streams (SETTINGS_INITIAL_WINDOW_SIZE).
     *
     * @param new_size New initial window size
     */
    void update_initial_window_size(uint32_t new_size) noexcept;

    /**
     * Get initial window size.
     */
    uint32_t initial_window_size() const noexcept { return initial_window_size_; }

private:
    std::unordered_map<uint32_t, Http2Stream> streams_;
    uint32_t initial_window_size_;
};

} // namespace http2
} // namespace bolt::api
