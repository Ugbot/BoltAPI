/**
 * HTTP/1.1 Connection Implementation
 *
 * Request/response lifecycle management with keep-alive support
 */

#include "boltapi/http/http1_connection.h"
#include "boltapi/core/logger.h"
#include "boltapi/net/sys_compat.h"
#include <cstring>
#include <algorithm>
#include <cerrno>
#include <ctime>
#include <charconv>

namespace bolt::api {
namespace http {

// ============================================================================
// Pre-built static response fragments (avoid per-request string building)
// ============================================================================
static constexpr char HTTP11_200[] = "HTTP/1.1 200 OK\r\n";
static constexpr char HTTP11_201[] = "HTTP/1.1 201 Created\r\n";
static constexpr char HTTP11_204[] = "HTTP/1.1 204 No Content\r\n";
static constexpr char HTTP11_400[] = "HTTP/1.1 400 Bad Request\r\n";
static constexpr char HTTP11_404[] = "HTTP/1.1 404 Not Found\r\n";
static constexpr char HTTP11_500[] = "HTTP/1.1 500 Internal Server Error\r\n";
static constexpr char CONN_KEEPALIVE[] = "Connection: keep-alive\r\n";
static constexpr char CONN_CLOSE[] = "Connection: close\r\n";
static constexpr char CRLF[] = "\r\n";

// Thread-local cached Date header (updated once per second)
thread_local char t_date_header[64] = "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n";
thread_local size_t t_date_header_len = 37;
thread_local time_t t_cached_time = 0;

// Thread-local response buffer (reused to avoid allocations)
thread_local std::vector<uint8_t> t_response_buffer;

// ============================================================================
// Thread-local buffer pool for pipeline responses
// Pre-allocates 16 x 8KB buffers per thread to avoid malloc/free in hot path
// ============================================================================
static constexpr size_t POOL_BUFFER_SIZE = 8192;
static constexpr size_t POOL_BUFFER_COUNT = 16;

struct alignas(64) PoolBuffer {
    uint8_t data[POOL_BUFFER_SIZE];
};

struct BufferPool {
    std::array<PoolBuffer, POOL_BUFFER_COUNT> buffers;
    std::array<bool, POOL_BUFFER_COUNT> in_use{};
    bool initialized = false;
    
    void init() noexcept {
        if (initialized) return;
        for (size_t i = 0; i < POOL_BUFFER_COUNT; i++) {
            in_use[i] = false;
        }
        initialized = true;
    }
    
    // Acquire a buffer from the pool
    // Returns pointer to buffer and its capacity, or nullptr if exhausted
    uint8_t* acquire(size_t& capacity) noexcept {
        if (!initialized) init();
        for (size_t i = 0; i < POOL_BUFFER_COUNT; i++) {
            if (!in_use[i]) {
                in_use[i] = true;
                capacity = POOL_BUFFER_SIZE;
                return buffers[i].data;
            }
        }
        capacity = 0;
        return nullptr;  // Pool exhausted
    }
    
    // Release a buffer back to the pool
    void release(uint8_t* buf) noexcept {
        if (!buf) return;
        for (size_t i = 0; i < POOL_BUFFER_COUNT; i++) {
            if (buffers[i].data == buf) {
                in_use[i] = false;
                return;
            }
        }
    }
};

thread_local BufferPool t_buffer_pool;

static inline void update_cached_date() noexcept {
    time_t now = time(nullptr);
    if (now != t_cached_time) {
        t_cached_time = now;
        struct tm tm_buf;
        gmtime_r(&now, &tm_buf);
        t_date_header_len = strftime(t_date_header, sizeof(t_date_header),
            "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", &tm_buf);
    }
}

// Fast status line lookup
static inline const char* get_status_line(uint16_t status, size_t& len) noexcept {
    switch (status) {
        case 200: len = sizeof(HTTP11_200) - 1; return HTTP11_200;
        case 201: len = sizeof(HTTP11_201) - 1; return HTTP11_201;
        case 204: len = sizeof(HTTP11_204) - 1; return HTTP11_204;
        case 400: len = sizeof(HTTP11_400) - 1; return HTTP11_400;
        case 404: len = sizeof(HTTP11_404) - 1; return HTTP11_404;
        case 500: len = sizeof(HTTP11_500) - 1; return HTTP11_500;
        default: len = 0; return nullptr;
    }
}

using core::result;
using core::ok;
using core::err;
using core::error_code;

Http1Connection::Http1Connection(int socket_fd)
    : socket_fd_(socket_fd)
    , request_start_time_(std::chrono::steady_clock::now())
    , last_activity_time_(std::chrono::steady_clock::now())
{
    input_buffer_.reserve(8192);   // 8KB initial buffer
    output_buffer_.reserve(8192);
}

Http1Connection::~Http1Connection() {
    // Socket cleanup handled by owner
}

Http1Connection::Http1Connection(Http1Connection&& other) noexcept
    : socket_fd_(other.socket_fd_)
    , state_(other.state_)
    , parser_(std::move(other.parser_))
    , input_buffer_(std::move(other.input_buffer_))
    , current_request_(other.current_request_)
    , body_bytes_read_(other.body_bytes_read_)
    , output_buffer_(std::move(other.output_buffer_))
    , output_offset_(other.output_offset_)
    , keep_alive_(other.keep_alive_)
    , requests_served_(other.requests_served_)
    , request_callback_(std::move(other.request_callback_))
    , error_message_(std::move(other.error_message_))
    , request_start_time_(other.request_start_time_)
    , last_activity_time_(other.last_activity_time_)
{
    other.socket_fd_ = -1;
}

Http1Connection& Http1Connection::operator=(Http1Connection&& other) noexcept {
    if (this != &other) {
        socket_fd_ = other.socket_fd_;
        state_ = other.state_;
        parser_ = std::move(other.parser_);
        input_buffer_ = std::move(other.input_buffer_);
        current_request_ = other.current_request_;
        body_bytes_read_ = other.body_bytes_read_;
        output_buffer_ = std::move(other.output_buffer_);
        output_offset_ = other.output_offset_;
        keep_alive_ = other.keep_alive_;
        requests_served_ = other.requests_served_;
        request_callback_ = std::move(other.request_callback_);
        error_message_ = std::move(other.error_message_);
        request_start_time_ = other.request_start_time_;
        last_activity_time_ = other.last_activity_time_;

        other.socket_fd_ = -1;
    }
    return *this;
}

result<size_t> Http1Connection::process_input(const uint8_t* data, size_t len) noexcept {
    if (state_ == Http1State::ERROR || state_ == Http1State::CLOSING) {
        return err<size_t>(error_code::invalid_state);
    }

    // Update activity timestamp - we received data
    mark_activity();

    // If transitioning from KEEPALIVE, mark new request start
    if (state_ == Http1State::KEEPALIVE) {
        mark_request_start();
        state_ = Http1State::READING_REQUEST;
    }

    // Append to input buffer
    input_buffer_.insert(input_buffer_.end(), data, data + len);

    // Parse-ahead loop: extract all complete requests from buffer
    while (pipeline_count_ < MAX_PIPELINE_DEPTH) {
        // Skip if we're past the buffer
        if (pipeline_parse_pos_ >= input_buffer_.size()) {
            break;
        }

        // Try to parse next request
        parser_.reset();
        HTTP1Request temp_request;
        size_t consumed = 0;
        
        int parse_result = parser_.parse(
            input_buffer_.data() + pipeline_parse_pos_,
            input_buffer_.size() - pipeline_parse_pos_,
            temp_request,
            consumed
        );

        if (parse_result < 0) {
            // Need more data - stop parsing
            break;
        }

        if (parse_result > 0) {
            // Parse error
            error_message_ = "HTTP parse error";
            state_ = Http1State::ERROR;
            return err<size_t>(error_code::parse_error);
        }

        // Successfully parsed a request - store in pipeline slot
        auto& slot = pipeline_requests_[pipeline_write_idx_];
        slot.buffer_start = pipeline_parse_pos_;
        slot.buffer_end = pipeline_parse_pos_ + consumed;
        slot.has_body = temp_request.has_content_length && temp_request.content_length > 0;
        slot.content_length = temp_request.content_length;
        slot.processed = false;
        
        // Cache parsed offsets to avoid re-parsing (string_views point into input_buffer_)
        const uint8_t* buf_base = input_buffer_.data();
        slot.method_start = reinterpret_cast<const uint8_t*>(temp_request.method_str.data()) - buf_base;
        slot.method_len = temp_request.method_str.size();
        
        // Use path directly if available, otherwise use url
        std::string_view path_sv = temp_request.path.empty() ? temp_request.url : temp_request.path;
        slot.path_start = reinterpret_cast<const uint8_t*>(path_sv.data()) - buf_base;
        slot.path_len = path_sv.size();
        
        // Query string
        if (!temp_request.query.empty()) {
            slot.query_start = reinterpret_cast<const uint8_t*>(temp_request.query.data()) - buf_base;
            slot.query_len = temp_request.query.size();
        } else {
            slot.query_start = 0;
            slot.query_len = 0;
        }
        
        // Cache headers (up to MAX_CACHED_HEADERS)
        slot.header_count = std::min(temp_request.header_count, 
                                      static_cast<size_t>(PipelinedRequest::MAX_CACHED_HEADERS));
        for (size_t i = 0; i < slot.header_count; ++i) {
            const auto& hdr = temp_request.headers[i];
            slot.header_offsets[i].name_start = static_cast<uint16_t>(
                reinterpret_cast<const uint8_t*>(hdr.name.data()) - buf_base);
            slot.header_offsets[i].name_len = static_cast<uint8_t>(
                std::min(hdr.name.size(), size_t(255)));
            slot.header_offsets[i].value_start = static_cast<uint16_t>(
                reinterpret_cast<const uint8_t*>(hdr.value.data()) - buf_base);
            slot.header_offsets[i].value_len = static_cast<uint16_t>(hdr.value.size());
        }

        // NOTE: Body is already handled by the parser - it returns -1 if body is incomplete,
        // and 'consumed' already includes the body bytes. The body data is available via
        // temp_request.body string_view. No additional body check needed here.

        // Update keep-alive based on first request (for connection state)
        if (pipeline_count_ == 0) {
            keep_alive_ = should_keep_alive_from_request(temp_request);
        }

        // Advance pipeline
        pipeline_parse_pos_ = slot.buffer_end;
        pipeline_write_idx_ = (pipeline_write_idx_ + 1) % MAX_PIPELINE_DEPTH;
        pipeline_count_++;

        LOG_DEBUG("HTTP1", "Parsed pipelined request %zu: %.*s %.*s (bytes %zu-%zu)",
                  pipeline_count_,
                  static_cast<int>(temp_request.method_str.size()), temp_request.method_str.data(),
                  static_cast<int>(temp_request.url.size()), temp_request.url.data(),
                  slot.buffer_start, slot.buffer_end);
    }

    // Process all pending requests and generate responses
    if (pipeline_count_ > 0) {
        process_pending_requests();
    }

    return ok(len);
}

bool Http1Connection::get_output(const uint8_t** out_data, size_t* out_len) noexcept {
    if (output_offset_ >= output_buffer_.size()) {
        return false;
    }

    *out_data = output_buffer_.data() + output_offset_;
    *out_len = output_buffer_.size() - output_offset_;
    return true;
}

void Http1Connection::commit_output(size_t len) noexcept {
    output_offset_ += len;

    // If all sent, check keep-alive
    if (output_offset_ >= output_buffer_.size()) {
        output_buffer_.clear();
        output_offset_ = 0;

        if (keep_alive_ && should_keep_alive()) {
            // Prepare for next request
            reset_for_next_request();
            state_ = Http1State::KEEPALIVE;
        } else {
            state_ = Http1State::CLOSING;
        }
    }
}

void Http1Connection::reset_for_next_request() noexcept {
    // Only compact input buffer when pipeline is fully drained
    if (pipeline_count_ == 0) {
        // All requests processed - compact input buffer
        if (pipeline_parse_pos_ > 0 && pipeline_parse_pos_ <= input_buffer_.size()) {
            input_buffer_.erase(input_buffer_.begin(), input_buffer_.begin() + pipeline_parse_pos_);
        }
        
        // Reset pipeline state
        pipeline_parse_pos_ = 0;
        pipeline_write_idx_ = 0;
        pipeline_read_idx_ = 0;
        
        // Release any pooled buffers and clear response slots
        for (auto& resp : pipeline_responses_) {
            if (resp.owns_buffer && resp.data) {
                t_buffer_pool.release(resp.data);
            }
            resp.clear();
        }
        for (auto& req : pipeline_requests_) {
            req = PipelinedRequest{};
        }
    }
    
    // Clear output state
    output_buffer_.clear();
    output_offset_ = 0;
    body_bytes_read_ = 0;
    bytes_consumed_ = 0;
    parser_.reset();
    current_request_ = HTTP1Request{};
    state_ = Http1State::READING_REQUEST;
    
    // Reset timestamps for next request
    auto now = std::chrono::steady_clock::now();
    request_start_time_ = now;
    last_activity_time_ = now;
}

result<void> Http1Connection::parse_request() noexcept {
    if (input_buffer_.empty()) {
        return ok();  // Need more data
    }

    size_t consumed = 0;
    int parse_result = parser_.parse(
        input_buffer_.data(),
        input_buffer_.size(),
        current_request_,
        consumed
    );

    if (parse_result < 0) {
        // Need more data
        return ok();
    }

    if (parse_result > 0) {
        // Parse error
        error_message_ = "HTTP parse error";
        return err<void>(error_code::parse_error);
    }

    // Store consumed bytes for pipelining support
    bytes_consumed_ = consumed;

    // Success - check keep-alive
    keep_alive_ = should_keep_alive_from_request(current_request_);

    // Debug: Log version and keep-alive status
    LOG_DEBUG("HTTP1", "HTTP version: %d keep-alive: %d", static_cast<int>(current_request_.version), keep_alive_);
    auto conn_hdr = current_request_.get_header("Connection");
    if (!conn_hdr.empty()) {
        LOG_DEBUG("HTTP1", "Connection header: %s", std::string(conn_hdr).c_str());
    }

    return ok();
}

result<void> Http1Connection::handle_request() noexcept {
    if (!request_callback_ && !fast_request_callback_) {
        error_message_ = "No request callback set";
        return err<void>(error_code::invalid_state);
    }

    Http1Response response;
    
    // Fast path: zero-copy callback (preferred)
    if (fast_request_callback_) {
        Http1RequestView view;
        view.method = current_request_.method_str;
        
        // Split URL into path and query string
        std::string_view url = current_request_.url;
        auto query_pos = url.find('?');
        if (query_pos != std::string_view::npos) {
            view.path = url.substr(0, query_pos);
            view.query_string = url.substr(query_pos + 1);
        } else {
            view.path = url;
            view.query_string = {};
        }
        
        // Copy header views (zero-copy - points into input buffer)
        view.header_count = std::min(current_request_.header_count, Http1RequestView::MAX_HEADERS);
        for (size_t i = 0; i < view.header_count; ++i) {
            view.headers[i] = {current_request_.headers[i].name, current_request_.headers[i].value};
        }
        
        // Body view (zero-copy)
        if (current_request_.has_content_length && current_request_.content_length > 0) {
            if (input_buffer_.size() >= current_request_.content_length) {
                const char* body_start = reinterpret_cast<const char*>(
                    input_buffer_.data() + input_buffer_.size() - current_request_.content_length);
                view.body = std::string_view(body_start, current_request_.content_length);
            }
        }
        
        LOG_DEBUG("HTTP1", "Calling fast_request_callback_...");
        response = fast_request_callback_(view);
    } else {
        // Legacy path: allocating callback
        std::unordered_map<std::string, std::string> headers;
        for (size_t i = 0; i < current_request_.header_count; ++i) {
            const auto& header = current_request_.headers[i];
            headers[std::string(header.name)] = std::string(header.value);
        }

        // Extract body
        std::string body;
        if (current_request_.has_content_length && current_request_.content_length > 0) {
            if (input_buffer_.size() >= current_request_.content_length) {
                body = std::string(
                    input_buffer_.end() - current_request_.content_length,
                    input_buffer_.end()
                );
            }
        }

        LOG_DEBUG("HTTP1", "Calling request_callback_...");
        response = request_callback_(
            std::string(current_request_.method_str),
            std::string(current_request_.url),
            headers,
            body
        );
    }

    LOG_DEBUG("HTTP1", "Callback returned, response status=%d", response.status);

    // Build response
    LOG_DEBUG("HTTP1", "Building response...");
    build_response(response);
    LOG_DEBUG("HTTP1", "Response built successfully, size=%zu bytes", output_buffer_.size());

    // Don't send here - let UnifiedServer handle sending through event loop
    return ok();
}

void Http1Connection::build_response(const Http1Response& response) noexcept {
    // Track WebSocket upgrade for connection mode transition
    pending_websocket_upgrade_ = response.websocket_upgrade;
    pending_websocket_path_ = response.websocket_path;

    // Reuse output buffer (just clear, keep capacity)
    output_buffer_.clear();
    
    // Pre-allocate estimated size
    size_t estimated = 256 + response.body.size();
    if (output_buffer_.capacity() < estimated) {
        output_buffer_.reserve(estimated);
    }

    // Status line - use pre-built strings for common codes
    size_t status_len = 0;
    const char* status_line = get_status_line(response.status, status_len);
    if (status_line) {
        output_buffer_.insert(output_buffer_.end(), status_line, status_line + status_len);
    } else {
        // Fallback for uncommon status codes
        char status_buf[64];
        int len = snprintf(status_buf, sizeof(status_buf), "HTTP/1.1 %u %s\r\n",
                          response.status, response.status_message.c_str());
        output_buffer_.insert(output_buffer_.end(), status_buf, status_buf + len);
    }

    // Track important headers
    bool has_content_length = false;
    bool has_connection = false;
    bool has_date = false;

    // Headers
    for (const auto& [name, value] : response.headers) {
        output_buffer_.insert(output_buffer_.end(), name.begin(), name.end());
        output_buffer_.push_back(':');
        output_buffer_.push_back(' ');
        output_buffer_.insert(output_buffer_.end(), value.begin(), value.end());
        output_buffer_.push_back('\r');
        output_buffer_.push_back('\n');

        // Fast check: compare length and first char before full string compare
        if (name.size() == 14 && (name[0] == 'C' || name[0] == 'c')) {
            has_content_length = true;
        } else if (name.size() == 10 && (name[0] == 'C' || name[0] == 'c')) {
            has_connection = true;
        } else if (name.size() == 4 && (name[0] == 'D' || name[0] == 'd')) {
            has_date = true;
        }
    }

    // Add Date header (cached, updated once/second)
    if (!has_date) {
        update_cached_date();
        output_buffer_.insert(output_buffer_.end(), t_date_header, t_date_header + t_date_header_len);
    }

    // Add Content-Length if not present (use to_chars, no allocation)
    if (!has_content_length && !response.body.empty()) {
        char cl_buf[48];
        char* ptr = cl_buf;
        memcpy(ptr, "Content-Length: ", 16);
        ptr += 16;
        auto [end, ec] = std::to_chars(ptr, ptr + 20, response.body.size());
        *end++ = '\r';
        *end++ = '\n';
        output_buffer_.insert(output_buffer_.end(), cl_buf, end);
    }

    // Add Connection header if not present (use pre-built strings)
    if (!has_connection) {
        if (keep_alive_) {
            output_buffer_.insert(output_buffer_.end(), CONN_KEEPALIVE, CONN_KEEPALIVE + sizeof(CONN_KEEPALIVE) - 1);
        } else {
            output_buffer_.insert(output_buffer_.end(), CONN_CLOSE, CONN_CLOSE + sizeof(CONN_CLOSE) - 1);
        }
    }

    // End of headers
    output_buffer_.push_back('\r');
    output_buffer_.push_back('\n');

    // Body
    if (!response.body.empty()) {
        output_buffer_.insert(output_buffer_.end(), response.body.begin(), response.body.end());
    }

    LOG_DEBUG("HTTP1", "Response built: %zu bytes", output_buffer_.size());
}

std::string Http1Connection::build_status_line(uint16_t status, const std::string& message) const {
    return "HTTP/1.1 " + std::to_string(status) + " " + message + "\r\n";
}

bool Http1Connection::should_keep_alive_from_request(const HTTP1Request& request) const noexcept {
    if (request.version == HTTP1Version::HTTP_1_0) {
        // HTTP/1.0: keep-alive only if explicitly requested
        return request.keep_alive;
    }

    if (request.version == HTTP1Version::HTTP_1_1) {
        // HTTP/1.1: keep-alive by default unless Connection: close
        auto conn_header = request.get_header("Connection");
        if (!conn_header.empty()) {
            // Case-insensitive compare for "close"
            std::string conn_str(conn_header);
            std::transform(conn_str.begin(), conn_str.end(), conn_str.begin(),
                         [](unsigned char c){ return std::tolower(c); });
            return conn_str.find("close") == std::string::npos;
        }
        return true;  // Default to keep-alive for HTTP/1.1
    }

    return false;
}

void Http1Connection::send_timeout_response() noexcept {
    // Build 408 Request Timeout response
    Http1Response timeout_response;
    timeout_response.status = 408;
    timeout_response.status_message = "Request Timeout";
    timeout_response.body = "Request Timeout: The server timed out waiting for the request.\r\n";
    timeout_response.add_header("Content-Type", "text/plain");
    timeout_response.add_header("Connection", "close");

    // Don't keep connection alive after timeout
    keep_alive_ = false;

    // Build the response
    build_response(timeout_response);

    // Set state to writing response (will be sent by caller)
    state_ = Http1State::WRITING_RESPONSE;

    LOG_INFO("HTTP1", "Sending 408 Request Timeout (elapsed: %llu ms)", static_cast<unsigned long long>(get_request_elapsed_ms()));
}

void Http1Connection::send_payload_too_large_response() noexcept {
    // Build 413 Payload Too Large response
    Http1Response response;
    response.status = 413;
    response.status_message = "Payload Too Large";
    response.body = "Payload Too Large: The request body exceeds the server's size limit.\r\n";
    response.add_header("Content-Type", "text/plain");
    response.add_header("Connection", "close");

    // Don't keep connection alive after rejection
    keep_alive_ = false;

    // Build the response
    build_response(response);

    // Set state to writing response
    state_ = Http1State::WRITING_RESPONSE;

    LOG_INFO("HTTP1", "Sending 413 Payload Too Large (Content-Length: %zu)", get_content_length());
}

void Http1Connection::send_header_too_large_response() noexcept {
    // Build 431 Request Header Fields Too Large response
    Http1Response response;
    response.status = 431;
    response.status_message = "Request Header Fields Too Large";
    response.body = "Request Header Fields Too Large: The request headers exceed the server's size limit.\r\n";
    response.add_header("Content-Type", "text/plain");
    response.add_header("Connection", "close");

    // Don't keep connection alive after rejection
    keep_alive_ = false;

    // Build the response
    build_response(response);

    // Set state to writing response
    state_ = Http1State::WRITING_RESPONSE;

    LOG_INFO("HTTP1", "Sending 431 Request Header Fields Too Large (header size: %zu)", input_buffer_.size());
}

bool Http1Connection::is_body_too_large(size_t max_body_size) const noexcept {
    // If max_body_size is 0, no limit enforced
    if (max_body_size == 0) return false;

    // Check Content-Length against limit
    size_t content_length = get_content_length();
    return content_length > max_body_size;
}

size_t Http1Connection::get_content_length() const noexcept {
    if (current_request_.has_content_length) {
        return current_request_.content_length;
    }
    return 0;
}

void Http1Connection::process_pending_requests() noexcept {
    // Process each unprocessed request in pipeline order
    size_t idx = pipeline_read_idx_;
    for (size_t i = 0; i < pipeline_count_; i++) {
        auto& req_slot = pipeline_requests_[idx];
        auto& resp_slot = pipeline_responses_[idx];
        
        // Skip already processed requests
        if (req_slot.processed) {
            idx = (idx + 1) % MAX_PIPELINE_DEPTH;
            continue;
        }
        
        // Build request view from cached offsets (no re-parsing needed!)
        const char* buf_base = reinterpret_cast<const char*>(input_buffer_.data());
        
        Http1RequestView view;
        view.method = std::string_view(buf_base + req_slot.method_start, req_slot.method_len);
        view.path = std::string_view(buf_base + req_slot.path_start, req_slot.path_len);
        
        if (req_slot.query_len > 0) {
            view.query_string = std::string_view(buf_base + req_slot.query_start, req_slot.query_len);
        } else {
            view.query_string = {};
        }

        // Reconstruct header views from cached offsets
        view.header_count = req_slot.header_count;
        for (size_t h = 0; h < view.header_count; h++) {
            const auto& hdr_off = req_slot.header_offsets[h];
            view.headers[h] = {
                std::string_view(buf_base + hdr_off.name_start, hdr_off.name_len),
                std::string_view(buf_base + hdr_off.value_start, hdr_off.value_len)
            };
        }
        
        // Body view
        if (req_slot.has_body && req_slot.content_length > 0) {
            size_t body_start = req_slot.buffer_end - req_slot.content_length;
            view.body = std::string_view(buf_base + body_start, req_slot.content_length);
        }
        
        // Call the request handler
        // Try ultra-fast callback first if set
        bool handled_by_ultra_fast = false;
        if (ultra_fast_callback_) {
            // Ultra-fast path: write directly to pooled buffer, zero allocations
            size_t capacity = 0;
            uint8_t* buf = t_buffer_pool.acquire(capacity);

            if (buf) {
                FastResponseWriter writer(buf, capacity);
                size_t written = ultra_fast_callback_(view, writer);

                if (written > 0) {
                    handled_by_ultra_fast = true;
                    resp_slot.data = buf;
                    resp_slot.size = written;
                    resp_slot.capacity = capacity;
                    resp_slot.owns_buffer = true;
                    resp_slot.ready = true;

                    // Check if this is a WebSocket upgrade response (HTTP/1.1 101)
                    // Ultra-fast callback doesn't set websocket_upgrade flag, so detect it here
                    static constexpr char ws_upgrade_prefix[] = "HTTP/1.1 101";
                    if (written >= sizeof(ws_upgrade_prefix) - 1 &&
                        memcmp(buf, ws_upgrade_prefix, sizeof(ws_upgrade_prefix) - 1) == 0) {
                        pending_websocket_upgrade_ = true;
                        pending_websocket_path_ = std::string(view.path);
                        LOG_DEBUG("HTTP1", "Detected WebSocket upgrade via ultra-fast callback for path: %s",
                                  pending_websocket_path_.c_str());
                    }
                    req_slot.processed = true;
                } else {
                    // Callback returned 0 - didn't handle this path
                    // Release buffer and fall through to normal routing
                    t_buffer_pool.release(buf);
                }
            } else {
                // Pool exhausted - use static error response
                handled_by_ultra_fast = true;
                static constexpr char err_resp[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\nConnection: close\r\n\r\nService Unavailable";
                resp_slot.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(err_resp));
                resp_slot.size = sizeof(err_resp) - 1;
                resp_slot.capacity = 0;
                resp_slot.owns_buffer = false;  // Don't release static buffer
                resp_slot.ready = true;
                req_slot.processed = true;
            }
        }

        // Normal routing path (used when ultra_fast_callback_ is not set or returned 0)
        if (!handled_by_ultra_fast) {
            Http1Response response;
            if (fast_request_callback_) {
                response = fast_request_callback_(view);
            } else if (request_callback_) {
                // Legacy callback - need to allocate
                std::unordered_map<std::string, std::string> headers;
                for (size_t h = 0; h < view.header_count; h++) {
                    headers[std::string(view.headers[h].first)] = std::string(view.headers[h].second);
                }
                // Reconstruct full URL with query string
                std::string full_url(view.path);
                if (!view.query_string.empty()) {
                    full_url += '?';
                    full_url += view.query_string;
                }
                response = request_callback_(
                    std::string(view.method),
                    full_url,
                    headers,
                    std::string(view.body)
                );
            } else {
                // No callback - return 500
                response.status = 500;
                response.status_message = "Internal Server Error";
                response.body = "No request handler configured";
            }
            
            // Build response into the pipeline slot
            build_pipelined_response(response, resp_slot);

            // Check if this is a WebSocket upgrade response (fast_request_callback path)
            if (response.websocket_upgrade) {
                pending_websocket_upgrade_ = true;
                pending_websocket_path_ = response.websocket_path;
                LOG_DEBUG("HTTP1", "WebSocket upgrade via fast_request_callback for path: %s",
                          pending_websocket_path_.c_str());
            }

            req_slot.processed = true;
        }
        
        LOG_DEBUG("HTTP1", "Processed pipelined request %zu, response %zu bytes",
                  i, resp_slot.size);
        
        idx = (idx + 1) % MAX_PIPELINE_DEPTH;
    }
    
    // Flush ready responses to output buffer
    flush_ready_responses();
}

void Http1Connection::flush_ready_responses() noexcept {
    // Copy ready responses to output_buffer_ for send()
    while (pipeline_count_ > 0) {
        auto& resp = pipeline_responses_[pipeline_read_idx_];
        
        if (!resp.ready) {
            // Head response not ready yet - must wait (head-of-line blocking)
            break;
        }
        
        // Append response to output buffer
        if (resp.data && resp.size > 0) {
            output_buffer_.insert(output_buffer_.end(), resp.data, resp.data + resp.size);
        }
        
        // Release buffer back to pool if we own it
        if (resp.owns_buffer && resp.data) {
            t_buffer_pool.release(resp.data);
        }
        
        // Clear slot for reuse
        resp.clear();
        
        // Advance read pointer
        pipeline_read_idx_ = (pipeline_read_idx_ + 1) % MAX_PIPELINE_DEPTH;
        pipeline_count_--;
        requests_served_++;
        
        LOG_DEBUG("HTTP1", "Flushed pipelined response, %zu remaining in pipeline", pipeline_count_);
    }
    
    // Update connection state
    if (!output_buffer_.empty()) {
        state_ = Http1State::WRITING_RESPONSE;
    } else if (pipeline_count_ == 0) {
        // Pipeline empty and no pending output
        state_ = keep_alive_ ? Http1State::KEEPALIVE : Http1State::CLOSING;
    }
}

void Http1Connection::build_pipelined_response(const Http1Response& response, PipelinedResponse& out) noexcept {
    // Acquire buffer from pool
    size_t capacity = 0;
    uint8_t* buf = t_buffer_pool.acquire(capacity);
    
    if (!buf) {
        // Pool exhausted - use static error response
        static constexpr char err_resp[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\nConnection: close\r\n\r\nService Unavailable";
        out.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(err_resp));
        out.size = sizeof(err_resp) - 1;
        out.capacity = 0;
        out.owns_buffer = false;
        out.ready = true;
        return;
    }
    
    size_t pos = 0;
    
    // Helper to write to buffer
    auto write = [&](const char* data, size_t len) -> bool {
        if (pos + len > capacity) return false;
        memcpy(buf + pos, data, len);
        pos += len;
        return true;
    };
    
    // Status line - try fast path first
    size_t status_len = 0;
    const char* status_line = get_status_line(response.status, status_len);
    if (status_line) {
        write(status_line, status_len);
    } else {
        // Fallback for uncommon status codes
        char status_buf[64];
        int len = snprintf(status_buf, sizeof(status_buf), "HTTP/1.1 %u %s\r\n",
                          response.status, response.status_message.c_str());
        write(status_buf, len);
    }
    
    // Track important headers
    bool has_content_length = false;
    bool has_connection = false;
    bool has_date = false;
    
    // Headers
    for (const auto& [name, value] : response.headers) {
        write(name.data(), name.size());
        write(": ", 2);
        write(value.data(), value.size());
        write("\r\n", 2);
        
        // Fast check: compare length and first char before full string compare
        if (name.size() == 14 && (name[0] == 'C' || name[0] == 'c')) {
            has_content_length = true;
        } else if (name.size() == 10 && (name[0] == 'C' || name[0] == 'c')) {
            has_connection = true;
        } else if (name.size() == 4 && (name[0] == 'D' || name[0] == 'd')) {
            has_date = true;
        }
    }
    
    // Add Date header (cached, updated once/second)
    if (!has_date) {
        update_cached_date();
        write(t_date_header, t_date_header_len);
    }
    
    // Add Content-Length using to_chars (no allocation)
    if (!has_content_length) {
        char cl_buf[48];
        char* ptr = cl_buf;
        memcpy(ptr, "Content-Length: ", 16);
        ptr += 16;
        auto [end, ec] = std::to_chars(ptr, ptr + 20, response.body.size());
        *end++ = '\r';
        *end++ = '\n';
        write(cl_buf, end - cl_buf);
    }
    
    // Add Connection header if not present (always keep-alive for pipelining)
    if (!has_connection) {
        write(CONN_KEEPALIVE, sizeof(CONN_KEEPALIVE) - 1);
    }
    
    // End of headers
    write("\r\n", 2);
    
    // Body
    if (!response.body.empty()) {
        write(response.body.data(), response.body.size());
    }
    
    // Set output
    out.data = buf;
    out.size = pos;
    out.capacity = capacity;
    out.owns_buffer = true;
    out.ready = true;
}

} // namespace http
} // namespace bolt::api
