#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <array>

namespace bolt::api {
namespace http {

/**
 * Zero-allocation HTTP/1.0 and HTTP/1.1 parser.
 * 
 * Based on llhttp state machine but adapted for:
 * - Zero heap allocations (stack only)
 * - Zero-copy parsing (string_view)
 * - No callbacks (direct returns)
 * - Inline hot paths
 * - No exceptions
 * 
 * HTTP/1.1 Spec: RFC 7230-7235
 * Algorithm from: llhttp (Node.js HTTP parser)
 * 
 * Performance targets:
 * - Parse request line: <50ns
 * - Parse header: <30ns per header
 * - Zero allocations
 * - Zero copies
 */

/**
 * HTTP method enumeration.
 */
enum class HTTP1Method : uint8_t {
    GET = 0,
    HEAD = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    CONNECT = 5,
    OPTIONS = 6,
    TRACE = 7,
    PATCH = 8,
    // Add more as needed
    UNKNOWN = 255
};

/**
 * HTTP version.
 */
enum class HTTP1Version : uint8_t {
    HTTP_1_0 = 0,
    HTTP_1_1 = 1,
    HTTP_2_0 = 2,  // Upgrade from HTTP/1.1
    UNKNOWN = 255
};

/**
 * Parser state.
 */
enum class HTTP1State : uint8_t {
    START,
    METHOD,
    URL,
    VERSION,
    HEADER_FIELD,
    HEADER_VALUE,
    BODY,
    COMPLETE,
    ERROR
};

/**
 * Parsed HTTP/1.x request.
 * 
 * All string_views point into the original buffer (zero-copy).
 */
struct HTTP1Request {
    HTTP1Method method{HTTP1Method::UNKNOWN};
    HTTP1Version version{HTTP1Version::HTTP_1_1};
    
    std::string_view method_str;
    std::string_view url;
    std::string_view path;      // Extracted from URL
    std::string_view query;     // Extracted from URL
    std::string_view fragment;  // Extracted from URL
    
    // Headers (max 100 for safety)
    static constexpr size_t MAX_HEADERS = 100;
    struct Header {
        std::string_view name;
        std::string_view value;
    };
    std::array<Header, MAX_HEADERS> headers;
    size_t header_count{0};
    
    // Body
    std::string_view body;
    
    // Content-Length (if present)
    uint64_t content_length{0};
    bool has_content_length{false};
    
    // Transfer-Encoding
    bool chunked{false};
    
    // Connection
    bool keep_alive{false};
    bool upgrade{false};
    std::string_view upgrade_protocol;
    
    /**
     * Get header value by name (case-insensitive).
     */
    std::string_view get_header(std::string_view name) const noexcept;
    
    /**
     * Check if header exists.
     */
    bool has_header(std::string_view name) const noexcept;
};

/**
 * HTTP/1.x parser (stateful).
 * 
 * Parses HTTP/1.0 and HTTP/1.1 requests with zero allocations.
 */
class HTTP1Parser {
public:
    HTTP1Parser();
    
    /**
     * Parse HTTP request from buffer.
     * 
     * @param data Input buffer (must remain valid during access to request)
     * @param len Buffer length
     * @param out_request Parsed request (views into data buffer)
     * @param out_consumed Bytes consumed from buffer
     * @return 0 on success, 1 on error, -1 if need more data
     * 
     * Note: out_request.headers contain string_views into the data buffer.
     * The buffer must remain valid while using the request.
     */
    int parse(
        const uint8_t* data,
        size_t len,
        HTTP1Request& out_request,
        size_t& out_consumed
    ) noexcept;
    
    /**
     * Reset parser state for new request.
     */
    void reset() noexcept;
    
    /**
     * Get current parser state.
     */
    HTTP1State get_state() const noexcept { return state_; }
    
    /**
     * Check if request is complete.
     */
    bool is_complete() const noexcept { return state_ == HTTP1State::COMPLETE; }
    
    /**
     * Check if parser is in error state.
     */
    bool has_error() const noexcept { return state_ == HTTP1State::ERROR; }
    
private:
    HTTP1State state_;
    size_t pos_;  // Current position in buffer
    
    // Temporary state for multi-step parsing
    size_t mark_;  // Start of current token
    
    /**
     * Parse method (GET, POST, etc.).
     */
    int parse_method(
        const uint8_t* data,
        size_t len,
        HTTP1Request& req
    ) noexcept;
    
    /**
     * Parse URL.
     */
    int parse_url(
        const uint8_t* data,
        size_t len,
        HTTP1Request& req
    ) noexcept;
    
    /**
     * Parse HTTP version.
     */
    int parse_version(
        const uint8_t* data,
        size_t len,
        HTTP1Request& req
    ) noexcept;
    
    /**
     * Parse header field.
     */
    int parse_header_field(
        const uint8_t* data,
        size_t len,
        HTTP1Request& req
    ) noexcept;
    
    /**
     * Parse header value.
     */
    int parse_header_value(
        const uint8_t* data,
        size_t len,
        HTTP1Request& req
    ) noexcept;
    
    /**
     * Parse URL components (path, query, fragment).
     */
    void parse_url_components(HTTP1Request& req) noexcept;
    
    /**
     * Check if character is a token character.
     */
    static bool is_token_char(uint8_t c) noexcept;
    
    /**
     * Check if character is whitespace.
     */
    static bool is_whitespace(uint8_t c) noexcept;
    
public:
    /**
     * Case-insensitive string compare (public for HTTP1Request::get_header).
     */
    static bool str_eq_ci(std::string_view a, std::string_view b) noexcept;
};

} // namespace http
} // namespace bolt::api

