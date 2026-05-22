#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

// Forward declarations for uWebSockets
#ifdef FA_USE_UWEBSOCKETS
namespace uWS {
    struct HttpResponse;
}
#endif

/**
 * HTTP response object with streaming and compression support.
 * 
 * Features:
 * - Streaming response support
 * - Automatic zstd compression
 * - JSON serialization
 * - File serving
 * - Chunked transfer encoding
 * - HTTP/2 server push
 */
class HttpResponse {
public:
    // HTTP status codes
    enum class Status {
        OK = 200,
        CREATED = 201,
        ACCEPTED = 202,
        NO_CONTENT = 204,
        PARTIAL_CONTENT = 206,
        MOVED_PERMANENTLY = 301,
        FOUND = 302,
        NOT_MODIFIED = 304,
        BAD_REQUEST = 400,
        UNAUTHORIZED = 401,
        FORBIDDEN = 403,
        NOT_FOUND = 404,
        METHOD_NOT_ALLOWED = 405,
        CONFLICT = 409,
        RANGE_NOT_SATISFIABLE = 416,
        UNPROCESSABLE_ENTITY = 422,
        TOO_MANY_REQUESTS = 429,
        INTERNAL_SERVER_ERROR = 500,
        NOT_IMPLEMENTED = 501,
        BAD_GATEWAY = 502,
        SERVICE_UNAVAILABLE = 503
    };

    // Response types
    enum class Type {
        JSON,
        TEXT,
        HTML,
        BINARY,
        STREAM,
        FILE
    };

    /**
     * Create a new HTTP response.
     */
    HttpResponse();
    
    ~HttpResponse();

    // Non-copyable, movable
    HttpResponse(const HttpResponse&) = delete;
    HttpResponse& operator=(const HttpResponse&) = delete;
    HttpResponse(HttpResponse&&) noexcept;
    HttpResponse& operator=(HttpResponse&&) noexcept;

    /**
     * Set HTTP status code.
     * 
     * @param status HTTP status code
     * @return Reference to this response
     */
    HttpResponse& status(Status status) noexcept;

    /**
     * Set response header.
     * 
     * @param name Header name
     * @param value Header value
     * @return Reference to this response
     */
    HttpResponse& header(const std::string& name, const std::string& value) noexcept;

    /**
     * Set content type.
     * 
     * @param content_type Content type (e.g., "application/json")
     * @return Reference to this response
     */
    HttpResponse& content_type(const std::string& content_type) noexcept;

    /**
     * Send JSON response.
     * 
     * @param data JSON data (will be serialized)
     * @return Reference to this response
     */
    HttpResponse& json(const std::string& data) noexcept;

    /**
     * Set response body without changing content type.
     *
     * @param data Body content
     * @return Reference to this response
     */
    HttpResponse& body(const std::string& data) noexcept;

    /**
     * Send text response.
     *
     * @param text Text content
     * @return Reference to this response
     */
    HttpResponse& text(const std::string& text) noexcept;

    /**
     * Send HTML response.
     * 
     * @param html HTML content
     * @return Reference to this response
     */
    HttpResponse& html(const std::string& html) noexcept;

    /**
     * Send binary response.
     * 
     * @param data Binary data
     * @return Reference to this response
     */
    HttpResponse& binary(const std::vector<uint8_t>& data) noexcept;

    /**
     * Send file response.
     * 
     * @param file_path Path to file
     * @return Reference to this response
     */
    HttpResponse& file(const std::string& file_path) noexcept;

    /**
     * Start streaming response.
     * 
     * @param content_type Content type for stream
     * @return Reference to this response
     */
    HttpResponse& stream(const std::string& content_type = "application/octet-stream") noexcept;

    /**
     * Write data to stream.
     * 
     * @param data Data to write
     * @return Reference to this response
     */
    HttpResponse& write(const std::string& data) noexcept;

    /**
     * Write binary data to stream.
     * 
     * @param data Binary data to write
     * @return Reference to this response
     */
    HttpResponse& write(const std::vector<uint8_t>& data) noexcept;

    /**
     * End streaming response.
     * 
     * @return Reference to this response
     */
    HttpResponse& end() noexcept;

    /**
     * Enable compression for this response.
     * 
     * @param enable Enable compression
     * @return Reference to this response
     */
    HttpResponse& compress(bool enable = true) noexcept;

    /**
     * Set compression level.
     * 
     * @param level Compression level (1-22 for zstd)
     * @return Reference to this response
     */
    HttpResponse& compression_level(int level) noexcept;

    /**
     * Redirect to another URL.
     * 
     * @param url URL to redirect to
     * @param permanent Use permanent redirect (301) instead of temporary (302)
     * @return Reference to this response
     */
    HttpResponse& redirect(const std::string& url, bool permanent = false) noexcept;

    /**
     * Set cookie.
     * 
     * @param name Cookie name
     * @param value Cookie value
     * @param options Cookie options (path, domain, expires, etc.)
     * @return Reference to this response
     */
    HttpResponse& cookie(const std::string& name, const std::string& value, 
                        const std::unordered_map<std::string, std::string>& options = {}) noexcept;

    /**
     * Clear cookie.
     *
     * @param name Cookie name
     * @param path Cookie path
     * @return Reference to this response
     */
    HttpResponse& clear_cookie(const std::string& name, const std::string& path = "/") noexcept;

    /**
     * Set ETag header for caching.
     *
     * @param etag ETag value (will be quoted if not already)
     * @return Reference to this response
     */
    HttpResponse& etag(const std::string& etag) noexcept;

    /**
     * Set Last-Modified header.
     *
     * @param timestamp Unix timestamp
     * @return Reference to this response
     */
    HttpResponse& last_modified(uint64_t timestamp) noexcept;

    /**
     * Set Last-Modified header from string.
     *
     * @param date HTTP date string (e.g., "Sat, 29 Oct 1994 19:43:31 GMT")
     * @return Reference to this response
     */
    HttpResponse& last_modified(const std::string& date) noexcept;

    /**
     * Set Cache-Control header.
     *
     * @param directive Cache-Control directive (e.g., "max-age=3600, public")
     * @return Reference to this response
     */
    HttpResponse& cache_control(const std::string& directive) noexcept;

    /**
     * Send 304 Not Modified response.
     *
     * Clears body and sets appropriate status.
     *
     * @return Reference to this response
     */
    HttpResponse& not_modified() noexcept;

    /**
     * Check if request's If-None-Match header matches our ETag.
     *
     * @param if_none_match Value of If-None-Match header from request
     * @return true if ETag matches (should return 304)
     */
    bool matches_etag(const std::string& if_none_match) const noexcept;

    /**
     * Check if content has been modified since the given date.
     *
     * @param if_modified_since Value of If-Modified-Since header from request
     * @return true if NOT modified (should return 304)
     */
    bool not_modified_since(const std::string& if_modified_since) const noexcept;

    /**
     * Get current ETag value.
     *
     * @return ETag value or empty string
     */
    const std::string& get_etag() const noexcept;

    /**
     * Get Last-Modified timestamp.
     *
     * @return Unix timestamp or 0 if not set
     */
    uint64_t get_last_modified() const noexcept;

    /**
     * Send partial content response (206).
     *
     * @param data Full content data
     * @param start Start byte offset
     * @param end End byte offset (inclusive)
     * @param total Total content length
     * @return Reference to this response
     */
    HttpResponse& partial_content(const std::string& data, size_t start, size_t end, size_t total) noexcept;

    /**
     * Send partial content response for binary data.
     *
     * @param data Full content data
     * @param start Start byte offset
     * @param end End byte offset (inclusive)
     * @param total Total content length
     * @return Reference to this response
     */
    HttpResponse& partial_content(const std::vector<uint8_t>& data, size_t start, size_t end, size_t total) noexcept;

    /**
     * Set Accept-Ranges header to indicate range support.
     *
     * @param unit Range unit (default: "bytes")
     * @return Reference to this response
     */
    HttpResponse& accept_ranges(const std::string& unit = "bytes") noexcept;

    /**
     * Send the response.
     * 
     * @return Error code (0 = success)
     */
    int send() noexcept;

    /**
     * Check if response has been sent.
     * 
     * @return true if sent, false otherwise
     */
    bool is_sent() const noexcept;

    /**
     * Get response size.
     * 
     * @return Response size in bytes
     */
    uint64_t get_size() const noexcept;

    /**
     * Get compression ratio.
     *
     * @return Compression ratio (0.0 = no compression, 1.0 = 100% compression)
     */
    double get_compression_ratio() const noexcept;

    /**
     * Serialize response to HTTP wire format.
     *
     * @param keep_alive Include Connection: keep-alive header
     * @return Complete HTTP response as string (status line + headers + body)
     */
    std::string to_http_wire_format(bool keep_alive = true) const noexcept;

    /**
     * Get status code (for bridge to UnifiedServer).
     *
     * @return HTTP status code
     */
    Status get_status_code() const noexcept { return status_; }

    /**
     * Get headers map (for bridge to UnifiedServer).
     *
     * @return Reference to headers map
     */
    const std::unordered_map<std::string, std::string>& get_headers() const noexcept { return headers_; }

    /**
     * Get response body (for bridge to UnifiedServer).
     *
     * @return Reference to response body
     */
    const std::string& get_body() const noexcept { return body_; }

    /**
     * Constructor for uWebSockets integration.
     *
     * @param res uWebSockets response object
     */
#ifdef FA_USE_UWEBSOCKETS
    HttpResponse(uWS::HttpResponse* res) noexcept;
#endif

private:
    Status status_;
    Type type_;
    std::unordered_map<std::string, std::string> headers_;
    std::string content_type_;
    std::string body_;
    std::vector<uint8_t> binary_body_;
    bool is_streaming_;
    bool is_sent_;
    bool compression_enabled_;
    int compression_level_;
    uint64_t original_size_;
    uint64_t compressed_size_;
    
    // Streaming callback
    std::function<void(const std::string&)> stream_callback_;
    
    // File serving
    std::string file_path_;
    
    // Cookies
    std::vector<std::string> cookies_;

    // Caching
    std::string etag_;
    uint64_t last_modified_timestamp_ = 0;

    // uWebSockets response object
#ifdef FA_USE_UWEBSOCKETS
    uWS::HttpResponse* uws_response_;
#endif

    /**
     * Apply compression to response body.
     * 
     * @return Error code (0 = success)
     */
    int apply_compression() noexcept;

    /**
     * Serialize headers to string.
     * 
     * @return Headers as string
     */
    std::string serialize_headers() const noexcept;

    /**
     * Get status text for status code.
     * 
     * @param status HTTP status code
     * @return Status text
     */
    std::string get_status_text(Status status) const noexcept;
};