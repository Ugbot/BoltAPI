#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <cstdint>
#include "boltapi/http/multipart_parser.h"

// Forward declarations for uWebSockets
#ifdef FA_USE_UWEBSOCKETS
namespace uWS {
    struct HttpRequest;
}
#endif

/**
 * HTTP request object with zero-copy access to headers and body.
 * 
 * Features:
 * - Zero-copy header access
 * - Streaming body support
 * - Path parameter extraction
 * - Query parameter parsing
 * - Multipart form data
 * - JSON body parsing
 */
class HttpRequest {
public:
    // HTTP methods
    enum class Method {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH,
        HEAD,
        OPTIONS,
        CONNECT,
        TRACE
    };

    /**
     * Get HTTP method.
     * 
     * @return HTTP method
     */
    Method get_method() const noexcept;

    /**
     * Get request path.
     * 
     * @return Request path
     */
    const std::string& get_path() const noexcept;

    /**
     * Get query string.
     * 
     * @return Query string
     */
    const std::string& get_query() const noexcept;

    /**
     * Get HTTP version.
     * 
     * @return HTTP version (e.g., "HTTP/1.1", "HTTP/2.0")
     */
    const std::string& get_version() const noexcept;

    /**
     * Get header value.
     * 
     * @param name Header name (case-insensitive)
     * @return Header value, or empty string if not found
     */
    std::string get_header(const std::string& name) const noexcept;

    /**
     * Get all headers.
     * 
     * @return Map of header name -> value
     */
    const std::unordered_map<std::string, std::string>& get_headers() const noexcept;

    /**
     * Get query parameter.
     * 
     * @param name Parameter name
     * @return Parameter value, or empty string if not found
     */
    std::string get_query_param(const std::string& name) const noexcept;

    /**
     * Get path parameter (from route pattern).
     * 
     * @param name Parameter name
     * @return Parameter value, or empty string if not found
     */
    std::string get_path_param(const std::string& name) const noexcept;

    /**
     * Get request body.
     * 
     * @return Request body as string
     */
    const std::string& get_body() const noexcept;

    /**
     * Get request body as bytes.
     * 
     * @return Request body as byte vector
     */
    const std::vector<uint8_t>& get_body_bytes() const noexcept;

    /**
     * Get content type.
     * 
     * @return Content type header value
     */
    std::string get_content_type() const noexcept;

    /**
     * Get content length.
     * 
     * @return Content length, or 0 if not specified
     */
    uint64_t get_content_length() const noexcept;

    /**
     * Check if request has JSON body.
     * 
     * @return true if content type is application/json
     */
    bool is_json() const noexcept;

    /**
     * Check if request has multipart body.
     *
     * @return true if content type is multipart/form-data
     */
    bool is_multipart() const noexcept;

    /**
     * Get all uploaded files from multipart request.
     *
     * Parses the multipart body on first call and caches the result.
     *
     * @return Vector of uploaded files
     */
    const std::vector<bolt::api::FileUpload>& files() noexcept;

    /**
     * Get all form fields from multipart request.
     *
     * Parses the multipart body on first call and caches the result.
     *
     * @return Vector of form fields
     */
    const std::vector<bolt::api::FormField>& form_fields() noexcept;

    /**
     * Get uploaded file by field name.
     *
     * @param name Field name
     * @return Pointer to file upload, or nullptr if not found
     */
    const bolt::api::FileUpload* get_file(const std::string& name) noexcept;

    /**
     * Get form field value by name.
     *
     * @param name Field name
     * @return Field value, or empty string if not found
     */
    std::string get_form_field(const std::string& name) noexcept;

    /**
     * Get client IP address.
     * 
     * @return Client IP address
     */
    const std::string& get_client_ip() const noexcept;

    /**
     * Get user agent.
     * 
     * @return User agent header value
     */
    std::string get_user_agent() const noexcept;

    /**
     * Get request ID (for tracing).
     * 
     * @return Unique request ID
     */
    uint64_t get_request_id() const noexcept;

    /**
     * Get request timestamp.
     * 
     * @return Request timestamp in nanoseconds
     */
    uint64_t get_timestamp() const noexcept;

    /**
     * Check if request is over HTTPS.
     * 
     * @return true if HTTPS, false otherwise
     */
    bool is_secure() const noexcept;

    /**
     * Get protocol (HTTP/1.1, HTTP/2, HTTP/3).
     * 
     * @return Protocol string
     */
    const std::string& get_protocol() const noexcept;

public:
    /**
     * Default constructor.
     */
    HttpRequest() noexcept;

    /**
     * Constructor for uWebSockets integration.
     *
     * @param req uWebSockets request object
     */
#ifdef FA_USE_UWEBSOCKETS
    HttpRequest(const uWS::HttpRequest* req) noexcept;
#endif

    /**
     * Create HttpRequest from parsed data.
     *
     * @param method HTTP method string
     * @param path Request path
     * @param headers Map of headers
     * @param body Request body
     * @return Populated HttpRequest object
     */
    static HttpRequest from_parsed_data(
        const std::string& method,
        const std::string& path,
        const std::unordered_map<std::string, std::string>& headers,
        const std::string& body
    ) noexcept;

private:
    Method method_;
    std::string path_;
    std::string query_;
    std::string version_;
    std::string protocol_;
    std::unordered_map<std::string, std::string> headers_;
    std::unordered_map<std::string, std::string> query_params_;
    std::unordered_map<std::string, std::string> path_params_;
    std::string body_;
    std::vector<uint8_t> body_bytes_;
    std::string client_ip_;
    uint64_t request_id_;
    uint64_t timestamp_;
    bool secure_;

    // Multipart form data (lazy-parsed and cached)
    mutable bool multipart_parsed_ = false;
    mutable std::vector<bolt::api::FileUpload> files_;
    mutable std::vector<bolt::api::FormField> form_fields_;

    // Parse query string into parameters
    void parse_query_params() noexcept;

    // Parse content type
    std::string parse_content_type() const noexcept;

    // Parse multipart body (lazy)
    void parse_multipart() const noexcept;
};