/**
 * HTTP CORS (Cross-Origin Resource Sharing) Middleware
 *
 * Production-grade CORS handling for APIs.
 *
 * Features:
 * - Preflight (OPTIONS) request handling
 * - Configurable allowed origins (including wildcards)
 * - Configurable allowed methods and headers
 * - Credentials support
 * - Max-age caching for preflight responses
 * - Origin validation
 */

#pragma once

#include "boltapi/http/http1_connection.h"
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <regex>
#include <functional>
#include <optional>

namespace bolt::api {
namespace http {

/**
 * CORS configuration
 */
struct CorsConfig {
    // Allowed origins
    // - "*" allows all origins (not recommended with credentials)
    // - Specific origins: "https://example.com"
    // - Patterns: "*.example.com" (requires custom matching)
    std::vector<std::string> allowed_origins = {"*"};

    // Allowed HTTP methods
    std::vector<std::string> allowed_methods = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
    };

    // Allowed request headers
    std::vector<std::string> allowed_headers = {
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With"
    };

    // Headers exposed to the client
    std::vector<std::string> expose_headers = {};

    // Allow credentials (cookies, authorization headers)
    bool allow_credentials = false;

    // Max age for preflight cache (seconds)
    // 0 means no caching, -1 means don't include header
    int max_age = 86400;  // 24 hours

    // Whether to pass through requests with no Origin header
    bool allow_no_origin = true;

    // Custom origin validator (for complex patterns)
    std::function<bool(const std::string&)> origin_validator = nullptr;

    CorsConfig() = default;
};

/**
 * CORS request type
 */
enum class CorsRequestType {
    NOT_CORS,           // No Origin header
    SIMPLE,             // Simple request (GET, HEAD, POST with simple content)
    PREFLIGHT,          // OPTIONS request with CORS headers
    ACTUAL              // Actual cross-origin request
};

/**
 * CORS check result
 */
struct CorsResult {
    bool allowed{false};
    CorsRequestType request_type{CorsRequestType::NOT_CORS};
    std::string allowed_origin;
    std::unordered_map<std::string, std::string> headers;
    bool is_preflight{false};
};

/**
 * CORS Middleware
 *
 * Handles CORS headers for HTTP requests.
 *
 * Usage:
 *   CorsConfig config;
 *   config.allowed_origins = {"https://example.com"};
 *   config.allow_credentials = true;
 *
 *   CorsMiddleware cors(config);
 *
 *   // Check request
 *   auto result = cors.check(method, request_headers);
 *   if (result.is_preflight) {
 *       // Return preflight response with result.headers
 *   } else if (result.allowed) {
 *       // Process request and add result.headers to response
 *   } else {
 *       // Return 403 Forbidden
 *   }
 */
class CorsMiddleware {
public:
    /**
     * Create CORS middleware with default configuration
     */
    CorsMiddleware() {
        build_sets();
    }

    /**
     * Create CORS middleware with custom configuration
     */
    explicit CorsMiddleware(const CorsConfig& config)
        : config_(config) {
        build_sets();
    }

    /**
     * Check CORS for request
     *
     * @param method HTTP method
     * @param headers Request headers
     * @return CORS result with headers to add to response
     */
    CorsResult check(
        const std::string& method,
        const std::unordered_map<std::string, std::string>& headers
    ) const noexcept {
        CorsResult result;

        // Get Origin header
        std::string origin = get_header_value(headers, "Origin");

        // No origin = not a CORS request
        if (origin.empty()) {
            result.request_type = CorsRequestType::NOT_CORS;
            result.allowed = config_.allow_no_origin;
            return result;
        }

        // Check if origin is allowed
        if (!is_origin_allowed(origin)) {
            result.request_type = CorsRequestType::ACTUAL;
            result.allowed = false;
            return result;
        }

        // Determine request type
        if (method == "OPTIONS") {
            // Check for preflight headers
            std::string request_method = get_header_value(headers, "Access-Control-Request-Method");
            if (!request_method.empty()) {
                result.request_type = CorsRequestType::PREFLIGHT;
                result.is_preflight = true;
                return handle_preflight(origin, headers, result);
            }
        }

        // Simple or actual request
        result.request_type = CorsRequestType::ACTUAL;
        result.allowed = true;
        result.allowed_origin = origin;

        // Add CORS headers for actual request
        add_cors_headers(result, origin);

        return result;
    }

    /**
     * Apply CORS headers to response
     *
     * Adds appropriate CORS headers based on the check result.
     *
     * @param result CORS check result
     * @param response Response to modify
     */
    static void apply_headers(
        const CorsResult& result,
        Http1Response& response
    ) noexcept {
        for (const auto& [name, value] : result.headers) {
            response.headers[name] = value;
        }
    }

    /**
     * Build preflight response
     *
     * Creates a complete 204 No Content response for preflight.
     *
     * @param result CORS check result (must be preflight)
     * @return Preflight response
     */
    static Http1Response build_preflight_response(const CorsResult& result) noexcept {
        Http1Response response;
        response.status = 204;
        response.status_message = "No Content";

        for (const auto& [name, value] : result.headers) {
            response.headers[name] = value;
        }

        return response;
    }

    /**
     * Get configuration (for introspection)
     */
    const CorsConfig& config() const noexcept {
        return config_;
    }

    /**
     * Update configuration
     */
    void set_config(const CorsConfig& config) noexcept {
        config_ = config;
        build_sets();
    }

private:
    CorsConfig config_;
    std::unordered_set<std::string> allowed_methods_set_;
    std::unordered_set<std::string> allowed_headers_set_;  // Lowercase
    bool allow_all_origins_{false};

    /**
     * Build lookup sets from config vectors
     */
    void build_sets() {
        allowed_methods_set_.clear();
        for (const auto& method : config_.allowed_methods) {
            allowed_methods_set_.insert(method);
        }

        allowed_headers_set_.clear();
        for (const auto& header : config_.allowed_headers) {
            allowed_headers_set_.insert(to_lowercase(header));
        }

        // Check for wildcard origin
        allow_all_origins_ = false;
        for (const auto& origin : config_.allowed_origins) {
            if (origin == "*") {
                allow_all_origins_ = true;
                break;
            }
        }
    }

    /**
     * Check if origin is allowed
     */
    bool is_origin_allowed(const std::string& origin) const noexcept {
        if (allow_all_origins_) {
            return true;
        }

        // Custom validator takes precedence
        if (config_.origin_validator) {
            return config_.origin_validator(origin);
        }

        // Check exact match
        for (const auto& allowed : config_.allowed_origins) {
            if (allowed == origin) {
                return true;
            }

            // Simple wildcard matching (*.example.com)
            if (allowed.size() > 2 && allowed[0] == '*' && allowed[1] == '.') {
                // Check if origin ends with the pattern (after *)
                std::string_view suffix(allowed.data() + 1, allowed.size() - 1);
                if (origin.size() > suffix.size()) {
                    std::string_view origin_suffix(
                        origin.data() + origin.size() - suffix.size(),
                        suffix.size()
                    );
                    if (origin_suffix == suffix) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Handle preflight request
     */
    CorsResult handle_preflight(
        const std::string& origin,
        const std::unordered_map<std::string, std::string>& headers,
        CorsResult& result
    ) const noexcept {
        result.allowed = true;
        result.allowed_origin = origin;

        // Check requested method
        std::string request_method = get_header_value(headers, "Access-Control-Request-Method");
        if (!request_method.empty() && allowed_methods_set_.find(request_method) == allowed_methods_set_.end()) {
            result.allowed = false;
            return result;
        }

        // Check requested headers
        std::string request_headers = get_header_value(headers, "Access-Control-Request-Headers");
        if (!request_headers.empty() && !are_headers_allowed(request_headers)) {
            result.allowed = false;
            return result;
        }

        // Add preflight response headers
        add_preflight_headers(result, origin);

        return result;
    }

    /**
     * Check if all requested headers are allowed
     */
    bool are_headers_allowed(const std::string& request_headers) const noexcept {
        // Parse comma-separated list
        size_t pos = 0;
        while (pos < request_headers.size()) {
            // Skip whitespace
            while (pos < request_headers.size() && request_headers[pos] == ' ') {
                pos++;
            }

            // Find end of header name
            size_t end = request_headers.find(',', pos);
            if (end == std::string::npos) {
                end = request_headers.size();
            }

            // Extract header name
            std::string header = request_headers.substr(pos, end - pos);
            // Trim trailing whitespace
            while (!header.empty() && header.back() == ' ') {
                header.pop_back();
            }

            // Check if allowed (case-insensitive)
            if (!header.empty() && allowed_headers_set_.find(to_lowercase(header)) == allowed_headers_set_.end()) {
                return false;
            }

            pos = end + 1;
        }

        return true;
    }

    /**
     * Add CORS headers for actual request
     */
    void add_cors_headers(CorsResult& result, const std::string& origin) const noexcept {
        // Access-Control-Allow-Origin
        if (allow_all_origins_ && !config_.allow_credentials) {
            result.headers["Access-Control-Allow-Origin"] = "*";
        } else {
            result.headers["Access-Control-Allow-Origin"] = origin;
        }

        // Access-Control-Allow-Credentials
        if (config_.allow_credentials) {
            result.headers["Access-Control-Allow-Credentials"] = "true";
        }

        // Access-Control-Expose-Headers
        if (!config_.expose_headers.empty()) {
            result.headers["Access-Control-Expose-Headers"] = join(config_.expose_headers, ", ");
        }
    }

    /**
     * Add preflight response headers
     */
    void add_preflight_headers(CorsResult& result, const std::string& origin) const noexcept {
        // All the regular CORS headers
        add_cors_headers(result, origin);

        // Access-Control-Allow-Methods
        result.headers["Access-Control-Allow-Methods"] = join(config_.allowed_methods, ", ");

        // Access-Control-Allow-Headers
        result.headers["Access-Control-Allow-Headers"] = join(config_.allowed_headers, ", ");

        // Access-Control-Max-Age
        if (config_.max_age >= 0) {
            result.headers["Access-Control-Max-Age"] = std::to_string(config_.max_age);
        }
    }

    /**
     * Get header value (case-insensitive lookup)
     */
    static std::string get_header_value(
        const std::unordered_map<std::string, std::string>& headers,
        const std::string& name
    ) noexcept {
        // Try exact match first
        auto it = headers.find(name);
        if (it != headers.end()) {
            return it->second;
        }

        // Try lowercase
        std::string lower = to_lowercase(name);
        it = headers.find(lower);
        if (it != headers.end()) {
            return it->second;
        }

        // Linear search for case-insensitive match
        for (const auto& [key, value] : headers) {
            if (to_lowercase(key) == lower) {
                return value;
            }
        }

        return "";
    }

    /**
     * Convert string to lowercase
     */
    static std::string to_lowercase(const std::string& s) noexcept {
        std::string result = s;
        for (char& c : result) {
            if (c >= 'A' && c <= 'Z') {
                c = c - 'A' + 'a';
            }
        }
        return result;
    }

    /**
     * Join strings with delimiter
     */
    static std::string join(const std::vector<std::string>& strings, const std::string& delimiter) noexcept {
        if (strings.empty()) {
            return "";
        }

        std::string result = strings[0];
        for (size_t i = 1; i < strings.size(); i++) {
            result += delimiter;
            result += strings[i];
        }
        return result;
    }
};

/**
 * Simple CORS configuration presets
 */
namespace cors_presets {

/**
 * Allow all origins (development)
 * NOT RECOMMENDED FOR PRODUCTION
 */
inline CorsConfig allow_all() {
    CorsConfig config;
    config.allowed_origins = {"*"};
    config.allow_credentials = false;  // Can't use credentials with *
    return config;
}

/**
 * Restrictive preset - single origin
 */
inline CorsConfig single_origin(const std::string& origin, bool allow_credentials = true) {
    CorsConfig config;
    config.allowed_origins = {origin};
    config.allow_credentials = allow_credentials;
    return config;
}

/**
 * Multiple specific origins
 */
inline CorsConfig multiple_origins(
    const std::vector<std::string>& origins,
    bool allow_credentials = true
) {
    CorsConfig config;
    config.allowed_origins = origins;
    config.allow_credentials = allow_credentials;
    return config;
}

/**
 * Same-origin only (no CORS)
 */
inline CorsConfig same_origin_only() {
    CorsConfig config;
    config.allowed_origins = {};  // No origins allowed
    config.allow_no_origin = true;  // Allow same-origin requests
    return config;
}

} // namespace cors_presets

} // namespace http
} // namespace bolt::api
