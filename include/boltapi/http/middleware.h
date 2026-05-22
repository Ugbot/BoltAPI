#pragma once

#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstdint>

// Forward declarations
class HttpRequest;
class HttpResponse;

/**
 * Middleware system for HTTP request/response processing.
 * 
 * Features:
 * - Rate limiting with sliding window
 * - Authentication middleware
 * - CORS support
 * - Request logging
 * - Security headers
 * - Compression detection
 */
class Middleware {
public:
    // Middleware types
    enum class Type {
        RATE_LIMIT,
        AUTHENTICATION,
        CORS,
        LOGGING,
        SECURITY,
        COMPRESSION
    };

    // Rate limiting configuration
    struct RateLimitConfig {
        uint32_t max_requests = 100;
        std::chrono::seconds window_size{60};
        bool enabled = true;
    };

    // Authentication configuration
    struct AuthConfig {
        std::string secret_key;
        std::string token_header = "Authorization";
        std::string token_prefix = "Bearer ";
        bool enabled = false;
    };

    // CORS configuration
    struct CorsConfig {
        std::vector<std::string> allowed_origins;
        std::vector<std::string> allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
        std::vector<std::string> allowed_headers = {"Content-Type", "Authorization"};
        bool allow_credentials = true;
        uint32_t max_age = 86400;  // 24 hours
    };

    // Security configuration
    struct SecurityConfig {
        bool enable_hsts = true;
        bool enable_csp = true;
        bool enable_xss_protection = true;
        bool enable_frame_options = true;
        std::string csp_policy = "default-src 'self'";
    };

    /**
     * Constructor.
     */
    Middleware();

    /**
     * Destructor.
     */
    ~Middleware();

    /**
     * Add middleware function.
     * 
     * @param type Middleware type
     * @param func Middleware function
     * @return Error code (0 = success)
     */
    int add_middleware(Type type, std::function<int(HttpRequest*, HttpResponse*)> func) noexcept;

    /**
     * Configure rate limiting.
     * 
     * @param config Rate limit configuration
     * @return Error code (0 = success)
     */
    int configure_rate_limit(const RateLimitConfig& config) noexcept;

    /**
     * Configure authentication.
     * 
     * @param config Authentication configuration
     * @return Error code (0 = success)
     */
    int configure_auth(const AuthConfig& config) noexcept;

    /**
     * Configure CORS.
     * 
     * @param config CORS configuration
     * @return Error code (0 = success)
     */
    int configure_cors(const CorsConfig& config) noexcept;

    /**
     * Configure security headers.
     * 
     * @param config Security configuration
     * @return Error code (0 = success)
     */
    int configure_security(const SecurityConfig& config) noexcept;

    /**
     * Process request through middleware chain.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success, 1 = blocked)
     */
    int process_request(HttpRequest* request, HttpResponse* response) noexcept;

    /**
     * Get middleware statistics.
     * 
     * @return Statistics map
     */
    std::unordered_map<std::string, uint64_t> get_stats() const noexcept;

private:
    // Middleware functions
    std::unordered_map<Type, std::function<int(HttpRequest*, HttpResponse*)>> middleware_funcs_;
    
    // Configuration
    RateLimitConfig rate_limit_config_;
    AuthConfig auth_config_;
    CorsConfig cors_config_;
    SecurityConfig security_config_;
    
    // Rate limiting state
    struct RateLimitEntry {
        std::atomic<uint32_t> request_count{0};
        std::chrono::steady_clock::time_point window_start;
        std::mutex mutex;
    };
    
    std::unordered_map<std::string, std::unique_ptr<RateLimitEntry>> rate_limit_entries_;
    std::mutex rate_limit_mutex_;
    
    // Statistics
    std::atomic<uint64_t> total_requests_;
    std::atomic<uint64_t> blocked_requests_;
    std::atomic<uint64_t> rate_limited_requests_;
    std::atomic<uint64_t> auth_failed_requests_;
    std::atomic<uint64_t> cors_preflight_requests_;
    
    /**
     * Rate limiting middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success, 1 = rate limited)
     */
    int rate_limit_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * Authentication middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success, 1 = auth failed)
     */
    int auth_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * CORS middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success)
     */
    int cors_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * Logging middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success)
     */
    int logging_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * Security headers middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success)
     */
    int security_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * Compression detection middleware.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @return Error code (0 = success)
     */
    int compression_middleware(HttpRequest* request, HttpResponse* response) noexcept;
    
    /**
     * Get client identifier for rate limiting.
     * 
     * @param request HTTP request
     * @return Client identifier
     */
    std::string get_client_id(HttpRequest* request) noexcept;
    
    /**
     * Check if request is rate limited.
     * 
     * @param client_id Client identifier
     * @return true if rate limited, false otherwise
     */
    bool is_rate_limited(const std::string& client_id) noexcept;
    
    /**
     * Validate authentication token.
     * 
     * @param token Authentication token
     * @return true if valid, false otherwise
     */
    bool validate_token(const std::string& token) noexcept;
    
    /**
     * Check CORS origin.
     * 
     * @param origin Origin header value
     * @return true if allowed, false otherwise
     */
    bool is_cors_origin_allowed(const std::string& origin) noexcept;
    
    /**
     * Check CORS method.
     * 
     * @param method HTTP method
     * @return true if allowed, false otherwise
     */
    bool is_cors_method_allowed(const std::string& method) noexcept;
    
    /**
     * Check CORS headers.
     * 
     * @param headers Request headers
     * @return true if allowed, false otherwise
     */
    bool are_cors_headers_allowed(const std::unordered_map<std::string, std::string>& headers) noexcept;
    
    /**
     * Add security headers.
     * 
     * @param response HTTP response
     */
    void add_security_headers(HttpResponse* response) noexcept;
    
    /**
     * Log request.
     * 
     * @param request HTTP request
     * @param response HTTP response
     */
    void log_request(HttpRequest* request, HttpResponse* response) noexcept;
};