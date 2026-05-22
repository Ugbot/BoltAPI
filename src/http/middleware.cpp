#include "boltapi/http/middleware.h"
#include "boltapi/http/request.h"
#include "boltapi/http/response.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>

Middleware::Middleware() 
    : total_requests_(0), blocked_requests_(0), rate_limited_requests_(0),
      auth_failed_requests_(0), cors_preflight_requests_(0) {
    
    // Register default middleware functions
    middleware_funcs_[Type::RATE_LIMIT] = [this](HttpRequest* req, HttpResponse* res) {
        return rate_limit_middleware(req, res);
    };
    
    middleware_funcs_[Type::AUTHENTICATION] = [this](HttpRequest* req, HttpResponse* res) {
        return auth_middleware(req, res);
    };
    
    middleware_funcs_[Type::CORS] = [this](HttpRequest* req, HttpResponse* res) {
        return cors_middleware(req, res);
    };
    
    middleware_funcs_[Type::LOGGING] = [this](HttpRequest* req, HttpResponse* res) {
        return logging_middleware(req, res);
    };
    
    middleware_funcs_[Type::SECURITY] = [this](HttpRequest* req, HttpResponse* res) {
        return security_middleware(req, res);
    };
    
    middleware_funcs_[Type::COMPRESSION] = [this](HttpRequest* req, HttpResponse* res) {
        return compression_middleware(req, res);
    };
}

Middleware::~Middleware() = default;

int Middleware::add_middleware(Type type, std::function<int(HttpRequest*, HttpResponse*)> func) noexcept {
    middleware_funcs_[type] = std::move(func);
    return 0;
}

int Middleware::configure_rate_limit(const RateLimitConfig& config) noexcept {
    rate_limit_config_ = config;
    return 0;
}

int Middleware::configure_auth(const AuthConfig& config) noexcept {
    auth_config_ = config;
    return 0;
}

int Middleware::configure_cors(const CorsConfig& config) noexcept {
    cors_config_ = config;
    return 0;
}

int Middleware::configure_security(const SecurityConfig& config) noexcept {
    security_config_ = config;
    return 0;
}

int Middleware::process_request(HttpRequest* request, HttpResponse* response) noexcept {
    total_requests_.fetch_add(1);
    
    // Process middleware in order
    std::vector<Type> middleware_order = {
        Type::CORS,
        Type::RATE_LIMIT,
        Type::AUTHENTICATION,
        Type::SECURITY,
        Type::COMPRESSION,
        Type::LOGGING
    };
    
    for (Type type : middleware_order) {
        auto it = middleware_funcs_.find(type);
        if (it != middleware_funcs_.end()) {
            int result = it->second(request, response);
            if (result != 0) {
                blocked_requests_.fetch_add(1);
                return result;
            }
        }
    }
    
    return 0;
}

std::unordered_map<std::string, uint64_t> Middleware::get_stats() const noexcept {
    std::unordered_map<std::string, uint64_t> stats;
    stats["total_requests"] = total_requests_.load();
    stats["blocked_requests"] = blocked_requests_.load();
    stats["rate_limited_requests"] = rate_limited_requests_.load();
    stats["auth_failed_requests"] = auth_failed_requests_.load();
    stats["cors_preflight_requests"] = cors_preflight_requests_.load();
    return stats;
}

int Middleware::rate_limit_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    if (!rate_limit_config_.enabled) {
        return 0;
    }
    
    std::string client_id = get_client_id(request);
    
    if (is_rate_limited(client_id)) {
        rate_limited_requests_.fetch_add(1);
        
        // Send 429 Too Many Requests
        response->status(HttpResponse::Status::TOO_MANY_REQUESTS)
               .header("Retry-After", std::to_string(rate_limit_config_.window_size.count()))
               .json("{\"error\":\"Rate limit exceeded\"}");
        
        return 1;
    }
    
    return 0;
}

int Middleware::auth_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    if (!auth_config_.enabled) {
        return 0;
    }
    
    std::string auth_header = request->get_header(auth_config_.token_header);
    
    if (auth_header.empty()) {
        auth_failed_requests_.fetch_add(1);
        
        response->status(HttpResponse::Status::UNAUTHORIZED)
               .json("{\"error\":\"Authentication required\"}");
        
        return 1;
    }
    
    // Extract token from header
    if (auth_header.substr(0, auth_config_.token_prefix.length()) != auth_config_.token_prefix) {
        auth_failed_requests_.fetch_add(1);
        
        response->status(HttpResponse::Status::UNAUTHORIZED)
               .json("{\"error\":\"Invalid token format\"}");
        
        return 1;
    }
    
    std::string token = auth_header.substr(auth_config_.token_prefix.length());
    
    if (!validate_token(token)) {
        auth_failed_requests_.fetch_add(1);
        
        response->status(HttpResponse::Status::UNAUTHORIZED)
               .json("{\"error\":\"Invalid token\"}");
        
        return 1;
    }
    
    return 0;
}

int Middleware::cors_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    std::string origin = request->get_header("Origin");
    std::string method = request->get_method() == HttpRequest::Method::GET ? "GET" : "POST";
    
    // Handle preflight requests
    if (method == "OPTIONS") {
        cors_preflight_requests_.fetch_add(1);
        
        std::string request_method = request->get_header("Access-Control-Request-Method");
        std::string request_headers = request->get_header("Access-Control-Request-Headers");
        
        // Check if origin is allowed
        if (!origin.empty() && !is_cors_origin_allowed(origin)) {
            response->status(HttpResponse::Status::FORBIDDEN)
                   .json("{\"error\":\"CORS origin not allowed\"}");
            return 1;
        }
        
        // Check if method is allowed
        if (!request_method.empty() && !is_cors_method_allowed(request_method)) {
            response->status(HttpResponse::Status::FORBIDDEN)
                   .json("{\"error\":\"CORS method not allowed\"}");
            return 1;
        }
        
        // Add CORS headers
        if (!origin.empty()) {
            response->header("Access-Control-Allow-Origin", origin);
        }
        
        response->header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
               .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
               .header("Access-Control-Max-Age", std::to_string(cors_config_.max_age));
        
        if (cors_config_.allow_credentials) {
            response->header("Access-Control-Allow-Credentials", "true");
        }
        
        response->status(HttpResponse::Status::OK);
        return 0;
    }
    
    // Handle actual requests
    if (!origin.empty() && !is_cors_origin_allowed(origin)) {
        response->status(HttpResponse::Status::FORBIDDEN)
               .json("{\"error\":\"CORS origin not allowed\"}");
        return 1;
    }
    
    // Add CORS headers for actual requests
    if (!origin.empty()) {
        response->header("Access-Control-Allow-Origin", origin);
    }
    
    if (cors_config_.allow_credentials) {
        response->header("Access-Control-Allow-Credentials", "true");
    }
    
    return 0;
}

int Middleware::logging_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    log_request(request, response);
    return 0;
}

int Middleware::security_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    add_security_headers(response);
    return 0;
}

int Middleware::compression_middleware(HttpRequest* request, HttpResponse* response) noexcept {
    // Compression disabled - this stub used to add Content-Encoding headers without
    // actually compressing, causing ERR_CONTENT_DECODING_FAILED in browsers.
    // Real compression should use CompressionMiddleware from compression_middleware.h
    // which actually compresses the response body.
    (void)request;
    (void)response;
    return 0;
}

std::string Middleware::get_client_id(HttpRequest* request) noexcept {
    // Use client IP as identifier
    std::string client_ip = request->get_client_ip();
    
    // Add user agent hash for more granular rate limiting
    std::string user_agent = request->get_user_agent();
    std::hash<std::string> hasher;
    size_t ua_hash = hasher(user_agent);
    
    return client_ip + ":" + std::to_string(ua_hash);
}

bool Middleware::is_rate_limited(const std::string& client_id) noexcept {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto it = rate_limit_entries_.find(client_id);
    if (it == rate_limit_entries_.end()) {
        // Create new entry
        auto entry = std::make_unique<RateLimitEntry>();
        entry->request_count.store(1);
        entry->window_start = std::chrono::steady_clock::now();
        rate_limit_entries_[client_id] = std::move(entry);
        return false;
    }
    
    RateLimitEntry* entry = it->second.get();
    std::lock_guard<std::mutex> entry_lock(entry->mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry->window_start);
    
    // Reset window if expired
    if (elapsed >= rate_limit_config_.window_size) {
        entry->request_count.store(1);
        entry->window_start = now;
        return false;
    }
    
    // Check if limit exceeded
    uint32_t current_count = entry->request_count.fetch_add(1);
    return current_count >= rate_limit_config_.max_requests;
}

bool Middleware::validate_token(const std::string& token) noexcept {
    // Simple token validation - in production, use proper JWT validation
    return !token.empty() && token.length() > 10;
}

bool Middleware::is_cors_origin_allowed(const std::string& origin) noexcept {
    if (cors_config_.allowed_origins.empty()) {
        return true;  // Allow all origins if none specified
    }
    
    return std::find(cors_config_.allowed_origins.begin(), 
                    cors_config_.allowed_origins.end(), origin) != cors_config_.allowed_origins.end();
}

bool Middleware::is_cors_method_allowed(const std::string& method) noexcept {
    return std::find(cors_config_.allowed_methods.begin(), 
                    cors_config_.allowed_methods.end(), method) != cors_config_.allowed_methods.end();
}

bool Middleware::are_cors_headers_allowed(const std::unordered_map<std::string, std::string>& headers) noexcept {
    // Check if all requested headers are allowed
    for (const auto& [name, value] : headers) {
        if (std::find(cors_config_.allowed_headers.begin(), 
                     cors_config_.allowed_headers.end(), name) == cors_config_.allowed_headers.end()) {
            return false;
        }
    }
    return true;
}

void Middleware::add_security_headers(HttpResponse* response) noexcept {
    if (security_config_.enable_hsts) {
        response->header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    
    if (security_config_.enable_csp) {
        response->header("Content-Security-Policy", security_config_.csp_policy);
    }
    
    if (security_config_.enable_xss_protection) {
        response->header("X-Content-Type-Options", "nosniff");
        response->header("X-XSS-Protection", "1; mode=block");
    }
    
    if (security_config_.enable_frame_options) {
        response->header("X-Frame-Options", "DENY");
    }
    
    // Remove server header
    response->header("Server", "Bolt API");
}

void Middleware::log_request(HttpRequest* request, HttpResponse* response) noexcept {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    std::string method = request->get_method() == HttpRequest::Method::GET ? "GET" : "POST";
    std::string path = request->get_path();
    std::string client_ip = request->get_client_ip();
    int status = 200;  // Default status
    
    std::cout << "[" << oss.str() << "] " 
              << client_ip << " " 
              << method << " " 
              << path << " " 
              << status << std::endl;
}
