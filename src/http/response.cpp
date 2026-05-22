#include "boltapi/http/response.h"
#include "boltapi/net/sys_compat.h"  // gmtime_r/strptime/timegm shims on Windows
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unordered_map>

// MSVC's <sys/stat.h> defines struct stat / stat() but not the POSIX
// S_ISREG macro. Provide it so file-metadata helpers compile on Windows.
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

namespace {

// MIME type lookup table
const std::unordered_map<std::string, std::string> MIME_TYPES = {
    // Web essentials
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".js", "text/javascript; charset=utf-8"},
    {".mjs", "text/javascript; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".xml", "application/xml; charset=utf-8"},

    // Images
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".webp", "image/webp"},
    {".avif", "image/avif"},

    // Fonts
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".ttf", "font/ttf"},
    {".otf", "font/otf"},
    {".eot", "application/vnd.ms-fontobject"},

    // Documents
    {".pdf", "application/pdf"},
    {".txt", "text/plain; charset=utf-8"},
    {".md", "text/markdown; charset=utf-8"},

    // Media
    {".mp3", "audio/mpeg"},
    {".wav", "audio/wav"},
    {".ogg", "audio/ogg"},
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".avi", "video/x-msvideo"},

    // Archives
    {".zip", "application/zip"},
    {".gz", "application/gzip"},
    {".tar", "application/x-tar"},

    // Data
    {".csv", "text/csv; charset=utf-8"},
    {".wasm", "application/wasm"},
    {".map", "application/json"},
};

std::string get_mime_type(const std::string& path) {
    // Find extension
    auto dot_pos = path.rfind('.');
    if (dot_pos == std::string::npos) {
        return "application/octet-stream";
    }

    std::string ext = path.substr(dot_pos);
    // Convert to lowercase
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    auto it = MIME_TYPES.find(ext);
    if (it != MIME_TYPES.end()) {
        return it->second;
    }

    return "application/octet-stream";
}

bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

time_t get_file_mtime(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

size_t get_file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

std::string format_http_date(time_t t) {
    char buf[64];
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return buf;
}

} // anonymous namespace

// uWebSockets integration disabled for now

// Default constructor
HttpResponse::HttpResponse() 
    : status_(Status::OK), type_(Type::TEXT), is_streaming_(false), 
      is_sent_(false), compression_enabled_(false), compression_level_(3),
      original_size_(0), compressed_size_(0) {
    // Pre-allocate headers map to avoid rehashing (reduces per-request allocations)
    headers_.reserve(16);  // Typical response has 5-15 headers
}

// uWebSockets constructor disabled for now

HttpResponse::~HttpResponse() = default;

HttpResponse& HttpResponse::status(Status status) noexcept {
    status_ = status;
    return *this;
}

HttpResponse& HttpResponse::header(const std::string& name, const std::string& value) noexcept {
    headers_[name] = value;
    return *this;
}

HttpResponse& HttpResponse::content_type(const std::string& content_type) noexcept {
    return header("content-type", content_type);
}

HttpResponse& HttpResponse::json(const std::string& data) noexcept {
    body_ = data;
    return content_type("application/json");
}

HttpResponse& HttpResponse::body(const std::string& data) noexcept {
    body_ = data;
    return *this;
}

HttpResponse& HttpResponse::text(const std::string& text) noexcept {
    body_ = text;
    return content_type("text/plain");
}

HttpResponse& HttpResponse::html(const std::string& html) noexcept {
    body_ = html;
    return content_type("text/html");
}

HttpResponse& HttpResponse::binary(const std::vector<uint8_t>& data) noexcept {
    binary_body_ = data;
    return content_type("application/octet-stream");
}

HttpResponse& HttpResponse::file(const std::string& file_path) noexcept {
    file_path_ = file_path;

    // Check if file exists
    if (!file_exists(file_path)) {
        status_ = Status::NOT_FOUND;
        body_ = R"({"error":"File not found"})";
        return content_type("application/json");
    }

    // Security check: prevent directory traversal
    if (file_path.find("..") != std::string::npos) {
        status_ = Status::FORBIDDEN;
        body_ = R"({"error":"Access denied"})";
        return content_type("application/json");
    }

    // Get file info
    size_t file_size = get_file_size(file_path);
    time_t mtime = get_file_mtime(file_path);

    // Read file content
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) {
        status_ = Status::INTERNAL_SERVER_ERROR;
        body_ = R"({"error":"Failed to read file"})";
        return content_type("application/json");
    }

    // Read into binary body for proper handling
    binary_body_.resize(file_size);
    ifs.read(reinterpret_cast<char*>(binary_body_.data()), file_size);

    // Set MIME type based on extension
    std::string mime = get_mime_type(file_path);
    content_type(mime);

    // Set caching headers
    if (mtime > 0) {
        header("last-modified", format_http_date(mtime));
    }

    // Generate simple ETag from size + mtime
    std::string etag = "\"" + std::to_string(file_size) + "-" + std::to_string(mtime) + "\"";
    header("etag", etag);

    // Cache for 1 hour by default for static assets
    header("cache-control", "public, max-age=3600");

    return *this;
}

HttpResponse& HttpResponse::stream(const std::string& content_type) noexcept {
    is_streaming_ = true;
    return this->content_type(content_type);
}

HttpResponse& HttpResponse::write(const std::string& data) noexcept {
    body_ += data;
    return *this;
}

HttpResponse& HttpResponse::write(const std::vector<uint8_t>& data) noexcept {
    binary_body_.insert(binary_body_.end(), data.begin(), data.end());
    return *this;
}

HttpResponse& HttpResponse::end() noexcept {
    is_streaming_ = false;
    return *this;
}

HttpResponse& HttpResponse::compress(bool enable) noexcept {
    compression_enabled_ = enable;
    return *this;
}

HttpResponse& HttpResponse::compression_level(int level) noexcept {
    compression_level_ = level;
    return *this;
}

HttpResponse& HttpResponse::redirect(const std::string& url, bool permanent) noexcept {
    status_ = permanent ? Status::MOVED_PERMANENTLY : Status::FOUND;
    return header("location", url);
}

HttpResponse& HttpResponse::cookie(
    const std::string& name, 
    const std::string& value, 
    const std::unordered_map<std::string, std::string>& options
) noexcept {
    std::string cookie_str = name + "=" + value;
    for (const auto& [key, val] : options) {
        cookie_str += "; " + key + "=" + val;
    }
    cookies_.push_back(cookie_str);
    return *this;
}

HttpResponse& HttpResponse::clear_cookie(const std::string& name, const std::string& path) noexcept {
    return cookie(name, "", {{"path", path}, {"expires", "Thu, 01 Jan 1970 00:00:00 GMT"}});
}

int HttpResponse::send() noexcept {
    if (is_sent_) return 0;
    
    original_size_ = body_.length() + binary_body_.size();
    
    // Compression disabled - stub code removed to prevent browser decode failures.
    // The old code added content-encoding: zstd header without actually compressing,
    // which caused ERR_CONTENT_DECODING_FAILED in browsers.
    compressed_size_ = original_size_;
    
    is_sent_ = true;
    return 0;
}

bool HttpResponse::is_sent() const noexcept {
    return is_sent_;
}

uint64_t HttpResponse::get_size() const noexcept {
    return body_.length() + binary_body_.size();
}

double HttpResponse::get_compression_ratio() const noexcept {
    if (original_size_ == 0) return 0.0;
    return 1.0 - (double(compressed_size_) / double(original_size_));
}

int HttpResponse::apply_compression() noexcept {
    // Simplified compression implementation
    return 0;
}

std::string HttpResponse::serialize_headers() const noexcept {
    std::string result;
    for (const auto& [name, value] : headers_) {
        result += name + ": " + value + "\r\n";
    }
    return result;
}

std::string HttpResponse::get_status_text(Status status) const noexcept {
    switch (status) {
        case Status::OK: return "OK";
        case Status::CREATED: return "Created";
        case Status::ACCEPTED: return "Accepted";
        case Status::NO_CONTENT: return "No Content";
        case Status::PARTIAL_CONTENT: return "Partial Content";
        case Status::MOVED_PERMANENTLY: return "Moved Permanently";
        case Status::FOUND: return "Found";
        case Status::NOT_MODIFIED: return "Not Modified";
        case Status::BAD_REQUEST: return "Bad Request";
        case Status::UNAUTHORIZED: return "Unauthorized";
        case Status::FORBIDDEN: return "Forbidden";
        case Status::NOT_FOUND: return "Not Found";
        case Status::METHOD_NOT_ALLOWED: return "Method Not Allowed";
        case Status::CONFLICT: return "Conflict";
        case Status::RANGE_NOT_SATISFIABLE: return "Range Not Satisfiable";
        case Status::UNPROCESSABLE_ENTITY: return "Unprocessable Entity";
        case Status::TOO_MANY_REQUESTS: return "Too Many Requests";
        case Status::INTERNAL_SERVER_ERROR: return "Internal Server Error";
        case Status::NOT_IMPLEMENTED: return "Not Implemented";
        case Status::BAD_GATEWAY: return "Bad Gateway";
        case Status::SERVICE_UNAVAILABLE: return "Service Unavailable";
        default: return "Unknown";
    }
}

std::string HttpResponse::to_http_wire_format(bool keep_alive) const noexcept {
    std::string response;
    response.reserve(512 + body_.size() + binary_body_.size());

    // Status line: "HTTP/1.1 200 OK\r\n"
    response += "HTTP/1.1 ";
    response += std::to_string(static_cast<int>(status_));
    response += " ";
    response += get_status_text(status_);
    response += "\r\n";

    // Content-Type header (if set or inferred from type)
    std::string content_type = content_type_;
    if (content_type.empty()) {
        auto ct_it = headers_.find("content-type");
        if (ct_it != headers_.end()) {
            content_type = ct_it->second;
        }
    }
    if (!content_type.empty()) {
        response += "Content-Type: ";
        response += content_type;
        response += "\r\n";
    }

    // Content-Length header
    size_t content_length = !binary_body_.empty() ? binary_body_.size() : body_.size();
    response += "Content-Length: ";
    response += std::to_string(content_length);
    response += "\r\n";

    // Connection header
    response += "Connection: ";
    response += keep_alive ? "keep-alive" : "close";
    response += "\r\n";

    // Additional headers (skip content-type and content-length if already set)
    for (const auto& [name, value] : headers_) {
        // Case-insensitive comparison for content-type and content-length
        std::string name_lower = name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        if (name_lower != "content-type" && name_lower != "content-length" && name_lower != "connection") {
            response += name;
            response += ": ";
            response += value;
            response += "\r\n";
        }
    }

    // Cookies
    for (const auto& cookie : cookies_) {
        response += "Set-Cookie: ";
        response += cookie;
        response += "\r\n";
    }

    // End of headers
    response += "\r\n";

    // Body
    if (!binary_body_.empty()) {
        response.append(reinterpret_cast<const char*>(binary_body_.data()), binary_body_.size());
    } else {
        response += body_;
    }

    return response;
}

// Move assignment and move constructor
HttpResponse::HttpResponse(HttpResponse&&) noexcept = default;
HttpResponse& HttpResponse::operator=(HttpResponse&&) noexcept = default;

// ============================================================================
// Caching and Conditional Response Methods
// ============================================================================

HttpResponse& HttpResponse::etag(const std::string& tag) noexcept {
    // Ensure ETag is quoted per RFC 7232
    if (tag.empty()) {
        etag_.clear();
        return *this;
    }

    if (tag.front() == '"' && tag.back() == '"') {
        etag_ = tag;
    } else if (tag.front() == 'W' && tag.size() > 2 && tag[1] == '/' && tag[2] == '"') {
        // Weak ETag: W/"..."
        etag_ = tag;
    } else {
        etag_ = "\"" + tag + "\"";
    }

    header("etag", etag_);
    return *this;
}

HttpResponse& HttpResponse::last_modified(uint64_t timestamp) noexcept {
    last_modified_timestamp_ = timestamp;
    header("last-modified", format_http_date(static_cast<time_t>(timestamp)));
    return *this;
}

HttpResponse& HttpResponse::last_modified(const std::string& date) noexcept {
    header("last-modified", date);
    // Parse date to timestamp for comparison
    struct tm tm = {};
    if (strptime(date.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm) != nullptr) {
        last_modified_timestamp_ = static_cast<uint64_t>(timegm(&tm));
    }
    return *this;
}

HttpResponse& HttpResponse::cache_control(const std::string& directive) noexcept {
    return header("cache-control", directive);
}

HttpResponse& HttpResponse::not_modified() noexcept {
    status_ = Status::NOT_MODIFIED;
    body_.clear();
    binary_body_.clear();
    // 304 responses must not include a body or content-length
    // But should include ETag, Cache-Control, etc.
    return *this;
}

bool HttpResponse::matches_etag(const std::string& if_none_match) const noexcept {
    if (etag_.empty() || if_none_match.empty()) {
        return false;
    }

    // Handle "*" which matches any ETag
    if (if_none_match == "*") {
        return true;
    }

    // If-None-Match can contain multiple ETags separated by commas
    // e.g., "etag1", "etag2", W/"weak-etag"
    size_t pos = 0;
    while (pos < if_none_match.size()) {
        // Skip whitespace and commas
        while (pos < if_none_match.size() &&
               (if_none_match[pos] == ' ' || if_none_match[pos] == ',' || if_none_match[pos] == '\t')) {
            pos++;
        }
        if (pos >= if_none_match.size()) break;

        // Find the ETag (quoted string)
        size_t start = pos;
        bool is_weak = false;

        // Check for weak ETag prefix
        if (if_none_match.size() > pos + 2 &&
            if_none_match[pos] == 'W' && if_none_match[pos + 1] == '/') {
            is_weak = true;
            pos += 2;
        }

        // Find quoted ETag
        if (pos < if_none_match.size() && if_none_match[pos] == '"') {
            pos++; // Skip opening quote
            size_t etag_start = pos;
            while (pos < if_none_match.size() && if_none_match[pos] != '"') {
                pos++;
            }
            std::string candidate_etag = if_none_match.substr(etag_start, pos - etag_start);
            if (pos < if_none_match.size()) pos++; // Skip closing quote

            // Build full ETag for comparison
            std::string full_candidate = is_weak ? "W/\"" + candidate_etag + "\"" : "\"" + candidate_etag + "\"";

            // Strong comparison: both must be strong and identical
            // Weak comparison: ignore W/ prefix for comparison
            if (etag_ == full_candidate) {
                return true;
            }

            // Also try weak comparison (ignore W/ prefix)
            std::string our_etag = etag_;
            std::string their_etag = full_candidate;
            if (our_etag.substr(0, 2) == "W/") our_etag = our_etag.substr(2);
            if (their_etag.substr(0, 2) == "W/") their_etag = their_etag.substr(2);
            if (our_etag == their_etag) {
                return true;
            }
        } else {
            // Skip to next comma
            while (pos < if_none_match.size() && if_none_match[pos] != ',') {
                pos++;
            }
        }
    }

    return false;
}

bool HttpResponse::not_modified_since(const std::string& if_modified_since) const noexcept {
    if (last_modified_timestamp_ == 0 || if_modified_since.empty()) {
        return false;
    }

    // Parse the If-Modified-Since header
    struct tm tm = {};
    if (strptime(if_modified_since.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm) == nullptr) {
        return false;
    }

    time_t client_time = timegm(&tm);
    return static_cast<uint64_t>(client_time) >= last_modified_timestamp_;
}

const std::string& HttpResponse::get_etag() const noexcept {
    return etag_;
}

uint64_t HttpResponse::get_last_modified() const noexcept {
    return last_modified_timestamp_;
}

// ============================================================================
// Range Request Methods (206 Partial Content)
// ============================================================================

HttpResponse& HttpResponse::partial_content(const std::string& data, size_t start, size_t end, size_t total) noexcept {
    if (start > end || end >= total) {
        status_ = Status::RANGE_NOT_SATISFIABLE;
        header("content-range", "bytes */" + std::to_string(total));
        body_.clear();
        return *this;
    }

    status_ = Status::PARTIAL_CONTENT;
    body_ = data.substr(start, end - start + 1);

    // Set Content-Range header: bytes start-end/total
    header("content-range", "bytes " + std::to_string(start) + "-" +
                            std::to_string(end) + "/" + std::to_string(total));

    return *this;
}

HttpResponse& HttpResponse::partial_content(const std::vector<uint8_t>& data, size_t start, size_t end, size_t total) noexcept {
    if (start > end || end >= total) {
        status_ = Status::RANGE_NOT_SATISFIABLE;
        header("content-range", "bytes */" + std::to_string(total));
        binary_body_.clear();
        return *this;
    }

    status_ = Status::PARTIAL_CONTENT;
    binary_body_.assign(data.begin() + start, data.begin() + end + 1);

    // Set Content-Range header: bytes start-end/total
    header("content-range", "bytes " + std::to_string(start) + "-" +
                            std::to_string(end) + "/" + std::to_string(total));

    return *this;
}

HttpResponse& HttpResponse::accept_ranges(const std::string& unit) noexcept {
    return header("accept-ranges", unit);
}
