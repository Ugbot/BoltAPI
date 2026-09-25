#include "boltapi/http/http1_parser.h"
#include <cassert>
#include <cctype>
#include <cstring>
#include <algorithm>

namespace bolt::api {
namespace http {

// ============================================================================
// HTTP1Request Implementation
// ============================================================================

std::string_view HTTP1Request::get_header(std::string_view name) const noexcept {
    for (size_t i = 0; i < header_count; ++i) {
        if (HTTP1Parser::str_eq_ci(headers[i].name, name)) {
            return headers[i].value;
        }
    }
    return {};
}

bool HTTP1Request::has_header(std::string_view name) const noexcept {
    return !get_header(name).empty();
}

// ============================================================================
// HTTP1Parser Implementation
// ============================================================================

HTTP1Parser::HTTP1Parser()
    : state_(HTTP1State::START), pos_(0), mark_(0) {
}

void HTTP1Parser::reset() noexcept {
    state_ = HTTP1State::START;
    pos_ = 0;
    mark_ = 0;
}

int HTTP1Parser::parse(
    const uint8_t* data,
    size_t len,
    HTTP1Request& out_request,
    size_t& out_consumed
) noexcept {
    if (!data || len == 0) {
        return -1;  // Need more data
    }

    pos_ = 0;
    mark_ = 0;

    // parse() restarts from the top of the buffer on every call, and the
    // engine's read loop passes the SAME HTTP1Request while an incomplete
    // body accumulates (one retry per socket read). The request's own
    // accumulation state must restart with it: without this, header_count
    // grew by the full header set on EVERY retry, tripping MAX_HEADERS after
    // ~a dozen reads — any body large enough to need >~12 reads (≈2 MB at
    // typical recv sizes) was answered 400 with no body. Found via S3
    // multipart part uploads (10 MB parts), which could never succeed.
    state_ = HTTP1State::START;
    out_request.header_count = 0;
    out_request.content_length = 0;
    out_request.has_content_length = false;
    out_request.chunked = false;
    out_request.upgrade = false;

    // Parse request line: METHOD SP URL SP VERSION CRLF
    
    // 1. Parse method
    if (parse_method(data, len, out_request) != 0) {
        return state_ == HTTP1State::ERROR ? 1 : -1;
    }
    
    // 2. Parse URL
    if (parse_url(data, len, out_request) != 0) {
        return state_ == HTTP1State::ERROR ? 1 : -1;
    }
    
    // 3. Parse version
    if (parse_version(data, len, out_request) != 0) {
        return state_ == HTTP1State::ERROR ? 1 : -1;
    }
    
    // 4. Parse headers
    while (pos_ < len) {
        // Check for end of headers (empty line)
        if (pos_ + 1 < len && data[pos_] == '\r' && data[pos_ + 1] == '\n') {
            pos_ += 2;
            state_ = HTTP1State::BODY;
            break;
        }

        if (parse_header_field(data, len, out_request) != 0) {
            return state_ == HTTP1State::ERROR ? 1 : -1;
        }

        if (parse_header_value(data, len, out_request) != 0) {
            return state_ == HTTP1State::ERROR ? 1 : -1;
        }
    }

    // Parse URL components
    parse_url_components(out_request);

    // Extract important headers
    auto content_len = out_request.get_header("content-length");
    if (!content_len.empty()) {
        out_request.content_length = std::stoull(std::string(content_len));
        out_request.has_content_length = true;
    }

    auto transfer_enc = out_request.get_header("transfer-encoding");
    if (!transfer_enc.empty() && transfer_enc.find("chunked") != std::string_view::npos) {
        out_request.chunked = true;
    }

    auto connection = out_request.get_header("connection");
    if (out_request.version == HTTP1Version::HTTP_1_1) {
        out_request.keep_alive = connection.empty() || str_eq_ci(connection, "keep-alive");
    } else {
        out_request.keep_alive = str_eq_ci(connection, "keep-alive");
    }

    auto upgrade = out_request.get_header("upgrade");
    if (!upgrade.empty()) {
        out_request.upgrade = true;
        out_request.upgrade_protocol = upgrade;
    }

    // 5. Chunked body: the raw framing is validated and handed back in
    // out_request.body; the caller decodes it in place (dechunk_in_place).
    if (out_request.chunked) {
        // Both framings on one request is the classic smuggling vector
        // (RFC 9112 6.3): refuse rather than pick one.
        if (out_request.has_content_length) {
            state_ = HTTP1State::ERROR;
            return 1;
        }
        size_t raw_len = 0;
        const int rc = scan_chunked(data + pos_, len - pos_, &raw_len);
        if (rc != 0) {
            if (rc > 0) state_ = HTTP1State::ERROR;
            return rc;
        }
        out_request.body = std::string_view(
            reinterpret_cast<const char*>(data + pos_), raw_len);
        pos_ += raw_len;
    }

    // 6. Parse body if Content-Length is present
    if (out_request.has_content_length && out_request.content_length > 0) {
        size_t body_start = pos_;
        size_t body_available = len - pos_;

        if (body_available < out_request.content_length) {
            // Not enough data for complete body
            return -1;  // Need more data
        }

        // Extract body as string_view (zero-copy)
        out_request.body = std::string_view(
            reinterpret_cast<const char*>(data + body_start),
            out_request.content_length
        );
        pos_ += out_request.content_length;
    }

    state_ = HTTP1State::COMPLETE;
    out_consumed = pos_;
    return 0;
}

namespace {

int hex_val(uint8_t c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// One chunk-size line: hex size, optional ";ext", CRLF. Returns 0 and sets
// *line_len / *size, -1 if the line is incomplete, 1 if malformed.
int chunk_size_line(const uint8_t* p, size_t len, size_t* line_len,
                    uint64_t* size) noexcept {
    assert(p != nullptr || len == 0);
    assert(line_len != nullptr && size != nullptr);
    uint64_t v = 0;
    size_t i = 0;
    for (; i < len && i < 17; ++i) {
        const int h = hex_val(p[i]);
        if (h < 0) break;
        v = (v << 4) | static_cast<uint64_t>(h);
    }
    if (i == len) return -1;
    if (i == 0 || i > 16) return 1;
    constexpr size_t kMaxLine = 4096;             // bounds chunk extensions
    for (; i < len && i < kMaxLine; ++i) {
        if (p[i] == '\n') return 1;             // bare LF
        if (p[i] != '\r') continue;
        if (i + 1 == len) return -1;
        if (p[i + 1] != '\n') return 1;
        *line_len = i + 2;
        *size = v;
        return 0;
    }
    return i == len ? -1 : 1;
}

}  // namespace

int HTTP1Parser::scan_chunked(const uint8_t* data, size_t len,
                              size_t* out_raw_len) noexcept {
    assert(out_raw_len != nullptr);
    assert(data != nullptr || len == 0);
    size_t pos = 0;
    // Every chunk costs at least 3 bytes, so len bounds the loop.
    for (size_t guard = 0; guard <= len; ++guard) {
        size_t line = 0;
        uint64_t size = 0;
        const int rc = chunk_size_line(data + pos, len - pos, &line, &size);
        if (rc != 0) return rc;
        pos += line;
        if (size == 0) break;
        if (size > len - pos) return -1;
        if (len - pos - size < 2) return -1;
        if (data[pos + size] != '\r' || data[pos + size + 1] != '\n') return 1;
        pos += static_cast<size_t>(size) + 2;
    }
    // Trailer section: header lines until an empty line.
    for (size_t guard = 0; guard <= len; ++guard) {
        const size_t start = pos;
        while (pos < len && data[pos] != '\n') ++pos;
        if (pos == len) return -1;
        if (pos == start || data[pos - 1] != '\r') return 1;
        ++pos;
        if (pos - start == 2) {
            *out_raw_len = pos;
            return 0;
        }
    }
    return 1;
}

size_t HTTP1Parser::dechunk_in_place(uint8_t* data, size_t raw_len) noexcept {
    assert(data != nullptr || raw_len == 0);
    size_t rd = 0;
    size_t wr = 0;
    for (size_t guard = 0; guard <= raw_len; ++guard) {
        size_t line = 0;
        uint64_t size = 0;
        const int rc = chunk_size_line(data + rd, raw_len - rd, &line, &size);
        assert(rc == 0);                       // scan_chunked validated it
        if (rc != 0 || size == 0) break;
        rd += line;
        std::memmove(data + wr, data + rd, static_cast<size_t>(size));
        wr += static_cast<size_t>(size);
        rd += static_cast<size_t>(size) + 2;
    }
    assert(wr <= raw_len);
    return wr;
}

int HTTP1Parser::parse_method(
    const uint8_t* data,
    size_t len,
    HTTP1Request& req
) noexcept {
    mark_ = pos_;
    
    // Find end of method (space)
    while (pos_ < len && data[pos_] != ' ') {
        if (!is_token_char(data[pos_])) {
            state_ = HTTP1State::ERROR;
            return 1;
        }
        pos_++;
    }
    
    if (pos_ >= len) {
        return -1;  // Need more data
    }
    
    // Extract method
    req.method_str = std::string_view(
        reinterpret_cast<const char*>(data + mark_),
        pos_ - mark_
    );
    
    // Map to enum
    if (req.method_str == "GET") req.method = HTTP1Method::GET;
    else if (req.method_str == "POST") req.method = HTTP1Method::POST;
    else if (req.method_str == "PUT") req.method = HTTP1Method::PUT;
    else if (req.method_str == "DELETE") req.method = HTTP1Method::DELETE;
    else if (req.method_str == "HEAD") req.method = HTTP1Method::HEAD;
    else if (req.method_str == "OPTIONS") req.method = HTTP1Method::OPTIONS;
    else if (req.method_str == "PATCH") req.method = HTTP1Method::PATCH;
    else if (req.method_str == "CONNECT") req.method = HTTP1Method::CONNECT;
    else if (req.method_str == "TRACE") req.method = HTTP1Method::TRACE;
    else req.method = HTTP1Method::UNKNOWN;
    
    pos_++;  // Skip space
    state_ = HTTP1State::URL;
    
    return 0;
}

int HTTP1Parser::parse_url(
    const uint8_t* data,
    size_t len,
    HTTP1Request& req
) noexcept {
    mark_ = pos_;
    
    // Find end of URL (space)
    while (pos_ < len && data[pos_] != ' ') {
        pos_++;
    }
    
    if (pos_ >= len) {
        return -1;  // Need more data
    }
    
    // Extract URL
    req.url = std::string_view(
        reinterpret_cast<const char*>(data + mark_),
        pos_ - mark_
    );
    
    pos_++;  // Skip space
    state_ = HTTP1State::VERSION;
    
    return 0;
}

int HTTP1Parser::parse_version(
    const uint8_t* data,
    size_t len,
    HTTP1Request& req
) noexcept {
    // Expect "HTTP/1.0" or "HTTP/1.1"
    if (pos_ + 10 > len) {
        return -1;  // Need more data
    }
    
    if (std::memcmp(data + pos_, "HTTP/1.1\r\n", 10) == 0) {
        req.version = HTTP1Version::HTTP_1_1;
        pos_ += 10;
    } else if (std::memcmp(data + pos_, "HTTP/1.0\r\n", 10) == 0) {
        req.version = HTTP1Version::HTTP_1_0;
        pos_ += 10;
    } else {
        state_ = HTTP1State::ERROR;
        return 1;
    }
    
    state_ = HTTP1State::HEADER_FIELD;
    return 0;
}

int HTTP1Parser::parse_header_field(
    const uint8_t* data,
    size_t len,
    HTTP1Request& req
) noexcept {
    if (req.header_count >= HTTP1Request::MAX_HEADERS) {
        state_ = HTTP1State::ERROR;
        return 1;
    }
    
    mark_ = pos_;
    
    // Find colon
    while (pos_ < len && data[pos_] != ':') {
        if (data[pos_] == '\r') {
            // End of headers
            return 0;
        }
        pos_++;
    }
    
    if (pos_ >= len) {
        return -1;  // Need more data
    }
    
    // Extract field name
    auto& header = req.headers[req.header_count];
    header.name = std::string_view(
        reinterpret_cast<const char*>(data + mark_),
        pos_ - mark_
    );
    
    pos_++;  // Skip colon
    
    // Skip whitespace after colon
    while (pos_ < len && (data[pos_] == ' ' || data[pos_] == '\t')) {
        pos_++;
    }
    
    state_ = HTTP1State::HEADER_VALUE;
    return 0;
}

int HTTP1Parser::parse_header_value(
    const uint8_t* data,
    size_t len,
    HTTP1Request& req
) noexcept {
    mark_ = pos_;
    
    // Find CRLF
    while (pos_ + 1 < len && !(data[pos_] == '\r' && data[pos_ + 1] == '\n')) {
        pos_++;
    }
    
    if (pos_ + 1 >= len) {
        return -1;  // Need more data
    }
    
    // Extract value (trim trailing whitespace)
    size_t value_end = pos_;
    while (value_end > mark_ && is_whitespace(data[value_end - 1])) {
        value_end--;
    }
    
    auto& header = req.headers[req.header_count];
    header.value = std::string_view(
        reinterpret_cast<const char*>(data + mark_),
        value_end - mark_
    );
    
    req.header_count++;
    pos_ += 2;  // Skip CRLF
    
    state_ = HTTP1State::HEADER_FIELD;
    return 0;
}

void HTTP1Parser::parse_url_components(HTTP1Request& req) noexcept {
    // Parse URL into path, query, fragment
    const char* url_data = req.url.data();
    size_t url_len = req.url.length();
    
    // Find query string (?)
    size_t query_pos = req.url.find('?');
    if (query_pos != std::string_view::npos) {
        req.path = std::string_view(url_data, query_pos);
        
        // Find fragment (#)
        size_t fragment_pos = req.url.find('#', query_pos);
        if (fragment_pos != std::string_view::npos) {
            req.query = std::string_view(url_data + query_pos + 1, fragment_pos - query_pos - 1);
            req.fragment = std::string_view(url_data + fragment_pos + 1, url_len - fragment_pos - 1);
        } else {
            req.query = std::string_view(url_data + query_pos + 1, url_len - query_pos - 1);
        }
    } else {
        // No query string, check for fragment
        size_t fragment_pos = req.url.find('#');
        if (fragment_pos != std::string_view::npos) {
            req.path = std::string_view(url_data, fragment_pos);
            req.fragment = std::string_view(url_data + fragment_pos + 1, url_len - fragment_pos - 1);
        } else {
            req.path = req.url;
        }
    }
}

bool HTTP1Parser::is_token_char(uint8_t c) noexcept {
    // RFC 7230: token characters
    return std::isalnum(c) || c == '!' || c == '#' || c == '$' || c == '%' ||
           c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' ||
           c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

bool HTTP1Parser::is_whitespace(uint8_t c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool HTTP1Parser::str_eq_ci(std::string_view a, std::string_view b) noexcept {
    if (a.length() != b.length()) {
        return false;
    }
    
    for (size_t i = 0; i < a.length(); ++i) {
        if (std::tolower(a[i]) != std::tolower(b[i])) {
            return false;
        }
    }
    
    return true;
}

} // namespace http
} // namespace bolt::api

