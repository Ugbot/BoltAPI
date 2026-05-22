/**
 * @file multipart_parser.h
 * @brief RFC 2046 compliant multipart/form-data parser
 *
 * Provides streaming multipart parsing for file uploads:
 * - Streaming parser (no full buffering required)
 * - Boundary detection and part separation
 * - Header parsing (Content-Disposition, Content-Type)
 * - Callback-based API for each part
 * - Memory-efficient with configurable limits
 *
 * Example:
 * @code
 * MultipartParser parser(boundary);
 *
 * parser.on_part_begin([](const PartHeaders& headers) {
 *     std::cout << "Part: " << headers.name << "\n";
 *     if (!headers.filename.empty()) {
 *         std::cout << "File: " << headers.filename << "\n";
 *     }
 * });
 *
 * parser.on_part_data([](const char* data, size_t len) {
 *     // Process chunk of part data
 * });
 *
 * parser.on_part_end([]() {
 *     // Part complete
 * });
 *
 * parser.parse(body.data(), body.size());
 * @endcode
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#include <BaseTsd.h>
#ifndef BOLTAPI_HAVE_SSIZE_T
#define BOLTAPI_HAVE_SSIZE_T 1
using ssize_t = SSIZE_T;
#endif
#endif

namespace bolt::api {

/**
 * Part headers from Content-Disposition and Content-Type.
 */
struct PartHeaders {
    std::string name;           // Field name from Content-Disposition
    std::string filename;       // Filename (empty for non-file fields)
    std::string content_type;   // Content-Type (default: text/plain)
    std::unordered_map<std::string, std::string> extra;  // Additional headers
};

/**
 * Parsed form field (text value).
 */
struct FormField {
    std::string name;
    std::string value;
};

/**
 * Parsed file upload.
 */
struct FileUpload {
    std::string name;           // Field name
    std::string filename;       // Original filename
    std::string content_type;   // MIME type
    std::vector<uint8_t> data;  // File contents
    size_t size;                // File size in bytes
};

/**
 * Streaming multipart parser.
 *
 * Parses multipart/form-data according to RFC 2046.
 * Supports streaming - data can be fed in chunks.
 */
class MultipartParser {
public:
    // Callbacks
    using OnPartBegin = std::function<void(const PartHeaders&)>;
    using OnPartData = std::function<void(const char*, size_t)>;
    using OnPartEnd = std::function<void()>;
    using OnError = std::function<void(const std::string&)>;

    // Parser states
    enum class State {
        START,
        BOUNDARY,
        HEADER_NAME,
        HEADER_VALUE,
        HEADER_END,
        PART_DATA,
        PART_END,
        END,
        ERROR
    };

    /**
     * Create parser with boundary string.
     *
     * @param boundary Boundary from Content-Type header
     */
    explicit MultipartParser(const std::string& boundary);

    /**
     * Create parser with boundary extracted from Content-Type.
     *
     * @param content_type Full Content-Type header value
     * @return Parser instance, or nullptr if boundary not found
     */
    static std::unique_ptr<MultipartParser> from_content_type(const std::string& content_type);

    // Set callbacks
    void on_part_begin(OnPartBegin callback) { on_part_begin_ = std::move(callback); }
    void on_part_data(OnPartData callback) { on_part_data_ = std::move(callback); }
    void on_part_end(OnPartEnd callback) { on_part_end_ = std::move(callback); }
    void on_error(OnError callback) { on_error_ = std::move(callback); }

    /**
     * Parse data chunk.
     *
     * @param data Pointer to data
     * @param len Data length
     * @return Number of bytes consumed, or -1 on error
     */
    ssize_t parse(const char* data, size_t len);

    /**
     * Check if parsing is complete.
     */
    bool is_complete() const { return state_ == State::END; }

    /**
     * Check if parser is in error state.
     */
    bool has_error() const { return state_ == State::ERROR; }

    /**
     * Get error message.
     */
    const std::string& error() const { return error_; }

    /**
     * Get current state.
     */
    State state() const { return state_; }

    /**
     * Reset parser for reuse.
     */
    void reset();

    /**
     * Extract boundary from Content-Type header.
     *
     * @param content_type Content-Type header value
     * @return Boundary string, or empty if not found
     */
    static std::string extract_boundary(const std::string& content_type);

private:
    std::string boundary_;
    std::string delimiter_;        // --boundary
    std::string end_delimiter_;    // --boundary--
    State state_;
    std::string error_;

    // Current part info
    PartHeaders current_headers_;
    std::string current_header_name_;
    std::string current_header_value_;

    // Buffer for handling partial boundary matches
    std::string buffer_;
    size_t buffer_pos_;

    // Callbacks
    OnPartBegin on_part_begin_;
    OnPartData on_part_data_;
    OnPartEnd on_part_end_;
    OnError on_error_;

    // Internal methods
    void emit_part_begin();
    void emit_part_data(const char* data, size_t len);
    void emit_part_end();
    void emit_error(const std::string& msg);

    void parse_content_disposition(const std::string& value);
    std::string trim(const std::string& s);
    std::string unquote(const std::string& s);

    // State machine processing methods (work on internal buffer)
    void process_start();
    void process_boundary();
    void process_header_name();
    void process_header_value();
    void process_part_data();
};

/**
 * Simple multipart parser for non-streaming use.
 *
 * Parses entire body at once and returns structured results.
 */
class MultipartFormData {
public:
    /**
     * Parse multipart body.
     *
     * @param content_type Content-Type header (must include boundary)
     * @param body Request body
     * @return true if parsing succeeded
     */
    bool parse(const std::string& content_type, const std::string& body);

    /**
     * Get form fields (text values).
     */
    const std::vector<FormField>& fields() const { return fields_; }

    /**
     * Get uploaded files.
     */
    const std::vector<FileUpload>& files() const { return files_; }

    /**
     * Get field by name.
     *
     * @param name Field name
     * @return Field value, or empty string if not found
     */
    std::string get_field(const std::string& name) const;

    /**
     * Get file by field name.
     *
     * @param name Field name
     * @return Pointer to FileUpload, or nullptr if not found
     */
    const FileUpload* get_file(const std::string& name) const;

    /**
     * Check if parsing was successful.
     */
    bool is_valid() const { return valid_; }

    /**
     * Get error message.
     */
    const std::string& error() const { return error_; }

private:
    std::vector<FormField> fields_;
    std::vector<FileUpload> files_;
    bool valid_ = false;
    std::string error_;
};

// ===========================================================================
// Implementation
// ===========================================================================

inline MultipartParser::MultipartParser(const std::string& boundary)
    : boundary_(boundary),
      delimiter_("--" + boundary),
      end_delimiter_("--" + boundary + "--"),
      state_(State::START),
      buffer_pos_(0) {
}

inline std::unique_ptr<MultipartParser> MultipartParser::from_content_type(const std::string& content_type) {
    std::string boundary = extract_boundary(content_type);
    if (boundary.empty()) {
        return nullptr;
    }
    return std::make_unique<MultipartParser>(boundary);
}

inline std::string MultipartParser::extract_boundary(const std::string& content_type) {
    // Look for boundary= in content type
    const std::string key = "boundary=";
    size_t pos = content_type.find(key);
    if (pos == std::string::npos) {
        return "";
    }

    pos += key.size();

    // Handle quoted boundary
    if (pos < content_type.size() && content_type[pos] == '"') {
        pos++;
        size_t end = content_type.find('"', pos);
        if (end == std::string::npos) {
            return "";
        }
        return content_type.substr(pos, end - pos);
    }

    // Unquoted boundary - read until semicolon or end
    size_t end = content_type.find(';', pos);
    if (end == std::string::npos) {
        end = content_type.size();
    }

    // Trim whitespace
    std::string boundary = content_type.substr(pos, end - pos);
    while (!boundary.empty() && (boundary.back() == ' ' || boundary.back() == '\t')) {
        boundary.pop_back();
    }

    return boundary;
}

inline void MultipartParser::reset() {
    state_ = State::START;
    error_.clear();
    current_headers_ = PartHeaders{};
    current_header_name_.clear();
    current_header_value_.clear();
    buffer_.clear();
    buffer_pos_ = 0;
}

inline void MultipartParser::emit_part_begin() {
    if (on_part_begin_) {
        on_part_begin_(current_headers_);
    }
}

inline void MultipartParser::emit_part_data(const char* data, size_t len) {
    if (on_part_data_ && len > 0) {
        on_part_data_(data, len);
    }
}

inline void MultipartParser::emit_part_end() {
    if (on_part_end_) {
        on_part_end_();
    }
}

inline void MultipartParser::emit_error(const std::string& msg) {
    error_ = msg;
    state_ = State::ERROR;
    if (on_error_) {
        on_error_(msg);
    }
}

inline std::string MultipartParser::trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) {
        start++;
    }
    size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t')) {
        end--;
    }
    return s.substr(start, end - start);
}

inline std::string MultipartParser::unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

inline void MultipartParser::parse_content_disposition(const std::string& value) {
    // Parse: form-data; name="field_name"; filename="file.txt"
    // The format is: disposition-type; param1=value1; param2=value2; ...
    current_headers_.name.clear();
    current_headers_.filename.clear();

    // Skip the disposition type (e.g., "form-data") and find first semicolon
    size_t pos = value.find(';');
    if (pos == std::string::npos) {
        return;  // No parameters
    }
    pos++;  // Skip the semicolon

    while (pos < value.size()) {
        // Skip whitespace
        while (pos < value.size() && (value[pos] == ' ' || value[pos] == '\t')) {
            pos++;
        }
        if (pos >= value.size()) break;

        // Find the next semicolon or end of string to get the parameter
        size_t param_end = value.find(';', pos);
        if (param_end == std::string::npos) {
            param_end = value.size();
        }

        // Extract this parameter (e.g., "name=\"value\"")
        std::string param = value.substr(pos, param_end - pos);
        pos = param_end + 1;  // Move past the semicolon

        // Find '=' in this parameter
        size_t eq = param.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(param.substr(0, eq));
        std::string val_part = param.substr(eq + 1);

        // Extract value, handling quotes
        std::string val;
        size_t val_start = 0;
        while (val_start < val_part.size() && (val_part[val_start] == ' ' || val_part[val_start] == '\t')) {
            val_start++;
        }

        if (val_start < val_part.size() && val_part[val_start] == '"') {
            // Quoted value
            val_start++;
            size_t val_end = val_part.find('"', val_start);
            if (val_end != std::string::npos) {
                val = val_part.substr(val_start, val_end - val_start);
            } else {
                val = val_part.substr(val_start);
            }
        } else {
            // Unquoted value
            val = trim(val_part.substr(val_start));
        }

        if (key == "name") {
            current_headers_.name = val;
        } else if (key == "filename") {
            current_headers_.filename = val;
        }
    }
}

inline ssize_t MultipartParser::parse(const char* data, size_t len) {
    // Append all data to buffer first
    buffer_.append(data, len);

    // Process as many states as possible from the buffer
    bool made_progress = true;
    while (made_progress && state_ != State::END && state_ != State::ERROR) {
        size_t old_buffer_size = buffer_.size();
        State old_state = state_;

        switch (state_) {
            case State::START:
                process_start();
                break;
            case State::BOUNDARY:
                process_boundary();
                break;
            case State::HEADER_NAME:
                process_header_name();
                break;
            case State::HEADER_VALUE:
                process_header_value();
                break;
            case State::HEADER_END:
                process_header_name();  // Handled by header_name
                break;
            case State::PART_DATA:
                process_part_data();
                break;
            default:
                return -1;
        }

        // We made progress if state changed or buffer size changed
        made_progress = (state_ != old_state || buffer_.size() != old_buffer_size);
    }

    return static_cast<ssize_t>(len);
}

// New internal processing methods that work on the buffer
inline void MultipartParser::process_start() {
    // Skip optional leading CRLF
    size_t pos = 0;
    if (buffer_.size() >= 2 && buffer_[0] == '\r' && buffer_[1] == '\n') {
        pos = 2;
    }

    // Look for delimiter
    size_t delim_pos = buffer_.find(delimiter_, pos);
    if (delim_pos == std::string::npos) {
        // Need more data
        if (buffer_.size() > delimiter_.size() * 2 + pos) {
            emit_error("Initial boundary not found");
        }
        return;
    }

    // Check for CRLF after delimiter
    size_t after = delim_pos + delimiter_.size();
    if (buffer_.size() < after + 2) {
        return;  // Need more data
    }

    if (buffer_[after] == '-' && buffer_[after + 1] == '-') {
        // End marker at start - empty body
        state_ = State::END;
        buffer_.clear();
        return;
    }

    if (buffer_[after] != '\r' || buffer_[after + 1] != '\n') {
        emit_error("Invalid boundary format");
        return;
    }

    // Move to header parsing
    state_ = State::HEADER_NAME;
    current_headers_ = PartHeaders{};
    current_headers_.content_type = "text/plain";
    buffer_.erase(0, after + 2);
}

inline void MultipartParser::process_boundary() {
    if (buffer_.size() < 2) {
        return;  // Need more data
    }

    // Check for end marker
    if (buffer_.size() >= end_delimiter_.size() &&
        buffer_.compare(0, end_delimiter_.size(), end_delimiter_) == 0) {
        state_ = State::END;
        buffer_.clear();
        return;
    }

    // Check for regular delimiter
    if (buffer_.size() >= delimiter_.size() &&
        buffer_.compare(0, delimiter_.size(), delimiter_) == 0) {
        size_t after = delimiter_.size();
        if (buffer_.size() < after + 2) {
            return;  // Need more data
        }

        if (buffer_[after] == '-' && buffer_[after + 1] == '-') {
            state_ = State::END;
            buffer_.clear();
            return;
        }

        if (buffer_[after] != '\r' || buffer_[after + 1] != '\n') {
            emit_error("Invalid boundary format");
            return;
        }

        // Start new part
        state_ = State::HEADER_NAME;
        current_headers_ = PartHeaders{};
        current_headers_.content_type = "text/plain";
        buffer_.erase(0, after + 2);
        return;
    }

    emit_error("Expected boundary");
}

inline void MultipartParser::process_header_name() {
    // Look for colon or CRLF (empty line = end of headers)
    size_t colon = buffer_.find(':');
    size_t crlf = buffer_.find("\r\n");

    if (crlf != std::string::npos && (colon == std::string::npos || crlf < colon)) {
        // Empty line - end of headers
        if (crlf == 0) {
            emit_part_begin();
            state_ = State::PART_DATA;
            buffer_.erase(0, 2);
            return;
        }
    }

    if (colon == std::string::npos) {
        // Need more data
        if (buffer_.size() > 1024) {
            emit_error("Header name too long");
        }
        return;
    }

    current_header_name_ = trim(buffer_.substr(0, colon));
    state_ = State::HEADER_VALUE;
    buffer_.erase(0, colon + 1);
}

inline void MultipartParser::process_header_value() {
    size_t crlf = buffer_.find("\r\n");
    if (crlf == std::string::npos) {
        if (buffer_.size() > 8192) {
            emit_error("Header value too long");
        }
        return;  // Need more data
    }

    current_header_value_ = trim(buffer_.substr(0, crlf));

    // Process header
    std::string lower_name = current_header_name_;
    for (char& c : lower_name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    if (lower_name == "content-disposition") {
        parse_content_disposition(current_header_value_);
    } else if (lower_name == "content-type") {
        current_headers_.content_type = current_header_value_;
    } else {
        current_headers_.extra[current_header_name_] = current_header_value_;
    }

    state_ = State::HEADER_NAME;
    buffer_.erase(0, crlf + 2);
}

inline void MultipartParser::process_part_data() {
    // Look for boundary in data (preceded by CRLF)
    const std::string search = "\r\n" + delimiter_;

    size_t pos = buffer_.find(search);
    if (pos != std::string::npos) {
        // Emit data before boundary
        if (pos > 0) {
            emit_part_data(buffer_.data(), pos);
        }
        emit_part_end();

        // Check what follows the delimiter
        size_t after = pos + search.size();
        if (buffer_.size() < after + 2) {
            // Need more data to determine if end or continuation
            buffer_.erase(0, pos + 2);  // Erase up to and including CRLF before boundary
            state_ = State::BOUNDARY;
            return;
        }

        if (buffer_[after] == '-' && buffer_[after + 1] == '-') {
            state_ = State::END;
            buffer_.clear();
            return;
        }

        if (buffer_[after] == '\r' && buffer_[after + 1] == '\n') {
            // Another part follows
            state_ = State::HEADER_NAME;
            current_headers_ = PartHeaders{};
            current_headers_.content_type = "text/plain";
            buffer_.erase(0, after + 2);
            return;
        }

        emit_error("Invalid boundary format");
        return;
    }

    // No boundary found - emit what we can
    // Keep enough bytes to match a potential partial boundary
    if (buffer_.size() > search.size()) {
        size_t safe_len = buffer_.size() - search.size();
        emit_part_data(buffer_.data(), safe_len);
        buffer_.erase(0, safe_len);
    }
}

// ===========================================================================
// MultipartFormData Implementation
// ===========================================================================

inline bool MultipartFormData::parse(const std::string& content_type, const std::string& body) {
    fields_.clear();
    files_.clear();
    valid_ = false;
    error_.clear();

    auto parser = MultipartParser::from_content_type(content_type);
    if (!parser) {
        error_ = "Invalid or missing boundary in Content-Type";
        return false;
    }

    // Current part being accumulated
    PartHeaders current_headers;
    std::vector<uint8_t> current_data;

    parser->on_part_begin([&](const PartHeaders& headers) {
        current_headers = headers;
        current_data.clear();
    });

    parser->on_part_data([&](const char* data, size_t len) {
        current_data.insert(current_data.end(), data, data + len);
    });

    parser->on_part_end([&]() {
        if (current_headers.filename.empty()) {
            // Text field
            FormField field;
            field.name = current_headers.name;
            field.value = std::string(current_data.begin(), current_data.end());
            fields_.push_back(std::move(field));
        } else {
            // File upload
            FileUpload file;
            file.name = current_headers.name;
            file.filename = current_headers.filename;
            file.content_type = current_headers.content_type;
            file.data = std::move(current_data);
            file.size = file.data.size();
            files_.push_back(std::move(file));
        }
    });

    parser->on_error([&](const std::string& msg) {
        error_ = msg;
    });

    ssize_t result = parser->parse(body.data(), body.size());
    if (result < 0 || parser->has_error()) {
        if (error_.empty()) {
            error_ = "Parse error";
        }
        return false;
    }

    valid_ = true;
    return true;
}

inline std::string MultipartFormData::get_field(const std::string& name) const {
    for (const auto& field : fields_) {
        if (field.name == name) {
            return field.value;
        }
    }
    return "";
}

inline const FileUpload* MultipartFormData::get_file(const std::string& name) const {
    for (const auto& file : files_) {
        if (file.name == name) {
            return &file;
        }
    }
    return nullptr;
}

} // namespace bolt::api
