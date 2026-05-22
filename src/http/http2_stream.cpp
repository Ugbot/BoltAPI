#include "boltapi/http/http2_stream.h"
#include <algorithm>

namespace bolt::api {
namespace http2 {

using core::result;
using core::error_code;
using core::ok;
using core::err;

// ============================================================================
// FastHeaders Implementation
// ============================================================================

std::string_view FastHeaders::intern_content_type(std::string_view value) noexcept {
    // Try to match common content-types to avoid allocation
    if (value == common_headers::CT_JSON) return common_headers::CT_JSON;
    if (value == common_headers::CT_TEXT_PLAIN) return common_headers::CT_TEXT_PLAIN;
    if (value == common_headers::CT_TEXT_HTML) return common_headers::CT_TEXT_HTML;
    if (value == common_headers::CT_OCTET_STREAM) return common_headers::CT_OCTET_STREAM;
    if (value == common_headers::CT_FORM_URLENCODED) return common_headers::CT_FORM_URLENCODED;
    if (value == common_headers::CT_MULTIPART) return common_headers::CT_MULTIPART;
    return {};  // Empty means not interned
}

std::string_view FastHeaders::intern_method(std::string_view value) noexcept {
    // Try to match common methods
    if (value == common_headers::METHOD_GET) return common_headers::METHOD_GET;
    if (value == common_headers::METHOD_POST) return common_headers::METHOD_POST;
    if (value == common_headers::METHOD_PUT) return common_headers::METHOD_PUT;
    if (value == common_headers::METHOD_DELETE) return common_headers::METHOD_DELETE;
    if (value == common_headers::METHOD_PATCH) return common_headers::METHOD_PATCH;
    if (value == common_headers::METHOD_HEAD) return common_headers::METHOD_HEAD;
    if (value == common_headers::METHOD_OPTIONS) return common_headers::METHOD_OPTIONS;
    return {};  // Empty means not interned
}

void FastHeaders::set_path(std::string_view p) {
    // Path usually needs to be stored (dynamic)
    path_storage_ = std::string(p);
    path_ = path_storage_;
}

void FastHeaders::set_authority(std::string_view a) {
    // Authority usually needs to be stored (dynamic)
    authority_storage_ = std::string(a);
    authority_ = authority_storage_;
}

void FastHeaders::add(std::string_view name, std::string_view value) {
    // Handle pseudo-headers
    if (!name.empty() && name[0] == ':') {
        if (name == common_headers::HDR_METHOD) {
            auto interned = intern_method(value);
            method_ = interned.empty() ? value : interned;
            return;
        }
        if (name == common_headers::HDR_PATH) {
            set_path(value);
            return;
        }
        if (name == common_headers::HDR_SCHEME) {
            scheme_ = value;
            return;
        }
        if (name == common_headers::HDR_AUTHORITY) {
            set_authority(value);
            return;
        }
        if (name == common_headers::HDR_STATUS) {
            status_ = value;
            return;
        }
    }
    
    // Try to use common header slots
    if (common_count_ < COMMON_HEADER_SLOTS) {
        auto& slot = common_headers_[common_count_];
        
        // Try to intern content-type value
        if (name == common_headers::HDR_CONTENT_TYPE) {
            auto interned = intern_content_type(value);
            if (!interned.empty()) {
                slot.set_view(common_headers::HDR_CONTENT_TYPE, interned);
                ++common_count_;
                return;
            }
        }
        
        // Store with owned copy (string_view lifetime not guaranteed)
        slot.set_owned(std::string(name), std::string(value));
        ++common_count_;
        return;
    }
    
    // Overflow to vector
    overflow_headers_.emplace_back(std::string(name), std::string(value));
}

void FastHeaders::add(std::string name, std::string value) {
    // Handle pseudo-headers  
    if (!name.empty() && name[0] == ':') {
        if (name == common_headers::HDR_METHOD) {
            auto interned = intern_method(value);
            method_ = interned.empty() ? value : interned;
            return;
        }
        if (name == common_headers::HDR_PATH) {
            path_storage_ = std::move(value);
            path_ = path_storage_;
            return;
        }
        if (name == common_headers::HDR_SCHEME) {
            scheme_ = value;  // scheme is usually "https" - short lived
            return;
        }
        if (name == common_headers::HDR_AUTHORITY) {
            authority_storage_ = std::move(value);
            authority_ = authority_storage_;
            return;
        }
        if (name == common_headers::HDR_STATUS) {
            status_ = value;
            return;
        }
    }
    
    // Try to use common header slots
    if (common_count_ < COMMON_HEADER_SLOTS) {
        auto& slot = common_headers_[common_count_];
        
        // Try to intern content-type value
        if (name == common_headers::HDR_CONTENT_TYPE) {
            auto interned = intern_content_type(value);
            if (!interned.empty()) {
                slot.set_view(common_headers::HDR_CONTENT_TYPE, interned);
                ++common_count_;
                return;
            }
        }
        
        slot.set_owned(std::move(name), std::move(value));
        ++common_count_;
        return;
    }
    
    // Overflow to vector
    overflow_headers_.emplace_back(std::move(name), std::move(value));
}

std::string_view FastHeaders::get(std::string_view name) const noexcept {
    // Check pseudo-headers first
    if (!name.empty() && name[0] == ':') {
        if (name == common_headers::HDR_METHOD) return method_;
        if (name == common_headers::HDR_PATH) return path_;
        if (name == common_headers::HDR_SCHEME) return scheme_;
        if (name == common_headers::HDR_AUTHORITY) return authority_;
        if (name == common_headers::HDR_STATUS) return status_;
    }
    
    // Search common headers
    for (size_t i = 0; i < common_count_; ++i) {
        if (common_headers_[i].name == name) {
            return common_headers_[i].value;
        }
    }
    
    // Search overflow
    for (const auto& h : overflow_headers_) {
        if (h.name == name) {
            return h.value;
        }
    }
    
    return {};
}

bool FastHeaders::has(std::string_view name) const noexcept {
    return !get(name).empty();
}

size_t FastHeaders::size() const noexcept {
    size_t count = 0;
    if (!method_.empty()) ++count;
    if (!path_.empty()) ++count;
    if (!scheme_.empty()) ++count;
    if (!authority_.empty()) ++count;
    if (!status_.empty()) ++count;
    return count + common_count_ + overflow_headers_.size();
}

void FastHeaders::clear() noexcept {
    method_ = {};
    path_ = {};
    scheme_ = {};
    authority_ = {};
    status_ = {};
    path_storage_.clear();
    authority_storage_.clear();
    common_count_ = 0;
    overflow_headers_.clear();
}

std::unordered_map<std::string, std::string> FastHeaders::to_map() const {
    std::unordered_map<std::string, std::string> result;
    result.reserve(size());
    
    for_each([&result](std::string_view name, std::string_view value) {
        result.emplace(std::string(name), std::string(value));
    });
    
    return result;
}

// Http2Stream implementation

Http2Stream::Http2Stream(uint32_t stream_id, uint32_t initial_window_size)
    : stream_id_(stream_id),
      send_window_(static_cast<int32_t>(initial_window_size)),
      recv_window_(static_cast<int32_t>(initial_window_size)) {}

void Http2Stream::on_headers_sent(bool end_stream) noexcept {
    switch (state_) {
    case StreamState::IDLE:
        state_ = end_stream ? StreamState::HALF_CLOSED_LOCAL : StreamState::OPEN;
        break;
    case StreamState::RESERVED_LOCAL:
        state_ = end_stream ? StreamState::HALF_CLOSED_LOCAL : StreamState::OPEN;
        break;
    case StreamState::OPEN:
        if (end_stream) {
            state_ = StreamState::HALF_CLOSED_LOCAL;
        }
        break;
    case StreamState::HALF_CLOSED_REMOTE:
        if (end_stream) {
            state_ = StreamState::CLOSED;
        }
        break;
    default:
        // Invalid state transition - stream already closed
        break;
    }
}

void Http2Stream::on_headers_received(bool end_stream) noexcept {
    switch (state_) {
    case StreamState::IDLE:
        state_ = end_stream ? StreamState::HALF_CLOSED_REMOTE : StreamState::OPEN;
        break;
    case StreamState::RESERVED_REMOTE:
        state_ = end_stream ? StreamState::HALF_CLOSED_REMOTE : StreamState::OPEN;
        break;
    case StreamState::OPEN:
        if (end_stream) {
            state_ = StreamState::HALF_CLOSED_REMOTE;
        }
        break;
    case StreamState::HALF_CLOSED_LOCAL:
        if (end_stream) {
            state_ = StreamState::CLOSED;
        }
        break;
    default:
        // Invalid state transition
        break;
    }
}

void Http2Stream::on_data_sent(bool end_stream) noexcept {
    if (end_stream) {
        switch (state_) {
        case StreamState::OPEN:
            state_ = StreamState::HALF_CLOSED_LOCAL;
            break;
        case StreamState::HALF_CLOSED_REMOTE:
            state_ = StreamState::CLOSED;
            break;
        default:
            // Invalid state
            break;
        }
    }
}

void Http2Stream::on_data_received(bool end_stream) noexcept {
    if (end_stream) {
        switch (state_) {
        case StreamState::OPEN:
            state_ = StreamState::HALF_CLOSED_REMOTE;
            break;
        case StreamState::HALF_CLOSED_LOCAL:
            state_ = StreamState::CLOSED;
            break;
        default:
            // Invalid state
            break;
        }
    }
}

void Http2Stream::on_rst_stream() noexcept {
    state_ = StreamState::CLOSED;
}

void Http2Stream::on_push_promise_sent() noexcept {
    if (state_ == StreamState::IDLE) {
        state_ = StreamState::RESERVED_LOCAL;
    }
}

void Http2Stream::on_push_promise_received() noexcept {
    if (state_ == StreamState::IDLE) {
        state_ = StreamState::RESERVED_REMOTE;
    }
}

result<void> Http2Stream::update_send_window(int32_t increment) noexcept {
    if (increment <= 0) {
        return err<void>(error_code::internal_error);
    }

    // Check for overflow (RFC 7540 Section 6.9.1)
    if (send_window_ > INT32_MAX - increment) {
        return err<void>(error_code::internal_error);
    }

    send_window_ += increment;
    return ok();
}

result<void> Http2Stream::update_recv_window(int32_t increment) noexcept {
    if (increment <= 0) {
        return err<void>(error_code::internal_error);
    }

    // Check for overflow
    if (recv_window_ > INT32_MAX - increment) {
        return err<void>(error_code::internal_error);
    }

    recv_window_ += increment;
    return ok();
}

result<void> Http2Stream::consume_send_window(uint32_t size) noexcept {
    // Check if we have enough window
    if (static_cast<int32_t>(size) > send_window_) {
        return err<void>(error_code::internal_error);
    }

    send_window_ -= static_cast<int32_t>(size);
    return ok();
}

result<void> Http2Stream::consume_recv_window(uint32_t size) noexcept {
    // Check if we have enough window
    if (static_cast<int32_t>(size) > recv_window_) {
        return err<void>(error_code::internal_error);
    }

    recv_window_ -= static_cast<int32_t>(size);
    return ok();
}

// StreamManager implementation

StreamManager::StreamManager(uint32_t initial_window_size)
    : initial_window_size_(initial_window_size) {}

result<Http2Stream*> StreamManager::create_stream(uint32_t stream_id) noexcept {
    // Check if stream already exists
    if (streams_.find(stream_id) != streams_.end()) {
        return err<Http2Stream*>(error_code::internal_error);
    }

    // Create new stream
    auto result = streams_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(stream_id),
        std::forward_as_tuple(stream_id, initial_window_size_)
    );

    if (!result.second) {
        return err<Http2Stream*>(error_code::internal_error);
    }

    return ok(&result.first->second);
}

Http2Stream* StreamManager::get_stream(uint32_t stream_id) noexcept {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return nullptr;
    }
    return &it->second;
}

void StreamManager::remove_stream(uint32_t stream_id) noexcept {
    streams_.erase(stream_id);
}

void StreamManager::update_initial_window_size(uint32_t new_size) noexcept {
    // Calculate difference
    int32_t diff = static_cast<int32_t>(new_size) - static_cast<int32_t>(initial_window_size_);

    // Update all existing streams
    for (auto& pair : streams_) {
        Http2Stream& stream = pair.second;

        // Update send window by difference
        if (diff > 0) {
            stream.update_send_window(diff);
        } else if (diff < 0) {
            // Decrease window (can go negative per spec)
            stream.send_window_ += diff;
        }
    }

    initial_window_size_ = new_size;
}

} // namespace http2
} // namespace bolt::api
