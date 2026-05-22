#pragma once
/**
 * @file request_body_buffer.h
 * @brief Reusable request body buffer backed by a thread-local arena.
 *
 * Shared abstraction for HTTP request body accumulation across all protocols
 * (HTTP/1.1, HTTP/2, HTTP/3). Wraps BodyBufferArena to provide a simple
 * append/view/reset API with automatic pool management.
 *
 * Usage patterns:
 *
 *   // Any protocol: accumulate from frame/socket data
 *   RequestBodyBuffer body;
 *   body.reserve(content_length, max_body_size);
 *   body.append(data, len);
 *   std::string_view sv = body.view();
 *   // destructor auto-releases arena buffer
 *
 *   // HTTP/1.1 two-phase: adopt partially-read stack buffer
 *   body.adopt(stack_buf, bytes_read);
 *   // then continue reading into body via writable_data()/advance()
 */

#include "boltapi/http/body_buffer_arena.h"
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace bolt::api {
namespace http {

class RequestBodyBuffer {
public:
    RequestBodyBuffer() = default;
    ~RequestBodyBuffer() = default;

    // Move-only (arena Handle is move-only)
    RequestBodyBuffer(RequestBodyBuffer&&) = default;
    RequestBodyBuffer& operator=(RequestBodyBuffer&&) = default;
    RequestBodyBuffer(const RequestBodyBuffer&) = delete;
    RequestBodyBuffer& operator=(const RequestBodyBuffer&) = delete;

    /// Pre-acquire arena buffer for a known body size (from Content-Length).
    /// Validates against max_body_size before allocating.
    /// Returns false if content_length exceeds max_body_size.
    bool reserve(size_t content_length, size_t max_body_size) {
        if (content_length > max_body_size) return false;
        if (content_length <= remaining()) return true;
        handle_ = thread_body_arena().acquire(content_length);
        buf_ = handle_.data();
        buf_cap_ = handle_.capacity();
        return true;
    }

    /// Append body data. Grows via arena if needed.
    bool append(const uint8_t* data, size_t len) {
        ensure_capacity(size_ + len);
        std::memcpy(buf_ + size_, data, len);
        size_ += len;
        return true;
    }

    bool append(const char* data, size_t len) {
        return append(reinterpret_cast<const uint8_t*>(data), len);
    }

    /// Adopt data already in a stack buffer (HTTP/1.1 two-phase pattern).
    /// Acquires arena buffer if needed, copies data_len bytes from src.
    void adopt(const uint8_t* src, size_t data_len) {
        if (data_len > buf_cap_) {
            handle_ = thread_body_arena().acquire(data_len);
            buf_ = handle_.data();
            buf_cap_ = handle_.capacity();
        }
        std::memcpy(buf_, src, data_len);
        size_ = data_len;
    }

    /// Raw pointer to body data.
    const uint8_t* data() const noexcept { return buf_; }
    uint8_t* writable_data() noexcept { return buf_; }

    /// Bytes written so far.
    size_t size() const noexcept { return size_; }

    /// Total buffer capacity.
    size_t capacity() const noexcept { return buf_cap_; }

    /// Space available for writing.
    size_t remaining() const noexcept { return buf_cap_ > size_ ? buf_cap_ - size_ : 0; }

    /// Zero-copy view of the body.
    std::string_view view() const noexcept {
        return {reinterpret_cast<const char*>(buf_), size_};
    }

    /// Copy body to std::string.
    std::string to_string() const {
        return std::string(reinterpret_cast<const char*>(buf_), size_);
    }

    /// Whether an arena buffer is currently held.
    bool is_arena_backed() const noexcept { return static_cast<bool>(handle_); }

    /// Release arena buffer, return to empty state.
    void reset() {
        handle_ = {};
        buf_ = nullptr;
        buf_cap_ = 0;
        size_ = 0;
    }

    /// Direct write access for socket reads: returns {write_ptr, max_writable_bytes}.
    std::pair<uint8_t*, size_t> write_head() noexcept {
        return {buf_ + size_, buf_cap_ - size_};
    }

    /// Advance size after writing n bytes at write_head().
    void advance(size_t n) noexcept { size_ += n; }

private:
    BodyBufferArena::Handle handle_;
    uint8_t* buf_ = nullptr;
    size_t buf_cap_ = 0;
    size_t size_ = 0;

    void ensure_capacity(size_t needed) {
        if (needed <= buf_cap_) return;
        auto new_handle = thread_body_arena().acquire(needed);
        if (size_ > 0 && buf_) {
            std::memcpy(new_handle.data(), buf_, size_);
        }
        handle_ = std::move(new_handle);
        buf_ = handle_.data();
        buf_cap_ = handle_.capacity();
    }
};

}  // namespace http
}  // namespace bolt::api
