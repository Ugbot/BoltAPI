#include "boltapi/http/websocket.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <chrono>

namespace bolt::api {
namespace http {

// Internal implementation details
struct WebSocketConnection::Impl {
    std::mutex send_mutex;
    std::queue<std::string> send_queue;
    
    // Compression context (future)
    void* deflate_ctx = nullptr;
    void* inflate_ctx = nullptr;
    
    // Timing
    std::chrono::steady_clock::time_point last_ping;
    std::chrono::steady_clock::time_point last_pong;
    
    Impl() {
        last_ping = std::chrono::steady_clock::now();
        last_pong = std::chrono::steady_clock::now();
    }
};

WebSocketConnection::WebSocketConnection(uint64_t connection_id, const Config& config)
    : impl_(std::make_unique<Impl>()),
      connection_id_(connection_id),
      config_(config),
      fragment_opcode_(OpCode::CONTINUATION) {
}

WebSocketConnection::~WebSocketConnection() {
    if (open_) {
        close(static_cast<uint16_t>(CloseCode::GOING_AWAY), "Connection destroyed");
    }
}

int WebSocketConnection::send_text(const std::string& message) {
    if (!open_ || closing_) {
        return -1;
    }
    
    // Validate UTF-8
    if (!websocket::FrameParser::validate_utf8(
        reinterpret_cast<const uint8_t*>(message.data()),
        message.size())) {
        return -2;  // Invalid UTF-8
    }
    
    return send_frame(
        OpCode::TEXT,
        reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        true
    );
}

int WebSocketConnection::send_binary(const uint8_t* data, size_t length) {
    if (!open_ || closing_) {
        return -1;
    }
    
    return send_frame(OpCode::BINARY, data, length, true);
}

int WebSocketConnection::send_ping(const uint8_t* data, size_t length) {
    if (!open_ || closing_) {
        return -1;
    }
    
    impl_->last_ping = std::chrono::steady_clock::now();
    return send_frame(OpCode::PING, data, length, true);
}

int WebSocketConnection::send_pong(const uint8_t* data, size_t length) {
    if (!open_ || closing_) {
        return -1;
    }
    
    impl_->last_pong = std::chrono::steady_clock::now();
    return send_frame(OpCode::PONG, data, length, true);
}

int WebSocketConnection::close(uint16_t code, const char* reason) {
    if (!open_ || closing_) {
        return 0;
    }
    
    closing_ = true;
    
    std::string frame;
    if (code == static_cast<uint16_t>(CloseCode::NO_STATUS)) {
        websocket::FrameParser::build_frame(OpCode::CLOSE, nullptr, 0, true, false, frame);
    } else {
        websocket::FrameParser::build_close_frame(
            static_cast<CloseCode>(code),
            reason,
            frame
        );
    }
    
    // Send close frame
    std::lock_guard<std::mutex> lock(impl_->send_mutex);
    impl_->send_queue.push(frame);
    
    // TODO: Actually send via network
    
    open_ = false;
    
    if (on_close) {
        on_close(code, reason ? reason : "");
    }
    
    return 0;
}

size_t WebSocketConnection::feed(const uint8_t* data, size_t length) {
    assert((data != nullptr || length == 0) && "feed: null with length");
    size_t pos = 0;
    // Every productive step consumes >= 1 byte, so `length` bounds the loop.
    for (size_t step = 0; step <= length && pos < length; ++step) {
        size_t used = 0;
        if (handle_frame(data + pos, length - pos, used) < 0) break;
        assert(used > 0 && used <= length - pos && "feed: no progress");
        pos += used;
    }
    assert(pos <= length && "feed overran");
    return pos;
}

int WebSocketConnection::handle_frame(const uint8_t* data, size_t length) {
    return feed(data, length) == length ? 0 : -1;
}

// Incremental: consumes at most one frame header or one run of payload bytes
// per call, so a frame of any size streams through a small read buffer.
// Returns -1 (consumed 0) when more bytes are needed, 0 on progress. Protocol
// violations queue a close frame, mark the connection closed and swallow the
// rest of the input (still 0, so the caller flushes the close frame).
int WebSocketConnection::handle_frame(const uint8_t* data, size_t length, size_t& consumed_out) {
    assert((data != nullptr || length == 0) && "handle_frame: null with length");
    consumed_out = 0;
    if (length == 0) return -1;
    if (!open_) {
        consumed_out = length;  // closed: discard anything the peer still sends
        return 0;
    }
    if (!in_frame_) return begin_frame(data, length, consumed_out);

    const size_t take = static_cast<size_t>(
        std::min<uint64_t>(frame_remaining_, static_cast<uint64_t>(length)));
    uint8_t* dest = nullptr;
    if (is_control(frame_.opcode)) {
        assert(ctrl_len_ + take <= sizeof(ctrl_buf_) && "control payload overflow");
        dest = ctrl_buf_ + ctrl_len_;
        ctrl_len_ += take;
    } else {
        const size_t at = fragment_buffer_.size();
        fragment_buffer_.resize(at + take);
        dest = fragment_buffer_.data() + at;
    }
    std::memcpy(dest, data, take);
    if (frame_.mask) {
        websocket::FrameParser::unmask(dest, take, frame_.masking_key,
                                       static_cast<size_t>(frame_offset_));
    }
    frame_offset_ += take;
    frame_remaining_ -= take;
    consumed_out = take;
    bytes_received_ += take;
    if (frame_remaining_ == 0) finish_frame();
    assert(consumed_out <= length && "consumed past input");
    return 0;
}

bool WebSocketConnection::is_control(OpCode op) noexcept {
    return (static_cast<uint8_t>(op) & 0x08) != 0;
}

// RFC 6455 §5.2-§5.5 header checks. Returns 0 or the close code to fail with.
uint16_t WebSocketConnection::check_header(const websocket::FrameHeader& h) const noexcept {
    const uint8_t op = static_cast<uint8_t>(h.opcode);
    if (h.rsv1 || h.rsv2 || h.rsv3) return 1002;  // no extension negotiated
    if (op > 0x2 && (op < 0x8 || op > 0xA)) return 1002;  // reserved opcode
    if (!h.mask) return 1002;  // §5.1: client-to-server frames are masked
    if (is_control(h.opcode)) {
        if (!h.fin || h.payload_length > kMaxControlPayload) return 1002;
        return 0;
    }
    if (h.opcode == OpCode::CONTINUATION) {
        if (!in_fragment_) return 1002;
    } else if (in_fragment_) {
        return 1002;  // new data message inside a fragmented one
    }
    const uint64_t have = static_cast<uint64_t>(fragment_buffer_.size());
    if (h.payload_length > config_.max_message_size ||
        have + h.payload_length > config_.max_message_size)
        return 1009;
    return 0;
}

int WebSocketConnection::begin_frame(const uint8_t* data, size_t length, size_t& consumed_out) {
    assert(!in_frame_ && "begin_frame inside a frame");
    assert(length > 0 && "begin_frame: empty");
    size_t hlen = 0;
    websocket::FrameHeader h;
    const int r = websocket::FrameParser::parse_header(data, length, h, hlen);
    if (r < 0) return -1;
    const uint16_t err = (r > 0) ? uint16_t{1002} : check_header(h);
    if (err != 0) {
        fail(err, err == 1009 ? "Message too big" : "Protocol error");
        consumed_out = length;
        return 0;
    }
    frame_ = h;
    in_frame_ = true;
    frame_offset_ = 0;
    frame_remaining_ = h.payload_length;
    if (is_control(h.opcode)) {
        ctrl_len_ = 0;
    } else if (h.opcode != OpCode::CONTINUATION) {
        in_fragment_ = true;
        fragment_opcode_ = h.opcode;
        fragment_buffer_.clear();
    }
    consumed_out = hlen;
    bytes_received_ += hlen;
    if (frame_remaining_ == 0) finish_frame();
    return 0;
}

void WebSocketConnection::finish_frame() {
    assert(in_frame_ && "finish_frame outside a frame");
    assert(frame_remaining_ == 0 && "finish_frame with payload left");
    in_frame_ = false;
    if (is_control(frame_.opcode)) {
        handle_control_frame(frame_.opcode, ctrl_buf_, ctrl_len_);
        return;
    }
    if (!frame_.fin) return;
    in_fragment_ = false;
    handle_message(fragment_opcode_, fragment_buffer_.data(), fragment_buffer_.size());
    fragment_buffer_.clear();
}

void WebSocketConnection::fail(uint16_t code, const char* reason) {
    assert(code >= 1000 && "fail: bad close code");
    if (on_error) on_error(reason);
    close(code, reason);
    open_ = false;
    in_frame_ = false;
}

bool WebSocketConnection::is_open() const noexcept {
    return open_;
}

uint64_t WebSocketConnection::get_id() const noexcept {
    return connection_id_;
}

uint64_t WebSocketConnection::messages_sent() const noexcept {
    return messages_sent_;
}

uint64_t WebSocketConnection::messages_received() const noexcept {
    return messages_received_;
}

uint64_t WebSocketConnection::bytes_sent() const noexcept {
    return bytes_sent_;
}

uint64_t WebSocketConnection::bytes_received() const noexcept {
    return bytes_received_;
}

void WebSocketConnection::set_socket_fd(int fd) noexcept {
    socket_fd_ = fd;
}

int WebSocketConnection::get_socket_fd() const noexcept {
    return socket_fd_;
}

bool WebSocketConnection::has_pending_output() const noexcept {
    std::lock_guard<std::mutex> lock(impl_->send_mutex);
    return !impl_->send_queue.empty();
}

const std::string* WebSocketConnection::get_pending_output() const noexcept {
    std::lock_guard<std::mutex> lock(impl_->send_mutex);
    if (impl_->send_queue.empty()) {
        return nullptr;
    }
    return &impl_->send_queue.front();
}

void WebSocketConnection::pop_pending_output() noexcept {
    std::lock_guard<std::mutex> lock(impl_->send_mutex);
    if (!impl_->send_queue.empty()) {
        impl_->send_queue.pop();
    }
}

const std::string& WebSocketConnection::get_path() const noexcept {
    return path_;
}

void WebSocketConnection::set_path(const std::string& path) noexcept {
    path_ = path;
}

int WebSocketConnection::send_frame(OpCode opcode, const uint8_t* data, size_t length, bool fin) {
    std::string frame;
    
    // Fragment if needed
    if (config_.auto_fragment && length > config_.fragment_size) {
        size_t offset = 0;
        bool first = true;
        
        while (offset < length) {
            size_t chunk_size = std::min(config_.fragment_size, length - offset);
            bool last = (offset + chunk_size == length);
            
            OpCode frame_opcode = first ? opcode : OpCode::CONTINUATION;
            
            std::string chunk_frame;
            websocket::FrameParser::build_frame(
                frame_opcode,
                data + offset,
                chunk_size,
                last,
                false,  // rsv1 (compression)
                chunk_frame
            );
            
            frame += chunk_frame;
            offset += chunk_size;
            first = false;
        }
    } else {
        websocket::FrameParser::build_frame(
            opcode,
            data,
            length,
            fin,
            false,  // rsv1 (compression)
            frame
        );
    }
    
    // Queue frame for sending
    std::lock_guard<std::mutex> lock(impl_->send_mutex);
    impl_->send_queue.push(frame);
    
    // TODO: Actually send via network
    
    bytes_sent_ += frame.size();
    if (fin) {
        messages_sent_++;
    }
    
    return 0;
}

void WebSocketConnection::handle_message(OpCode opcode, const uint8_t* data, size_t length) {
    messages_received_++;


    if (opcode == OpCode::TEXT) {
        // Validate UTF-8
        if (!websocket::FrameParser::validate_utf8(data, length)) {
            if (on_error) {
                on_error("Invalid UTF-8 in text message");
            }
            close(static_cast<uint16_t>(CloseCode::INVALID_PAYLOAD), "Invalid UTF-8");
            return;
        }


        if (on_text_message) {
            std::string message(reinterpret_cast<const char*>(data), length);
            on_text_message(message);
        } else {
        }
    } else if (opcode == OpCode::BINARY) {
        if (on_binary_message) {
            on_binary_message(data, length);
        }
    }
}

void WebSocketConnection::handle_control_frame(OpCode opcode, const uint8_t* data, size_t length) {
    if (opcode == OpCode::PING) {
        // Respond with pong
        send_pong(data, length);
        if (on_ping) {
            on_ping();
        }
    } else if (opcode == OpCode::PONG) {
        impl_->last_pong = std::chrono::steady_clock::now();
        if (on_pong) {
            on_pong();
        }
    } else if (opcode == OpCode::CLOSE) {
        CloseCode code;
        std::string reason;
        if (websocket::FrameParser::parse_close_payload(data, length, code, reason) != 0) {
            fail(static_cast<uint16_t>(code), "Invalid close frame");
            return;
        }
        // Echo the peer's code (RFC 6455 §5.5.1); an empty close gets an empty
        // reply. close() fires on_close once; a reply to our own close only
        // finishes the handshake.
        if (!closing_) {
            close(static_cast<uint16_t>(code), reason.c_str());
        }
        open_ = false;
    }
}

} // namespace http
} // namespace bolt::api





