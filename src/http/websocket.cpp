#include "boltapi/http/websocket.h"
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
    websocket::FrameParser::build_close_frame(
        static_cast<CloseCode>(code),
        reason,
        frame
    );
    
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

int WebSocketConnection::handle_frame(const uint8_t* data, size_t length) {
    size_t consumed = 0;
    return handle_frame(data, length, consumed);
}

int WebSocketConnection::handle_frame(const uint8_t* data, size_t length, size_t& consumed_out) {
    consumed_out = 0;
    websocket::FrameHeader header;
    const uint8_t* payload_start = nullptr;
    size_t payload_length = 0;
    
    int result = parser_.parse_frame(
        data,
        length,
        consumed_out,
        header,
        payload_start,
        payload_length
    );
    
    if (result != 0) {
        return result;  // Need more data or error
    }
    
    // Reset parser for next frame
    parser_.reset();
    
    // Unmask if masked (client frames should be masked)
    std::vector<uint8_t> payload_copy;
    const uint8_t* payload = payload_start;
    
    if (header.mask && payload_start && payload_length > 0) {
        payload_copy.assign(payload_start, payload_start + payload_length);
        websocket::FrameParser::unmask(
            payload_copy.data(),
            payload_length,
            header.masking_key,
            0
        );
        payload = payload_copy.data();
    }
    
    bytes_received_ += consumed_out;
    
    // Handle control frames
    if (header.opcode == OpCode::CLOSE ||
        header.opcode == OpCode::PING ||
        header.opcode == OpCode::PONG) {
        handle_control_frame(header.opcode, payload, payload_length);
        return 0;
    }
    
    // Handle data frames (with fragmentation)
    if (!in_fragment_) {
        if (header.opcode == OpCode::TEXT || header.opcode == OpCode::BINARY) {
            if (header.fin) {
                // Complete message in one frame
                handle_message(header.opcode, payload, payload_length);
            } else {
                // Start of fragmented message
                in_fragment_ = true;
                fragment_opcode_ = header.opcode;
                fragment_buffer_.assign(payload, payload + payload_length);
            }
        }
    } else {
        // Continuation of fragmented message
        if (header.opcode != OpCode::CONTINUATION) {
            // Protocol error
            if (on_error) {
                on_error("Unexpected opcode in fragmented message");
            }
            close(static_cast<uint16_t>(CloseCode::PROTOCOL_ERROR), "Protocol error");
            return -1;
        }
        
        fragment_buffer_.insert(fragment_buffer_.end(), payload, payload + payload_length);
        
        if (header.fin) {
            // End of fragmented message
            handle_message(
                fragment_opcode_,
                fragment_buffer_.data(),
                fragment_buffer_.size()
            );
            in_fragment_ = false;
            fragment_buffer_.clear();
        }
        
        // Check max message size
        if (fragment_buffer_.size() > config_.max_message_size) {
            if (on_error) {
                on_error("Message too large");
            }
            close(static_cast<uint16_t>(CloseCode::MESSAGE_TOO_BIG), "Message too large");
            return -1;
        }
    }
    
    return 0;
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
        
        websocket::FrameParser::parse_close_payload(data, length, code, reason);
        
        // Send close response if not already closing
        if (!closing_) {
            close(static_cast<uint16_t>(code), reason.c_str());
        }
        
        open_ = false;
        
        if (on_close) {
            on_close(static_cast<uint16_t>(code), reason.c_str());
        }
    }
}

} // namespace http
} // namespace bolt::api





