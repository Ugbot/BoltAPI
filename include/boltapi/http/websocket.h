#pragma once

#include "boltapi/http/websocket_parser.h"
#include <memory>
#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>

namespace bolt::api {
namespace http {

/**
 * WebSocket connection handler.
 * 
 * High-performance WebSocket implementation with:
 * - Text and binary message support
 * - Automatic ping/pong handling
 * - Permessage-deflate compression
 * - Fragmentation support
 * - Close handshake
 */
class WebSocketConnection {
public:
    // Configuration
    struct Config {
        bool enable_compression;
        size_t max_message_size;
        uint32_t ping_interval_ms;
        uint32_t pong_timeout_ms;
        bool auto_fragment;
        size_t fragment_size;

        Config()
            : enable_compression(true),
              max_message_size(16 * 1024 * 1024),
              ping_interval_ms(30000),
              pong_timeout_ms(5000),
              auto_fragment(true),
              fragment_size(65536) {}
    };
    
    // Opcodes (re-export for convenience)
    using OpCode = websocket::OpCode;
    using CloseCode = websocket::CloseCode;
    
    /**
     * Create WebSocket connection.
     * 
     * @param connection_id Unique connection ID
     * @param config Configuration
     */
    explicit WebSocketConnection(uint64_t connection_id, const Config& config = Config{});
    
    ~WebSocketConnection();

    // Non-copyable, non-movable
    WebSocketConnection(const WebSocketConnection&) = delete;
    WebSocketConnection& operator=(const WebSocketConnection&) = delete;
    WebSocketConnection(WebSocketConnection&&) = delete;
    WebSocketConnection& operator=(WebSocketConnection&&) = delete;
    
    /**
     * Send text message.
     * 
     * @param message Text message
     * @return 0 on success, error code otherwise
     */
    int send_text(const std::string& message);
    
    /**
     * Send binary message.
     * 
     * @param data Binary data
     * @param length Data length
     * @return 0 on success, error code otherwise
     */
    int send_binary(const uint8_t* data, size_t length);
    
    /**
     * Send ping frame.
     * 
     * @param data Optional ping data
     * @param length Data length
     * @return 0 on success, error code otherwise
     */
    int send_ping(const uint8_t* data = nullptr, size_t length = 0);
    
    /**
     * Send pong frame.
     * 
     * @param data Optional pong data
     * @param length Data length
     * @return 0 on success, error code otherwise
     */
    int send_pong(const uint8_t* data = nullptr, size_t length = 0);
    
    /**
     * Close connection.
     * 
     * @param code Close code
     * @param reason Close reason (optional)
     * @return 0 on success, error code otherwise
     */
    int close(uint16_t code = 1000, const char* reason = nullptr);
    
    /**
     * Feed received bytes: processes every complete header / payload run in
     * `data` and returns how many bytes were consumed. Unconsumed bytes are a
     * partial frame header; keep them and call again with more appended.
     * Frames of any size stream through (payload is not buffered here beyond
     * the bounded message assembly). Protocol errors close the connection.
     */
    size_t feed(const uint8_t* data, size_t length);

    /** feed() and report whether all input was consumed (0) or not (-1). */
    int handle_frame(const uint8_t* data, size_t length);

    /**
     * One incremental step: consumes one frame header or one run of payload.
     * @return 0 on progress (`consumed` > 0), -1 if more data is needed
     *         (`consumed` == 0).
     */
    int handle_frame(const uint8_t* data, size_t length, size_t& consumed);

    /**
     * Set socket file descriptor for direct I/O.
     *
     * @param fd Socket file descriptor
     */
    void set_socket_fd(int fd) noexcept;

    /**
     * Get socket file descriptor.
     */
    int get_socket_fd() const noexcept;

    /**
     * Check if there's pending output to send.
     */
    bool has_pending_output() const noexcept;

    /**
     * Get pending output frame.
     * Returns the front of the send queue without removing it.
     *
     * @return Pointer to output data, or nullptr if empty
     */
    const std::string* get_pending_output() const noexcept;

    /**
     * Pop the front of the send queue after sending.
     */
    void pop_pending_output() noexcept;

    /**
     * Get WebSocket path (for handler lookup).
     */
    const std::string& get_path() const noexcept;

    /**
     * Set WebSocket path.
     */
    void set_path(const std::string& path) noexcept;
    
    /**
     * Check if connection is open.
     */
    bool is_open() const noexcept;
    
    /**
     * Get connection ID.
     */
    uint64_t get_id() const noexcept;
    
    /**
     * Get number of messages sent.
     */
    uint64_t messages_sent() const noexcept;
    
    /**
     * Get number of messages received.
     */
    uint64_t messages_received() const noexcept;
    
    /**
     * Get total bytes sent.
     */
    uint64_t bytes_sent() const noexcept;
    
    /**
     * Get total bytes received.
     */
    uint64_t bytes_received() const noexcept;
    
    // Callbacks
    std::function<void(const std::string&)> on_text_message;
    std::function<void(const uint8_t*, size_t)> on_binary_message;
    std::function<void(uint16_t, const char*)> on_close;
    std::function<void(const char*)> on_error;
    std::function<void()> on_ping;
    std::function<void()> on_pong;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    uint64_t connection_id_;
    Config config_;
    int socket_fd_{-1};
    std::string path_;
    
    std::atomic<bool> open_{true};
    std::atomic<bool> closing_{false};
    std::atomic<uint64_t> messages_sent_{0};
    std::atomic<uint64_t> messages_received_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> bytes_received_{0};
    
    // Incremental frame state (a frame streams through the caller's buffer).
    static constexpr size_t kMaxControlPayload = kWsMaxControlPayload;
    websocket::FrameHeader frame_;
    bool in_frame_{false};
    uint64_t frame_remaining_{0};
    uint64_t frame_offset_{0};  // payload bytes seen (mask key rotation)
    uint8_t ctrl_buf_[kMaxControlPayload];
    size_t ctrl_len_{0};

    // Message assembly (single-frame and fragmented), bounded by
    // config_.max_message_size before any payload byte is buffered.
    std::vector<uint8_t> fragment_buffer_;
    OpCode fragment_opcode_;
    bool in_fragment_{false};

    static bool is_control(OpCode op) noexcept;
    uint16_t check_header(const websocket::FrameHeader& h) const noexcept;
    int begin_frame(const uint8_t* data, size_t length, size_t& consumed_out);
    void finish_frame();
    void fail(uint16_t code, const char* reason);
    
    /**
     * Send frame.
     * 
     * @param opcode Frame opcode
     * @param data Payload data
     * @param length Payload length
     * @param fin FIN bit
     * @return 0 on success, error code otherwise
     */
    int send_frame(OpCode opcode, const uint8_t* data, size_t length, bool fin = true);
    
    /**
     * Handle complete message.
     * 
     * @param opcode Message opcode
     * @param data Message data
     * @param length Message length
     */
    void handle_message(OpCode opcode, const uint8_t* data, size_t length);
    
    /**
     * Handle control frame.
     * 
     * @param opcode Control opcode
     * @param data Frame data
     * @param length Frame length
     */
    void handle_control_frame(OpCode opcode, const uint8_t* data, size_t length);
};

} // namespace http
} // namespace bolt::api
