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
     * Handle incoming frame data.
     *
     * Called by server when data is received.
     *
     * @param data Frame data
     * @param length Data length
     * @return 0 on success, -1 if more data needed, positive error code otherwise
     */
    int handle_frame(const uint8_t* data, size_t length);

    /**
     * Handle incoming frame data with consumed bytes output.
     *
     * @param data Frame data
     * @param length Data length
     * @param consumed Output: number of bytes consumed
     * @return 0 on success, -1 if more data needed, positive error code otherwise
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
    
    websocket::FrameParser parser_;
    
    // Fragmented message assembly
    std::vector<uint8_t> fragment_buffer_;
    OpCode fragment_opcode_;
    bool in_fragment_{false};
    
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
