/**
 * TLS Socket with Async Handshake
 *
 * Wraps TcpSocket with OpenSSL TLS layer for secure connections.
 *
 * Features:
 * - Non-blocking TLS handshake
 * - Zero-copy I/O using OpenSSL BIO
 * - ALPN protocol retrieval
 * - Integration with EventLoop
 * - Efficient buffer management
 *
 * Architecture:
 * - Uses memory BIOs for SSL I/O
 * - Application data flows through SSL_read/SSL_write
 * - Network data flows through underlying TcpSocket
 */

#pragma once

#include "boltapi/net/tcp_socket.h"
#include "boltapi/net/tls_context.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <string>
#include <memory>

namespace bolt::api {
namespace net {

/**
 * TLS Socket State
 */
enum class TlsState {
    HANDSHAKE_NEEDED,    // TLS handshake not yet started
    HANDSHAKE_IN_PROGRESS,  // Handshake ongoing
    CONNECTED,           // Handshake complete, ready for data
    ERROR,               // TLS error occurred
    CLOSED               // Connection closed
};

/**
 * TLS Socket (wraps TcpSocket with OpenSSL)
 *
 * Non-blocking TLS socket that integrates with event loop.
 * Uses OpenSSL memory BIOs for zero-copy I/O.
 *
 * Usage (Server):
 *   auto tls_socket = TlsSocket::accept(tcp_socket, tls_context);
 *   int result = tls_socket->handshake();  // Call until returns 0
 *   if (result == 0) {
 *       std::string protocol = tls_socket->get_alpn_protocol();
 *       // Route to HTTP/2 or HTTP/1.1 handler based on protocol
 *   }
 *
 * Usage (Client):
 *   auto tls_socket = TlsSocket::connect(tcp_socket, tls_context);
 *   int result = tls_socket->handshake();
 *   // ... similar to server
 */
class TlsSocket {
public:
    /**
     * Create TLS socket in server mode (accept)
     *
     * @param tcp_socket Accepted TCP connection (moved)
     * @param context TLS context with server certificate
     * @return TLS socket ready for handshake
     */
    static std::unique_ptr<TlsSocket> accept(
        TcpSocket&& tcp_socket,
        std::shared_ptr<TlsContext> context
    );

    /**
     * Create TLS socket in client mode (connect)
     *
     * @param tcp_socket Connected TCP socket (moved)
     * @param context TLS context
     * @param server_name SNI hostname (optional)
     * @return TLS socket ready for handshake
     */
    static std::unique_ptr<TlsSocket> connect(
        TcpSocket&& tcp_socket,
        std::shared_ptr<TlsContext> context,
        const std::string& server_name = ""
    );

    /**
     * Destructor - cleans up SSL resources
     */
    ~TlsSocket();

    // Non-copyable, movable
    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;
    TlsSocket(TlsSocket&& other) noexcept;
    TlsSocket& operator=(TlsSocket&& other) noexcept;

    /**
     * Perform TLS handshake (non-blocking)
     *
     * Call repeatedly until returns 0 (success) or negative (error).
     *
     * @return 0 on success (handshake complete)
     *         1 if needs more data (call again after socket readable/writable)
     *         -1 on error
     */
    int handshake();

    /**
     * Read decrypted data from TLS connection
     *
     * Non-blocking read. Returns number of bytes read, or:
     * - 0: Connection closed
     * - -1: Error or would block (check errno)
     *
     * @param buffer Destination buffer
     * @param len Buffer size
     * @return Bytes read, 0 on EOF, -1 on error/would block
     */
    ssize_t read(void* buffer, size_t len);

    /**
     * Write data to TLS connection (encrypts and buffers)
     *
     * Non-blocking write. May not send all data immediately.
     *
     * @param buffer Data to write
     * @param len Data length
     * @return Bytes written, or -1 on error
     */
    ssize_t write(const void* buffer, size_t len);

    /**
     * Flush buffered encrypted data to underlying socket
     *
     * Call this after write() to actually send data over network.
     * Call repeatedly until returns true.
     *
     * @return true if all data flushed, false if would block
     */
    bool flush();

    /**
     * Process incoming network data through SSL
     *
     * Call this when the underlying socket is readable.
     * Reads encrypted data from socket and feeds it to SSL.
     *
     * @return Number of bytes read from socket, 0 on EOF, -1 on error
     */
    ssize_t process_incoming();

    /**
     * Get ALPN negotiated protocol
     *
     * Call after handshake is complete.
     *
     * @return Protocol name (e.g., "h2", "http/1.1"), or empty string if no ALPN
     */
    std::string get_alpn_protocol() const;

    /**
     * Get current TLS state
     */
    TlsState get_state() const { return state_; }

    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const {
        return state_ == TlsState::CONNECTED;
    }

    /**
     * Get underlying TCP socket file descriptor
     */
    int fd() const { return tcp_socket_.fd(); }

    /**
     * Get underlying TCP socket (for event loop registration)
     */
    TcpSocket& get_tcp_socket() { return tcp_socket_; }
    const TcpSocket& get_tcp_socket() const { return tcp_socket_; }

    /**
     * Get last error message
     */
    const std::string& get_error() const { return error_message_; }

    /**
     * Check if there's pending encrypted data to send
     */
    bool has_pending_output() const;

    /**
     * Check if there's pending decrypted data available to read
     *
     * IMPORTANT: After TLS handshake completes, application data may already
     * be decrypted and waiting. With edge-triggered event loops, no new READ
     * event will be triggered for this buffered data. Call this method after
     * handshake to check for pending data.
     */
    bool has_pending_input() const;

    /**
     * Check if connection needs WRITE event registration
     *
     * Returns true if there's unsent data in write buffer.
     * Event loop should register for WRITE events and call flush() when ready.
     */
    bool needs_write_event() const;

private:
    /**
     * Private constructor - use factory methods
     */
    TlsSocket(
        TcpSocket&& tcp_socket,
        std::shared_ptr<TlsContext> context,
        bool is_server
    );

    /**
     * Initialize SSL object
     */
    bool init_ssl(bool is_server, const std::string& server_name);

    /**
     * Perform SSL handshake step
     */
    int do_handshake_step();

    /**
     * Flush encrypted data from Wbio to socket
     */
    ssize_t flush_encrypted_output();

    /**
     * Read encrypted data from socket into Rbio
     */
    ssize_t read_encrypted_input();

    /**
     * Get OpenSSL error string
     */
    static std::string get_ssl_error(SSL* ssl, int ret);

    TcpSocket tcp_socket_;
    std::shared_ptr<TlsContext> context_;
    SSL* ssl_ = nullptr;
    BIO* rbio_ = nullptr;  // Read BIO (encrypted data from network)
    BIO* wbio_ = nullptr;  // Write BIO (encrypted data to network)
    TlsState state_ = TlsState::HANDSHAKE_NEEDED;
    std::string error_message_;
    bool is_server_ = false;

    // Write buffering for backpressure handling
    std::vector<uint8_t> write_buffer_;  // Plaintext data awaiting encryption/transmission
    size_t write_offset_ = 0;            // How much of write_buffer_ has been sent
};

} // namespace net
} // namespace bolt::api
