/**
 * Coroutine-based TLS Socket
 *
 * Provides awaitable TLS operations that integrate with IODispatcher.
 * Wraps the existing TlsSocket with coroutine-friendly interfaces.
 *
 * Architecture:
 * - TLS encrypt/decrypt happens inline (TlsSocket handles this)
 * - Underlying I/O uses IODispatcher awaitables
 * - Handshake, read, write are all co_await-able
 */

#pragma once

#include "boltapi/net/tls_socket.h"
#include "boltapi/net/tls_context.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/coro_task.h"
#include <memory>
#include <string>

namespace bolt::api {
namespace net {

/**
 * Coroutine-based TLS Socket
 *
 * Usage:
 *   CoroTlsSocket tls_socket(io_dispatcher, fd, tls_context, true);
 *   int result = co_await tls_socket.handshake();
 *   if (result == 0) {
 *       std::string protocol = tls_socket.get_alpn_protocol();
 *       ssize_t n = co_await tls_socket.read(buffer, sizeof(buffer));
 *       co_await tls_socket.write(response, response_len);
 *   }
 */
class CoroTlsSocket {
public:
    /**
     * Create coroutine TLS socket for server-side connection
     *
     * @param io IODispatcher for underlying I/O
     * @param fd Accepted socket file descriptor
     * @param context TLS context with server certificate
     */
    CoroTlsSocket(IODispatcher& io, int fd, std::shared_ptr<TlsContext> context);

    /**
     * Create from existing TlsSocket (for migration)
     */
    CoroTlsSocket(IODispatcher& io, std::unique_ptr<TlsSocket> tls_socket);

    ~CoroTlsSocket();

    // Non-copyable, movable
    CoroTlsSocket(const CoroTlsSocket&) = delete;
    CoroTlsSocket& operator=(const CoroTlsSocket&) = delete;
    CoroTlsSocket(CoroTlsSocket&& other) noexcept;
    CoroTlsSocket& operator=(CoroTlsSocket&& other) noexcept;

    /**
     * Perform TLS handshake asynchronously
     *
     * @return 0 on success, -1 on error
     */
    core::coro_task<int> handshake();

    /**
     * Read decrypted data asynchronously
     *
     * @param buffer Destination buffer
     * @param len Buffer size
     * @return Bytes read, 0 on EOF, -1 on error
     */
    core::coro_task<ssize_t> read(void* buffer, size_t len);

    /**
     * Write data through TLS asynchronously
     *
     * @param buffer Data to write
     * @param len Data length
     * @return Bytes written, or -1 on error
     */
    core::coro_task<ssize_t> write(const void* buffer, size_t len);

    /**
     * Close the TLS connection
     */
    void close();

    /**
     * Get ALPN negotiated protocol
     */
    std::string get_alpn_protocol() const;

    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const;

    /**
     * Get underlying file descriptor
     */
    int fd() const;

    /**
     * Get last error message
     */
    const std::string& get_error() const;

private:
    IODispatcher& io_;
    std::unique_ptr<TlsSocket> tls_socket_;
    int fd_;
    std::string error_message_;
};

/**
 * Factory function to create CoroTlsSocket and perform handshake
 *
 * @param io IODispatcher for underlying I/O
 * @param fd Accepted socket file descriptor
 * @param context TLS context
 * @return Pair of (CoroTlsSocket, handshake_result). Check result == 0 for success.
 */
core::coro_task<std::pair<std::unique_ptr<CoroTlsSocket>, int>> accept_tls(
    IODispatcher& io,
    int fd,
    std::shared_ptr<TlsContext> context
);

} // namespace net
} // namespace bolt::api
