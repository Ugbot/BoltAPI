/**
 * Coroutine-based TLS Socket Implementation
 */

#include "boltapi/net/coro_tls_socket.h"
#include "boltapi/net/tcp_socket.h"
#include "boltapi/net/sys_compat.h"
#include <iostream>

namespace bolt::api {
namespace net {

// =============================================================================
// Constructor / Destructor
// =============================================================================

CoroTlsSocket::CoroTlsSocket(IODispatcher& io, int fd, std::shared_ptr<TlsContext> context)
    : io_(io)
    , fd_(fd) {
    // Set non-blocking
    sys::set_nonblocking(fd);

    // Create TcpSocket wrapper (it won't own the fd in this path)
    TcpSocket tcp_socket(fd);
    tcp_socket.release();  // Don't close on destructor - we manage the fd

    // Create a new TcpSocket for the TlsSocket (it will be moved)
    TcpSocket tcp_for_tls(fd);

    // Create TlsSocket
    tls_socket_ = TlsSocket::accept(std::move(tcp_for_tls), std::move(context));
    if (!tls_socket_) {
        error_message_ = "Failed to create TLS socket";
    }
}

CoroTlsSocket::CoroTlsSocket(IODispatcher& io, std::unique_ptr<TlsSocket> tls_socket)
    : io_(io)
    , tls_socket_(std::move(tls_socket))
    , fd_(tls_socket_ ? tls_socket_->fd() : -1) {
}

CoroTlsSocket::~CoroTlsSocket() {
    // TlsSocket destructor handles cleanup
}

CoroTlsSocket::CoroTlsSocket(CoroTlsSocket&& other) noexcept
    : io_(other.io_)
    , tls_socket_(std::move(other.tls_socket_))
    , fd_(other.fd_)
    , error_message_(std::move(other.error_message_)) {
    other.fd_ = -1;
}

CoroTlsSocket& CoroTlsSocket::operator=(CoroTlsSocket&& other) noexcept {
    if (this != &other) {
        tls_socket_ = std::move(other.tls_socket_);
        fd_ = other.fd_;
        error_message_ = std::move(other.error_message_);
        other.fd_ = -1;
    }
    return *this;
}

// =============================================================================
// Coroutine Operations
// =============================================================================

core::coro_task<int> CoroTlsSocket::handshake() {
    if (!tls_socket_) {
        co_return -1;
    }

    while (true) {
        // Process any pending encrypted input
        tls_socket_->process_incoming();

        // Try handshake step
        int result = tls_socket_->handshake();

        if (result == 0) {
            // Handshake complete
            co_return 0;
        } else if (result < 0) {
            // Error
            error_message_ = tls_socket_->get_error();
            co_return -1;
        }

        // result > 0: need more I/O
        // Flush any pending output
        tls_socket_->flush();

        // Wait for socket to be readable (more TLS handshake data)
        char dummy[1];
        ssize_t n = co_await io_.async_read(fd_, dummy, 0);  // Just wait for readable
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            error_message_ = "Socket error during handshake";
            co_return -1;
        }

        // Read encrypted data from socket into TLS
        ssize_t encrypted_bytes = tls_socket_->process_incoming();
        if (encrypted_bytes == 0) {
            error_message_ = "Connection closed during handshake";
            co_return -1;
        }
    }
}

core::coro_task<ssize_t> CoroTlsSocket::read(void* buffer, size_t len) {
    if (!tls_socket_) {
        co_return -1;
    }

    while (true) {
        // Try to read decrypted data
        ssize_t n = tls_socket_->read(buffer, len);

        if (n > 0) {
            co_return n;
        } else if (n == 0) {
            // EOF
            co_return 0;
        }

        // n < 0: need more encrypted data
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            error_message_ = "TLS read error";
            co_return -1;
        }

        // Wait for socket to be readable
        ssize_t bytes = co_await io_.async_read(fd_, buffer, 0);  // Just wait for readable
        if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            co_return -1;
        }

        // Process incoming encrypted data
        ssize_t encrypted = tls_socket_->process_incoming();
        if (encrypted == 0) {
            // EOF
            co_return 0;
        }
    }
}

core::coro_task<ssize_t> CoroTlsSocket::write(const void* buffer, size_t len) {
    if (!tls_socket_) {
        co_return -1;
    }

    // Write to TLS (encrypts into buffer)
    ssize_t written = tls_socket_->write(buffer, len);
    if (written <= 0) {
        error_message_ = "TLS write error";
        co_return -1;
    }

    // Flush encrypted data to socket
    while (!tls_socket_->flush()) {
        // Need to wait for socket to be writable
        ssize_t n = co_await io_.async_write(fd_, nullptr, 0);  // Just wait for writable
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            error_message_ = "Socket write error";
            co_return -1;
        }
    }

    co_return written;
}

void CoroTlsSocket::close() {
    if (tls_socket_) {
        io_.async_close(fd_);
        tls_socket_.reset();
    }
    fd_ = -1;
}

std::string CoroTlsSocket::get_alpn_protocol() const {
    if (tls_socket_) {
        return tls_socket_->get_alpn_protocol();
    }
    return "";
}

bool CoroTlsSocket::is_handshake_complete() const {
    if (tls_socket_) {
        return tls_socket_->is_handshake_complete();
    }
    return false;
}

int CoroTlsSocket::fd() const {
    return fd_;
}

const std::string& CoroTlsSocket::get_error() const {
    return error_message_;
}

// =============================================================================
// Factory Function
// =============================================================================

core::coro_task<std::pair<std::unique_ptr<CoroTlsSocket>, int>> accept_tls(
    IODispatcher& io,
    int fd,
    std::shared_ptr<TlsContext> context
) {
    auto tls_socket = std::make_unique<CoroTlsSocket>(io, fd, std::move(context));

    int result = co_await tls_socket->handshake();

    co_return std::make_pair(std::move(tls_socket), result);
}

} // namespace net
} // namespace bolt::api
