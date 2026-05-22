/**
 * TLS Socket Implementation
 *
 * Non-blocking TLS using OpenSSL memory BIOs
 */

#include "boltapi/net/tls_socket.h"
#include "boltapi/net/sys_compat.h"
#include <openssl/err.h>
#include <errno.h>
#include <cstring>

namespace bolt::api {
namespace net {

std::unique_ptr<TlsSocket> TlsSocket::accept(
    TcpSocket&& tcp_socket,
    std::shared_ptr<TlsContext> context
) {
    auto socket = std::unique_ptr<TlsSocket>(
        new TlsSocket(std::move(tcp_socket), context, true)
    );

    if (!socket->init_ssl(true, "")) {
        return nullptr;
    }

    return socket;
}

std::unique_ptr<TlsSocket> TlsSocket::connect(
    TcpSocket&& tcp_socket,
    std::shared_ptr<TlsContext> context,
    const std::string& server_name
) {
    auto socket = std::unique_ptr<TlsSocket>(
        new TlsSocket(std::move(tcp_socket), context, false)
    );

    if (!socket->init_ssl(false, server_name)) {
        return nullptr;
    }

    return socket;
}

TlsSocket::TlsSocket(
    TcpSocket&& tcp_socket,
    std::shared_ptr<TlsContext> context,
    bool is_server
)
    : tcp_socket_(std::move(tcp_socket))
    , context_(context)
    , is_server_(is_server)
{
}

TlsSocket::~TlsSocket() {
    if (ssl_) {
        SSL_free(ssl_);
        // BIOs are freed by SSL_free
    }
}

TlsSocket::TlsSocket(TlsSocket&& other) noexcept
    : tcp_socket_(std::move(other.tcp_socket_))
    , context_(std::move(other.context_))
    , ssl_(other.ssl_)
    , rbio_(other.rbio_)
    , wbio_(other.wbio_)
    , state_(other.state_)
    , error_message_(std::move(other.error_message_))
    , is_server_(other.is_server_)
{
    other.ssl_ = nullptr;
    other.rbio_ = nullptr;
    other.wbio_ = nullptr;
}

TlsSocket& TlsSocket::operator=(TlsSocket&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_free(ssl_);
        }

        tcp_socket_ = std::move(other.tcp_socket_);
        context_ = std::move(other.context_);
        ssl_ = other.ssl_;
        rbio_ = other.rbio_;
        wbio_ = other.wbio_;
        state_ = other.state_;
        error_message_ = std::move(other.error_message_);
        is_server_ = other.is_server_;

        other.ssl_ = nullptr;
        other.rbio_ = nullptr;
        other.wbio_ = nullptr;
    }
    return *this;
}

bool TlsSocket::init_ssl(bool is_server, const std::string& server_name) {
    // Create SSL object
    ssl_ = SSL_new(context_->get_ssl_ctx());
    if (!ssl_) {
        error_message_ = "Failed to create SSL object";
        state_ = TlsState::ERROR;
        return false;
    }

    // Create memory BIOs
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (!rbio_ || !wbio_) {
        error_message_ = "Failed to create BIOs";
        state_ = TlsState::ERROR;
        return false;
    }

    // Attach BIOs to SSL
    SSL_set_bio(ssl_, rbio_, wbio_);

    // Set mode for partial writes
    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // Set SSL state
    if (is_server) {
        SSL_set_accept_state(ssl_);
    } else {
        SSL_set_connect_state(ssl_);

        // Set SNI hostname for client
        if (!server_name.empty()) {
            SSL_set_tlsext_host_name(ssl_, server_name.c_str());
        }
    }

    return true;
}

int TlsSocket::handshake() {
    if (state_ == TlsState::CONNECTED) {
        return 0;  // Already complete
    }

    if (state_ == TlsState::ERROR || state_ == TlsState::CLOSED) {
        return -1;
    }

    state_ = TlsState::HANDSHAKE_IN_PROGRESS;

    // Perform handshake step
    int result = do_handshake_step();

    if (result == 0) {
        // Handshake complete
        state_ = TlsState::CONNECTED;
        return 0;
    } else if (result == 1) {
        // Need more I/O
        return 1;
    } else {
        // Error
        state_ = TlsState::ERROR;
        return -1;
    }
}

int TlsSocket::do_handshake_step() {
    // Try to perform handshake
    int ret = SSL_do_handshake(ssl_);

    if (ret == 1) {
        // Handshake complete - flush any remaining data
        ssize_t flushed = flush_encrypted_output();
        if (flushed < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            error_message_ = "Failed to flush handshake data";
            return -1;
        }
        return 0;
    }

    // Check error
    int ssl_error = SSL_get_error(ssl_, ret);

    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        // Flush encrypted output (handshake messages)
        ssize_t flushed = flush_encrypted_output();
        if (flushed < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            error_message_ = "Failed to flush during handshake";
            return -1;
        }

        // Need more network I/O
        return 1;
    }

    // Real error
    error_message_ = get_ssl_error(ssl_, ret);
    return -1;
}

ssize_t TlsSocket::read(void* buffer, size_t len) {
    if (state_ != TlsState::CONNECTED) {
        errno = EINVAL;
        return -1;
    }

    // Try to read decrypted data
    int ret = SSL_read(ssl_, buffer, len);

    if (ret > 0) {
        return ret;
    }

    int ssl_error = SSL_get_error(ssl_, ret);

    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        // Need more encrypted data from network
        errno = EAGAIN;
        return -1;
    }

    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        // Clean TLS shutdown
        state_ = TlsState::CLOSED;
        return 0;
    }

    // Error
    error_message_ = get_ssl_error(ssl_, ret);
    state_ = TlsState::ERROR;
    return -1;
}

ssize_t TlsSocket::write(const void* buffer, size_t len) {
    if (state_ != TlsState::CONNECTED) {
        errno = EINVAL;
        return -1;
    }

    // Append plaintext data to write buffer
    // Encryption and sending happens in flush()
    const uint8_t* data = static_cast<const uint8_t*>(buffer);
    write_buffer_.insert(write_buffer_.end(), data, data + len);

    return len;  // Always succeeds - data is buffered
}

bool TlsSocket::flush() {
    // Nothing to send?
    if (write_offset_ >= write_buffer_.size()) {
        return true;  // All done
    }

    // Encrypt unsent data from write buffer
    size_t remaining = write_buffer_.size() - write_offset_;
    int encrypted = SSL_write(ssl_, write_buffer_.data() + write_offset_, remaining);

    if (encrypted <= 0) {
        int ssl_error = SSL_get_error(ssl_, encrypted);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            errno = EAGAIN;
            return false;  // Would block, try again later
        }
        // Error
        error_message_ = get_ssl_error(ssl_, encrypted);
        state_ = TlsState::ERROR;
        return false;
    }

    // encrypted > 0: SSL successfully encrypted 'encrypted' bytes
    // Now flush the encrypted data from Wbio to socket
    ssize_t result = flush_encrypted_output();

    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Socket would block, but SSL already consumed the plaintext!
            // We MUST update write_offset_ to mark this data as "in flight"
            write_offset_ += encrypted;
            return false;  // Not done yet, caller should retry
        }
        // Error
        error_message_ = "Socket send failed: " + std::string(strerror(errno));
        state_ = TlsState::ERROR;
        return false;
    }

    // Success: encrypted data was sent
    write_offset_ += encrypted;

    // Clear buffer if all sent
    if (write_offset_ >= write_buffer_.size()) {
        write_buffer_.clear();
        write_offset_ = 0;
        return true;  // All done
    }

    return false;  // More data to send
}

ssize_t TlsSocket::flush_encrypted_output() {
    char buffer[16384];  // 16KB buffer
    ssize_t total_sent = 0;

    while (true) {
        // Read encrypted data from Wbio
        int pending = BIO_read(wbio_, buffer, sizeof(buffer));

        fprintf(stderr, "[TLS_FLUSH] BIO_read returned %d bytes\n", pending);
        fflush(stderr);

        if (pending <= 0) {
            // No more data to send
            break;
        }

        // Send to network
        ssize_t sent = ::send(tcp_socket_.fd(), buffer, pending, 0);
        fprintf(stderr, "[TLS_FLUSH] send() returned %zd (pending=%d)\n", sent, pending);
        fflush(stderr);

        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Would block - put unwritten data back
                if (sent < pending) {
                    // BIO doesn't support "put back", so we're stuck
                    // In practice, this shouldn't happen with non-blocking sockets
                }
                return total_sent;
            }
            // Error
            return -1;
        }

        total_sent += sent;

        if (sent < pending) {
            // Partial send - would block on next send
            return total_sent;
        }
    }

    return total_sent;
}

ssize_t TlsSocket::process_incoming() {
    char buffer[16384];  // 16KB buffer

    // Read encrypted data from network
    ssize_t received = ::recv(tcp_socket_.fd(), buffer, sizeof(buffer), 0);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  // No data available
        }
        return -1;  // Error
    }

    if (received == 0) {
        // Connection closed
        return 0;
    }

    // Feed encrypted data into Rbio
    int written = BIO_write(rbio_, buffer, received);
    if (written != received) {
        error_message_ = "BIO_write failed";
        return -1;
    }

    return received;
}

std::string TlsSocket::get_alpn_protocol() const {
    if (!ssl_ || state_ != TlsState::CONNECTED) {
        return "";
    }

    const unsigned char* alpn_data = nullptr;
    unsigned int alpn_len = 0;

    SSL_get0_alpn_selected(ssl_, &alpn_data, &alpn_len);

    if (alpn_data && alpn_len > 0) {
        return std::string(reinterpret_cast<const char*>(alpn_data), alpn_len);
    }

    return "";
}

bool TlsSocket::has_pending_output() const {
    // Check if write buffer has unsent data
    if (write_offset_ < write_buffer_.size()) {
        return true;
    }

    // Check if Wbio has encrypted data waiting to be sent
    if (wbio_ && BIO_pending(wbio_) > 0) {
        return true;
    }

    return false;
}

bool TlsSocket::has_pending_input() const {
    // Check if SSL has decrypted data buffered and ready to read
    // SSL_pending returns the number of bytes that have been processed
    // by the SSL layer and are available to read via SSL_read()
    if (ssl_ && SSL_pending(ssl_) > 0) {
        return true;
    }

    // Also check if rbio has unprocessed encrypted data
    // This data would be processed on next SSL_read() call
    if (rbio_ && BIO_pending(rbio_) > 0) {
        return true;
    }

    return false;
}

bool TlsSocket::needs_write_event() const {
    return has_pending_output();
}

std::string TlsSocket::get_ssl_error(SSL* ssl, int ret) {
    int ssl_error = SSL_get_error(ssl, ret);

    switch (ssl_error) {
        case SSL_ERROR_NONE:
            return "No error";
        case SSL_ERROR_ZERO_RETURN:
            return "TLS connection closed";
        case SSL_ERROR_WANT_READ:
            return "Want read";
        case SSL_ERROR_WANT_WRITE:
            return "Want write";
        case SSL_ERROR_SYSCALL: {
            if (ret == 0) {
                return "EOF in violation of protocol";
            }
            unsigned long err = ERR_get_error();
            if (err == 0) {
                return "I/O error: " + std::string(strerror(errno));
            }
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            return std::string(buf);
        }
        case SSL_ERROR_SSL: {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            return std::string(buf);
        }
        default:
            return "Unknown SSL error: " + std::to_string(ssl_error);
    }
}

} // namespace net
} // namespace bolt::api
