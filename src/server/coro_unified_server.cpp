/**
 * Coroutine-based Unified HTTP Server Implementation
 *
 * Implements the Seastar-inspired architecture:
 * - 1-2 I/O threads dispatch events
 * - N worker threads execute coroutines
 * - Coroutines yield on blocking I/O
 */

#include "boltapi/server/coro_unified_server.h"
#include "boltapi/net/coro_tls_socket.h"
#include "boltapi/net/tls_cert_generator.h"
#include "boltapi/http/http1_parser.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/http/request_body_buffer.h"
#include "boltapi/net/sys_compat.h"
#include <algorithm>
#include <iostream>
#include <cstring>
#include <cctype>
#include <chrono>
#include <charconv>
#include <vector>

namespace bolt::api {
namespace http {

namespace {

// Branchless-ish ASCII helpers for the response hot path — NO allocation (the old
// path copied each header name into a std::string just to lowercase-compare).
inline char to_lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}
// Case-insensitive equality: `a` vs a lowercase literal `lower`.
inline bool ieq_ascii(std::string_view a, std::string_view lower) noexcept {
    if (a.size() != lower.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (to_lower_ascii(a[i]) != lower[i]) return false;
    }
    return true;
}
// Case-insensitive substring presence of a lowercase `needle` in `hay`.
inline bool contains_ci(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || hay.size() < needle.size()) return false;
    const std::size_t end = hay.size() - needle.size();
    for (std::size_t i = 0; i <= end; ++i) {
        std::size_t k = 0;
        for (; k < needle.size(); ++k) {
            if (to_lower_ascii(hay[i + k]) != needle[k]) break;
        }
        if (k == needle.size()) return true;
    }
    return false;
}
// Append an unsigned integer as decimal via to_chars (stack buffer, no alloc).
inline void append_uint(std::string& out, std::uint64_t v) {
    char tmp[20];
    auto [p, ec] = std::to_chars(tmp, tmp + sizeof(tmp), v);
    (void)ec;
    out.append(tmp, static_cast<std::size_t>(p - tmp));
}

}  // namespace

// =============================================================================
// Static Member Initialization
// =============================================================================

std::unordered_map<std::string, WebSocketHandler> CoroUnifiedServer::s_websocket_handlers_;
std::unordered_map<std::string, CoroSSEHandler> CoroUnifiedServer::s_sse_handlers_;
Http1Connection::UltraFastCallback CoroUnifiedServer::s_ultra_fast_callback_ = nullptr;
CoroUnifiedServer* CoroUnifiedServer::s_instance_ = nullptr;

// ---------------------------------------------------------------------------
// conn_read / conn_write — route connection app I/O through the TLS socket when
// the connection is encrypted (tls != nullptr), else the raw fd. This is what
// makes HTTP/1.1 + HTTP/2 application data go out as TLS records on an HTTPS
// connection: previously only the handshake went through TLS and app data was
// written raw to the fd (plaintext), which a real TLS client rejects as a
// "bad record type". noexcept-free path; bounded by the caller's loops.
// ---------------------------------------------------------------------------
namespace {
core::coro_task<ssize_t> conn_write(net::IODispatcher& io, int fd,
                                    net::CoroTlsSocket* tls,
                                    const void* data, std::size_t len) {
    if (tls != nullptr) co_return co_await tls->write(data, len);
    co_return co_await io.async_write(fd, data, len);
}
core::coro_task<ssize_t> conn_read(net::IODispatcher& io, int fd,
                                   net::CoroTlsSocket* tls,
                                   void* data, std::size_t len) {
    if (tls != nullptr) co_return co_await tls->read(data, len);
    co_return co_await io.async_read(fd, data, len);
}
}  // namespace

// =============================================================================
// Constructor / Destructor
// =============================================================================

CoroUnifiedServer::CoroUnifiedServer(const CoroUnifiedServerConfig& config)
    : config_(config) {

    // Auto-detect number of workers
    if (config_.num_workers == 0) {
        config_.num_workers = std::thread::hardware_concurrency();
        if (config_.num_workers == 0) {
            config_.num_workers = 4;
        }
    }
}

CoroUnifiedServer::~CoroUnifiedServer() {
    stop();
}

// =============================================================================
// Handler Configuration
// =============================================================================

void CoroUnifiedServer::set_handler(CoroHttpHandler handler) {
    handler_ = std::move(handler);
}

void CoroUnifiedServer::add_websocket_handler(const std::string& path, WebSocketHandler handler) {
    s_websocket_handlers_[path] = std::move(handler);
    std::cout << "[CoroUnifiedServer] Registered WebSocket handler: " << path << std::endl;
}

WebSocketHandler* CoroUnifiedServer::get_websocket_handler(const std::string& path) {
    auto it = s_websocket_handlers_.find(path);
    if (it != s_websocket_handlers_.end()) {
        return &it->second;
    }
    return nullptr;
}

void CoroUnifiedServer::add_sse_handler(const std::string& path, CoroSSEHandler handler) {
    s_sse_handlers_[path] = std::move(handler);
    std::cout << "[CoroUnifiedServer] Registered SSE handler: " << path << std::endl;
}

CoroSSEHandler* CoroUnifiedServer::get_sse_handler(const std::string& path) {
    auto it = s_sse_handlers_.find(path);
    if (it != s_sse_handlers_.end()) {
        return &it->second;
    }
    return nullptr;
}

// =============================================================================
// Start / Stop
// =============================================================================

int CoroUnifiedServer::start() {
    if (start_background() != 0) {
        return -1;
    }

    // Block until stop requested or shutdown complete
    while (!stop_requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // If draining, wait for graceful shutdown to complete
    if (is_draining()) {
        std::unique_lock<std::mutex> lock(shutdown_mutex_);
        auto timeout = std::chrono::milliseconds(config_.shutdown_timeout_ms);
        shutdown_cv_.wait_for(lock, timeout, [this]() {
            return shutdown_state_.load(std::memory_order_acquire) == CoroShutdownState::STOPPED;
        });
    }

    return 0;
}

int CoroUnifiedServer::start_background() {
    CoroShutdownState expected = CoroShutdownState::STOPPED;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::RUNNING)) {
        error_message_ = "Server already running or draining";
        return -1;
    }

    stop_requested_.store(false, std::memory_order_relaxed);

    // Set global instance for signal handlers
    s_instance_ = this;

    // Install signal handlers if enabled
    if (config_.enable_signal_handlers) {
        install_signal_handlers();
    }

    std::cout << "CoroUnifiedServer starting..." << std::endl;
    std::cout << "  I/O threads: " << config_.num_io_threads << std::endl;
    std::cout << "  Worker threads: " << config_.num_workers << std::endl;

    // Create worker thread pool
    core::WorkerPoolConfig worker_config;
    worker_config.num_workers = config_.num_workers;
    worker_pool_ = std::make_unique<core::WorkerThreadPool>(worker_config);
    worker_pool_->start();

    // Create I/O dispatcher
    net::IODispatcherConfig io_config;
    io_config.num_io_threads = config_.num_io_threads;
    io_config.worker_pool = worker_pool_.get();
    io_dispatcher_ = std::make_unique<net::IODispatcher>(io_config);
    io_dispatcher_->start();

    // Initialize TLS context if TLS enabled
    if (config_.enable_tls) {
        net::TlsContextConfig tls_config;
        tls_config.alpn_protocols = config_.alpn_protocols;

        // Use configured certificate files if provided, otherwise generate self-signed
        if (!config_.cert_file.empty() && !config_.key_file.empty()) {
            // Use external certificate files
            tls_config.cert_file = config_.cert_file;
            tls_config.key_file = config_.key_file;
            std::cout << "  TLS using certificate: " << config_.cert_file << std::endl;
        } else if (!config_.cert_data.empty() && !config_.key_data.empty()) {
            // Use in-memory certificate data
            tls_config.cert_data = config_.cert_data;
            tls_config.key_data = config_.key_data;
            std::cout << "  TLS using in-memory certificate" << std::endl;
        } else {
            // Generate self-signed certificate as fallback
            net::CertGeneratorConfig cert_config;
            cert_config.common_name = "localhost";
            cert_config.organization = "Bolt API";
            cert_config.validity_days = 365;

            auto generated = net::TlsCertGenerator::generate(cert_config);
            if (!generated.success) {
                error_message_ = "Failed to generate self-signed certificate: " + generated.error;
                std::cerr << error_message_ << std::endl;
                worker_pool_->stop();
                io_dispatcher_->stop();
                shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
                s_instance_ = nullptr;
                return -1;
            }

            tls_config.cert_data = generated.cert_pem;
            tls_config.key_data = generated.key_pem;
            std::cout << "  TLS using self-signed certificate" << std::endl;
        }

        tls_context_ = net::TlsContext::create_server(tls_config);
        if (!tls_context_ || !tls_context_->is_valid()) {
            error_message_ = "Failed to create TLS context: " +
                (tls_context_ ? tls_context_->get_error() : "null context");
            std::cerr << error_message_ << std::endl;
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  TLS enabled, ALPN: "
                  << config_.alpn_protocols.size() << " protocols" << std::endl;

        // Create TLS listener
        net::CoroTcpListenerConfig tls_listener_config;
        tls_listener_config.host = config_.host;
        tls_listener_config.port = config_.tls_port;
        tls_listener_config.backlog = config_.backlog;
        tls_listener_config.num_io_threads = config_.num_io_threads;
        tls_listener_config.num_workers = config_.num_workers;

        // TLS connection handler captures 'this'
        // Note: We pass the shared IODispatcher to avoid creating duplicates
        auto tls_handler = [this](net::IODispatcher& io, int fd) -> core::coro_task<void> {
            co_await handle_tls_connection(io, fd);
        };

        // Pass shared IODispatcher and WorkerThreadPool to avoid duplicates
        tls_listener_ = std::make_unique<net::CoroTcpListener>(
            tls_listener_config, std::move(tls_handler),
            io_dispatcher_.get(), worker_pool_.get());
        if (tls_listener_->start_background() != 0) {
            error_message_ = "Failed to start TLS listener on port " +
                std::to_string(config_.tls_port) + " (errno: " + std::to_string(errno) + ")";
            std::cerr << error_message_ << std::endl;
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  TLS listener: " << config_.host << ":" << config_.tls_port << std::endl;
    }

    // Create cleartext HTTP/1.1 listener
    if (config_.enable_http1_cleartext) {
        net::CoroTcpListenerConfig http1_listener_config;
        http1_listener_config.host = config_.host;
        http1_listener_config.port = config_.http1_port;
        http1_listener_config.backlog = config_.backlog;
        http1_listener_config.num_io_threads = config_.num_io_threads;
        http1_listener_config.num_workers = config_.num_workers;

        // Cleartext HTTP/1.1 handler
        // Note: We pass the shared IODispatcher to avoid creating duplicates
        auto cleartext_handler = [this](net::IODispatcher& io, int fd) -> core::coro_task<void> {
            co_await handle_cleartext_connection(io, fd);
        };

        // Pass shared IODispatcher and WorkerThreadPool to avoid duplicates
        cleartext_listener_ = std::make_unique<net::CoroTcpListener>(
            http1_listener_config, std::move(cleartext_handler),
            io_dispatcher_.get(), worker_pool_.get());
        if (cleartext_listener_->start_background() != 0) {
            error_message_ = "Failed to start cleartext listener on port " +
                std::to_string(config_.http1_port) + " (errno: " + std::to_string(errno) + ")";
            std::cerr << error_message_ << std::endl;
            if (tls_listener_) tls_listener_->stop();
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  HTTP/1.1 cleartext: " << config_.host << ":" << config_.http1_port << std::endl;
    }

    std::cout << "CoroUnifiedServer started" << std::endl;
    return 0;
}

void CoroUnifiedServer::stop() {
    CoroShutdownState expected = CoroShutdownState::RUNNING;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::STOPPED)) {
        // Already stopped or draining
        if (expected == CoroShutdownState::DRAINING) {
            // Force stop from draining state
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
        } else {
            return;  // Already stopped
        }
    }

    stop_requested_.store(true, std::memory_order_release);

    // Stop listeners
    if (tls_listener_) {
        tls_listener_->stop();
    }
    if (cleartext_listener_) {
        cleartext_listener_->stop();
    }

    // Stop I/O dispatcher
    if (io_dispatcher_) {
        io_dispatcher_->stop();
    }

    // Stop worker pool
    if (worker_pool_) {
        worker_pool_->stop();
    }

    // Clear global instance
    if (s_instance_ == this) {
        s_instance_ = nullptr;
    }

    std::cout << "CoroUnifiedServer stopped" << std::endl;
}

// =============================================================================
// Graceful Shutdown
// =============================================================================

bool CoroUnifiedServer::shutdown_gracefully() {
    CoroShutdownState expected = CoroShutdownState::RUNNING;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::DRAINING)) {
        // Not running - either already draining or stopped
        return expected == CoroShutdownState::STOPPED;
    }

    std::cout << "[CoroUnifiedServer] Initiating graceful shutdown..." << std::endl;
    stop_requested_.store(true, std::memory_order_release);

    // Stop accepting new connections
    if (tls_listener_) {
        tls_listener_->stop();
    }
    if (cleartext_listener_) {
        cleartext_listener_->stop();
    }

    // Wait for active connections to drain
    std::unique_lock<std::mutex> lock(shutdown_mutex_);
    auto timeout = std::chrono::milliseconds(config_.shutdown_timeout_ms);
    auto deadline = std::chrono::steady_clock::now() + timeout;

    bool drained = shutdown_cv_.wait_until(lock, deadline, [this]() {
        return connections_active_.load(std::memory_order_relaxed) == 0;
    });

    if (drained) {
        std::cout << "[CoroUnifiedServer] All connections drained, shutdown complete" << std::endl;
    } else {
        std::cout << "[CoroUnifiedServer] Shutdown timeout, forcing close of "
                  << connections_active_.load(std::memory_order_relaxed)
                  << " connections" << std::endl;
    }

    // Complete shutdown
    shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);

    // Stop I/O dispatcher and worker pool
    if (io_dispatcher_) {
        io_dispatcher_->stop();
    }
    if (worker_pool_) {
        worker_pool_->stop();
    }

    // Clear global instance
    if (s_instance_ == this) {
        s_instance_ = nullptr;
    }

    return drained;
}

// =============================================================================
// Signal Handlers
// =============================================================================

void CoroUnifiedServer::install_signal_handlers() {
    s_instance_ = this;

#ifdef _WIN32
    // Windows has no sigaction; std::signal supports SIGINT/SIGTERM.
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
#endif

    std::cout << "[CoroUnifiedServer] Signal handlers installed (SIGTERM, SIGINT)" << std::endl;
}

void CoroUnifiedServer::signal_handler(int signum) {
    const char* sig_name = (signum == SIGTERM) ? "SIGTERM" : "SIGINT";
    (void)sig_name;
    // Use a raw write for async-signal-safety (no printf/cout in signal handlers)
    const char msg[] = "[CoroUnifiedServer] Received signal, initiating graceful shutdown\n";
#ifdef _WIN32
    (void)_write(STDOUT_FILENO, msg, static_cast<unsigned>(sizeof(msg) - 1));
#else
    (void)::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
#endif

    if (s_instance_) {
        // Initiate graceful shutdown from background thread to avoid
        // blocking in signal handler
        s_instance_->stop_requested_.store(true, std::memory_order_release);

        // Try to transition to draining state
        CoroShutdownState expected = CoroShutdownState::RUNNING;
        s_instance_->shutdown_state_.compare_exchange_strong(
            expected, CoroShutdownState::DRAINING, std::memory_order_release);
    }
}

// =============================================================================
// Ultra-Fast Callback
// =============================================================================

void CoroUnifiedServer::set_ultra_fast_callback(Http1Connection::UltraFastCallback callback) {
    s_ultra_fast_callback_ = callback;
    std::cout << "[CoroUnifiedServer] Ultra-fast callback set" << std::endl;
}

Http1Connection::UltraFastCallback CoroUnifiedServer::get_ultra_fast_callback() noexcept {
    return s_ultra_fast_callback_;
}

// =============================================================================
// TLS Connection Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_tls_connection(net::IODispatcher& io, int fd) {
    connections_accepted_.fetch_add(1, std::memory_order_relaxed);

    // Check if we're accepting new connections (graceful shutdown support)
    if (!track_connection_open()) {
        // Draining - reject new connection
        io.async_close(fd);
        co_return;
    }

    // Create coroutine TLS socket and perform handshake
    auto [tls_socket, handshake_result] = co_await net::accept_tls(
        io, fd, tls_context_);

    if (handshake_result != 0 || !tls_socket) {
        // Handshake failed
        io.async_close(fd);
        track_connection_close();
        co_return;
    }

    // Detect protocol via ALPN
    std::string alpn = tls_socket->get_alpn_protocol();

    if (alpn == "h2") {
        // HTTP/2
        requests_http2_.fetch_add(1, std::memory_order_relaxed);
        co_await handle_http2_connection(io, fd, tls_socket.get());
    } else {
        // Default to HTTP/1.1 (alpn == "http/1.1" or empty)
        requests_http1_.fetch_add(1, std::memory_order_relaxed);
        co_await handle_http1_connection(io, fd, tls_socket.get());
    }

    track_connection_close();
}

// =============================================================================
// Cleartext HTTP/1.1 Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_cleartext_connection(net::IODispatcher& io, int fd) {
    connections_accepted_.fetch_add(1, std::memory_order_relaxed);

    // Check if we're accepting new connections (graceful shutdown support)
    if (!track_connection_open()) {
        // Draining - reject new connection
        io.async_close(fd);
        co_return;
    }

    requests_http1_.fetch_add(1, std::memory_order_relaxed);

    // Set non-blocking
    net::sys::set_nonblocking(fd);

    co_await handle_http1_connection(io, fd, nullptr);

    track_connection_close();
}

// =============================================================================
// HTTP/1.1 Request Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_http1_connection(
    net::IODispatcher& io, int fd, net::CoroTlsSocket* tls) {

    // Two-phase buffer strategy:
    // Phase 1: 8KB stack buffer for headers (zero allocation fast path)
    // Phase 2: RequestBodyBuffer for large bodies (thread-local arena pool)
    static constexpr size_t STACK_BUF_SIZE = 8192;
    uint8_t stack_buf[STACK_BUF_SIZE];
    uint8_t* buf = stack_buf;
    size_t buf_cap = STACK_BUF_SIZE;
    size_t buf_len = 0;
    RequestBodyBuffer body_buf;   // RAII — auto-releases arena buffer on destruction
    bool body_detected = false;   // set when Content-Length found in headers

    HTTP1Parser parser;

    // Timeout tracking
    using clock = std::chrono::steady_clock;
    auto request_timeout = std::chrono::milliseconds(config_.request_timeout_ms);
    auto idle_timeout = std::chrono::milliseconds(config_.idle_timeout_ms);
    bool is_first_request = true;

    bool keep_alive = true;
    // Per-connection reusable response buffer — clear() retains capacity, so
    // response serialization performs NO heap allocation after the first request
    // (TigerStyle: no per-request alloc on the response path).
    std::string resp_buf;
    resp_buf.reserve(4096);
    while (keep_alive && !stop_requested_.load(std::memory_order_relaxed)) {
        // Track start time for timeout
        auto request_start = clock::now();

        // HTTP Pipelining: Try to parse from existing buffer first before reading
        HTTP1Request parsed_req;
        size_t consumed = 0;
        int parse_result = -1;  // Need more data by default

        // Try parsing if we have data in buffer (pipelining case)
        if (buf_len > 0) {
            parse_result = parser.parse(buf, buf_len, parsed_req, consumed);
        }

        // If we need more data, read from socket
        while (parse_result < 0 && !stop_requested_.load(std::memory_order_relaxed)) {
            // Buffer full — need to grow or reject
            if (buf_len >= buf_cap) {
                if (!body_detected) {
                    const char* r = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }
                const char* r = "HTTP/1.1 413 Payload Too Large\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                io.async_close(fd);
                co_return;
            }

            // Header size limit (only before body detected)
            if (!body_detected && buf_len > config_.max_header_size) {
                const char* r = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                io.async_close(fd);
                co_return;
            }

            // Read more data into current buffer. Cleartext takes the dispatcher
            // awaitable DIRECTLY (no conn_read coroutine frame — zero alloc on the
            // hot path); TLS keeps the framed helper.
            ssize_t n = tls ? co_await conn_read(io, fd, tls, buf + buf_len, buf_cap - buf_len)
                            : co_await io.async_read(fd, buf + buf_len, buf_cap - buf_len);
            if (n <= 0) {
                io.async_close(fd);
                co_return;
            }
            buf_len += n;

            // Try parsing again
            parse_result = parser.parse(buf, buf_len, parsed_req, consumed);

            if (parse_result < 0) {
                // Content-Length known but body incomplete → acquire arena buffer
                if (!body_detected && parsed_req.has_content_length) {
                    body_detected = true;
                    if (parsed_req.content_length > config_.max_body_size) {
                        const char* r = "HTTP/1.1 413 Payload Too Large\r\n"
                            "Content-Length: 0\r\nConnection: close\r\n\r\n";
                        co_await conn_write(io, fd, tls,r, strlen(r));
                        io.async_close(fd);
                        co_return;
                    }
                    // Need room for headers + body
                    size_t needed = config_.max_header_size + parsed_req.content_length;
                    if (needed > STACK_BUF_SIZE) {
                        body_buf.reserve(needed, config_.max_body_size + config_.max_header_size);
                        body_buf.adopt(stack_buf, buf_len);
                        buf = body_buf.writable_data();
                        buf_cap = body_buf.capacity();
                    }
                }

                // Chunked without Content-Length — not yet supported
                if (!body_detected && parsed_req.chunked && !parsed_req.has_content_length) {
                    const char* r = "HTTP/1.1 501 Not Implemented\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }

                // Timeout check
                auto elapsed = clock::now() - request_start;
                auto timeout = is_first_request ? request_timeout : idle_timeout;
                if (elapsed > timeout) {
                    const char* r = "HTTP/1.1 408 Request Timeout\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }
            }
        }

        if (parse_result > 0) {
            // Parse error - send 400 Bad Request
            const char* bad_request =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            co_await conn_write(io, fd, tls,bad_request, strlen(bad_request));
            break;
        }

        // Check if we should exit after parsing (stop requested during read loop)
        if (stop_requested_.load(std::memory_order_relaxed)) {
            break;
        }

        // Request completed - no longer first request
        is_first_request = false;

        // Enforce the header-size limit on the COMPLETED parse as well, not just
        // mid-read. The in-loop check (above) only fires when more data is still
        // needed; a request whose oversized headers arrive in a single recv (and
        // fit under the stack buffer) parses on the first attempt and would
        // otherwise bypass the limit. The header block is everything consumed
        // minus the body bytes. Mirrors the post-parse 413 body check below.
        if (config_.max_header_size != 0) {
            const size_t header_bytes =
                consumed > parsed_req.body.size()
                    ? consumed - parsed_req.body.size()
                    : consumed;
            if (header_bytes > config_.max_header_size) {
                const char* too_large =
                    "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                co_await conn_write(io, fd, tls,too_large, strlen(too_large));
                break;
            }
        }

        // Parse successful - convert to CoroHttpRequest (ZERO-COPY).
        // All views below point into `buf` (the connection read buffer on this
        // coroutine frame, or the body arena). That buffer stays alive — the
        // frame is suspended — across the worker-thread handler co_await and is
        // only reset AFTER the response is written (end of this loop iteration),
        // so every view is valid for the whole request, including keep-alive.
        CoroHttpRequest req;
        req.method = std::string_view(parsed_req.method_str);
        req.path = std::string_view(parsed_req.path);
        const size_t hdr_n = std::min(parsed_req.header_count,
                                      CoroHttpRequest::MAX_HEADERS);
        for (size_t i = 0; i < hdr_n; i++) {
            req.add_header(std::string_view(parsed_req.headers[i].name),
                           std::string_view(parsed_req.headers[i].value));
        }
        req.body = std::string_view(parsed_req.body);

        // Check body size limits
        {
            bool has_cl = false;
            std::string_view cl_val = req.find_header("Content-Length", &has_cl);
            if (has_cl) {
                size_t content_length = 0;
                for (char c : cl_val) {
                    if (c < '0' || c > '9') break;
                    content_length = content_length * 10 + static_cast<size_t>(c - '0');
                }
                if (content_length > config_.max_body_size) {
                    // Body too large - send 413 Payload Too Large
                    const char* too_large =
                        "HTTP/1.1 413 Payload Too Large\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    co_await conn_write(io, fd, tls,too_large, strlen(too_large));
                    break;
                }
            }
        }

        // Check if actual body exceeds limit
        if (req.body.size() > config_.max_body_size) {
            const char* too_large =
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            co_await conn_write(io, fd, tls,too_large, strlen(too_large));
            break;
        }

        // Track request
        requests_total_.fetch_add(1, std::memory_order_relaxed);

        // Check for ultra-fast callback (bypasses all routing for maximum performance)
        auto ultra_fast_cb = get_ultra_fast_callback();
        if (ultra_fast_cb) {
            // Build zero-copy request view
            Http1RequestView view;
            view.method = std::string_view(parsed_req.method_str);
            
            // Parse path and query string
            std::string_view full_path(parsed_req.path);
            size_t query_pos = full_path.find('?');
            if (query_pos != std::string_view::npos) {
                view.path = full_path.substr(0, query_pos);
                view.query_string = full_path.substr(query_pos + 1);
            } else {
                view.path = full_path;
                view.query_string = {};
            }
            
            view.body = std::string_view(parsed_req.body);
            
            // Copy headers to view
            view.header_count = std::min(parsed_req.header_count, Http1RequestView::MAX_HEADERS);
            for (size_t i = 0; i < view.header_count; i++) {
                view.headers[i] = {
                    std::string_view(parsed_req.headers[i].name),
                    std::string_view(parsed_req.headers[i].value)
                };
            }
            
            // Prepare response buffer (reuse our existing buffer for output)
            static constexpr size_t RESPONSE_BUFFER_SIZE = 65536;
            uint8_t response_buffer[RESPONSE_BUFFER_SIZE];
            FastResponseWriter writer(response_buffer, RESPONSE_BUFFER_SIZE);
            
            // Call ultra-fast callback
            size_t response_size = ultra_fast_cb(view, writer);
            
            if (response_size > 0) {
                // Send the response
                co_await conn_write(io, fd, tls,response_buffer, response_size);
                
                // Check keep-alive and continue loop
                keep_alive = parsed_req.keep_alive;
                
                // Shift buffer (remove consumed data)
                if (consumed < buf_len) {
                    memmove(buf, buf + consumed, buf_len - consumed);
                    buf_len -= consumed;
                } else {
                    buf_len = 0;
                }

                // Release arena buffer if used, copy leftover back to stack
                if (body_buf.is_arena_backed()) {
                    if (buf_len > 0 && buf_len <= STACK_BUF_SIZE) {
                        std::memcpy(stack_buf, buf, buf_len);
                    } else if (buf_len > STACK_BUF_SIZE) {
                        buf_len = 0;
                    }
                    body_buf.reset();
                    buf = stack_buf;
                    buf_cap = STACK_BUF_SIZE;
                }
                body_detected = false;

                // Reclaim the per-request bolt::Arena (no-op when the arena flag
                // is OFF). Safe here: the response is fully written, req.body was
                // copied out, and any pipelined leftover is already in stack_buf
                // (copied above before body_buf.reset()), so no live view points
                // into the arena.
                thread_body_arena_reset();

                // Reset parser for next request
                parser.reset();
                continue;  // Skip normal handler processing
            }
            // If callback returns 0, fall through to normal routing
        }

        // Check for WebSocket upgrade request
        bool has_upgrade = false, has_ws_key = false;
        std::string_view upgrade_sv  = req.find_header("Upgrade", &has_upgrade);
        std::string_view ws_key_sv   = req.find_header("Sec-WebSocket-Key", &has_ws_key);
        std::string_view conn_sv     = req.find_header("Connection");
        std::string_view ws_ver_sv   = req.find_header("Sec-WebSocket-Version");

        if (has_upgrade && has_ws_key) {
            std::string upgrade_val(upgrade_sv);
            std::string connection_val(conn_sv);
            std::string ws_version(ws_ver_sv);
            std::string ws_key(ws_key_sv);

            if (websocket::HandshakeUtils::validate_upgrade_request(
                    std::string(req.method), upgrade_val, connection_val, ws_version, ws_key)) {

                // Check if we have a handler for this path
                WebSocketHandler* ws_handler = get_websocket_handler(std::string(req.path));
                if (ws_handler) {
                    // Valid WebSocket upgrade - compute accept key and send 101
                    std::string accept_key = websocket::HandshakeUtils::compute_accept_key(ws_key);

                    std::string ws_response =
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: " + accept_key + "\r\n"
                        "\r\n";

                    co_await conn_write(io, fd, tls,ws_response.data(), ws_response.size());

                    std::cout << "[CoroUnifiedServer] WebSocket upgrade for path: " << req.path << std::endl;

                    // Create WebSocket connection
                    static std::atomic<uint64_t> ws_connection_id{0};
                    WebSocketConnection ws_conn(++ws_connection_id);
                    ws_conn.set_socket_fd(fd);
                    ws_conn.set_path(std::string(req.path));

                    // Invoke user handler to set up callbacks
                    (*ws_handler)(ws_conn);

                    // Handle WebSocket frames in coroutine loop
                    co_await handle_websocket_connection(io, fd, ws_conn, tls);

                    // WebSocket connection closed
                    io.async_close(fd);
                    co_return;
                }
                // No handler - fall through to 404
            }
        }

        // Check for SSE request (Accept: text/event-stream).
        // find_header is already case-insensitive, so one lookup suffices.
        std::string_view accept_value = req.find_header("Accept");

        // Match SSE either by Accept header or by registered path (allows curl testing)
        CoroSSEHandler* sse_handler = get_sse_handler(std::string(req.path));
        if (sse_handler && (accept_value.empty() ||
            accept_value.find("text/event-stream") != std::string_view::npos)) {
            {
                // Send SSE headers (include CORS for cross-origin EventSource)
                const char* sse_headers =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: keep-alive\r\n"
                    "X-Accel-Buffering: no\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                    "\r\n";
                co_await conn_write(io, fd, tls,sse_headers, strlen(sse_headers));

                std::cout << "[CoroUnifiedServer] SSE stream for path: " << req.path << std::endl;

                // Call SSE handler (streams events until done or client disconnects)
                co_await (*sse_handler)(io, fd, req);

                // SSE stream ended
                io.async_close(fd);
                co_return;
            }
            // No handler - fall through to regular HTTP handler
        }

        // Call handler for regular HTTP request
        CoroHttpResponse response;
        if (handler_) {
            response = co_await handler_(req);
        } else {
            // Default response
            response.status = 200;
            response.status_message = "OK";
            response.headers.set("Content-Type", "text/plain");
            response.body = "Hello, World!";
        }

        // Check if chunked transfer encoding is requested (no allocation).
        bool use_chunked = false;
        auto transfer_encoding_it = response.headers.find("Transfer-Encoding");
        if (transfer_encoding_it != response.headers.end() &&
            contains_ci(transfer_encoding_it->value, "chunked")) {
            use_chunked = true;
        }

        // Build the HTTP/1.1 response into the per-connection reusable buffer.
        // clear() keeps capacity -> zero heap allocation after the first request;
        // to_chars / branchless compares replace the old to_string / per-header
        // std::string lowercasing that allocated on every response.
        std::string& resp_str = resp_buf;
        resp_str.clear();
        resp_str += "HTTP/1.1 ";
        append_uint(resp_str, response.status);
        resp_str += ' ';
        resp_str += response.status_message;
        resp_str += "\r\n";

        // Add Content-Length if not present and not chunked
        if (!use_chunked && response.headers.find("Content-Length") == response.headers.end()) {
            resp_str += "Content-Length: ";
            append_uint(resp_str, response.body.size());
            resp_str += "\r\n";
        }

        // Add headers (skip zstd content-encoding as browsers don't support it)
        for (const auto& [name, value] : response.headers) {
            // Skip ANY content-encoding with zstd value (branchless ci key check).
            if (ieq_ascii(name, "content-encoding") && value == "zstd") {
                continue;  // Skip zstd header - browser will fail to decode
            }
            resp_str += name;
            resp_str += ": ";
            resp_str += value;
            resp_str += "\r\n";
        }

        // Check keep-alive
        keep_alive = parsed_req.keep_alive;
        if (!keep_alive) {
            resp_str += "Connection: close\r\n";
        }

        resp_str += "\r\n";

        if (use_chunked) {
            // For chunked encoding, send headers first
            co_await conn_write(io, fd, tls,resp_str.data(), resp_str.size());

            // Send body as chunk(s) if there is content
            if (!response.body.empty()) {
                // Format: {size_hex}\r\n{data}\r\n
                char size_buf[32];
                int len = snprintf(size_buf, sizeof(size_buf), "%zx\r\n", response.body.size());
                std::string chunk;
                chunk.reserve(len + response.body.size() + 2);
                chunk.append(size_buf, len);
                chunk.append(response.body);
                chunk.append("\r\n");
                co_await conn_write(io, fd, tls,chunk.data(), chunk.size());
            }

            // Send final empty chunk: 0\r\n\r\n
            const char* final_chunk = "0\r\n\r\n";
            co_await conn_write(io, fd, tls,final_chunk, 5);
        } else {
            // Non-chunked: send headers + body together (cleartext writes via the
            // dispatcher awaitable directly — no conn_write coroutine frame).
            resp_str += response.body;
            if (tls) {
                co_await conn_write(io, fd, tls, resp_str.data(), resp_str.size());
            } else {
                co_await io.async_write(fd, resp_str.data(), resp_str.size());
            }
        }

        // Pipelining timeout check: before processing next request from buffer,
        // verify we haven't exceeded idle timeout since start of this request
        if (buf_len > consumed) {
            auto elapsed = clock::now() - request_start;
            if (elapsed > idle_timeout) {
                const char* r = "HTTP/1.1 408 Request Timeout\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                break;
            }
        }

        // Shift buffer (remove consumed data)
        if (consumed < buf_len) {
            memmove(buf, buf + consumed, buf_len - consumed);
            buf_len -= consumed;
        } else {
            buf_len = 0;
        }

        // Release arena buffer if used, copy leftover back to stack
        if (body_buf.is_arena_backed()) {
            if (buf_len > 0 && buf_len <= STACK_BUF_SIZE) {
                std::memcpy(stack_buf, buf, buf_len);
            } else if (buf_len > STACK_BUF_SIZE) {
                buf_len = 0;
            }
            body_buf.reset();
            buf = stack_buf;
            buf_cap = STACK_BUF_SIZE;
        }
        body_detected = false;

        // Reclaim the per-request bolt::Arena (no-op when the arena flag is
        // OFF). Safe here: the response is fully written, req.body / response
        // already hold their own std::string copies, and any pipelined leftover
        // is already in stack_buf (copied above before body_buf.reset()), so no
        // live view points into the arena.
        thread_body_arena_reset();

        // Reset parser for next request
        parser.reset();
    }

    io.async_close(fd);
}

// =============================================================================
// HTTP/2 Request Handler
// =============================================================================

// Pending HTTP/2 request info for async processing
struct PendingH2Request {
    uint32_t stream_id;
    CoroHttpRequest request;
};

core::coro_task<void> CoroUnifiedServer::handle_http2_connection(
    net::IODispatcher& io, int fd, net::CoroTlsSocket* tls) {

    // Create HTTP/2 connection
    http2::Http2Connection h2_conn(true);  // Server mode

    // Buffer for I/O
    static constexpr size_t BUFFER_SIZE = 16384;
    uint8_t buffer[BUFFER_SIZE];

    // Queue for pending requests (populated by callback, processed by main loop)
    std::vector<PendingH2Request> pending_requests;

    // Set request callback to queue requests for async processing
    h2_conn.set_request_callback([this, &pending_requests](http2::Http2Stream* stream) {
        if (!stream) return;

        // Convert stream request to CoroHttpRequest.
        // HTTP/2 SHIM: unlike H1 (whose views point into the long-lived
        // connection read buffer), this request is queued and processed in the
        // I/O loop AFTER subsequent reads, and its source HPACK strings live in
        // the stream object whose lifetime we don't pin here. So H2 OWNS its
        // bytes in req.owned_storage_ and points the views there — stable for
        // the whole request including the handler hop. H1 stays truly zero-copy.
        CoroHttpRequest req;

        // Extract method, path, and headers from request_headers()
        for (const auto& [name, value] : stream->request_headers()) {
            if (name == ":method") {
                req.method = req.own(value);
            } else if (name == ":path") {
                req.path = req.own(value);
            } else if (!name.empty() && name[0] != ':') {
                // Regular header (skip other pseudo-headers like :scheme, :authority)
                std::string_view nv = req.own(name);
                std::string_view vv = req.own(value);
                req.add_header(nv, vv);
            }
        }

        // Get body (owned copy from the stream's body buffer)
        req.body = req.own(stream->request_body());

        // Track request
        requests_total_.fetch_add(1, std::memory_order_relaxed);

        // Queue for async processing (can't call async handler from callback)
        pending_requests.push_back(PendingH2Request{stream->id(), std::move(req)});
    });

    // Main I/O loop
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        // Send any pending output
        const uint8_t* out_data = nullptr;
        size_t out_len = 0;
        while (h2_conn.get_output(&out_data, &out_len)) {
            ssize_t written = co_await conn_write(io, fd, tls,out_data, out_len);
            if (written <= 0) {
                io.async_close(fd);
                co_return;
            }
            h2_conn.commit_output(static_cast<size_t>(written));
        }

        // Read incoming data
        ssize_t n = co_await conn_read(io, fd, tls,buffer, BUFFER_SIZE);
        if (n <= 0) {
            break;  // Connection closed or error
        }

        // Process incoming data (this calls the callback for complete requests)
        auto result = h2_conn.process_input(buffer, static_cast<size_t>(n));
        if (!result) {
            // Protocol error
            break;
        }

        // Process any pending requests asynchronously
        for (auto& pending : pending_requests) {
            CoroHttpResponse response;
            if (handler_) {
                response = co_await handler_(pending.request);
            } else {
                // Default response
                response.status = 200;
                response.status_message = "OK";
                response.headers.set("Content-Type", "text/plain");
                response.body = "Hello, World!";
            }

            // Send response on the HTTP/2 stream
            h2_conn.send_response(
                pending.stream_id,
                response.status,
                response.headers,
                response.body
            );
        }
        pending_requests.clear();

        // Check connection state
        if (!h2_conn.is_active()) {
            break;
        }
    }

    // Send GOAWAY if we haven't already
    if (h2_conn.is_active()) {
        h2_conn.send_goaway(http2::ErrorCode::NO_ERROR);

        // Flush output
        const uint8_t* out_data = nullptr;
        size_t out_len = 0;
        while (h2_conn.get_output(&out_data, &out_len)) {
            ssize_t written = co_await conn_write(io, fd, tls,out_data, out_len);
            if (written <= 0) break;
            h2_conn.commit_output(static_cast<size_t>(written));
        }
    }

    // Reclaim the per-request bolt::Arena (no-op when the arena flag is OFF).
    // Done at connection teardown rather than per-stream: HTTP/2 multiplexes
    // many streams whose bodies may still be mid-accumulation across reads, so a
    // per-stream reset would risk wiping another stream's live body view. By
    // teardown every stream body has either been copied out to a std::string
    // (stream->request_body() in the request callback) or abandoned, and the
    // self-guarding reset only reclaims once no arena view is outstanding.
    thread_body_arena_reset();

    io.async_close(fd);
}

// =============================================================================
// WebSocket Connection Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_websocket_connection(
    net::IODispatcher& io, int fd, WebSocketConnection& ws_conn,
    net::CoroTlsSocket* tls) {

    static constexpr size_t WS_BUFFER_SIZE = 16384;
    uint8_t buffer[WS_BUFFER_SIZE];
    size_t buffer_len = 0;

    while (!stop_requested_.load(std::memory_order_relaxed) && ws_conn.is_open()) {
        // Send any pending output first
        while (ws_conn.has_pending_output()) {
            const std::string* output = ws_conn.get_pending_output();
            if (output && !output->empty()) {
                ssize_t written = co_await conn_write(io, fd, tls,output->data(), output->size());
                if (written <= 0) {
                    // Write failed - close connection
                    ws_conn.close(1001, "write error");
                    co_return;
                }
            }
            ws_conn.pop_pending_output();
        }

        // Read incoming WebSocket frames
        ssize_t n = co_await conn_read(io, fd, tls,buffer + buffer_len, WS_BUFFER_SIZE - buffer_len);
        if (n <= 0) {
            // Connection closed or error
            if (ws_conn.on_close) {
                ws_conn.on_close(1000, "connection closed");
            }
            co_return;
        }
        buffer_len += static_cast<size_t>(n);

        // Process all complete frames in buffer
        while (buffer_len > 0 && ws_conn.is_open()) {
            size_t consumed = 0;
            int result = ws_conn.handle_frame(buffer, buffer_len, consumed);
            
            if (result < 0) {
                // Need more data - keep buffer and read more
                break;
            } else if (result > 0) {
                // Frame processing error
                if (ws_conn.on_error) {
                    ws_conn.on_error("frame processing error");
                }
                co_return;
            }
            
            // result == 0: frame processed successfully
            // Remove consumed bytes from buffer
            if (consumed > 0 && consumed <= buffer_len) {
                if (consumed < buffer_len) {
                    memmove(buffer, buffer + consumed, buffer_len - consumed);
                }
                buffer_len -= consumed;
            } else {
                // No bytes consumed but success - shouldn't happen, but prevent infinite loop
                break;
            }
            
            // Send any responses queued by the handler immediately
            while (ws_conn.has_pending_output()) {
                const std::string* output = ws_conn.get_pending_output();
                if (output && !output->empty()) {
                    ssize_t written = co_await conn_write(io, fd, tls,output->data(), output->size());
                    if (written <= 0) {
                        ws_conn.close(1001, "write error");
                        co_return;
                    }
                }
                ws_conn.pop_pending_output();
            }
        }
    }

    // Send any final pending output
    while (ws_conn.has_pending_output()) {
        const std::string* output = ws_conn.get_pending_output();
        if (output && !output->empty()) {
            co_await conn_write(io, fd, tls,output->data(), output->size());
        }
        ws_conn.pop_pending_output();
    }
}

// =============================================================================
// Statistics
// =============================================================================

CoroUnifiedServer::Stats CoroUnifiedServer::get_stats() const noexcept {
    return Stats{
        .connections_accepted = connections_accepted_.load(std::memory_order_relaxed),
        .connections_active = connections_active_.load(std::memory_order_relaxed),
        .requests_total = requests_total_.load(std::memory_order_relaxed),
        .requests_http1 = requests_http1_.load(std::memory_order_relaxed),
        .requests_http2 = requests_http2_.load(std::memory_order_relaxed),
    };
}

} // namespace http
} // namespace bolt::api
