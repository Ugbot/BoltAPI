/**
 * Coroutine-based Unified HTTP Server
 *
 * Implements the Seastar-inspired architecture:
 * - 1-2 I/O threads dispatch events
 * - N worker threads execute coroutines
 * - Coroutines yield on blocking I/O
 *
 * This is the new architecture that replaces the N-threads-N-event-loops model.
 *
 * Features:
 * - HTTP/2 over TLS (h2) via ALPN
 * - HTTP/1.1 over TLS via ALPN
 * - HTTP/1.1 cleartext
 * - Zero-allocation per-request (using pre-allocated coroutine pools)
 * - True async with chained coroutines
 */

#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/net/coro_tcp_listener.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/net/tls_context.h"
#include "boltapi/net/coro_tls_socket.h"
#include "boltapi/http/http1_parser.h"
#include "boltapi/http/http1_connection.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/http/response_headers.h"
#include "boltapi/http/websocket.h"
#include "boltapi/http/websocket_parser.h"
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bolt::api {
namespace http {

/**
 * Server shutdown state for graceful shutdown support
 */
enum class CoroShutdownState {
    RUNNING,    // Normal operation
    DRAINING,   // Not accepting new connections, waiting for in-flight to complete
    STOPPED     // Fully stopped
};

/**
 * Ultra-fast callback for maximum performance HTTP/1.1 handling.
 * 
 * This callback writes directly to a pre-allocated buffer with zero allocations.
 * Best for benchmarks and high-throughput scenarios.
 * 
 * @param view Zero-copy request view
 * @param out_buffer Pre-allocated output buffer
 * @param out_size Size of output buffer
 * @return Number of bytes written to out_buffer, or -1 on error
 */
using CoroUltraFastCallback = Http1Connection::UltraFastCallback;

/**
 * HTTP Request Handler (coroutine version)
 *
 * Handler receives request details and returns a task that produces the response.
 *
 * ZERO-COPY: method/path/body and every header name/value are std::string_view
 * pointing into the per-request parse buffer (the connection read buffer, which
 * lives in the connection coroutine frame and stays alive — suspended — across
 * the worker-thread handler hop and until the response is written). The header
 * set is a fixed-capacity, allocation-free array (no unordered_map, no per-field
 * std::string). See coro_unified_server.cpp for the full lifetime argument.
 *
 * The HTTP/2 path cannot guarantee that its decoded HPACK strings outlive the
 * handler the way the H1 read buffer does, so it owns its backing storage in a
 * small per-request arena (CoroHttpRequest::owned_storage_) and points the views
 * at that. H1 leaves owned_storage_ empty (truly zero-copy).
 */
struct CoroHttpHeaderView {
    std::string_view name;
    std::string_view value;
};

struct CoroHttpRequest {
    // Matches Http1RequestView::MAX_HEADERS so the H1 fast path and the
    // dispatch path share the same bound (also caps H2 header fan-out).
    static constexpr size_t MAX_HEADERS = 64;

    std::string_view method;
    std::string_view path;
    std::string_view body;

    CoroHttpHeaderView headers[MAX_HEADERS];
    size_t header_count = 0;

    // ASCII case-insensitive header lookup (linear scan — few headers, this is
    // branch-light and cache-friendly vs. an unordered_map probe). Returns a
    // null/empty view when the header is absent. `found` is set when provided.
    std::string_view find_header(std::string_view name,
                                 bool* found = nullptr) const noexcept {
        for (size_t i = 0; i < header_count; ++i) {
            if (iequals_ci(headers[i].name, name)) {
                if (found) *found = true;
                return headers[i].value;
            }
        }
        if (found) *found = false;
        return std::string_view{};
    }

    bool has_header(std::string_view name) const noexcept {
        bool f = false;
        (void)find_header(name, &f);
        return f;
    }

    // Append a header view; silently drops past MAX_HEADERS (the parser already
    // bounds at MAX_HEADERS, and the engine's 431 header-size check fires first).
    void add_header(std::string_view name, std::string_view value) noexcept {
        if (header_count < MAX_HEADERS) {
            headers[header_count].name = name;
            headers[header_count].value = value;
            ++header_count;
        }
    }

    // --- HTTP/2-only owned backing store ---
    // H1 never touches this (views point into the connection read buffer). H2
    // copies its decoded header/method/path/body bytes here and points the views
    // into this stable, request-lifetime storage. Reserved once, never during
    // the hot H1 path.
    // NOTE: std::deque guarantees stable element addresses across push_back, so
    // string_views returned by earlier own() calls stay valid as more are added
    // (std::vector would reallocate and dangle them). H2-only; never on H1.
    void own_clear() { owned_storage_.clear(); }
    std::string_view own(std::string_view s) {
        owned_storage_.emplace_back(s);
        return std::string_view(owned_storage_.back());
    }

private:
    static bool iequals_ci(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i], cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    }

    std::deque<std::string> owned_storage_;  // empty on the H1 zero-copy path
};

// CoroResponseHeaders: owned, flat, bounded response-header store that replaces
// the per-response std::unordered_map. Defined in its own header so the HTTP/2
// path can consume it without an include cycle. See response_headers.h.
struct CoroHttpResponse {
    uint16_t status = 200;
    std::string status_message = "OK";
    CoroResponseHeaders headers;
    std::string body;
};

using CoroHttpHandler = std::function<core::coro_task<CoroHttpResponse>(const CoroHttpRequest&)>;

/**
 * WebSocket Handler Callback
 *
 * Pure C++ WebSocket handler - runs entirely in C++.
 * The handler is invoked when a WebSocket connection is established.
 * Set up message callbacks on the connection inside the handler.
 */
using WebSocketHandler = std::function<void(WebSocketConnection&)>;

/**
 * SSE (Server-Sent Events) Handler Callback for coroutine server
 *
 * The handler receives the I/O dispatcher, file descriptor, and request.
 * It should stream events by writing directly to the fd via io.async_write().
 * The connection stays open until the handler completes or client disconnects.
 *
 * Example:
 *   [](net::IODispatcher& io, int fd, const CoroHttpRequest& req) -> core::coro_task<void> {
 *       SSEWriter sse(io, fd);
 *       for (int i = 0; i < 10; i++) {
 *           co_await sse.send_event("message", "event " + std::to_string(i));
 *       }
 *   }
 */
using CoroSSEHandler = std::function<core::coro_task<void>(
    net::IODispatcher& io, int fd, const CoroHttpRequest& req)>;

/**
 * SSE Writer helper for coroutine handlers
 *
 * Provides convenient methods for sending SSE events.
 */
class SSEWriter {
public:
    SSEWriter(net::IODispatcher& io, int fd) : io_(io), fd_(fd) {}

    /**
     * Send an SSE event with optional event type and ID.
     * 
     * @param event_type Event type (e.g., "message", "update")
     * @param data Event data
     * @param id Optional event ID
     * @return Task that completes when data is sent
     */
    core::coro_task<bool> send_event(
        const std::string& event_type,
        const std::string& data,
        const std::string& id = ""
    ) {
        std::string message;
        if (!id.empty()) {
            message += "id: " + id + "\n";
        }
        if (!event_type.empty()) {
            message += "event: " + event_type + "\n";
        }
        
        // Handle multi-line data
        size_t pos = 0;
        size_t prev = 0;
        while ((pos = data.find('\n', prev)) != std::string::npos) {
            message += "data: " + data.substr(prev, pos - prev) + "\n";
            prev = pos + 1;
        }
        message += "data: " + data.substr(prev) + "\n";
        message += "\n";  // End of event
        
        ssize_t result = co_await io_.async_write(fd_, message.data(), message.size());
        co_return result > 0;
    }

    /**
     * Send a simple data-only event.
     */
    core::coro_task<bool> send_data(const std::string& data) {
        std::string message = "data: " + data + "\n\n";
        ssize_t result = co_await io_.async_write(fd_, message.data(), message.size());
        co_return result > 0;
    }

    /**
     * Send a comment (keep-alive).
     */
    core::coro_task<bool> send_comment(const std::string& comment = "") {
        std::string message = ": " + comment + "\n\n";
        ssize_t result = co_await io_.async_write(fd_, message.data(), message.size());
        co_return result > 0;
    }

    /**
     * Send a retry interval hint to the client.
     */
    core::coro_task<bool> send_retry(int retry_ms) {
        std::string message = "retry: " + std::to_string(retry_ms) + "\n\n";
        ssize_t result = co_await io_.async_write(fd_, message.data(), message.size());
        co_return result > 0;
    }

private:
    net::IODispatcher& io_;
    int fd_;
};

/**
 * Coroutine Unified Server Configuration
 */
struct CoroUnifiedServerConfig {
    // TLS configuration
    bool enable_tls = true;
    uint16_t tls_port = 443;
    std::string host = "0.0.0.0";

    // Certificate configuration
    std::string cert_file;
    std::string key_file;
    std::string cert_data;  // In-memory certificate (PEM)
    std::string key_data;   // In-memory private key (PEM)

    // ALPN protocols
    std::vector<std::string> alpn_protocols = {"h2", "http/1.1"};

    // Cleartext HTTP/1.1
    bool enable_http1_cleartext = true;
    uint16_t http1_port = 8080;

    // Worker configuration (Seastar-inspired)
    size_t num_io_threads = 1;     // 1-2 recommended
    size_t num_workers = 0;        // 0 = auto (CPU count)

    // Backlog
    int backlog = 1024;

    // Request timeout configuration
    uint32_t request_timeout_ms = 30000;  // Max time for request to be received (30s)
    uint32_t idle_timeout_ms = 60000;     // Max time between requests on keep-alive (60s)

    // Body size limits
    size_t max_body_size = 10 * 1024 * 1024;  // Max request body size (10MB default)
    size_t max_header_size = 8192;            // Max header size (8KB default)

    // Graceful shutdown configuration
    uint32_t shutdown_timeout_ms = 30000;   // Max time to wait for connections to drain (30s)
    bool enable_signal_handlers = true;     // Install SIGTERM/SIGINT handlers

    // Pure C++ mode - always true for CoroUnifiedServer
    bool pure_cpp_mode = true;
};

/**
 * Coroutine-based Unified HTTP Server
 *
 * High-performance HTTP server using the Seastar-inspired coroutine-on-threadpool
 * architecture.
 *
 * Usage:
 *   CoroUnifiedServerConfig config;
 *   config.tls_port = 8443;
 *   config.http1_port = 8080;
 *
 *   CoroUnifiedServer server(config);
 *   server.set_handler([](const CoroHttpRequest& req) -> core::coro_task<CoroHttpResponse> {
 *       CoroHttpResponse response;
 *       response.status = 200;
 *       response.body = "Hello, World!";
 *       response.headers["Content-Type"] = "text/plain";
 *       co_return response;
 *   });
 *
 *   server.start();  // Blocks
 */
class CoroUnifiedServer {
public:
    explicit CoroUnifiedServer(const CoroUnifiedServerConfig& config);
    ~CoroUnifiedServer();

    // Non-copyable, non-movable
    CoroUnifiedServer(const CoroUnifiedServer&) = delete;
    CoroUnifiedServer& operator=(const CoroUnifiedServer&) = delete;

    /**
     * Set the HTTP request handler
     */
    void set_handler(CoroHttpHandler handler);

    /**
     * Register a pure C++ WebSocket handler
     *
     * @param path WebSocket path (e.g., "/ws/echo")
     * @param handler Callback invoked when WebSocket connection established
     */
    void add_websocket_handler(const std::string& path, WebSocketHandler handler);

    /**
     * Get WebSocket handler for a path
     *
     * @param path WebSocket path
     * @return Pointer to handler, or nullptr if not found
     */
    static WebSocketHandler* get_websocket_handler(const std::string& path);

    /**
     * Register a pure C++ SSE (Server-Sent Events) handler
     *
     * The handler receives I/O dispatcher and fd for async event streaming.
     * SSE headers are automatically sent before the handler is called.
     *
     * @param path SSE endpoint path (e.g., "/events")
     * @param handler Coroutine that streams events to the client
     */
    void add_sse_handler(const std::string& path, CoroSSEHandler handler);

    /**
     * Get SSE handler for a path
     *
     * @param path SSE endpoint path
     * @return Pointer to handler, or nullptr if not found
     */
    static CoroSSEHandler* get_sse_handler(const std::string& path);

    /**
     * Start the server (blocking)
     */
    int start();

    /**
     * Start the server in background (non-blocking)
     */
    int start_background();

    /**
     * Stop the server
     */
    void stop();

    /**
     * Initiate graceful shutdown
     *
     * Stops accepting new connections and waits for in-flight requests to complete.
     * Times out after shutdown_timeout_ms if connections don't drain.
     *
     * @return true if shutdown completed within timeout, false if forced
     */
    bool shutdown_gracefully();

    /**
     * Set ultra-fast callback for maximum performance HTTP/1.1 handling.
     * 
     * This callback writes directly to a pre-allocated buffer with zero allocations.
     * Best for benchmarks and high-throughput scenarios. Bypasses normal routing.
     *
     * @param callback Raw function pointer for zero-overhead dispatch
     */
    void set_ultra_fast_callback(Http1Connection::UltraFastCallback callback);

    /**
     * Get ultra-fast callback
     *
     * @return Pointer to callback, or nullptr if not set
     */
    static Http1Connection::UltraFastCallback get_ultra_fast_callback() noexcept;

    /**
     * Check if server is running (not stopped or draining)
     */
    bool is_running() const noexcept {
        CoroShutdownState state = shutdown_state_.load(std::memory_order_acquire);
        return state == CoroShutdownState::RUNNING;
    }

    /**
     * Check if server is accepting new connections
     * Returns false during DRAINING or STOPPED states
     */
    bool is_accepting() const noexcept {
        CoroShutdownState state = shutdown_state_.load(std::memory_order_acquire);
        return state == CoroShutdownState::RUNNING;
    }

    /**
     * Check if server is in shutdown/draining state
     */
    bool is_draining() const noexcept {
        CoroShutdownState state = shutdown_state_.load(std::memory_order_acquire);
        return state == CoroShutdownState::DRAINING;
    }

    /**
     * Get current shutdown state
     */
    CoroShutdownState get_shutdown_state() const noexcept {
        return shutdown_state_.load(std::memory_order_acquire);
    }

    /**
     * Get number of active connections
     */
    uint64_t get_active_connections() const noexcept {
        return connections_active_.load(std::memory_order_relaxed);
    }

    /**
     * Get the server's unified async I/O dispatcher (the event loop that backs
     * all TCP/HTTP connections). Valid only AFTER start()/start_background()
     * has created it; returns nullptr before then. Used to run additional
     * protocols (e.g. WebRTC UDP) on the SAME unified loop instead of a private
     * thread.
     */
    net::IODispatcher* io_dispatcher() noexcept { return io_dispatcher_.get(); }

    /**
     * Track connection open - returns false if draining (reject connection)
     */
    bool track_connection_open() noexcept {
        if (!is_accepting()) return false;
        connections_active_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    /**
     * Track connection close - decrements counter and notifies shutdown if last connection
     */
    void track_connection_close() noexcept {
        uint64_t prev = connections_active_.fetch_sub(1, std::memory_order_acq_rel);
        if (prev == 1 && is_draining()) {
            shutdown_cv_.notify_all();
        }
    }

    /**
     * Get last error message
     */
    const std::string& get_error() const noexcept {
        return error_message_;
    }

    /**
     * Get global server instance (for signal handlers)
     */
    static CoroUnifiedServer* get_instance() noexcept {
        return s_instance_;
    }

    /**
     * Get request timeout in milliseconds
     */
    uint32_t get_request_timeout_ms() const noexcept {
        return config_.request_timeout_ms;
    }

    /**
     * Get idle timeout in milliseconds
     */
    uint32_t get_idle_timeout_ms() const noexcept {
        return config_.idle_timeout_ms;
    }

    /**
     * Get max body size in bytes
     */
    size_t get_max_body_size() const noexcept {
        return config_.max_body_size;
    }

    /**
     * Get max header size in bytes
     */
    size_t get_max_header_size() const noexcept {
        return config_.max_header_size;
    }

    /**
     * Get statistics
     */
    struct Stats {
        uint64_t connections_accepted;
        uint64_t connections_active;
        uint64_t requests_total;
        uint64_t requests_http1;
        uint64_t requests_http2;
    };

    Stats get_stats() const noexcept;

private:
    // TLS connection handler coroutine
    core::coro_task<void> handle_tls_connection(net::IODispatcher& io, int fd);

    // Cleartext HTTP/1.1 handler coroutine
    core::coro_task<void> handle_cleartext_connection(net::IODispatcher& io, int fd);

    // HTTP/1.1 request handling loop
    core::coro_task<void> handle_http1_connection(net::IODispatcher& io, int fd, net::CoroTlsSocket* tls);

    // HTTP/2 request handling loop
    core::coro_task<void> handle_http2_connection(net::IODispatcher& io, int fd, net::CoroTlsSocket* tls);

    // WebSocket connection handler coroutine
    core::coro_task<void> handle_websocket_connection(
        net::IODispatcher& io, int fd, WebSocketConnection& ws_conn,
        net::CoroTlsSocket* tls);

    // Signal handler installation
    void install_signal_handlers();
    static void signal_handler(int signum);

    // Pure C++ WebSocket handlers (path → handler mapping)
    static std::unordered_map<std::string, WebSocketHandler> s_websocket_handlers_;

    // Pure C++ SSE handlers (path → handler mapping)
    static std::unordered_map<std::string, CoroSSEHandler> s_sse_handlers_;

    // Ultra-fast callback for bypassing routing (maximum performance)
    static Http1Connection::UltraFastCallback s_ultra_fast_callback_;

    // Global instance for signal handlers
    static CoroUnifiedServer* s_instance_;

    CoroUnifiedServerConfig config_;
    CoroHttpHandler handler_;

    // TLS context
    std::shared_ptr<net::TlsContext> tls_context_;

    // Workers and I/O infrastructure
    std::unique_ptr<core::WorkerThreadPool> worker_pool_;
    std::unique_ptr<net::IODispatcher> io_dispatcher_;

    // Listeners
    std::unique_ptr<net::CoroTcpListener> tls_listener_;
    std::unique_ptr<net::CoroTcpListener> cleartext_listener_;

    std::string error_message_;

    // Graceful shutdown support
    std::atomic<CoroShutdownState> shutdown_state_{CoroShutdownState::STOPPED};
    std::atomic<bool> stop_requested_{false};
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_cv_;

    // Statistics (cache-line aligned to prevent false sharing)
    alignas(core::kCacheLineSize) std::atomic<uint64_t> connections_accepted_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> connections_active_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> requests_total_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> requests_http1_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> requests_http2_{0};
};

} // namespace http
} // namespace bolt::api
