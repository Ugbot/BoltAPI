/**
 * Bolt API TCP Listener - Multi-threaded TCP server
 *
 * Features:
 * - SO_REUSEPORT for kernel-level load balancing (Linux)
 * - Automatic worker thread creation
 * - Integration with EventLoop
 * - Thread-per-core architecture
 */

#pragma once

#include "boltapi/net/event_loop.h"
#include "boltapi/net/tcp_socket.h"
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

namespace bolt::api {
namespace net {

/**
 * Connection callback
 *
 * Called when a new connection is accepted.
 * @param socket The accepted client socket
 * @param event_loop The event loop for this worker thread
 */
using ConnectionCallback = std::function<void(TcpSocket socket, EventLoop* event_loop)>;

/**
 * TCP Listener configuration
 */
struct TcpListenerConfig {
    std::string host = "0.0.0.0";      // Bind address
    uint16_t port = 8070;              // Bind port
    int backlog = 1024;                // Listen backlog
    uint16_t num_workers = 0;          // 0 = auto (recommended_worker_count())
    bool use_reuseport = true;         // Use SO_REUSEPORT if available (Linux)
};

/**
 * Multi-threaded TCP Listener
 *
 * Creates multiple worker threads, each with its own event loop.
 * On Linux with SO_REUSEPORT, each worker accepts connections directly.
 * On other platforms, uses a single acceptor thread that distributes
 * connections to workers via a lockfree queue.
 */
class TcpListener {
public:
    /**
     * Create a TCP listener
     * @param config Listener configuration
     * @param connection_cb Callback for new connections
     */
    TcpListener(const TcpListenerConfig& config, ConnectionCallback connection_cb);

    /**
     * Destructor stops the listener
     */
    ~TcpListener();

    // Non-copyable, non-movable
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;
    TcpListener(TcpListener&&) = delete;
    TcpListener& operator=(TcpListener&&) = delete;

    /**
     * Start listening and accepting connections
     * This creates worker threads and blocks until stop() is called.
     * @return 0 on success, -1 on error
     */
    int start();

    /**
     * Stop the listener
     * Thread-safe. Can be called from any thread.
     */
    void stop();

    /**
     * Check if listener is running
     */
    bool is_running() const;

    /**
     * Get number of worker threads
     */
    uint16_t num_workers() const { return config_.num_workers; }

    /**
     * Get listener configuration
     */
    const TcpListenerConfig& config() const { return config_; }

private:
    void worker_thread(int worker_id);
    int create_listen_socket();

    TcpListenerConfig config_;
    ConnectionCallback connection_cb_;
    std::vector<std::thread> worker_threads_;
    std::vector<EventLoop*> event_loops_;  // Track event loops for shutdown
    std::atomic<bool> running_{false};
    std::mutex event_loops_mutex_;  // Protect event_loops_ vector
};

} // namespace net
} // namespace bolt::api
