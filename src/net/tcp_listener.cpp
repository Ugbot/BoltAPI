/**
 * Bolt API TCP Listener - Implementation
 */

#include "boltapi/net/tcp_listener.h"
#include "boltapi/core/logger.h"
#include "boltapi/net/sys_compat.h"
#include <csignal>
#include <cstring>

namespace bolt::api {
namespace net {

TcpListener::TcpListener(const TcpListenerConfig& config, ConnectionCallback connection_cb)
    : config_(config)
    , connection_cb_(std::move(connection_cb))
{
    // Auto-detect number of workers
    if (config_.num_workers == 0) {
        config_.num_workers = recommended_worker_count();
    }
}

TcpListener::~TcpListener() {
    stop();
}

int TcpListener::start() {
    if (running_.load()) {
        return -1;  // Already running
    }

    running_.store(true);

    LOG_INFO("TCP", "Starting TCP listener on %s:%d", config_.host.c_str(), config_.port);
    LOG_INFO("TCP", "Workers: %d, SO_REUSEPORT: %s", 
             config_.num_workers, config_.use_reuseport ? "enabled" : "disabled");

    // Create worker threads
    for (uint16_t i = 0; i < config_.num_workers; i++) {
        worker_threads_.emplace_back([this, i]() {
            worker_thread(i);
        });
    }

    // Wait for all workers to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    worker_threads_.clear();
    return 0;
}

void TcpListener::stop() {
    running_.store(false);

    // Stop all event loops
    std::lock_guard<std::mutex> lock(event_loops_mutex_);
    for (auto* event_loop : event_loops_) {
        if (event_loop) {
            event_loop->stop();
        }
    }
}

bool TcpListener::is_running() const {
    return running_.load();
}

void TcpListener::worker_thread(int worker_id) {
    LOG_INFO("TCP", "Worker %d starting", worker_id);

    // Create event loop for this worker
    auto event_loop = create_event_loop();
    if (!event_loop) {
        LOG_ERROR("TCP", "Worker %d: Failed to create event loop", worker_id);
        return;
    }

    LOG_INFO("TCP", "Worker %d: Using %s event loop", worker_id, event_loop->platform_name());

    // Register event loop for shutdown
    {
        std::lock_guard<std::mutex> lock(event_loops_mutex_);
        event_loops_.push_back(event_loop.get());
    }

    // Create listen socket
    int listen_fd = create_listen_socket();
    if (listen_fd < 0) {
        LOG_ERROR("TCP", "Worker %d: Failed to create listen socket: %s", worker_id, strerror(errno));
        return;
    }

    LOG_INFO("TCP", "Worker %d: Listening on fd %d", worker_id, listen_fd);

    // Accept handler
    auto accept_handler = [this, event_loop = event_loop.get()](int fd, IOEvent events, void* user_data) {
        LOG_DEBUG("TCP", "accept_handler called fd=%d events=%d", fd, static_cast<int>(events));

        if (!(events & IOEvent::READ)) {
            LOG_DEBUG("TCP", "Not a READ event, returning");
            return;
        }

        // Accept all pending connections (edge-triggered)
        while (true) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            // Accept directly without wrapping listen fd
            int client_fd = static_cast<int>(::accept(fd, (struct sockaddr*)&client_addr, &addr_len));

            if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No more connections
                    LOG_DEBUG("TCP", "No more connections to accept");
                    break;
                }
                LOG_ERROR("TCP", "Accept error: %s", strerror(errno));
                continue;
            }

            LOG_DEBUG("TCP", "Accepted connection client_fd=%d", client_fd);

            // Wrap client fd in TcpSocket
            TcpSocket socket(client_fd);

            // Call connection callback
            LOG_DEBUG("TCP", "Calling connection callback for fd=%d", client_fd);
            connection_cb_(std::move(socket), event_loop);
            LOG_DEBUG("TCP", "Connection callback returned for fd=%d", client_fd);
        }
    };

    // Add listen socket to event loop
    if (event_loop->add_fd(listen_fd, IOEvent::READ | IOEvent::EDGE, accept_handler, nullptr) < 0) {
        LOG_ERROR("TCP", "Worker %d: Failed to add listen socket to event loop: %s", worker_id, strerror(errno));
        sys::close_socket(listen_fd);
        return;
    }

    // Run event loop
    LOG_INFO("TCP", "Worker %d: Running event loop", worker_id);
    event_loop->run();

    // Cleanup
    event_loop->remove_fd(listen_fd);
    sys::close_socket(listen_fd);

    LOG_INFO("TCP", "Worker %d stopped", worker_id);
}

int TcpListener::create_listen_socket() {
    TcpSocket socket;

    if (!socket.is_valid()) {
        return -1;
    }

    // Set socket options
    if (socket.set_reuseaddr() < 0) {
        LOG_ERROR("TCP", "Failed to set SO_REUSEADDR: %s", strerror(errno));
        return -1;
    }

    // Set SO_REUSEPORT if enabled (allows multiple processes/threads to bind to same port)
    if (config_.use_reuseport) {
        if (socket.set_reuseport() < 0) {
            // SO_REUSEPORT might not be available, continue anyway
            LOG_WARN("TCP", "Failed to set SO_REUSEPORT: %s", strerror(errno));
        }
    }

    // Set non-blocking
    if (socket.set_nonblocking() < 0) {
        LOG_ERROR("TCP", "Failed to set non-blocking: %s", strerror(errno));
        return -1;
    }

    // Bind
    if (socket.bind(config_.host, config_.port) < 0) {
        LOG_ERROR("TCP", "Failed to bind to %s:%d: %s", config_.host.c_str(), config_.port, strerror(errno));
        return -1;
    }

    // Listen
    if (socket.listen(config_.backlog) < 0) {
        LOG_ERROR("TCP", "Failed to listen: %s", strerror(errno));
        return -1;
    }

    // Release ownership and return fd
    return socket.release();
}

} // namespace net
} // namespace bolt::api
