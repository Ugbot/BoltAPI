/**
 * epoll-based async I/O implementation (Linux)
 * 
 * High-performance async I/O using epoll.
 */

#include "boltapi/core/async_io.h"

#ifdef __linux__

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <vector>
#include <unordered_map>
#include <memory>
#include <atomic>
#include <mutex>
#include <cstring>

namespace bolt::api {
namespace core {

/**
 * Pending I/O operation
 */
struct pending_op {
    io_op operation;
    int fd;
    io_callback callback;
    void* user_data;
    
    // For read/write
    void* buffer{nullptr};
    size_t size{0};
    
    // For connect
    struct sockaddr_storage addr;
    socklen_t addrlen{0};
    
    // Event flags
    uint32_t events{0};
};

/**
 * epoll implementation
 */
struct epoll_io::impl {
    int epoll_fd{-1};
    int wake_fd{-1};
    async_io_config config;

    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};

    // Wake mechanism
    async_io::wake_callback wake_cb;
    std::atomic<bool> wake_pending{false};

    // Pending operations indexed by FD
    std::mutex ops_mutex;
    std::unordered_map<int, std::unique_ptr<pending_op>> pending_ops;

    // Statistics
    std::atomic<uint64_t> stat_accepts{0};
    std::atomic<uint64_t> stat_reads{0};
    std::atomic<uint64_t> stat_writes{0};
    std::atomic<uint64_t> stat_connects{0};
    std::atomic<uint64_t> stat_closes{0};
    std::atomic<uint64_t> stat_polls{0};
    std::atomic<uint64_t> stat_events{0};
    std::atomic<uint64_t> stat_errors{0};
    std::atomic<uint64_t> stat_wakes{0};

    impl(const async_io_config& cfg) : config(cfg) {
        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd < 0) {
            // Handle error
        }

        // Create eventfd for wake mechanism
        wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (wake_fd >= 0) {
            // Register wake_fd with epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET;  // Edge-triggered
            ev.data.fd = wake_fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &ev);
        }
    }
    
    ~impl() {
        if (wake_fd >= 0) {
            close(wake_fd);
        }
        if (epoll_fd >= 0) {
            close(epoll_fd);
        }
    }
    
    int set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) return -1;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    int register_op(std::unique_ptr<pending_op> op, uint32_t events) {
        std::lock_guard<std::mutex> lock(ops_mutex);
        
        op->events = events;
        
        // Add epoll event
        struct epoll_event ev;
        ev.events = events | EPOLLET | EPOLLONESHOT;  // Edge-triggered, one-shot
        ev.data.fd = op->fd;
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, op->fd, &ev) < 0) {
            // Try MOD if ADD fails (fd already registered)
            if (errno == EEXIST) {
                if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, op->fd, &ev) < 0) {
                    stat_errors.fetch_add(1, std::memory_order_relaxed);
                    return -1;
                }
            } else {
                stat_errors.fetch_add(1, std::memory_order_relaxed);
                return -1;
            }
        }
        
        // Store operation
        pending_ops[op->fd] = std::move(op);
        return 0;
    }
    
    pending_op* find_and_remove_op(int fd) {
        std::lock_guard<std::mutex> lock(ops_mutex);
        
        auto it = pending_ops.find(fd);
        if (it == pending_ops.end()) {
            return nullptr;
        }
        
        pending_op* op = it->second.release();
        pending_ops.erase(it);
        return op;
    }
};

epoll_io::epoll_io(const async_io_config& config)
    : impl_(std::make_unique<impl>(config)) {
}

epoll_io::~epoll_io() {
    stop();
}

int epoll_io::accept_async(
    int listen_fd,
    io_callback callback,
    void* user_data
) noexcept {
    impl_->set_nonblocking(listen_fd);
    
    auto op = std::make_unique<pending_op>();
    op->operation = io_op::accept;
    op->fd = listen_fd;
    op->callback = std::move(callback);
    op->user_data = user_data;
    
    impl_->stat_accepts.fetch_add(1, std::memory_order_relaxed);
    return impl_->register_op(std::move(op), EPOLLIN);
}

int epoll_io::read_async(
    int fd,
    void* buffer,
    size_t size,
    io_callback callback,
    void* user_data
) noexcept {
    impl_->set_nonblocking(fd);
    
    auto op = std::make_unique<pending_op>();
    op->operation = io_op::read;
    op->fd = fd;
    op->buffer = buffer;
    op->size = size;
    op->callback = std::move(callback);
    op->user_data = user_data;
    
    impl_->stat_reads.fetch_add(1, std::memory_order_relaxed);
    return impl_->register_op(std::move(op), EPOLLIN);
}

int epoll_io::write_async(
    int fd,
    const void* buffer,
    size_t size,
    io_callback callback,
    void* user_data
) noexcept {
    impl_->set_nonblocking(fd);
    
    auto op = std::make_unique<pending_op>();
    op->operation = io_op::write;
    op->fd = fd;
    op->buffer = const_cast<void*>(buffer);
    op->size = size;
    op->callback = std::move(callback);
    op->user_data = user_data;
    
    impl_->stat_writes.fetch_add(1, std::memory_order_relaxed);
    return impl_->register_op(std::move(op), EPOLLOUT);
}

int epoll_io::connect_async(
    int fd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    io_callback callback,
    void* user_data
) noexcept {
    impl_->set_nonblocking(fd);
    
    auto op = std::make_unique<pending_op>();
    op->operation = io_op::connect;
    op->fd = fd;
    op->callback = std::move(callback);
    op->user_data = user_data;
    memcpy(&op->addr, addr, addrlen);
    op->addrlen = addrlen;
    
    // Start connection
    int ret = connect(fd, addr, addrlen);
    if (ret < 0 && errno != EINPROGRESS) {
        impl_->stat_errors.fetch_add(1, std::memory_order_relaxed);
        return -1;
    }
    
    impl_->stat_connects.fetch_add(1, std::memory_order_relaxed);
    return impl_->register_op(std::move(op), EPOLLOUT);
}

int epoll_io::close_async(int fd) noexcept {
    // Remove from epoll
    epoll_ctl(impl_->epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    
    impl_->stat_closes.fetch_add(1, std::memory_order_relaxed);
    return close(fd);
}

int epoll_io::poll(uint32_t timeout_us) noexcept {
    if (impl_->epoll_fd < 0) return -1;
    
    impl_->stat_polls.fetch_add(1, std::memory_order_relaxed);
    
    struct epoll_event events[128];
    int timeout_ms = timeout_us / 1000;
    
    int n = epoll_wait(impl_->epoll_fd, events, 128, timeout_ms);
    if (n < 0) {
        if (errno != EINTR) {
            impl_->stat_errors.fetch_add(1, std::memory_order_relaxed);
        }
        return -1;
    }
    
    impl_->stat_events.fetch_add(n, std::memory_order_relaxed);
    
    // Process events
    for (int i = 0; i < n; ++i) {
        const struct epoll_event& ev = events[i];
        int fd = ev.data.fd;

        // Check for wake event (eventfd)
        if (fd == impl_->wake_fd) {
            impl_->stat_wakes.fetch_add(1, std::memory_order_relaxed);
            impl_->wake_pending.store(false, std::memory_order_release);

            // Read from eventfd to clear it
            uint64_t val;
            read(impl_->wake_fd, &val, sizeof(val));

            // Invoke wake callback
            if (impl_->wake_cb) {
                impl_->wake_cb();
            }
            continue;
        }

        // Find and remove pending operation
        pending_op* op = impl_->find_and_remove_op(fd);
        if (!op) continue;
        
        std::unique_ptr<pending_op> op_guard(op);
        
        // Execute operation
        io_event event;
        event.operation = op->operation;
        event.fd = op->fd;
        event.user_data = op->user_data;
        event.flags = ev.events;
        event.result = 0;
        
        // Check for errors
        if (ev.events & (EPOLLERR | EPOLLHUP)) {
            event.result = -1;
        } else {
            switch (op->operation) {
                case io_op::accept: {
                    struct sockaddr_storage addr;
                    socklen_t addrlen = sizeof(addr);
                    int client_fd = accept(op->fd, (struct sockaddr*)&addr, &addrlen);
                    event.result = client_fd;
                    break;
                }
                
                case io_op::read: {
                    ssize_t bytes = read(op->fd, op->buffer, op->size);
                    event.result = bytes;
                    break;
                }
                
                case io_op::write: {
                    ssize_t bytes = write(op->fd, op->buffer, op->size);
                    event.result = bytes;
                    break;
                }
                
                case io_op::connect: {
                    // Check for connection error
                    int error = 0;
                    socklen_t len = sizeof(error);
                    getsockopt(op->fd, SOL_SOCKET, SO_ERROR, &error, &len);
                    event.result = error == 0 ? 0 : -1;
                    break;
                }
                
                default:
                    break;
            }
        }
        
        // Invoke callback
        if (op->callback) {
            op->callback(event);
        }
    }
    
    return n;
}

void epoll_io::run() noexcept {
    if (impl_->running.exchange(true)) {
        return;  // Already running
    }
    
    impl_->stop_requested.store(false);
    
    while (!impl_->stop_requested.load(std::memory_order_acquire)) {
        poll(impl_->config.poll_timeout_us);
    }
    
    impl_->running.store(false);
}

void epoll_io::stop() noexcept {
    impl_->stop_requested.store(true, std::memory_order_release);
}

bool epoll_io::is_running() const noexcept {
    return impl_->running.load(std::memory_order_acquire);
}

async_io::stats epoll_io::get_stats() const noexcept {
    stats s;
    s.accepts = impl_->stat_accepts.load(std::memory_order_relaxed);
    s.reads = impl_->stat_reads.load(std::memory_order_relaxed);
    s.writes = impl_->stat_writes.load(std::memory_order_relaxed);
    s.connects = impl_->stat_connects.load(std::memory_order_relaxed);
    s.closes = impl_->stat_closes.load(std::memory_order_relaxed);
    s.polls = impl_->stat_polls.load(std::memory_order_relaxed);
    s.events = impl_->stat_events.load(std::memory_order_relaxed);
    s.errors = impl_->stat_errors.load(std::memory_order_relaxed);
    s.wakes = impl_->stat_wakes.load(std::memory_order_relaxed);
    return s;
}

void epoll_io::wake() noexcept {
    // Thread-safe wake using eventfd
    // Only trigger if not already pending (avoid redundant wakes)
    bool expected = false;
    if (impl_->wake_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (impl_->wake_fd >= 0) {
            uint64_t val = 1;
            write(impl_->wake_fd, &val, sizeof(val));
        }
    }
}

void epoll_io::set_wake_callback(wake_callback callback) noexcept {
    impl_->wake_cb = std::move(callback);
}

} // namespace core
} // namespace bolt::api

#endif // __linux__









