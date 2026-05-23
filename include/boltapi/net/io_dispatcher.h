// I/O Dispatcher - Bridges async I/O callbacks to coroutine awaitables
//
// Provides a Seastar-inspired model:
// - 1-2 event loop threads dispatch I/O events
// - N worker threads (from WorkerThreadPool) execute coroutines
// - Coroutines yield on I/O, worker threads pick up other work
//
// Design:
// - async_io (kqueue/epoll/io_uring) handles the actual I/O
// - IODispatcher provides awaitable wrappers
// - When I/O completes, coroutine is submitted to worker pool

#pragma once

#include "boltapi/core/async_io.h"
#include "boltapi/core/coro_task.h"
#include "boltapi/core/worker_pool.h"
#include <atomic>
#include <coroutine>
#include <memory>
#include <thread>
#include <vector>

namespace bolt::api {
namespace net {

// Forward declarations
class IODispatcher;

// =============================================================================
// Awaitable I/O Operations
// =============================================================================

/// Awaitable for async read operations
class ReadAwaitable {
public:
    ReadAwaitable(IODispatcher* dispatcher, int fd, void* buf, size_t len) noexcept
        : dispatcher_(dispatcher), fd_(fd), buf_(buf), len_(len) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    ssize_t await_resume() const noexcept { return result_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int fd_;
    void* buf_;
    size_t len_;
    ssize_t result_ = 0;
};

/// Awaitable for async write operations
class WriteAwaitable {
public:
    WriteAwaitable(IODispatcher* dispatcher, int fd, const void* buf, size_t len) noexcept
        : dispatcher_(dispatcher), fd_(fd), buf_(buf), len_(len) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    ssize_t await_resume() const noexcept { return result_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int fd_;
    const void* buf_;
    size_t len_;
    ssize_t result_ = 0;
};

/// Awaitable for async datagram receive (UDP recvfrom).
///
/// The awaitable OWNS the peer-address out-params it forwards to the backend:
/// `src`/`srclen` point at caller storage that MUST outlive the co_await (the
/// awaitable is a temporary that lives across the suspension point, so passing
/// pointers to caller-stack/long-lived storage is correct). On resume, the
/// caller reads the filled-in src/srclen plus the byte count.
class RecvFromAwaitable {
public:
    RecvFromAwaitable(IODispatcher* dispatcher, int fd, void* buf, size_t len,
                      struct sockaddr* src, socklen_t* srclen) noexcept
        : dispatcher_(dispatcher), fd_(fd), buf_(buf), len_(len),
          src_(src), srclen_(srclen) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    ssize_t await_resume() const noexcept { return result_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int fd_;
    void* buf_;
    size_t len_;
    struct sockaddr* src_;
    socklen_t* srclen_;
    ssize_t result_ = 0;
};

/// Awaitable for async datagram send (UDP sendto).
class SendToAwaitable {
public:
    SendToAwaitable(IODispatcher* dispatcher, int fd, const void* buf, size_t len,
                    const struct sockaddr* dst, socklen_t dstlen) noexcept
        : dispatcher_(dispatcher), fd_(fd), buf_(buf), len_(len),
          dst_(dst), dstlen_(dstlen) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    ssize_t await_resume() const noexcept { return result_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int fd_;
    const void* buf_;
    size_t len_;
    const struct sockaddr* dst_;
    socklen_t dstlen_;
    ssize_t result_ = 0;
};

/// Awaitable for async accept operations
class AcceptAwaitable {
public:
    AcceptAwaitable(IODispatcher* dispatcher, int listen_fd) noexcept
        : dispatcher_(dispatcher), listen_fd_(listen_fd) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    int await_resume() const noexcept { return result_fd_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int listen_fd_;
    int result_fd_ = -1;
};

/// Awaitable for async connect operations
class ConnectAwaitable {
public:
    ConnectAwaitable(IODispatcher* dispatcher, int fd,
                     const struct sockaddr* addr, socklen_t addrlen) noexcept
        : dispatcher_(dispatcher), fd_(fd), addr_(addr), addrlen_(addrlen) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept;
    int await_resume() const noexcept { return result_; }

private:
    friend class IODispatcher;
    IODispatcher* dispatcher_;
    int fd_;
    const struct sockaddr* addr_;
    socklen_t addrlen_;
    int result_ = 0;
};

// =============================================================================
// I/O Dispatcher
// =============================================================================

/// Configuration for IODispatcher
struct IODispatcherConfig {
    size_t num_io_threads = 1;        // Number of event loop threads (1-2 recommended)
    core::async_io_config io_config;  // Configuration for async_io backend
    core::WorkerThreadPool* worker_pool = nullptr;  // Worker pool for coroutine execution
};

/// I/O Dispatcher - bridges async I/O to coroutines
class IODispatcher {
public:
    /// Create dispatcher with configuration
    explicit IODispatcher(const IODispatcherConfig& config);

    /// Create dispatcher with worker pool (uses defaults for rest)
    explicit IODispatcher(core::WorkerThreadPool* pool);

    ~IODispatcher();

    // Non-copyable, non-movable
    IODispatcher(const IODispatcher&) = delete;
    IODispatcher& operator=(const IODispatcher&) = delete;

    /// Start the I/O dispatcher threads
    void start();

    /// Stop the dispatcher (waits for threads to finish)
    void stop();

    /// Check if running
    bool is_running() const noexcept {
        return running_.load(std::memory_order_relaxed);
    }

    // =========================================================================
    // Awaitable I/O Operations
    // =========================================================================

    /// Async read - returns awaitable
    /// @param fd File descriptor to read from
    /// @param buf Buffer to read into
    /// @param len Maximum bytes to read
    /// @return Awaitable that yields bytes read, or -1 on error
    ReadAwaitable async_read(int fd, void* buf, size_t len) noexcept {
        return ReadAwaitable(this, fd, buf, len);
    }

    /// Async write - returns awaitable
    /// @param fd File descriptor to write to
    /// @param buf Buffer to write from
    /// @param len Bytes to write
    /// @return Awaitable that yields bytes written, or -1 on error
    WriteAwaitable async_write(int fd, const void* buf, size_t len) noexcept {
        return WriteAwaitable(this, fd, buf, len);
    }

    /// Async accept - returns awaitable
    /// @param listen_fd Listening socket file descriptor
    /// @return Awaitable that yields accepted fd, or -1 on error
    AcceptAwaitable async_accept(int listen_fd) noexcept {
        return AcceptAwaitable(this, listen_fd);
    }

    /// Async connect - returns awaitable
    /// @param fd Socket file descriptor
    /// @param addr Address to connect to
    /// @param addrlen Address length
    /// @return Awaitable that yields 0 on success, -1 on error
    ConnectAwaitable async_connect(int fd, const struct sockaddr* addr, socklen_t addrlen) noexcept {
        return ConnectAwaitable(this, fd, addr, addrlen);
    }

    /// Async datagram receive (UDP) - returns awaitable.
    /// @param fd Datagram socket file descriptor
    /// @param buf Buffer to receive into
    /// @param len Buffer capacity
    /// @param src [out] peer address (filled on completion); must outlive co_await
    /// @param srclen [in/out] capacity on entry, actual peer-addr length on exit
    /// @return Awaitable that yields bytes received, or -1 on error
    RecvFromAwaitable async_recvfrom(int fd, void* buf, size_t len,
                                     struct sockaddr* src, socklen_t* srclen) noexcept {
        return RecvFromAwaitable(this, fd, buf, len, src, srclen);
    }

    /// Async datagram send (UDP) - returns awaitable.
    /// @param fd Datagram socket file descriptor
    /// @param buf Buffer to send from
    /// @param len Bytes to send
    /// @param dst Destination address
    /// @param dstlen Destination address length
    /// @return Awaitable that yields bytes sent, or -1 on error
    SendToAwaitable async_sendto(int fd, const void* buf, size_t len,
                                 const struct sockaddr* dst, socklen_t dstlen) noexcept {
        return SendToAwaitable(this, fd, buf, len, dst, dstlen);
    }

    /// Close a file descriptor asynchronously
    void async_close(int fd) noexcept;

    // =========================================================================
    // Coroutine-style wrappers (return coro_task)
    // =========================================================================

    /// Read as coroutine task
    core::coro_task<ssize_t> read(int fd, void* buf, size_t len);

    /// Write as coroutine task
    core::coro_task<ssize_t> write(int fd, const void* buf, size_t len);

    /// Accept as coroutine task
    core::coro_task<int> accept(int listen_fd);

    /// Connect as coroutine task
    core::coro_task<int> connect(int fd, const struct sockaddr* addr, socklen_t addrlen);

    // =========================================================================
    // Access to underlying infrastructure
    // =========================================================================

    /// Get the async_io engine (for advanced use)
    core::async_io* io_engine() noexcept { return io_.get(); }

    /// Get the worker pool
    core::WorkerThreadPool* worker_pool() noexcept { return worker_pool_; }

    /// Get number of I/O threads
    size_t num_io_threads() const noexcept { return io_threads_.size(); }

    // =========================================================================
    // Statistics
    // =========================================================================

    struct Stats {
        uint64_t reads_started;
        uint64_t reads_completed;
        uint64_t writes_started;
        uint64_t writes_completed;
        uint64_t accepts_started;
        uint64_t accepts_completed;
        uint64_t connects_started;
        uint64_t connects_completed;
    };

    Stats get_stats() const noexcept;

private:
    friend class ReadAwaitable;
    friend class WriteAwaitable;
    friend class AcceptAwaitable;
    friend class ConnectAwaitable;
    friend class RecvFromAwaitable;
    friend class SendToAwaitable;

    void io_thread_loop(size_t thread_id);

    // Submit coroutine to worker pool for resumption
    void resume_on_worker(std::coroutine_handle<> handle) noexcept;

    IODispatcherConfig config_;
    std::unique_ptr<core::async_io> io_;
    core::WorkerThreadPool* worker_pool_;
    bool owns_worker_pool_ = false;  // Did we create the pool?

    std::vector<std::thread> io_threads_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};

    // Stats
    alignas(core::kCacheLineSize) std::atomic<uint64_t> reads_started_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> reads_completed_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> writes_started_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> writes_completed_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> accepts_started_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> accepts_completed_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> connects_started_{0};
    alignas(core::kCacheLineSize) std::atomic<uint64_t> connects_completed_{0};
};

// =============================================================================
// Global IODispatcher Access
// =============================================================================

/// Get the global I/O dispatcher instance
IODispatcher& global_io_dispatcher();

/// Initialize global I/O dispatcher with worker pool
/// Must be called before using async operations
void init_global_io_dispatcher(core::WorkerThreadPool* pool);

/// Initialize global I/O dispatcher with full config
void init_global_io_dispatcher(const IODispatcherConfig& config);

} // namespace net
} // namespace bolt::api
