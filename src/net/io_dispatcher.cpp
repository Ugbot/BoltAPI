// I/O Dispatcher Implementation
//
// Bridges async I/O callbacks to coroutine awaitables using the
// worker thread pool architecture.

#include "boltapi/net/io_dispatcher.h"
#include <mutex>
#include <iostream>

namespace bolt::api {
namespace net {

// =============================================================================
// Awaitable Implementations
// =============================================================================

void ReadAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->reads_started_.fetch_add(1, std::memory_order_relaxed);

    // Capture state for callback
    ReadAwaitable* self = this;

    // Submit async read to the I/O engine
    int rc = dispatcher_->io_->read_async(
        fd_, buf_, len_,
        [self, handle](const core::io_event& event) {
            // Store result
            self->result_ = event.result;
            self->dispatcher_->reads_completed_.fetch_add(1, std::memory_order_relaxed);

            // Resume coroutine on worker thread
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        // Error submitting - set error result and resume immediately
        result_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

void WriteAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->writes_started_.fetch_add(1, std::memory_order_relaxed);

    WriteAwaitable* self = this;

    int rc = dispatcher_->io_->write_async(
        fd_, buf_, len_,
        [self, handle](const core::io_event& event) {
            self->result_ = event.result;
            self->dispatcher_->writes_completed_.fetch_add(1, std::memory_order_relaxed);
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        result_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

void RecvFromAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->reads_started_.fetch_add(1, std::memory_order_relaxed);

    RecvFromAwaitable* self = this;

    // Forward the caller-owned peer-address out-params straight to the backend.
    // They (and `buf_`) must outlive the op — the awaitable temporary lives
    // across the suspension point, and the caller guarantees `src_`/`srclen_`
    // storage outlives the co_await.
    int rc = dispatcher_->io_->recvfrom_async(
        fd_, buf_, len_, src_, srclen_,
        [self, handle](const core::io_event& event) {
            self->result_ = event.result;
            self->dispatcher_->reads_completed_.fetch_add(1, std::memory_order_relaxed);
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        result_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

void SendToAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->writes_started_.fetch_add(1, std::memory_order_relaxed);

    SendToAwaitable* self = this;

    int rc = dispatcher_->io_->sendto_async(
        fd_, buf_, len_, dst_, dstlen_,
        [self, handle](const core::io_event& event) {
            self->result_ = event.result;
            self->dispatcher_->writes_completed_.fetch_add(1, std::memory_order_relaxed);
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        result_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

void AcceptAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->accepts_started_.fetch_add(1, std::memory_order_relaxed);

    AcceptAwaitable* self = this;

    int rc = dispatcher_->io_->accept_async(
        listen_fd_,
        [self, handle](const core::io_event& event) {
            self->result_fd_ = static_cast<int>(event.result);
            self->dispatcher_->accepts_completed_.fetch_add(1, std::memory_order_relaxed);
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        result_fd_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

void ConnectAwaitable::await_suspend(std::coroutine_handle<> handle) noexcept {
    dispatcher_->connects_started_.fetch_add(1, std::memory_order_relaxed);

    ConnectAwaitable* self = this;

    int rc = dispatcher_->io_->connect_async(
        fd_, addr_, addrlen_,
        [self, handle](const core::io_event& event) {
            self->result_ = static_cast<int>(event.result);
            self->dispatcher_->connects_completed_.fetch_add(1, std::memory_order_relaxed);
            self->dispatcher_->resume_on_worker(handle);
        },
        nullptr
    );

    if (rc != 0) {
        result_ = -1;
        dispatcher_->resume_on_worker(handle);
    }
}

// =============================================================================
// IODispatcher Implementation
// =============================================================================

IODispatcher::IODispatcher(const IODispatcherConfig& config)
    : config_(config)
    , worker_pool_(config.worker_pool) {

    // Create async I/O engine
    io_ = core::async_io::create(config_.io_config);

    // If no worker pool provided, create one
    if (!worker_pool_) {
        owns_worker_pool_ = true;
        // Worker pool will be created and started in start()
    }

    // Ensure at least 1 I/O thread
    if (config_.num_io_threads == 0) {
        config_.num_io_threads = 1;
    }
}

IODispatcher::IODispatcher(core::WorkerThreadPool* pool)
    : IODispatcher(IODispatcherConfig{.worker_pool = pool}) {}

IODispatcher::~IODispatcher() {
    stop();

    if (owns_worker_pool_ && worker_pool_) {
        delete worker_pool_;
    }
}

void IODispatcher::start() {
    if (running_.exchange(true)) {
        return;  // Already running
    }

    shutdown_requested_.store(false, std::memory_order_relaxed);

    // Create worker pool if needed
    if (owns_worker_pool_ && !worker_pool_) {
        auto* pool = new core::WorkerThreadPool(core::WorkerPoolConfig{});
        pool->start();
        worker_pool_ = pool;
    }

    // Start I/O threads
    io_threads_.reserve(config_.num_io_threads);
    for (size_t i = 0; i < config_.num_io_threads; ++i) {
        io_threads_.emplace_back(&IODispatcher::io_thread_loop, this, i);
    }

    std::cout << "IODispatcher started with " << config_.num_io_threads
              << " I/O thread(s) and "
              << (worker_pool_ ? worker_pool_->num_workers() : 0)
              << " worker threads" << std::endl;
}

void IODispatcher::stop() {
    if (!running_.exchange(false)) {
        return;  // Not running
    }

    shutdown_requested_.store(true, std::memory_order_release);

    // Stop the async I/O engine (this will wake any blocked poll())
    if (io_) {
        io_->stop();
    }

    // Join I/O threads
    for (auto& t : io_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    io_threads_.clear();

    // Stop worker pool if we own it
    if (owns_worker_pool_ && worker_pool_) {
        worker_pool_->stop();
    }

    std::cout << "IODispatcher stopped" << std::endl;
}

void IODispatcher::io_thread_loop(size_t thread_id) {
    std::cout << "IODispatcher I/O thread " << thread_id << " started" << std::endl;

    while (!shutdown_requested_.load(std::memory_order_acquire)) {
        // Poll for I/O events with timeout
        // 1ms timeout to check shutdown periodically without burning CPU
        io_->poll(1000);  // 1000 microseconds = 1ms
    }

    // Final drain of pending events
    io_->poll(0);

    std::cout << "IODispatcher I/O thread " << thread_id << " stopped" << std::endl;
}

void IODispatcher::resume_on_worker(std::coroutine_handle<> handle) noexcept {
    if (!handle || handle.done()) {
        return;
    }

    // Inline resume (default): run the coroutine on THIS event-loop thread up to
    // its next co_await — no per-request worker handoff. This is the hot path; the
    // coroutine suspends back to the poll loop at its next async op, so the stack is
    // bounded (no recursion). The worker pool is used only when inline_resume is
    // disabled (handlers that do blocking work inline).
    if (config_.inline_resume || worker_pool_ == nullptr) {
        handle.resume();
        return;
    }

    // Worker-pool handoff (opt-out path): submit; block-spin only if the queue is full.
    if (!worker_pool_->submit(handle)) {
        worker_pool_->submit_wait(handle);
    }
}

void IODispatcher::async_close(int fd) noexcept {
    if (io_) {
        io_->close_async(fd);
    }
}

// =============================================================================
// Coroutine Task Wrappers
// =============================================================================

core::coro_task<ssize_t> IODispatcher::read(int fd, void* buf, size_t len) {
    ssize_t result = co_await async_read(fd, buf, len);
    co_return result;
}

core::coro_task<ssize_t> IODispatcher::write(int fd, const void* buf, size_t len) {
    ssize_t result = co_await async_write(fd, buf, len);
    co_return result;
}

core::coro_task<int> IODispatcher::accept(int listen_fd) {
    int result = co_await async_accept(listen_fd);
    co_return result;
}

core::coro_task<int> IODispatcher::connect(int fd, const struct sockaddr* addr, socklen_t addrlen) {
    int result = co_await async_connect(fd, addr, addrlen);
    co_return result;
}

// =============================================================================
// Statistics
// =============================================================================

IODispatcher::Stats IODispatcher::get_stats() const noexcept {
    return Stats{
        .reads_started = reads_started_.load(std::memory_order_relaxed),
        .reads_completed = reads_completed_.load(std::memory_order_relaxed),
        .writes_started = writes_started_.load(std::memory_order_relaxed),
        .writes_completed = writes_completed_.load(std::memory_order_relaxed),
        .accepts_started = accepts_started_.load(std::memory_order_relaxed),
        .accepts_completed = accepts_completed_.load(std::memory_order_relaxed),
        .connects_started = connects_started_.load(std::memory_order_relaxed),
        .connects_completed = connects_completed_.load(std::memory_order_relaxed),
    };
}

// =============================================================================
// Global Instance
// =============================================================================

static std::unique_ptr<IODispatcher> g_io_dispatcher;
static std::once_flag g_io_dispatcher_init_flag;

IODispatcher& global_io_dispatcher() {
    std::call_once(g_io_dispatcher_init_flag, []() {
        if (!g_io_dispatcher) {
            // Create with default config and global worker pool
            g_io_dispatcher = std::make_unique<IODispatcher>(
                &core::global_worker_pool()
            );
            g_io_dispatcher->start();
        }
    });
    return *g_io_dispatcher;
}

void init_global_io_dispatcher(core::WorkerThreadPool* pool) {
    std::call_once(g_io_dispatcher_init_flag, [pool]() {
        g_io_dispatcher = std::make_unique<IODispatcher>(pool);
        g_io_dispatcher->start();
    });
}

void init_global_io_dispatcher(const IODispatcherConfig& config) {
    std::call_once(g_io_dispatcher_init_flag, [&config]() {
        g_io_dispatcher = std::make_unique<IODispatcher>(config);
        g_io_dispatcher->start();
    });
}

} // namespace net
} // namespace bolt::api
