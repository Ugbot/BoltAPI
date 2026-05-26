// boltapi/http/dispatch_task.h — coroutine task whose frame is arena-backed.
//
// A near-clone of `core::coro_task<T>` with one critical difference: the
// promise_type has `operator new` / `operator delete` that draw the coroutine
// frame from `FrameArenaPool` (see http/frame_arena.h) instead of `::operator
// new`. That kills the per-request ~3840-byte dispatch coroutine frame
// allocation that the alloc gate (`tests/dispatch_alloc_test.cpp`) flagged.
//
// Used ONLY by `App::dispatch_coro_` (and the HTTP/3 / H1/H2 awaiters that
// drive it). Other coroutine sites stay on `core::coro_task<T>` — touching
// that general-purpose type would route every accept/read/write coroutine
// through the same 256-arena pool and exhaust it under load.
//
// Allocation layout: each frame is prefixed with a header that stores the
// `FrameArena*` it was carved from (or nullptr on a heap fallback when the
// pool is exhausted / the frame is too big for an arena). `operator delete`
// reads the header and either releases the arena or `::operator delete`s the
// heap allocation. Range-check via `frame_pool_owns` distinguishes the two.
//
// TigerStyle: bounded (the pool has a fixed 256 arenas of 8 KiB each); no
// hidden growth; the heap fallback is the only escape valve and is documented.

#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/http/frame_arena.h"

#include <cassert>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <new>
#include <type_traits>
#include <utility>

namespace bolt::api::http {

// Header prepended to every dispatch_task frame. Stores which arena (if any)
// the frame was carved from, so `operator delete` knows how to reclaim. Aligned
// to max_align_t so the returned pointer (header_size after the raw start)
// satisfies all alignment requirements for the coroutine frame.
struct alignas(std::max_align_t) DispatchFrameHeader {
    FrameArena* arena;  // nullptr → heap fallback (use ::operator delete on raw)
};
static_assert(sizeof(DispatchFrameHeader) % alignof(std::max_align_t) == 0,
              "DispatchFrameHeader must be a multiple of max_align");
inline constexpr std::size_t kDispatchHeaderSize = sizeof(DispatchFrameHeader);

// dispatch_task<T> — same surface as core::coro_task<T> for awaiter/release/done,
// so co_await sites are drop-in.
template <typename T>
class dispatch_task {
public:
    struct promise_type {
        alignas(T) unsigned char value_storage_[sizeof(T)];
        alignas(std::exception_ptr) unsigned char exception_storage_[sizeof(std::exception_ptr)];
        bool has_value_ = false;
        bool has_exception_ = false;
        std::coroutine_handle<> continuation_;

        T& value() { return *reinterpret_cast<T*>(value_storage_); }
        std::exception_ptr& exception() {
            return *reinterpret_cast<std::exception_ptr*>(exception_storage_);
        }

        dispatch_task get_return_object() {
            return dispatch_task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept { return {}; }

        struct final_awaiter {
            bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_type> h) noexcept {
                auto& promise = h.promise();
                if (promise.continuation_) {
                    return promise.continuation_;  // resume parent (same as coro_task<T>)
                }
                return std::noop_coroutine();
            }
            void await_resume() noexcept {}
        };
        final_awaiter final_suspend() noexcept { return {}; }

        void return_value(T&& val) noexcept(std::is_nothrow_move_constructible_v<T>) {
            new (value_storage_) T(std::move(val));
            has_value_ = true;
        }
        void return_value(const T& val) noexcept(std::is_nothrow_copy_constructible_v<T>) {
            new (value_storage_) T(val);
            has_value_ = true;
        }
        void unhandled_exception() noexcept {
#ifdef __cpp_exceptions
            new (exception_storage_) std::exception_ptr(std::current_exception());
            has_exception_ = true;
#else
            std::cerr << "FATAL: dispatch_task unhandled exception" << std::endl;
            std::abort();
#endif
        }

        ~promise_type() {
            if (has_value_) value().~T();
            if (has_exception_) exception().~exception_ptr();
        }

        // ----- Arena-backed frame allocation -----
        //
        // The coroutine compiler calls promise_type::operator new(size_t) to
        // allocate the entire coroutine frame (promise + locals + bookkeeping).
        // We prefix it with a DispatchFrameHeader holding the FrameArena*, then
        // return a pointer past the header. operator delete walks back to the
        // header to reclaim.
        //
        // Heap fallback: pool exhausted or frame too big for an arena → store
        // arena=nullptr in the header and use ::operator new for the alloc;
        // operator delete spots arena==nullptr and ::operator delete's it.
        static void* operator new(std::size_t n) noexcept {
            const std::size_t total = n + kDispatchHeaderSize;
            FrameArena* arena = frame_pool_acquire();
            if (arena != nullptr) {
                void* raw = arena->allocate(total);
                if (raw != nullptr) {
                    auto* hdr = static_cast<DispatchFrameHeader*>(raw);
                    hdr->arena = arena;
                    return static_cast<char*>(raw) + kDispatchHeaderSize;
                }
                // Frame too big for an arena slot — return the arena, fall to heap.
                frame_pool_release(arena);
            }
            // Heap fallback. Mark header arena=nullptr so delete knows.
            void* raw = ::operator new(total, std::nothrow);
            if (raw == nullptr) return nullptr;
            auto* hdr = static_cast<DispatchFrameHeader*>(raw);
            hdr->arena = nullptr;
            return static_cast<char*>(raw) + kDispatchHeaderSize;
        }

        static void operator delete(void* p) noexcept {
            if (p == nullptr) return;
            void* raw = static_cast<char*>(p) - kDispatchHeaderSize;
            auto* hdr = static_cast<DispatchFrameHeader*>(raw);
            if (hdr->arena != nullptr) {
                // Arena-backed: return the arena to the pool (reset wipes the
                // bump offset; the frame's storage is logically free).
                frame_pool_release(hdr->arena);
            } else {
                // Heap fallback (pool was exhausted).
                ::operator delete(raw);
            }
        }
    };

    struct awaiter {
        std::coroutine_handle<promise_type> handle_;
        bool await_ready() const noexcept { return handle_.done(); }
        std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
            handle_.promise().continuation_ = awaiting;
            return handle_;
        }
        T await_resume() {
            auto& promise = handle_.promise();
            if (promise.has_exception_) {
                std::cerr << "FATAL: dispatch_task has exception (-fno-exceptions)" << std::endl;
                std::abort();
            }
            if (!promise.has_value_) {
                std::cerr << "FATAL: dispatch_task has no value" << std::endl;
                std::abort();
            }
            return std::move(promise.value());
        }
    };

    awaiter operator co_await() && { return awaiter{handle_}; }

    explicit dispatch_task(std::coroutine_handle<promise_type> h) noexcept
        : handle_(h) {}
    dispatch_task(dispatch_task&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    dispatch_task& operator=(dispatch_task&& other) noexcept {
        if (this != &other) {
            if (handle_) handle_.destroy();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    dispatch_task(const dispatch_task&) = delete;
    dispatch_task& operator=(const dispatch_task&) = delete;

    ~dispatch_task() {
        if (handle_) handle_.destroy();
    }

    explicit operator bool() const noexcept { return handle_ != nullptr; }
    bool done() const noexcept { return handle_ && handle_.done(); }
    std::coroutine_handle<promise_type> release() noexcept {
        return std::exchange(handle_, nullptr);
    }
    bool resume() {
        if (!handle_ || handle_.done()) return false;
        handle_.resume();
        return !handle_.done();
    }

private:
    std::coroutine_handle<promise_type> handle_;
};

}  // namespace bolt::api::http
