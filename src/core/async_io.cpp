/**
 * Async I/O - Factory and common implementation
 */

#include "boltapi/core/async_io.h"
#include <iostream>

namespace bolt::api {
namespace core {

std::unique_ptr<async_io> async_io::create(const async_io_config& config) {
    io_backend backend = config.backend;
    
    // Auto-detect best backend for platform
    if (backend == io_backend::auto_detect) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        backend = io_backend::kqueue;
#elif defined(__linux__)
        // Try io_uring first, fall back to epoll
        backend = io_backend::io_uring;  // TODO: Check kernel version
#elif defined(_WIN32)
        backend = io_backend::iocp;
#else
        std::cerr << "No async I/O backend available for this platform" << std::endl;
        return nullptr;
#endif
    }
    
    // Create backend-specific implementation
    switch (backend) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        case io_backend::kqueue:
            return std::make_unique<kqueue_io>(config);
#endif
            
#ifdef __linux__
        case io_backend::epoll:
            return std::make_unique<epoll_io>(config);
            
        case io_backend::io_uring:
            // TODO: Check if io_uring is available
            // Fall back to epoll if not
            return std::make_unique<epoll_io>(config);
#endif
            
#ifdef _WIN32
        case io_backend::iocp:
            return std::make_unique<iocp_io>(config);
#endif
            
        default:
            std::cerr << "Unsupported async I/O backend" << std::endl;
            return nullptr;
    }
}

} // namespace core
} // namespace bolt::api

