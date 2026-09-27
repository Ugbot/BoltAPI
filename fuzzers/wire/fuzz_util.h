// fuzz_util.h — shared helpers for the wire-protocol harnesses.
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define FUZZ_CHECK(cond)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "FUZZ_CHECK failed: %s at %s:%d\n", #cond,   \
                         __FILE__, __LINE__);                                \
            std::abort();                                                    \
        }                                                                    \
    } while (0)

namespace boltapi_fuzz {

// Bounded cursor over the fuzz input: reads past the end yield zeros.
struct Input {
    const std::uint8_t* p;
    std::size_t n;
    std::size_t off = 0;

    Input(const std::uint8_t* data, std::size_t size) noexcept : p(data), n(size) {
        assert(data != nullptr || size == 0);
    }
    bool empty() const noexcept { return off >= n; }
    std::size_t left() const noexcept { return n - off; }
    std::uint8_t u8() noexcept { return off < n ? p[off++] : 0; }
    std::uint16_t u16() noexcept {
        const std::uint16_t hi = u8();
        return static_cast<std::uint16_t>((hi << 8) | u8());
    }
    std::uint32_t u32() noexcept {
        const std::uint32_t hi = u16();
        return (hi << 16) | u16();
    }
    // Up to `max` bytes (fewer at the end of input).
    const std::uint8_t* take(std::size_t want, std::size_t* got) noexcept {
        assert(got != nullptr);
        const std::size_t k = want < left() ? want : left();
        const std::uint8_t* at = p + off;
        off += k;
        *got = k;
        assert(off <= n);
        return at;
    }
};

#if !defined(_WIN32)
// Serve `data` as one client connection: `serve(fd)` runs on this thread
// against a socketpair whose peer writes the input, half-closes, and drains
// every reply until the server side closes.
template <typename Serve>
void run_session(const std::uint8_t* data, std::size_t size, Serve&& serve) {
    assert(data != nullptr || size == 0);
    static const bool sigpipe_ignored = [] {
        ::signal(SIGPIPE, SIG_IGN);
        return true;
    }();
    (void)sigpipe_ignored;
    int sv[2] = {-1, -1};
    FUZZ_CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    const int client = sv[0];
    const int server = sv[1];
    std::thread writer([client, data, size] {
        std::size_t sent = 0;
        while (sent < size) {   // bounded by size: every pass sends >= 1 byte
            const ssize_t w = ::send(client, data + sent, size - sent, 0);
            if (w <= 0) break;
            sent += static_cast<std::size_t>(w);
        }
        ::shutdown(client, SHUT_WR);
    });
    std::thread reader([client] {
        char sink[16384];
        for (;;) {   // ends when the server side closes
            const ssize_t r = ::recv(client, sink, sizeof(sink), 0);
            if (r <= 0) break;
        }
    });
    serve(server);
    ::close(server);   // EOF for the reader, EPIPE for a blocked writer
    writer.join();
    reader.join();
    ::close(client);
}
#endif

}  // namespace boltapi_fuzz
