// http1_server.cpp — the whole cleartext connection loop of a real App
// (read / parse / pipeline / 100-continue / chunked bodies / dispatch /
// buffered and chunked responses / partial writes). Each input is one TCP
// connection: its bytes are written in fuzzer-sized pieces, the write side
// is shut, and the reply stream is read through a small receive buffer. The
// server must stay up, and every reply must be a well-framed HTTP/1.1
// response. A few inputs a crash in the server shows as a crash here.
//
// Input: byte 0 seeds the write splitter; the rest is the connection stream.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"
#include "fuzz_util.h"

#include <cerrno>
#include <cstdio>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr std::size_t kMaxReply = 8u << 20;
constexpr int kReadTimeoutMs = 3000;

uint16_t g_port = 0;

void start_server() {
    sys::startup();
    // One server per process; the port varies by pid so parallel jobs coexist.
    g_port = static_cast<uint16_t>(20000 + (::getpid() % 20000));
    api::App::Config cfg;
    cfg.server.max_body_size = 256 * 1024;
    cfg.server.request_timeout_ms = 2000;
    cfg.server.idle_timeout_ms = 2000;
    auto* app = new api::App(cfg);  // lives for the process
    app->post("/echo", [](api::Request& req, api::Response& res) { res.ok().text(req.body()); });
    app->get("/big", [](api::Request&, api::Response& res) {
        res.ok().text(std::string(200000, 'b'));
    });
    app->get("/chunked", [](api::Request&, api::Response& res) {
        res.ok().header("Transfer-Encoding", "chunked").text(std::string(40000, 'c'));
    });
    app->get("/", [](api::Request&, api::Response& res) { res.ok().text("root"); });
    if (app->start_background("127.0.0.1", g_port) != 0) std::abort();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

int new_socket() {
    const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    FUZZ_CHECK(fd >= 0);
    int rcv = 8 * 1024;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcv), sizeof(rcv));
    timeval tv{kReadTimeoutMs / 1000, (kReadTimeoutMs % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#if defined(SO_NOSIGPIPE)
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    return fd;
}

int connect_server() {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // Ephemeral ports run out at thousands of connections a second (each
    // spends 2*MSL in TIME_WAIT): wait for one rather than fail. A refused
    // connection means the listener is gone, which is a finding.
    int last_errno = 0;
    for (int attempt = 0; attempt < 6000; ++attempt) {  // <= 60 s
        const int fd = new_socket();
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) return fd;
        last_errno = errno;
        sys::close_socket(fd);
        if (last_errno == ECONNREFUSED && attempt > 100) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::fprintf(stderr, "connect failed: errno %d (%s)\n", last_errno, std::strerror(last_errno));
    FUZZ_CHECK(false && "server stopped accepting");
    return -1;
}

// Walks the reply stream: status line, fields, then a Content-Length or
// chunked body. Stops at the first incomplete message (the server may close
// mid-stream on a timeout); what it walks must be well-formed.
void check_replies(const std::string& r) {
    std::size_t pos = 0;
    for (std::size_t guard = 0; guard < 4096 && pos < r.size(); ++guard) {
        FUZZ_CHECK(r.compare(pos, 9, "HTTP/1.1 ") == 0 || r.size() - pos < 9);
        const std::size_t he = r.find("\r\n\r\n", pos);
        if (he == std::string::npos) return;
        const std::string head = r.substr(pos, he - pos);
        FUZZ_CHECK(head.size() >= 12);
        const int status = std::atoi(head.c_str() + 9);
        FUZZ_CHECK(status >= 100 && status <= 599);
        std::size_t body = he + 4;
        const bool chunked = head.find("Transfer-Encoding: chunked") != std::string::npos;
        const std::size_t cl = head.find("Content-Length: ");
        FUZZ_CHECK(!(chunked && cl != std::string::npos));
        if (status == 100) {
            pos = body;
            continue;
        }
        if (chunked) {
            for (std::size_t g = 0; g < r.size(); ++g) {
                const std::size_t eol = r.find("\r\n", body);
                if (eol == std::string::npos) return;
                const unsigned long n = std::strtoul(r.c_str() + body, nullptr, 16);
                if (eol + 2 + n + 2 > r.size()) return;
                FUZZ_CHECK(r.compare(eol + 2 + n, 2, "\r\n") == 0);
                body = eol + 2 + n + 2;
                if (n == 0) break;
            }
        } else if (cl != std::string::npos) {
            const unsigned long n = std::strtoul(head.c_str() + cl + 16, nullptr, 10);
            if (body + n > r.size()) return;
            body += n;
        }
        pos = body;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (g_port == 0) start_server();
    if (size < 1) return 0;
    boltapi_fuzz::Splitter split(data[0]);
    const int fd = connect_server();
    std::size_t off = 1;
    for (std::size_t g = 0; off < size && g < size; ++g) {
        const std::size_t n = split.chunk(size - off);
        const ssize_t w = sys::send_bytes(fd, data + off, n);
        if (w <= 0) break;  // server already closed (400 / 413 / 431)
        off += static_cast<std::size_t>(w);
    }
    ::shutdown(fd, SHUT_WR);
    std::string reply;
    char buf[4096];
    for (std::size_t g = 0; g < kMaxReply / 16; ++g) {
        const ssize_t n = sys::recv_bytes(fd, buf, sizeof(buf));
        if (n <= 0) break;
        reply.append(buf, static_cast<std::size_t>(n));
        if (reply.size() > kMaxReply) break;
    }
    linger lg{1, 0};  // RST on close: no TIME_WAIT to exhaust ephemeral ports
    ::setsockopt(fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
    sys::close_socket(fd);
    // An h2c preface switches the connection to HTTP/2 (h2_connection covers it).
    static constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const bool h2c = size - 1 >= sizeof(kPreface) - 1 &&
                     std::memcmp(data + 1, kPreface, sizeof(kPreface) - 1) == 0;
    if (!h2c) check_replies(reply);
    return 0;
}
