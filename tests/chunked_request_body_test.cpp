// Transfer-Encoding: chunked request bodies and Expect: 100-continue (G2ICE-215).
//
// The AWS C++ SDK (pyarrow 25) sends S3 UploadPart as a chunked request and
// waits for "100 Continue". The parser used to report such a request complete
// with an EMPTY body and leave the framing on the socket.
//
// Plain main(): returns 0 on success, 1 on failure. No gtest.

#include "boltapi/http/http1_parser.h"
#include "boltapi/server/coro_unified_server.h"
#include "boltapi/net/sys_compat.h"

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

using bolt::api::http::CoroHttpRequest;
using bolt::api::http::CoroHttpResponse;
using bolt::api::http::CoroUnifiedServer;
using bolt::api::http::CoroUnifiedServerConfig;
using bolt::api::http::HTTP1Parser;
using bolt::api::http::HTTP1Request;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 18797;
int g_failures = 0;

void check(bool cond, const char* what) {
    std::fprintf(stderr, "[chunked] %s %s\n", cond ? "ok:  " : "FAIL:", what);
    if (!cond) ++g_failures;
}

uint64_t fnv(std::string_view s) {
    uint64_t h = 1469598103934665603ull;
    for (const char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

std::string digest(std::string_view s) {
    return "LEN:" + std::to_string(s.size()) + ":SUM:" + std::to_string(fnv(s));
}

std::string chunked(const std::string& body, size_t chunk, const char* trailer) {
    std::string out;
    char hex[32];
    for (size_t off = 0; off < body.size(); off += chunk) {
        const size_t n = std::min(chunk, body.size() - off);
        std::snprintf(hex, sizeof(hex), "%zx;ext=1\r\n", n);
        out += hex;
        out.append(body, off, n);
        out += "\r\n";
    }
    out += "0\r\n";
    out += trailer;
    out += "\r\n";
    return out;
}

int connect_client() {
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return -1;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return -1;
    }
    // A missing 100 Continue must fail the check, not hang the test.
#if defined(_WIN32)
    DWORD tv = 5000;
#else
    timeval tv{5, 0};
#endif
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv),
                 sizeof(tv));
    return fd;
}

void send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        const ssize_t n = sys::send_bytes(fd, s.data() + off, s.size() - off);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

std::string read_until_close(int fd) {
    std::string out;
    char buf[4096];
    for (int i = 0; i < 100000; ++i) {
        const ssize_t n = sys::recv_bytes(fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

std::string round_trip(const std::string& request) {
    const int fd = connect_client();
    if (fd < 0) return {};
    send_all(fd, request);
    std::string out = read_until_close(fd);
    sys::close_socket(fd);
    return out;
}

std::string post_head(const char* extra) {
    return std::string("POST /d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n") +
           extra;
}

void parser_unit() {
    size_t n = 0;
    const std::string ok = "3\r\nabc\r\n0\r\nx-amz-checksum: z\r\n\r\nNEXT";
    auto u = [](const std::string& s) {
        return reinterpret_cast<const uint8_t*>(s.data());
    };
    check(HTTP1Parser::scan_chunked(u(ok), ok.size(), &n) == 0 &&
              n == ok.size() - 4, "scan: complete body with trailer, stops before NEXT");
    for (size_t cut = 0; cut < ok.size() - 4; ++cut) {
        if (HTTP1Parser::scan_chunked(u(ok), cut, &n) != -1) {
            check(false, "scan: every strict prefix is incomplete");
            break;
        }
    }
    const std::string bad_crlf = "3\r\nabcX\r\n0\r\n\r\n";
    check(HTTP1Parser::scan_chunked(u(bad_crlf), bad_crlf.size(), &n) == 1,
          "scan: chunk data not followed by CRLF is malformed");
    const std::string bad_hex = "zz\r\n";
    check(HTTP1Parser::scan_chunked(u(bad_hex), bad_hex.size(), &n) == 1,
          "scan: non-hex size is malformed");
    const std::string huge = "11111111111111111\r\n";
    check(HTTP1Parser::scan_chunked(u(huge), huge.size(), &n) == 1,
          "scan: 17-digit size is malformed");
    std::string dec = ok;
    const size_t m = HTTP1Parser::dechunk_in_place(
        reinterpret_cast<uint8_t*>(dec.data()), ok.size() - 4);
    check(m == 3 && dec.compare(0, 3, "abc") == 0, "dechunk: in place");

    const std::string both = "PUT /p HTTP/1.1\r\nContent-Length: 3\r\n"
                             "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    HTTP1Parser p;
    HTTP1Request r;
    size_t consumed = 0;
    check(p.parse(u(both), both.size(), r, consumed) == 1,
          "parse: Content-Length together with chunked is refused");
}

}  // namespace

int main() {
    sys::startup();
#if !defined(_WIN32)
    std::signal(SIGPIPE, SIG_IGN);
#endif
    parser_unit();

    CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_http1_cleartext = true;
    config.http1_port = kPort;
    config.host = "127.0.0.1";
    config.num_io_threads = 1;
    config.num_workers = 2;
    config.enable_signal_handlers = false;
    config.max_body_size = 8u * 1024u * 1024u;

    CoroUnifiedServer server(config);
    server.set_handler([](const CoroHttpRequest& req)
                           -> bolt::api::http::dispatch_task<CoroHttpResponse> {
        CoroHttpResponse resp;
        resp.status = 200;
        resp.status_message = "OK";
        resp.headers["Content-Type"] = "text/plain";
        resp.body = digest(req.body);
        co_return resp;
    });
    if (server.start_background() != 0) {
        std::fprintf(stderr, "[chunked] FAIL: server did not start\n");
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    {
        const std::string body = "hello world";
        const std::string r = round_trip(
            post_head("Transfer-Encoding: chunked\r\n\r\n") +
            chunked(body, 5, "x-amz-checksum-crc64nvme: AAAA\r\n"));
        check(r.find(" 200 ") != std::string::npos &&
                  r.find(digest(body)) != std::string::npos,
              "small chunked body with extensions and trailer is decoded");
    }
    {
        std::string body(3u * 1024u * 1024u + 17u, '\0');
        for (size_t i = 0; i < body.size(); ++i) {
            body[i] = static_cast<char>((i * 131u) ^ (i >> 7));
        }
        const std::string r = round_trip(
            post_head("Transfer-Encoding: chunked\r\n\r\n") +
            chunked(body, 16384, ""));
        check(r.find(digest(body)) != std::string::npos,
              "3 MB chunked body grows the buffer and arrives intact");
    }
    {
        const std::string body(9u * 1024u * 1024u, 'x');
        const std::string r = round_trip(
            post_head("Transfer-Encoding: chunked\r\n\r\n") +
            chunked(body, 1u << 20, ""));
        check(r.find(" 413 ") != std::string::npos,
              "chunked body over max_body_size is refused with 413");
    }
    {
        const std::string r = round_trip(
            post_head("Transfer-Encoding: chunked\r\n\r\n") +
            "3\r\nabcX\r\n0\r\n\r\n");
        check(r.find(" 400 ") != std::string::npos, "malformed chunk -> 400");
    }
    {
        // Pipelined: chunked request then a second request on one connection.
        const std::string two =
            std::string("POST /d HTTP/1.1\r\nHost: x\r\n"
                        "Transfer-Encoding: chunked\r\n\r\n") +
            chunked("first", 2, "") + post_head("Content-Length: 6\r\n\r\n") +
            "second";
        const std::string r = round_trip(two);
        check(r.find(digest("first")) != std::string::npos &&
                  r.find(digest("second")) != std::string::npos,
              "pipelined request after a chunked one is parsed");
    }
    {
        // Expect: 100-continue: the interim response must arrive BEFORE the
        // body is sent, for both framings.
        for (const char* framing : {"Content-Length: 4\r\n",
                                    "Transfer-Encoding: chunked\r\n"}) {
            const int fd = connect_client();
            check(fd >= 0, "connect for 100-continue");
            if (fd < 0) continue;
            send_all(fd, post_head(framing) + "Expect: 100-continue\r\n\r\n");
            char buf[256] = {};
            const ssize_t n = sys::recv_bytes(fd, buf, sizeof(buf) - 1);
            check(n > 0 && std::strncmp(buf, "HTTP/1.1 100 Continue\r\n\r\n", 25) == 0,
                  "100 Continue sent before the body");
            const bool is_chunked = std::strstr(framing, "chunked") != nullptr;
            send_all(fd, is_chunked ? chunked("data", 3, "") : std::string("data"));
            const std::string r = read_until_close(fd);
            sys::close_socket(fd);
            check(r.find(digest("data")) != std::string::npos,
                  "body after 100 Continue is delivered");
        }
    }

    server.stop();
    if (g_failures == 0) {
        std::fprintf(stderr, "[chunked] SUCCESS\n");
        return 0;
    }
    std::fprintf(stderr, "[chunked] FAILURE: %d check(s)\n", g_failures);
    return 1;
}
