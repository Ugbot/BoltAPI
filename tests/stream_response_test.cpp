// stream_response_test.cpp — gtest coverage for App-level streaming responses
// (STATION-96: Response::stream / Transfer-Encoding: chunked incremental output).
//
// Spins a REAL App on an ephemeral cleartext HTTP/1.1 port (background threads)
// and drives it with a raw client socket. Proves:
//   * a BUFFERED route still returns byte-identical output (no regression)
//   * a STREAMING route emits Transfer-Encoding: chunked with NO Content-Length,
//     multiple chunk frames, and de-chunks to the exact expected payload
//   * an auth middleware that short-circuits (401) runs BEFORE the streaming
//     producer — no stream is started for an unauthorized request
//   * empty producer writes never emit a premature 0-length (terminating) chunk
//
// The client is chunked-aware: it reads until the terminating "0\r\n\r\n", so it
// exercises the real on-the-wire framing rather than a Content-Length read.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19244;  // high, unlikely-busy port for this suite

struct RawResponse {
    std::string headers_block;  // raw header bytes (excl the CRLFCRLF)
    std::string raw_body;       // everything after CRLFCRLF (still chunk-framed)
    int status = 0;
    bool ok = false;
};

std::string header_value_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");  // skip status line
    if (pos == std::string::npos) return {};
    pos += 2;
    while (pos < headers.size()) {
        std::size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (char& c : key) c = static_cast<char>(std::tolower((unsigned char)c));
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                std::size_t b = 0, e = val.size();
                while (b < e && (val[b] == ' ' || val[b] == '\t')) ++b;
                while (e > b && (val[e - 1] == ' ' || val[e - 1] == '\t')) --e;
                return val.substr(b, e - b);
            }
        }
        pos = eol + 2;
    }
    return {};
}

// Send `raw`, read the FULL response. For a chunked response, keep reading until
// the terminating "0\r\n\r\n" is seen; otherwise stop at Content-Length.
RawResponse do_request(const std::string& raw) {
    RawResponse out;
    sys::startup();

    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return out;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return out;
    }

    std::size_t sent = 0;
    while (sent < raw.size()) {
        ssize_t n = sys::send_bytes(fd, raw.data() + sent, raw.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }

    std::string buf;
    char tmp[4096];
    std::size_t header_end = std::string::npos;
    long long content_length = -1;
    bool chunked = false;

    for (;;) {
        if (header_end != std::string::npos) {
            if (chunked) {
                // Done when we've received the terminating zero-length chunk.
                if (buf.find("\r\n0\r\n\r\n", header_end) != std::string::npos ||
                    buf.compare(header_end + 4, 5, "0\r\n\r\n") == 0) {
                    break;
                }
            } else if (content_length >= 0) {
                const std::size_t have_body = buf.size() - (header_end + 4);
                if (have_body >= static_cast<std::size_t>(content_length)) break;
            } else {
                break;  // no CL, not chunked, headers done -> done
            }
        }
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers_block = buf.substr(0, header_end);
                std::string cl = header_value_ci(out.headers_block, "Content-Length");
                if (!cl.empty()) content_length = std::stoll(cl);
                std::string te = header_value_ci(out.headers_block, "Transfer-Encoding");
                for (char& c : te) c = static_cast<char>(std::tolower((unsigned char)c));
                if (te.find("chunked") != std::string::npos) chunked = true;
            }
        }
        if (buf.size() > (1u << 20)) break;  // safety cap
    }

    sys::close_socket(fd);
    if (header_end == std::string::npos) return out;

    const std::string& h = out.headers_block;
    std::size_t sp1 = h.find(' ');
    if (sp1 != std::string::npos) out.status = std::atoi(h.c_str() + sp1 + 1);
    out.raw_body = buf.substr(header_end + 4);
    out.ok = true;
    return out;
}

// De-chunk a Transfer-Encoding: chunked body. Also reports the number of
// non-terminating chunk frames seen (each frame == one producer write()).
std::string dechunk(const std::string& raw, int* frame_count) {
    std::string out;
    int frames = 0;
    std::size_t pos = 0;
    while (pos < raw.size()) {
        std::size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos) break;
        const std::string sz = raw.substr(pos, eol - pos);
        std::size_t len = 0;
        try {
            len = static_cast<std::size_t>(std::stoul(sz, nullptr, 16));
        } catch (...) {
            break;
        }
        pos = eol + 2;
        if (len == 0) break;  // terminating chunk
        if (pos + len > raw.size()) break;
        out.append(raw, pos, len);
        pos += len + 2;  // data + trailing CRLF
        ++frames;
    }
    if (frame_count) *frame_count = frames;
    return out;
}

std::string make_request(const char* method, const std::string& target,
                         bool authorized) {
    std::string r;
    r += method;
    r += ' ';
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n";
    if (authorized) r += "X-Test-Auth: ok\r\n";
    r += "Content-Length: 0\r\n\r\n";
    return r;
}

// ---------------------------------------------------------------------------
class StreamResponse : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();

        // Auth middleware: 401 unless the X-Test-Auth: ok header is present.
        // Proves auth runs (and can short-circuit) BEFORE the streaming producer.
        app_->use([](api::Request& req, api::Response& res,
                     std::function<void()> next) {
            if (req.header_view("X-Test-Auth") != "ok") {
                res.status(401).json("{\"error\":\"unauthorized\"}");
                return;  // short-circuit: handler/producer never runs
            }
            next();
        });

        // Buffered control route (must stay byte-identical).
        app_->get("/buf", [](api::Request&, api::Response& res) {
            res.ok().text("BUFFERED-OK");
        });

        // Streaming route: five content frames, each flushed as its own chunk.
        app_->get("/stream", [](api::Request&, api::Response& res) {
            res.stream("text/event-stream",
                       [](const api::Response::StreamSink& sink) {
                for (int i = 0; i < 5; ++i) {
                    sink("data: frame-" + std::to_string(i) + "\n\n");
                    sink("");  // empty write must be dropped (no 0-length chunk)
                }
                sink("data: [DONE]\n\n");
            });
        });

        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }

    static void TearDownTestSuite() {
        if (app_) {
            app_->stop();
            delete app_;
            app_ = nullptr;
        }
    }

    static api::App* app_;
};

api::App* StreamResponse::app_ = nullptr;

// Buffered route is unchanged: Content-Length, exact body, no chunking.
TEST_F(StreamResponse, BufferedRouteByteIdentical) {
    RawResponse r = do_request(make_request("GET", "/buf", true));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Length"), "11");
    EXPECT_TRUE(header_value_ci(r.headers_block, "Transfer-Encoding").empty());
    EXPECT_EQ(r.raw_body, "BUFFERED-OK");
}

// Streaming route: chunked, no Content-Length, multiple frames, exact payload.
TEST_F(StreamResponse, StreamsChunkedFrames) {
    RawResponse r = do_request(make_request("GET", "/stream", true));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Type"), "text/event-stream");
    EXPECT_EQ(header_value_ci(r.headers_block, "Transfer-Encoding"), "chunked");
    EXPECT_TRUE(header_value_ci(r.headers_block, "Content-Length").empty());

    int frames = 0;
    const std::string body = dechunk(r.raw_body, &frames);

    // Six non-empty writes -> six chunk frames (the five empty writes dropped).
    EXPECT_EQ(frames, 6);

    std::string expected;
    for (int i = 0; i < 5; ++i) expected += "data: frame-" + std::to_string(i) + "\n\n";
    expected += "data: [DONE]\n\n";
    EXPECT_EQ(body, expected);
}

// Auth middleware short-circuits before any stream is started.
TEST_F(StreamResponse, AuthShortCircuitsBeforeStream) {
    RawResponse r = do_request(make_request("GET", "/stream", false));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 401);
    // 401 is a normal buffered response: Content-Length, not chunked.
    EXPECT_TRUE(header_value_ci(r.headers_block, "Transfer-Encoding").empty());
    EXPECT_EQ(r.raw_body, "{\"error\":\"unauthorized\"}");
}

}  // namespace
