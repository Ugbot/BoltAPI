// query_param_test.cpp — regression gate for Request::query_param() on HTTP/1.
//
// Background: the HTTP/1 parser strips '?...' from the URL before path
// capture, so Request::query()/query_param() used to return empty even when a
// query string was present. The fix is to carry the parsed query through on
// CoroHttpRequest::query and read from it in Request::query().
//
// This test spins a real App on an ephemeral cleartext HTTP/1.1 port, registers
// GET /echo that joins query_param("foo") + "|" + query_param("bar"), and
// verifies:
//   1. GET /echo?foo=hello&bar=world  -> body "hello|world"
//   2. GET /echo                       -> body "|" (both empty, no crash)
//   3. GET /echo?foo=hi                -> body "hi|" (missing key returns "")
//
// Pattern mirrors tests/app_integration_test.cpp (raw socket client +
// Content-Length parsing); no new harness.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19219;  // distinct from other tests in the suite

std::string header_value_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");
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

struct HttpResponse {
    int status = 0;
    std::string headers_block;
    std::string body;
    bool ok = false;
};

HttpResponse do_request(const std::string& raw) {
    HttpResponse out;
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

    for (;;) {
        if (header_end != std::string::npos) {
            const std::size_t have_body = buf.size() - (header_end + 4);
            if (content_length >= 0 &&
                have_body >= static_cast<std::size_t>(content_length)) {
                break;
            }
            if (content_length < 0) break;
        }
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers_block = buf.substr(0, header_end);
                std::string cl = header_value_ci(out.headers_block, "Content-Length");
                if (!cl.empty()) {
                    content_length = std::stoll(cl);
                }
            }
        }
        if (buf.size() > (1u << 20)) break;
    }

    sys::close_socket(fd);

    if (header_end == std::string::npos) return out;
    {
        const std::string& h = out.headers_block;
        std::size_t sp1 = h.find(' ');
        if (sp1 != std::string::npos) {
            out.status = std::atoi(h.c_str() + sp1 + 1);
        }
    }
    out.body = buf.substr(header_end + 4);
    if (content_length >= 0 &&
        out.body.size() > static_cast<std::size_t>(content_length)) {
        out.body.resize(static_cast<std::size_t>(content_length));
    }
    out.ok = true;
    return out;
}

std::string make_get(const std::string& target) {
    std::string r;
    r += "GET ";
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    return r;
}

class QueryParam : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();
        app_->get("/echo", [](api::Request& req, api::Response& res) {
            std::string foo = req.query_param("foo");
            std::string bar = req.query_param("bar");
            res.ok().text(foo + "|" + bar);
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

api::App* QueryParam::app_ = nullptr;

TEST_F(QueryParam, BothParamsPresent) {
    HttpResponse r = do_request(make_get("/echo?foo=hello&bar=world"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "hello|world");
}

TEST_F(QueryParam, NoQueryString) {
    HttpResponse r = do_request(make_get("/echo"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "|");
}

TEST_F(QueryParam, OnlyOneParamPresent) {
    HttpResponse r = do_request(make_get("/echo?foo=hi"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "hi|");
}

TEST_F(QueryParam, ParamsInReverseOrder) {
    HttpResponse r = do_request(make_get("/echo?bar=B&foo=A"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "A|B");
}

}  // namespace
