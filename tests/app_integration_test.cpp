// app_integration_test.cpp — gtest integration coverage for bolt::api::App.
//
// Spins a REAL App on an ephemeral cleartext HTTP/1.1 port (background threads)
// and drives it with a raw client socket. Exercises:
//   * multiple routes: static, '{param}', and a trailing '*' wildcard
//   * multiple verbs: GET / POST / PUT / DELETE / HEAD
//   * path-param extraction (/users/{id}, /users/{id}/posts/{pid})
//   * request-body echo on POST/PUT (randomized via tests/util/http_fuzz.h)
//   * 404 on an unregistered path
//   * the Response fluent surface (status / headers / json / text)
//   * randomized fuzz inputs hitting registered routes -> dispatch correctness
//
// The client parses Content-Length so it reads exactly one full response even
// on keep-alive (no reliance on Connection: close). HEAD responses carry the
// header but no body, which the client honors.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"
#include "util/http_fuzz.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace core = bolt::api::core;
namespace sys  = bolt::api::net::sys;
namespace bt   = boltapi::test;

namespace {

constexpr uint16_t kPort = 19211;  // high, unlikely-busy port for this suite

// ---------------------------------------------------------------------------
// Minimal blocking HTTP/1.1 client. Sends `raw`, reads one complete response
// (headers + Content-Length body). Returns the full response text or "".
// ---------------------------------------------------------------------------
struct HttpResponse {
    int status = 0;
    std::string headers_block;  // raw header bytes (incl request line)
    std::string body;
    bool ok = false;
};

std::string header_value_ci(const std::string& headers, const char* name) {
    // Case-insensitive search line-wise for "name:".
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

HttpResponse do_request(const std::string& raw, bool is_head) {
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
        // Stop once we have full headers + the declared body.
        if (header_end != std::string::npos) {
            const std::size_t have_body = buf.size() - (header_end + 4);
            if (is_head) break;  // HEAD: no body regardless of CL
            if (content_length >= 0 &&
                have_body >= static_cast<std::size_t>(content_length)) {
                break;
            }
            if (content_length < 0) break;  // no CL and headers done -> done
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
        if (buf.size() > (1u << 20)) break;  // safety cap
    }

    sys::close_socket(fd);

    if (header_end == std::string::npos) return out;
    // Parse status code from the status line: "HTTP/1.1 <code> <reason>".
    {
        const std::string& h = out.headers_block;
        std::size_t sp1 = h.find(' ');
        if (sp1 != std::string::npos) {
            out.status = std::atoi(h.c_str() + sp1 + 1);
        }
    }
    if (!is_head) {
        out.body = buf.substr(header_end + 4);
        if (content_length >= 0 &&
            out.body.size() > static_cast<std::size_t>(content_length)) {
            out.body.resize(static_cast<std::size_t>(content_length));
        }
    }
    out.ok = true;
    return out;
}

std::string make_request(const char* method, const std::string& target,
                         const std::string& body = {}) {
    std::string r;
    r += method;
    r += ' ';
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: ";
    r += std::to_string(body.size());
    r += "\r\n\r\n";
    r += body;
    return r;
}

// ---------------------------------------------------------------------------
// Test fixture: builds an App with a representative route table, runs it on a
// background thread for the whole suite.
// ---------------------------------------------------------------------------
class AppIntegration : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();

        // Static routes across verbs.
        app_->get("/health", [](api::Request&, api::Response& res) {
            res.ok().text("UP");
        });
        app_->post("/echo", [](api::Request& req, api::Response& res) {
            // Echo the body back as JSON-ish wrapper to exercise json().
            res.created().json(std::string(req.body()));
        });
        app_->put("/items", [](api::Request& req, api::Response& res) {
            res.ok().header("X-Verb", "PUT").send(std::string(req.body()));
        });
        app_->del("/items", [](api::Request&, api::Response& res) {
            res.no_content();
        });
        app_->head("/health", [](api::Request&, api::Response& res) {
            // HEAD: set headers/status; body suppressed on the wire by client.
            res.ok().header("X-Health", "ok").text("UP");
        });

        // Param routes.
        app_->get("/users/{id}", [](api::Request& req, api::Response& res) {
            res.ok().json(std::string("{\"id\":\"") +
                          req.path_param("id") + "\"}");
        });
        app_->get("/users/{id}/posts/{pid}",
                  [](api::Request& req, api::Response& res) {
            res.ok().json(std::string("{\"id\":\"") + req.path_param("id") +
                          "\",\"pid\":\"" + req.path_param("pid") + "\"}");
        });

        // Async param route (exercises the async handler path).
        app_->post_async("/users/{id}/notes",
            [](api::Request& req, api::Response& res)
                -> core::coro_task<void> {
                res.created().json(std::string("{\"id\":\"") +
                                   req.path_param("id") + "\",\"note\":\"" +
                                   std::string(req.body()) + "\"}");
                co_return;
            });

        // Wildcard route (static files style).
        app_->get("/files/*", [](api::Request& req, api::Response& res) {
            res.ok().text(std::string(req.path_param_view("*")));
        });

        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        // Allow the accept loop to bind/listen.
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

api::App* AppIntegration::app_ = nullptr;

// ---------------------------------------------------------------------------
TEST_F(AppIntegration, StaticGet) {
    HttpResponse r = do_request(make_request("GET", "/health"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "UP");
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Type"),
              "text/plain; charset=utf-8");
}

TEST_F(AppIntegration, PostBodyEchoAsJson) {
    const std::string payload = "{\"k\":\"value-1234\"}";
    HttpResponse r = do_request(make_request("POST", "/echo", payload), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 201);  // created()
    EXPECT_EQ(r.body, payload);
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Type"),
              "application/json");
}

TEST_F(AppIntegration, PutWithHeaderAndBody) {
    const std::string payload = "item-payload-xyz";
    HttpResponse r = do_request(make_request("PUT", "/items", payload), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, payload);
    EXPECT_EQ(header_value_ci(r.headers_block, "X-Verb"), "PUT");
}

TEST_F(AppIntegration, DeleteNoContent) {
    HttpResponse r = do_request(make_request("DELETE", "/items"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 204);
    EXPECT_TRUE(r.body.empty());
}

TEST_F(AppIntegration, HeadHasHeadersNoBody) {
    HttpResponse r = do_request(make_request("HEAD", "/health"), true);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(header_value_ci(r.headers_block, "X-Health"), "ok");
    EXPECT_TRUE(r.body.empty());
}

TEST_F(AppIntegration, SinglePathParam) {
    HttpResponse r = do_request(make_request("GET", "/users/42"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "{\"id\":\"42\"}");
}

TEST_F(AppIntegration, MultiPathParam) {
    HttpResponse r = do_request(make_request("GET", "/users/7/posts/99"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "{\"id\":\"7\",\"pid\":\"99\"}");
}

TEST_F(AppIntegration, AsyncParamRoutePost) {
    HttpResponse r =
        do_request(make_request("POST", "/users/55/notes", "hello"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 201);
    EXPECT_EQ(r.body, "{\"id\":\"55\",\"note\":\"hello\"}");
}

TEST_F(AppIntegration, WildcardCapturesTail) {
    HttpResponse r = do_request(make_request("GET", "/files/a/b/c.txt"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "a/b/c.txt");
}

TEST_F(AppIntegration, QueryStringIgnoredForRouting) {
    HttpResponse r = do_request(make_request("GET", "/users/13?expand=true"),
                                false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "{\"id\":\"13\"}");
}

TEST_F(AppIntegration, UnknownPathIs404) {
    HttpResponse r = do_request(make_request("GET", "/does/not/exist"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 404);
}

TEST_F(AppIntegration, WrongMethodIs404) {
    // /health is GET/HEAD only; POST must not match.
    HttpResponse r = do_request(make_request("POST", "/health", "x"), false);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 404);
}

// ---------------------------------------------------------------------------
// Randomized driver: build requests with the seeded fuzz body generator and
// fire them at registered routes, asserting dispatch correctness. We use the
// fuzz RNG to vary the param value AND the POST body, hitting GET /users/{id}
// and POST /users/{id}/notes across many seeds.
// ---------------------------------------------------------------------------
TEST_F(AppIntegration, RandomizedRoutedRequests) {
    bt::FuzzRng rng{0xB017C0DEu};
    constexpr int kIters = 80;
    int ok_get = 0, ok_post = 0;

    for (int i = 0; i < kIters; ++i) {
        // Numeric-ish id from the RNG (URL-safe; single segment).
        const std::string id = std::to_string(rng.in_range(1, 1000000));

        // GET /users/{id} -> echoes id back in JSON.
        {
            HttpResponse r =
                do_request(make_request("GET", "/users/" + id), false);
            ASSERT_TRUE(r.ok) << "iter " << i;
            EXPECT_EQ(r.status, 200);
            const std::string expect = "{\"id\":\"" + id + "\"}";
            EXPECT_EQ(r.body, expect);
            if (r.status == 200 && r.body == expect) ++ok_get;
        }

        // POST /users/{id}/notes with a randomized fuzz body.
        {
            bt::GeneratedRequest g = bt::generate_request(rng);
            // Use only a body-safe payload (no CRLF; fuzz body is printable).
            const std::string note = g.body;  // may be empty
            HttpResponse r = do_request(
                make_request("POST", "/users/" + id + "/notes", note), false);
            ASSERT_TRUE(r.ok) << "iter " << i;
            EXPECT_EQ(r.status, 201);
            const std::string expect =
                "{\"id\":\"" + id + "\",\"note\":\"" + note + "\"}";
            EXPECT_EQ(r.body, expect);
            if (r.status == 201 && r.body == expect) ++ok_post;
        }
    }

    EXPECT_EQ(ok_get, kIters);
    EXPECT_EQ(ok_post, kIters);
}

}  // namespace
