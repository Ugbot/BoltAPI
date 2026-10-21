// fixed_length_response_test.cpp — gtest coverage for the fixed-length
// (identity, NOT chunked) response paths: Response::send_borrowed / send_owned /
// send_fixed / content_length.
//
// Response::stream() forces Transfer-Encoding: chunked, which cannot carry a
// Content-Length — so it can serve neither a 206 Range reply (Content-Length +
// Content-Range are REQUIRED) nor a HEAD reply. These are the additive
// identity-framed alternatives, and this suite pins their wire format.
//
// Spins a REAL App on an ephemeral cleartext HTTP/1.1 port (background threads)
// and drives it with a raw client socket, so every assertion is about bytes that
// actually crossed a socket. Proves:
//   * send_borrowed  -> 200 + Content-Length + exact bytes, NO Transfer-Encoding
//   * send_borrowed  -> 206 + Content-Range + Content-Length == slice length
//   * send_fixed     -> identity streaming: Content-Length, NO chunk framing,
//                       exactly the declared byte count, for 200 AND 206
//   * content_length -> a HEAD reply declares a length with an EMPTY body
//   * a producer that OVER-produces is refused at the declared length (the
//     surplus never reaches the wire)
//   * a producer that UNDER-produces terminates the connection rather than
//     leave a short body under a declared length
//   * HTTP/1.1 keep-alive still works after a fixed-length response: a SECOND
//     request on the SAME connection is answered correctly
//   * the classic buffered + chunked-streaming paths are unchanged

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"
#include "../src/server/h1_fixed_stream_wait.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19277;  // distinct from the other socket suites
constexpr std::size_t kObjSize = 4096;
constexpr std::size_t kLargeSize = 8u * 1024u * 1024u;
std::atomic<unsigned> g_suppressed_fixed_calls{0}, g_suppressed_chunked_calls{0};
constexpr std::array<const char*, 5> kBodyShapes = {
    "buffered", "owned", "borrowed", "fixed", "chunked"};

void set_bodyless_shape(api::Response& res, std::size_t shape, uint16_t status) {
    res.status(status);
    switch (shape) {
    case 0: res.text("FORBIDDEN"); break;
    case 1: res.send_owned(std::string("FORBIDDEN")); break;
    case 2: res.send_borrowed("FORBIDDEN"); break;
    case 3:
        res.send_fixed(9, [](const api::Response::StreamSink& sink) {
            g_suppressed_fixed_calls.fetch_add(1);
            sink("FORBIDDEN");
        });
        break;
    case 4:
        res.stream("text/plain", [](const api::Response::StreamSink& sink) {
            g_suppressed_chunked_calls.fetch_add(1);
            sink("FORBIDDEN");
        });
        break;
    default: ADD_FAILURE() << "unknown body shape";
    }
    if (status == 204) {
        res.raw().headers.append("Content-Length", "999");
        res.raw().headers.append("content-length", "999");
        res.raw().headers.append("Transfer-Encoding", "chunked");
        res.raw().headers.append("transfer-encoding", "chunked");
    }
}

// Process-lifetime bytes: exactly the lifetime class send_borrowed requires
// (valid until well after the response is written).
std::string& object_bytes() {
    static std::string* obj = [] {
        auto* s = new std::string();
        s->reserve(kObjSize);
        for (std::size_t i = 0; i < kObjSize; ++i) {
            s->push_back(static_cast<char>('A' + (i % 26)));
        }
        return s;
    }();
    return *obj;
}

std::string header_value_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");  // skip status line
    if (pos == std::string::npos) return {};
    pos += 2;
    while (pos < headers.size()) {
        std::size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        const std::string line = headers.substr(pos, eol - pos);
        const std::size_t colon = line.find(':');
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

int connect_client(uint16_t port = kPort) {
    sys::startup();
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return -1;
    // Bound failed regressions: the old reactor path cannot answer the second
    // request until this timeout lets the first client start draining.
#ifdef _WIN32
    DWORD timeout = 3000;
#else
    timeval timeout{3, 0};
#endif
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
        sys::close_socket(fd);
        return -1;
    }
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return -1;
    }
    return fd;
}

bool send_all(int fd, const std::string& raw) {
    std::size_t sent = 0;
    while (sent < raw.size()) {
        ssize_t n = sys::send_bytes(fd, raw.data() + sent, raw.size() - sent);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

struct RawResponse {
    std::string headers_block;
    std::string body;
    int  status         = 0;
    long long declared  = -1;    // Content-Length as announced
    bool chunked        = false;
    bool ok             = false;  // a complete, well-framed response was read
    bool truncated      = false;  // peer closed before Content-Length was met
};

// Read ONE response off an already-connected socket. `carry` holds bytes read
// past the end of this response (pipelining / keep-alive) so the caller can read
// the next response from the same connection without losing data.
RawResponse read_one(int fd, std::string& carry, bool head_request = false) {
    RawResponse out;
    std::string buf = carry;
    carry.clear();
    char tmp[4096];
    std::size_t header_end = std::string::npos;
    bool peer_closed = false;

    for (;;) {
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers_block = buf.substr(0, header_end);
                const std::string cl = header_value_ci(out.headers_block, "Content-Length");
                if (!cl.empty()) out.declared = std::stoll(cl);
                std::string te = header_value_ci(out.headers_block, "Transfer-Encoding");
                for (char& c : te) c = static_cast<char>(std::tolower((unsigned char)c));
                out.chunked = te.find("chunked") != std::string::npos;
            }
        }
        if (header_end != std::string::npos) {
            // A HEAD reply carries no body regardless of Content-Length.
            const std::size_t want = (head_request || out.declared < 0)
                                         ? 0
                                         : static_cast<std::size_t>(out.declared);
            const std::size_t have = buf.size() - (header_end + 4);
            if (out.chunked) {
                if (buf.find("0\r\n\r\n", header_end + 4) != std::string::npos) break;
            } else if (have >= want) {
                break;
            }
        }
        if (peer_closed) break;
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) { peer_closed = true; continue; }
        buf.append(tmp, static_cast<std::size_t>(n));
        if (buf.size() > kLargeSize + (1u << 16)) break;  // safety cap
    }

    if (header_end == std::string::npos) return out;
    const std::size_t sp1 = out.headers_block.find(' ');
    if (sp1 != std::string::npos) {
        out.status = std::atoi(out.headers_block.c_str() + sp1 + 1);
    }
    const std::string rest = buf.substr(header_end + 4);
    if (!out.chunked && out.declared >= 0 && !head_request) {
        const std::size_t want = static_cast<std::size_t>(out.declared);
        if (rest.size() < want) {
            out.body      = rest;
            out.truncated = true;
            out.ok        = true;
            return out;
        }
        out.body = rest.substr(0, want);
        carry    = rest.substr(want);  // leftover belongs to the NEXT response
    } else {
        out.body = rest;
    }
    out.ok = true;
    return out;
}

std::string make_request(const char* method, const char* target, bool close_after) {
    std::string r;
    r += method;
    r += ' ';
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\n";
    r += close_after ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
    r += "Content-Length: 0\r\n\r\n";
    return r;
}

// One request on its own connection.
RawResponse do_request(const char* method, const char* target,
                       bool head_request = false, uint16_t port = kPort) {
    RawResponse out;
    const int fd = connect_client(port);
    if (fd < 0) return out;
    if (!send_all(fd, make_request(method, target, /*close_after=*/true))) {
        sys::close_socket(fd);
        return out;
    }
    std::string carry;
    out = read_one(fd, carry, head_request);
    sys::close_socket(fd);
    return out;
}

struct BodylessPair {
    std::string first_head;
    std::string next_wire;
    bool closed = false;
};

// Read ONLY the first headers, byte by byte. Any forbidden body or final chunk
// must remain in front of response 2; read_one(head_request) cannot prove this.
BodylessPair bodyless_then_get(const char* method, const char* target,
                              uint16_t port = kPort, const char* next = "/buf") {
    BodylessPair pair;
    const int fd = connect_client(port);
    if (fd < 0) return pair;
    bool ok = send_all(fd, make_request(method, target, false));
    char c = 0;
    for (unsigned i = 0; ok && i < (1u << 16); ++i) {
        ok = sys::recv_bytes(fd, &c, 1) == 1;
        if (!ok) break;
        pair.first_head += c;
        if (pair.first_head.ends_with("\r\n\r\n")) break;
    }
    ok = ok && pair.first_head.ends_with("\r\n\r\n") &&
        send_all(fd, make_request("GET", next, true));
    char buf[4096];
    for (unsigned i = 0; ok && i < 16; ++i) {
        const ssize_t n = sys::recv_bytes(fd, buf, sizeof(buf));
        if (n == 0) { pair.closed = true; break; }
        if (n < 0) break;
        pair.next_wire.append(buf, static_cast<std::size_t>(n));
    }
    sys::close_socket(fd);
    return pair;
}

void expect_bodyless_shapes(const char* method, uint16_t status) {
    const unsigned fixed_before = g_suppressed_fixed_calls.load();
    const unsigned chunked_before = g_suppressed_chunked_calls.load();
    for (std::size_t shape = 0; shape < kBodyShapes.size(); ++shape) {
        const std::string target = "/bodyless/" + std::to_string(status) + "/" + kBodyShapes[shape];
        SCOPED_TRACE(std::string(method) + " " + target);
        const BodylessPair pair = bodyless_then_get(method, target.c_str());
        ASSERT_TRUE(pair.closed);
        ASSERT_TRUE(pair.first_head.starts_with("HTTP/1.1 " + std::to_string(status) + " "));
        EXPECT_TRUE(header_value_ci(pair.first_head, "Transfer-Encoding").empty());
        EXPECT_EQ(header_value_ci(pair.first_head, "Content-Length"),
                  status == 204 || shape == 4 ? "" : "9");
        ASSERT_TRUE(pair.next_wire.starts_with("HTTP/1.1 200 OK\r\n")) << pair.next_wire;
        const std::size_t end = pair.next_wire.find("\r\n\r\n");
        ASSERT_NE(end, std::string::npos);
        EXPECT_EQ(header_value_ci(pair.next_wire.substr(0, end), "Content-Length"), "11");
        EXPECT_EQ(pair.next_wire.substr(end + 4), "BUFFERED-OK");
    }
    EXPECT_EQ(g_suppressed_fixed_calls.load(), fixed_before);
    EXPECT_EQ(g_suppressed_chunked_calls.load(), chunked_before);
}

// ---------------------------------------------------------------------------
class FixedLengthResponse : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();
        const std::string& obj = object_bytes();

        // Control: the classic buffered path must stay byte-identical.
        app_->get("/buf", [](api::Request&, api::Response& res) {
            res.ok().text("BUFFERED-OK");
        });

        for (const uint16_t status : std::array<uint16_t, 3>{200, 204, 304}) {
            for (std::size_t shape = 0; shape < kBodyShapes.size(); ++shape) {
                const std::string path = "/bodyless/" + std::to_string(status) + "/" + kBodyShapes[shape];
                const auto handler = [shape, status](api::Request&, api::Response& res) {
                    set_bodyless_shape(res, shape, status);
                };
                app_->head(path, handler);
                if (status != 200) app_->get(path, handler);
            }
        }
        app_->head("/bodyless/fullfixed", [](api::Request&, api::Response& res) {
            for (unsigned i = 0; i < api::http::CoroResponseHeaders::MAX_RESPONSE_HEADERS; ++i)
                res.raw().headers.append("X-Fill-" + std::to_string(i), "x");
            set_bodyless_shape(res, 3, 200);  // builder cannot append its length
        });
        app_->get("/bodyless/metadata304", [](api::Request&, api::Response& res) {
            res.status(304).content_length(99).send_borrowed("FORBIDDEN");
        });

        // Control: the classic chunked stream must stay chunked.
        app_->get("/chunked", [](api::Request&, api::Response& res) {
            res.stream("text/plain", [](const api::Response::StreamSink& sink) {
                sink("aaa");
                sink("bbb");
            });
        });

        // 200 over a zero-copy borrowed body.
        app_->get("/obj", [&obj](api::Request&, api::Response& res) {
            res.status(200)
               .content_type("application/octet-stream")
               .header("Accept-Ranges", "bytes")
               .send_borrowed(obj);
        });

        // 206 over a borrowed slice: Content-Length must be the SLICE length.
        app_->get("/range", [&obj](api::Request&, api::Response& res) {
            res.status(206)
               .header("Content-Range", "bytes 100-199/4096")
               .content_type("application/octet-stream")
               .send_borrowed(std::string_view(obj).substr(100, 100));
        });

        // 200 identity STREAMING: three producer writes, no chunk framing.
        app_->get("/fixed", [&obj](api::Request&, api::Response& res) {
            res.status(200).send_fixed(
                "application/octet-stream", 3000,
                [&obj](const api::Response::StreamSink& sink) {
                    sink(std::string_view(obj).substr(0, 1000));
                    sink("");  // empty writes are dropped, not framed
                    sink(std::string_view(obj).substr(1000, 1000));
                    sink(std::string_view(obj).substr(2000, 1000));
                });
        });

        // 206 identity STREAMING.
        app_->get("/fixedrange", [&obj](api::Request&, api::Response& res) {
            res.status(206)
               .header("Content-Range", "bytes 10-109/4096")
               .send_fixed("application/octet-stream", 100,
                           [&obj](const api::Response::StreamSink& sink) {
                               sink(std::string_view(obj).substr(10, 50));
                               sink(std::string_view(obj).substr(60, 50));
                           });
        });

        // HEAD: declare the length, produce no body at all.
        app_->head("/head", [](api::Request&, api::Response& res) {
            res.status(200)
               .content_type("application/octet-stream")
               .content_length(kObjSize);
        });

        // Moved (one-copy) body.
        app_->get("/owned", [](api::Request&, api::Response& res) {
            std::string built(512, 'z');
            res.status(200).content_type("text/plain").send_owned(std::move(built));
        });

        // Guard: the producer tries to write MORE than it declared.
        app_->get("/over", [](api::Request&, api::Response& res) {
            res.status(200).send_fixed("text/plain", 10,
                                       [](const api::Response::StreamSink& sink) {
                                           sink("0123456789");
                                           sink("MUST-NOT-SHIP");
                                       });
        });

        // Guard: the producer writes FEWER bytes than it declared.
        app_->get("/short", [](api::Request&, api::Response& res) {
            res.status(200).send_fixed("text/plain", 100,
                                       [](const api::Response::StreamSink& sink) {
                                           sink("only-ten!!");
                                       });
        });

        // G2ICE-251: offloaded handler owns its large slice; the other route
        // reuses producer-local scratch after every sink call (file-read shape).
        api::App* app = app_;
        app_->get_async("/fixedbig", [app](api::Request&, api::Response& res)
                                             -> api::core::coro_task<void> {
            co_await app->offload([&res] {
                std::string owned;
                owned.reserve(kLargeSize);
                for (std::size_t i = 0; i < kLargeSize / kObjSize; ++i)
                    owned += object_bytes();
                res.send_fixed(kLargeSize, [owned = std::move(owned)](
                        const api::Response::StreamSink& sink) { sink(owned); });
            });
        });
        app_->get("/fixedscratch", [](api::Request&, api::Response& res) {
            res.status(206).header("Content-Range", "bytes 0-8388607/8388608")
               .send_fixed(kLargeSize, [](const api::Response::StreamSink& sink) {
                    char scratch[kObjSize];
                    for (std::size_t i = 0; i < kLargeSize / kObjSize; ++i) {
                        std::memcpy(scratch, object_bytes().data(), sizeof(scratch));
                        sink(std::string_view(scratch, sizeof(scratch)));
                        std::memset(scratch, 0, sizeof(scratch));
                    }
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

api::App* FixedLengthResponse::app_ = nullptr;

// --- Regression guards: the pre-existing paths are untouched ---------------

TEST_F(FixedLengthResponse, BufferedRouteUnchanged) {
    const RawResponse r = do_request("GET", "/buf");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_FALSE(r.chunked);
    EXPECT_EQ(r.declared, 11);
    EXPECT_EQ(r.body, "BUFFERED-OK");
}

TEST_F(FixedLengthResponse, ChunkedStreamStillChunkedAndLengthless) {
    const RawResponse r = do_request("GET", "/chunked");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.chunked);
    EXPECT_EQ(r.declared, -1) << "chunked must NOT carry Content-Length";
}

// --- send_borrowed: zero-copy identity bodies ------------------------------

TEST_F(FixedLengthResponse, BorrowedBodyIsIdentityFramedAndExact) {
    const RawResponse r = do_request("GET", "/obj");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_FALSE(r.chunked) << "a borrowed body must never be chunk-framed";
    ASSERT_EQ(r.declared, static_cast<long long>(kObjSize));
    ASSERT_EQ(r.body.size(), kObjSize)
        << "written length must equal the declared Content-Length";
    EXPECT_EQ(r.body, object_bytes());
    EXPECT_FALSE(r.truncated);
}

TEST_F(FixedLengthResponse, BorrowedRangeReplyCarriesLengthAndContentRange) {
    const RawResponse r = do_request("GET", "/range");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 206);
    EXPECT_FALSE(r.chunked);
    ASSERT_EQ(r.declared, 100);
    ASSERT_EQ(r.body.size(), 100u);
    EXPECT_EQ(r.body, object_bytes().substr(100, 100));
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Range"), "bytes 100-199/4096");
}

TEST_F(FixedLengthResponse, OwnedBodyIsExact) {
    const RawResponse r = do_request("GET", "/owned");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    ASSERT_EQ(r.declared, 512);
    EXPECT_EQ(r.body, std::string(512, 'z'));
}

// --- send_fixed: identity producer streaming -------------------------------

TEST_F(FixedLengthResponse, FixedStreamHasLengthAndNoChunkFraming) {
    const RawResponse r = do_request("GET", "/fixed");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_FALSE(r.chunked) << "send_fixed must not set Transfer-Encoding";
    ASSERT_EQ(r.declared, 3000);
    ASSERT_EQ(r.body.size(), 3000u);
    EXPECT_EQ(r.body, object_bytes().substr(0, 3000))
        << "raw identity bytes -- no chunk size prefixes may appear in the body";
}

TEST_F(FixedLengthResponse, FixedStreamServesA206) {
    const RawResponse r = do_request("GET", "/fixedrange");
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 206);
    EXPECT_FALSE(r.chunked);
    ASSERT_EQ(r.declared, 100);
    ASSERT_EQ(r.body.size(), 100u);
    EXPECT_EQ(r.body, object_bytes().substr(10, 50) + object_bytes().substr(60, 50));
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Range"), "bytes 10-109/4096");
}

// --- HEAD: a declared length with no body ----------------------------------

TEST_F(FixedLengthResponse, HeadDeclaresLengthWithEmptyBody) {
    const RawResponse r = do_request("HEAD", "/head", /*head_request=*/true);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.declared, static_cast<long long>(kObjSize))
        << "an explicit Content-Length on an empty body must survive to the wire";
    EXPECT_TRUE(r.body.empty()) << "HEAD must carry no payload";
    EXPECT_FALSE(r.chunked);
}

TEST_F(FixedLengthResponse, HeadSuppressesEveryBodyShapeBeforeNextResponse) {
    expect_bodyless_shapes("HEAD", 200);
}

TEST_F(FixedLengthResponse, NoContentSuppressesEveryBodyShapeAndFraming) {
    expect_bodyless_shapes("GET", 204);
}

TEST_F(FixedLengthResponse, NotModifiedSuppressesEveryBodyShapeRetainingLength) {
    expect_bodyless_shapes("GET", 304);
}

TEST_F(FixedLengthResponse, HeadNoContentStillForbidsContentLength) {
    expect_bodyless_shapes("HEAD", 204);
}

TEST_F(FixedLengthResponse, SuppressedLengthSurvivesFullHeadersAndExplicitMetadata) {
    const unsigned before = g_suppressed_fixed_calls.load();
    const BodylessPair full = bodyless_then_get("HEAD", "/bodyless/fullfixed");
    ASSERT_TRUE(full.closed);
    EXPECT_EQ(header_value_ci(full.first_head, "Content-Length"), "9");
    EXPECT_TRUE(full.next_wire.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(full.next_wire.ends_with("\r\n\r\nBUFFERED-OK"));
    EXPECT_EQ(g_suppressed_fixed_calls.load(), before);
    const BodylessPair metadata = bodyless_then_get("GET", "/bodyless/metadata304");
    ASSERT_TRUE(metadata.closed);
    EXPECT_EQ(header_value_ci(metadata.first_head, "Content-Length"), "99");
    EXPECT_TRUE(metadata.next_wire.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(metadata.next_wire.ends_with("\r\n\r\nBUFFERED-OK"));
}

// --- The declared-length guarantee -----------------------------------------

TEST_F(FixedLengthResponse, OverProducingProducerIsRefusedAtDeclaredLength) {
    const RawResponse r = do_request("GET", "/over");
    ASSERT_TRUE(r.ok);
    ASSERT_EQ(r.declared, 10);
    ASSERT_EQ(r.body.size(), 10u);
    EXPECT_EQ(r.body, "0123456789");
    EXPECT_EQ(r.headers_block.find("MUST-NOT-SHIP"), std::string::npos);
    EXPECT_EQ(r.body.find("MUST-NOT-SHIP"), std::string::npos)
        << "bytes past the declared length must never reach the wire";
}

TEST_F(FixedLengthResponse, UnderProducingProducerClosesInsteadOfMisFraming) {
    // The server cannot un-send the headers, so the only correct recovery is to
    // close: the client sees a truncated response and errors, instead of the
    // connection silently mis-framing whatever response came next on it.
    const int fd = connect_client();
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, make_request("GET", "/short", /*close_after=*/false)));

    std::string carry;
    const RawResponse r = read_one(fd, carry);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.declared, 100);
    EXPECT_LT(r.body.size(), 100u);
    EXPECT_TRUE(r.truncated) << "a short body under a declared length must not be "
                                "presented as a complete response";

    // And the connection must be gone, not left poisoned for a next request.
    ASSERT_TRUE(send_all(fd, make_request("GET", "/buf", /*close_after=*/true)) == false ||
                true);  // the write may or may not fail depending on close timing
    char tmp[256];
    const ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
    EXPECT_LE(n, 0) << "connection must be closed after a length mismatch";
    sys::close_socket(fd);
}

// --- Keep-alive after a fixed-length response ------------------------------

TEST_F(FixedLengthResponse, KeepAliveSurvivesBorrowedAndFixedResponses) {
    const int fd = connect_client();
    ASSERT_GE(fd, 0);
    std::string carry;

    // 1) zero-copy borrowed 200
    ASSERT_TRUE(send_all(fd, make_request("GET", "/obj", /*close_after=*/false)));
    const RawResponse r1 = read_one(fd, carry);
    ASSERT_TRUE(r1.ok);
    ASSERT_EQ(r1.status, 200);
    ASSERT_EQ(r1.body.size(), kObjSize);
    ASSERT_FALSE(r1.truncated);

    // 2) identity fixed-length STREAM on the SAME connection
    ASSERT_TRUE(send_all(fd, make_request("GET", "/fixed", /*close_after=*/false)));
    const RawResponse r2 = read_one(fd, carry);
    ASSERT_TRUE(r2.ok);
    ASSERT_EQ(r2.status, 200);
    ASSERT_EQ(r2.declared, 3000);
    ASSERT_EQ(r2.body.size(), 3000u);
    EXPECT_EQ(r2.body, object_bytes().substr(0, 3000));

    // 3) 206 range on the SAME connection -- proves the stream left the
    //    connection perfectly framed, not one byte out of alignment.
    ASSERT_TRUE(send_all(fd, make_request("GET", "/range", /*close_after=*/true)));
    const RawResponse r3 = read_one(fd, carry);
    ASSERT_TRUE(r3.ok);
    EXPECT_EQ(r3.status, 206);
    ASSERT_EQ(r3.declared, 100);
    EXPECT_EQ(r3.body, object_bytes().substr(100, 100));

    sys::close_socket(fd);
}

}  // namespace

// G2ICE-251: do not drain the first body until another connection has answered.
// SO_RCVBUF forces backpressure; the old synchronous fixed-stream sender wedges
// the reactor here. A sleep before draining cannot prove this property.
namespace {
void check_delayed_drain(const char* target) {
    const int fd = connect_client();
    ASSERT_GE(fd, 0);
    int receive_bytes = 16 * 1024;
    ASSERT_EQ(::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                          reinterpret_cast<const char*>(&receive_bytes),
                          sizeof(receive_bytes)), 0);
    ASSERT_TRUE(send_all(fd, make_request("GET", target, false)));
    std::string head;
    char c = 0;
    for (std::size_t i = 0; i < (1u << 16); ++i) {
        if (sys::recv_bytes(fd, &c, 1) != 1) break;
        head += c;
        if (head.ends_with("\r\n\r\n")) break;
    }
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));
    EXPECT_EQ(header_value_ci(head, "Content-Length"), std::to_string(kLargeSize));
    const RawResponse fast = do_request("GET", "/buf");
    EXPECT_TRUE(fast.ok) << "other connection stalled behind unread fixed body";
    EXPECT_EQ(fast.body, "BUFFERED-OK");
    // Drain and compare in bounded scratch, avoiding a second whole-body copy.
    std::size_t received = 0;
    bool exact = true;
    char bytes[kObjSize];
    for (std::size_t i = 0; i < kLargeSize && received < kLargeSize; ++i) {
        const ssize_t n = sys::recv_bytes(fd, bytes, sizeof(bytes));
        if (n <= 0) break;
        for (ssize_t j = 0; j < n; ++j)
            exact &= bytes[j] == object_bytes()[(received + static_cast<std::size_t>(j)) % kObjSize];
        received += static_cast<std::size_t>(n);
    }
    EXPECT_EQ(received, kLargeSize);
    EXPECT_TRUE(exact);
    // Reuse after complete drain must still frame the following response.
    EXPECT_TRUE(send_all(fd, make_request("GET", "/buf", true)));
    std::string carry;
    const RawResponse next = read_one(fd, carry);
    EXPECT_TRUE(next.ok);
    EXPECT_EQ(next.body, "BUFFERED-OK");
    sys::close_socket(fd);
}

TEST_F(FixedLengthResponse, OtherConnectionCompletesBeforeOwnedBodyDrains) {
    check_delayed_drain("/fixedbig");
}

TEST_F(FixedLengthResponse, OtherConnectionCompletesBeforeScratchRangeDrains) {
    check_delayed_drain("/fixedscratch");
}

TEST_F(FixedLengthResponse, ConcurrentRangeStreamsKeepScratchAndFramingExact) {
    std::array<std::thread, 4> readers;
    std::atomic<unsigned> failures{0};
    for (auto& reader : readers) reader = std::thread([&failures] {
        const RawResponse r = do_request("GET", "/fixedscratch");
        bool exact = r.ok && !r.truncated && r.status == 206 &&
                     r.declared == static_cast<long long>(kLargeSize) &&
                     r.body.size() == kLargeSize && !r.chunked;
        for (std::size_t i = 0; exact && i < r.body.size(); ++i)
            exact = r.body[i] == object_bytes()[i % kObjSize];
        if (!exact) failures.fetch_add(1);
    });
    for (auto& reader : readers) reader.join();
    EXPECT_EQ(failures.load(), 0u);
}
}  // namespace

namespace {
constexpr uint16_t kLifecyclePort = 19329;

class FixedStreamLifecycle : public ::testing::Test {
protected:
    void SetUp() override {
        api::App::Config config;
        config.server.num_workers = 1;
        config.server.num_streaming_workers = 2;  // exactly one fixed-stream slot
        app_ = new api::App(config);
        app_->get("/hold", [this](api::Request&, api::Response& res) {
            res.send_fixed(kLargeSize, [this](const api::Response::StreamSink& sink) {
                started_.store(true);
                char scratch[kObjSize];
                std::memset(scratch, 'q', sizeof(scratch));
                for (std::size_t i = 0; i < kLargeSize / sizeof(scratch); ++i)
                    sink(std::string_view(scratch, sizeof(scratch)));
                finished_.store(true);
            });
        });
        app_->get("/small", [](api::Request&, api::Response& res) {
            res.send_fixed(5, [](const api::Response::StreamSink& sink) { sink("SMALL"); });
        });
        app_->get("/buffered", [](api::Request&, api::Response& res) { res.text("NEXT"); });
        app_->head("/suppressed", [this](api::Request&, api::Response& res) {
            res.send_fixed(9, [this](const api::Response::StreamSink& sink) {
                suppressed_calls_.fetch_add(1);
                sink("FORBIDDEN");
            });
        });
        ASSERT_EQ(app_->start_background("127.0.0.1", kLifecyclePort), 0);
    }
    void TearDown() override {
        app_->stop();
        delete app_;
    }
    int hold_body() {
        const int fd = connect_client(kLifecyclePort);
        if (fd < 0) return -1;
        int window = 16 * 1024;
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                reinterpret_cast<const char*>(&window), sizeof(window)) != 0 ||
            !send_all(fd, make_request("GET", "/hold", false))) {
            sys::close_socket(fd);
            return -1;
        }
        std::string head;
        char c = 0;
        for (std::size_t i = 0; i < (1u << 16); ++i) {
            if (sys::recv_bytes(fd, &c, 1) != 1) break;
            head += c;
            if (head.ends_with("\r\n\r\n")) return fd;
        }
        sys::close_socket(fd);
        return -1;
    }
    bool wait_finished() {
        for (unsigned i = 0; i < 1000 && !finished_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return finished_.load();
    }
    api::App* app_ = nullptr;
    std::atomic<bool> started_{false};
    std::atomic<bool> finished_{false};
    std::atomic<unsigned> suppressed_calls_{0};
};

TEST_F(FixedStreamLifecycle, HeadNeedsNoSlotWhenFixedCapacityIsOccupied) {
    const int fd = hold_body();
    ASSERT_GE(fd, 0);
    const BodylessPair pair = bodyless_then_get("HEAD", "/suppressed",
                                               kLifecyclePort, "/buffered");
    EXPECT_TRUE(pair.closed);
    EXPECT_TRUE(pair.first_head.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_EQ(header_value_ci(pair.first_head, "Content-Length"), "9");
    EXPECT_TRUE(pair.next_wire.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(pair.next_wire.ends_with("\r\n\r\nNEXT"));
    EXPECT_EQ(suppressed_calls_.load(), 0u);
    linger reset{1, 0};
    EXPECT_EQ(::setsockopt(fd, SOL_SOCKET, SO_LINGER,
                          reinterpret_cast<const char*>(&reset), sizeof(reset)), 0);
    sys::close_socket(fd);
    EXPECT_TRUE(wait_finished());
}

TEST_F(FixedStreamLifecycle, ExhaustionRefusesBeforeHeadersAndResetReleasesSlot) {
    const int fd = hold_body();
    ASSERT_GE(fd, 0);
    const RawResponse refused = do_request("GET", "/small", false, kLifecyclePort);
    EXPECT_TRUE(refused.ok);
    EXPECT_EQ(refused.status, 503);
    EXPECT_FALSE(refused.chunked);
    EXPECT_FALSE(refused.truncated);
    EXPECT_EQ(refused.declared, static_cast<long long>(refused.body.size()));
    EXPECT_NE(refused.body.find("capacity exhausted"), std::string::npos);

    linger reset{1, 0};
    EXPECT_EQ(::setsockopt(fd, SOL_SOCKET, SO_LINGER,
                          reinterpret_cast<const char*>(&reset), sizeof(reset)), 0);
    sys::close_socket(fd);
    EXPECT_TRUE(wait_finished());
    RawResponse next;
    for (unsigned i = 0; i < 100; ++i) {
        next = do_request("GET", "/small", false, kLifecyclePort);
        if (next.status == 200) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(next.ok);
    EXPECT_EQ(next.status, 200);
    EXPECT_EQ(next.body, "SMALL");
}

TEST_F(FixedStreamLifecycle, StopCancelsProducerWithUnreadBody) {
    const int fd = hold_body();
    ASSERT_GE(fd, 0);
    for (unsigned i = 0; i < 1000 && !started_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(started_.load());
    EXPECT_FALSE(finished_.load());
    const auto before = std::chrono::steady_clock::now();
    app_->stop();
    const auto elapsed = std::chrono::steady_clock::now() - before;
    EXPECT_LT(elapsed, std::chrono::seconds(2));
    EXPECT_TRUE(finished_.load());
    sys::close_socket(fd);
}
}  // namespace

namespace {
constexpr uint16_t kMultiReactorPort = 19330;
std::atomic<unsigned> g_probe_zero{0}, g_probe_one{0}, g_probe_other{0};

api::core::detached_task check_reactor_identity(
        api::net::IODispatcher& io, api::net::IODispatcher& foreign,
        std::size_t expected, std::atomic<unsigned>& completed,
        std::atomic<unsigned>& failures) {
    if (io.current_io_thread_index() != expected ||
        foreign.current_io_thread_index() != SIZE_MAX) failures.fetch_add(1);
    completed.fetch_add(1);
    co_return;
}

// Exercise the production listener's fresh-fd assignment. A handler must never
// move this connection for the test: response completion and keepalive I/O must
// stay on the naturally accepted owner. Bound probes because SO_REUSEPORT's
// selection on Linux is not round-robin; macOS uses the bounded Bolt handoff.
int connect_natural_owner(std::size_t expected) {
    assert(expected < 2);
    constexpr unsigned kMaxOwnerProbes = 64;
    for (unsigned probe_index = 0; probe_index < kMaxOwnerProbes; ++probe_index) {
        const int fd = connect_client(kMultiReactorPort);
        if (fd < 0) return -1;
        std::string carry;
        if (!send_all(fd, make_request("GET", "/where", false))) {
            sys::close_socket(fd);
            return -1;
        }
        const RawResponse probe = read_one(fd, carry);
        const std::string accepted = header_value_ci(probe.headers_block, "X-Accept-Reactor");
        if (accepted == "0") g_probe_zero.fetch_add(1);
        else if (accepted == "1") g_probe_one.fetch_add(1);
        else g_probe_other.fetch_add(1);
        const bool valid = probe.ok && probe.status == 200 &&
            (accepted == "0" || accepted == "1") && probe.body == accepted && carry.empty();
        if (valid && accepted == std::to_string(expected)) return fd;
        sys::close_socket(fd);
        if (!valid) return -1;
    }
    return -1;  // absent natural fanout fails; never substitute a test handoff
}

int open_unread_range(bool pinned) {
    const int fd = pinned ? connect_natural_owner(1) : connect_client(kMultiReactorPort);
    if (fd < 0) return -1;
    int window = 16 * 1024;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
            reinterpret_cast<const char*>(&window), sizeof(window)) != 0 ||
        !send_all(fd, make_request("GET", "/range", false))) {
        sys::close_socket(fd);
        return -1;
    }
    std::string head;
    char c = 0;
    for (std::size_t i = 0; i < (1u << 16); ++i) {
        if (sys::recv_bytes(fd, &c, 1) != 1) break;
        head += c;
        if (head.ends_with("\r\n\r\n")) {
            if (head.starts_with("HTTP/1.1 206 ") &&
                (!pinned || header_value_ci(head, "X-Reactor") == "1")) return fd;
            break;
        }
    }
    sys::close_socket(fd);
    return -1;
}

void check_multi_reactor_client(std::atomic<unsigned>& failures, bool pinned,
                               std::size_t expected) {
        for (unsigned round = 0; round < 4; ++round) {
            const int fd = pinned ? connect_natural_owner(expected)
                                  : connect_client(kMultiReactorPort);
            if (fd < 0) { failures.fetch_add(1); continue; }
            int window = 16 * 1024;
            if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                    reinterpret_cast<const char*>(&window), sizeof(window)) != 0 ||
                !send_all(fd, make_request("GET", "/range", false))) {
                failures.fetch_add(1);
                sys::close_socket(fd);
                continue;
            }
            std::string carry;
            char c = 0;
            for (std::size_t i = 0; i < (1u << 16); ++i) {
                if (sys::recv_bytes(fd, &c, 1) != 1) break;
                carry += c;
                if (carry.ends_with("\r\n\r\n")) break;
            }
            const std::string owner = header_value_ci(carry, "X-Reactor");
            if (pinned && owner != std::to_string(expected)) failures.fetch_add(1);
            // This must complete on the SAME reactor before draining the range.
            // An arbitrary second connection could land on the other reactor
            // and conceal a producer that still blocks its owner.
            if (pinned) {
                const int other = connect_natural_owner(expected);
                if (other < 0) failures.fetch_add(1);
                else sys::close_socket(other);
            } else {
                const RawResponse other = do_request("GET", "/where", false, kMultiReactorPort);
                if (!other.ok || other.status != 200) failures.fetch_add(1);
            }
            const RawResponse range = read_one(fd, carry);
            bool exact = range.ok && !range.truncated && range.status == 206 &&
                         range.body.size() == kLargeSize && !range.chunked;
            for (std::size_t i = 0; exact && i < range.body.size(); ++i)
                exact = range.body[i] == 'r';
            if (!exact || !send_all(fd, make_request("GET", "/where", true)))
                failures.fetch_add(1);
            const RawResponse next = read_one(fd, carry);
            if (!next.ok || next.status != 200 || (pinned && next.body != owner))
                failures.fetch_add(1);  // a wrong-reactor wake migrates this connection
            sys::close_socket(fd);
        }
}

TEST(FixedStreamMultiReactor, OwnerIdentityAndConcurrentDelayedRanges) {
    g_probe_zero.store(0);
    g_probe_one.store(0);
    g_probe_other.store(0);
    api::net::IODispatcherConfig foreign_config;
    api::net::IODispatcher foreign(foreign_config);
    EXPECT_EQ(foreign.current_io_thread_index(), SIZE_MAX);
    api::http::CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_signal_handlers = false;
    config.host = "127.0.0.1";
    config.http1_port = kMultiReactorPort;
    config.num_io_threads = 2;
    config.num_workers = 2;
    // Captures outlive server destruction even if a fatal assertion returns.
    std::atomic<unsigned> failures{0};
    std::atomic<unsigned> seen{0};
    std::atomic<unsigned> checked{0};
    api::http::CoroUnifiedServer server(config);
    server.set_handler([&](const api::http::CoroHttpRequest& req)
                                -> api::http::dispatch_task<api::http::CoroHttpResponse> {
        auto* io = server.io_dispatcher();
        const std::size_t accepted = io->current_io_thread_index();
        const std::size_t owner = io->current_io_thread_index();
        api::http::CoroHttpResponse raw;
        api::Response res(raw);
        if (owner >= 2 || foreign.current_io_thread_index() != SIZE_MAX)
            failures.fetch_add(1);
        if (owner < 2) seen.fetch_or(1u << owner);
        res.header("X-Reactor", std::to_string(owner));
        if (req.path == "/where") {
            res.header("X-Accept-Reactor", std::to_string(accepted));
            res.ok().text(std::to_string(owner));
        } else {
            res.status(206).header("Content-Range", "bytes 0-8388607/8388608")
               .send_fixed(kLargeSize, [&, io](const api::Response::StreamSink& sink) {
                    if (io->current_io_thread_index() != SIZE_MAX)
                        failures.fetch_add(1);  // production must leave BOTH reactors
                    char scratch[kObjSize];
                    std::memset(scratch, 'r', sizeof(scratch));
                    for (std::size_t i = 0; i < kLargeSize / sizeof(scratch); ++i)
                        sink(std::string_view(scratch, sizeof(scratch)));
                });
        }
        co_return raw;
    });
    ASSERT_EQ(server.start_background(), 0);
    auto* io = server.io_dispatcher();
    EXPECT_EQ(io->current_io_thread_index(), SIZE_MAX);  // test thread is foreign
    for (std::size_t i = 0; i < 2; ++i) {
        auto check = check_reactor_identity(*io, foreign, i, checked, failures);
        auto handle = check.release();
        const bool posted = io->post_to_io_thread(i, handle);
        EXPECT_TRUE(posted);
        if (!posted) handle.destroy();
    }
    for (unsigned i = 0; i < 1000 && checked.load() != 2; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_EQ(checked.load(), 2u);

    std::array<std::thread, 4> clients;
    const bool pinned = io->per_thread_engines();
    for (std::size_t i = 0; i < clients.size(); ++i)
        clients[i] = std::thread([&, expected = i % 2] {
            check_multi_reactor_client(failures, pinned, expected);
        });
    for (auto& client : clients) client.join();
    std::fprintf(stderr, "[multi accept] owner0=%u owner1=%u other=%u seen=%u\n",
        g_probe_zero.load(), g_probe_one.load(), g_probe_other.load(), seen.load());
    EXPECT_EQ(failures.load(), 0u);
    EXPECT_NE(seen.load(), 0u);
    if (pinned) {
        EXPECT_GT(g_probe_zero.load(), 0u);
        EXPECT_GT(g_probe_one.load(), 0u);
        EXPECT_EQ(g_probe_other.load(), 0u);
        EXPECT_EQ(seen.load(), 3u);
    }
    const int unread = open_unread_range(pinned);
    ASSERT_GE(unread, 0);
    EXPECT_GT(server.get_active_connections(), 0u);
    server.stop();
    EXPECT_EQ(server.get_active_connections(), 0u)
        << "stop must release the suspended HTTP request, not only its producer";
    sys::close_socket(unread);
    EXPECT_EQ(io->current_io_thread_index(), SIZE_MAX);
}
}  // namespace

namespace {
struct ArmingGate {
    std::atomic<bool> armed{false}, release{false}, barrier{false};
    std::atomic<bool> resumed{false}, premature{false}, returned{false}, inline_ok{false};
    std::atomic<std::size_t> reactor{SIZE_MAX};
};

api::core::coro_task<void> arming_probe(api::net::IODispatcher& io, ArmingGate& gate) {
    gate.reactor.store(io.current_io_thread_index());
    gate.premature.store(!gate.release.load());
    gate.resumed.store(true);
    co_return;
}

api::core::detached_task pause_arming(api::http::H1FixedStreamSlot* slot,
        ArmingGate& gate, bool completion_only, std::coroutine_handle<> probe) {
    const bool parked = api::http::h1_fixed_stream_suspend(slot, completion_only, probe,
        [&gate]() noexcept {
            gate.armed.store(true);
            while (!gate.release.load()) gate.release.wait(false);
        });
    // FIFO barrier proves an unsafe posted resume has already run. Avoid double
    // resuming the probe in a negative control; its frame is owned by the test.
    if (!parked && gate.inline_ok.load() && !gate.resumed.load()) probe.resume();
    gate.returned.store(true);
    co_return;
}

api::core::detached_task arming_barrier(ArmingGate& gate) {
    gate.barrier.store(true);
    co_return;
}

void check_arming_interleave(bool completion_only) {
    ArmingGate gate;  // all captures outlive the I/O dispatcher and worker pool
    api::http::H1FixedStreamPool slots(1);
    ASSERT_TRUE(slots.valid());
    api::core::WorkerPoolConfig workers_config;
    workers_config.num_workers = 1;
    workers_config.blocking_workers = 1;
    api::core::WorkerThreadPool workers(workers_config);
    api::net::IODispatcherConfig config;
    config.num_io_threads = 2;
    config.worker_pool = &workers;
    api::net::IODispatcher io(config);
    auto* slot = slots.acquire(io, 0, 1);  // captured owner differs from completion thread
    ASSERT_NE(slot, nullptr);
    slot->references.fetch_add(1);  // retain both refs until all synthetic work joins
    auto probe = arming_probe(io, gate);
    workers.start();
    io.start();
    auto arm = pause_arming(slot, gate, completion_only, probe.get_handle());
    auto arm_handle = arm.release();
    const bool posted = io.post_to_io_thread(1, arm_handle);
    EXPECT_TRUE(posted);
    if (!posted) arm_handle.destroy();
    for (unsigned i = 0; i < 1000 && !gate.armed.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(gate.armed.load());
    if (completion_only) slot->done.store(true, std::memory_order_release);
    else slot->pending.store(1, std::memory_order_release);
    slot->wake();
    auto barrier = arming_barrier(gate);
    auto barrier_handle = barrier.release();
    const bool barrier_posted = io.post_to_io_thread(0, barrier_handle);
    EXPECT_TRUE(barrier_posted);
    if (!barrier_posted) barrier_handle.destroy();
    for (unsigned i = 0; i < 1000 && !gate.barrier.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(gate.barrier.load());
    EXPECT_FALSE(gate.resumed.load()) << "owner 0 resumed an awaiter still arming on 1";
    gate.inline_ok.store(gate.barrier.load());
    gate.release.store(true);  // no fatal assertion/return may bypass this release
    gate.release.notify_all();
    for (unsigned i = 0; i < 1000 && !gate.returned.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    io.stop();
    workers.stop();
    EXPECT_TRUE(gate.returned.load());
    EXPECT_TRUE(gate.resumed.load());
    EXPECT_FALSE(gate.premature.load());
    EXPECT_EQ(gate.reactor.load(), 1u);
    slot->release();
    slot->release();
}

TEST(FixedStreamSharedCompletion, DataCannotResumeDuringArmingOnAnotherReactor) {
    check_arming_interleave(false);
}
TEST(FixedStreamSharedCompletion, CompletionCannotResumeDuringArmingOnAnotherReactor) {
    check_arming_interleave(true);
}

int request_headers(uint16_t port, const char* path) {
    const int fd = connect_client(port);
    if (fd < 0) return -1;
    if (!send_all(fd, make_request("GET", path, false))) {
        sys::close_socket(fd);
        return -1;
    }
    std::string head;
    char c = 0;
    for (unsigned i = 0; i < (1u << 16); ++i) {
        if (sys::recv_bytes(fd, &c, 1) != 1) break;
        head += c;
        if (head.ends_with("\r\n\r\n")) return fd;
    }
    sys::close_socket(fd);
    return -1;
}

TEST(FixedStreamShutdown, FiniteProducerAfterDeadlineReleasesRequestContext) {
    constexpr uint16_t port = 19331;
    std::atomic<bool> release{false}, started{false}, finished{false}, stopped{false};
    api::http::CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_signal_handlers = false;
    config.host = "127.0.0.1";
    config.http1_port = port;
    config.num_workers = 1;
    config.num_streaming_workers = 2;
    config.shutdown_timeout_ms = 1;
    api::http::CoroUnifiedServer server(config);
    server.set_handler([&](const api::http::CoroHttpRequest&)
            -> api::http::dispatch_task<api::http::CoroHttpResponse> {
        api::http::CoroHttpResponse raw;
        api::Response res(raw);
        res.send_fixed(5, [&](const api::Response::StreamSink& sink) {
            started.store(true);
            while (!release.load()) release.wait(false);
            sink("READY");
            finished.store(true);
        });
        co_return raw;
    });
    ASSERT_EQ(server.start_background(), 0);
    const int fd = request_headers(port, "/fixed");
    EXPECT_GE(fd, 0);
    if (fd < 0) {
        release.store(true);
        release.notify_all();
        server.stop();
        return;
    }
    for (unsigned i = 0; i < 1000 && !started.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(started.load());
    std::thread stopper([&] { server.stop(); stopped.store(true); });
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_FALSE(stopped.load());
    release.store(true);  // always release finite producer before joining stop
    release.notify_all();
    stopper.join();
    EXPECT_TRUE(stopped.load());
    EXPECT_TRUE(finished.load());
    EXPECT_EQ(server.get_active_connections(), 0u);
    sys::close_socket(fd);
}

TEST(FixedStreamAdmission, FullBlockingQueueRefusesBeforePublishingFixedHeaders) {
    constexpr uint16_t port = 19332;
    std::atomic<bool> release{false};
    std::atomic<unsigned> entered{0};
    api::http::CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_signal_handlers = false;
    config.host = "127.0.0.1";
    config.http1_port = port;
    config.num_workers = 1;
    config.num_streaming_workers = 2;
    api::http::CoroUnifiedServer server(config);
    server.set_handler([](const api::http::CoroHttpRequest&)
            -> api::http::dispatch_task<api::http::CoroHttpResponse> {
        api::http::CoroHttpResponse raw;
        api::Response res(raw);
        res.send_fixed(5, [](const api::Response::StreamSink& sink) { sink("READY"); });
        co_return raw;
    });
    ASSERT_EQ(server.start_background(), 0);
    auto* workers = server.io_dispatcher()->worker_pool();
    for (unsigned i = 0; i < 2; ++i) EXPECT_TRUE(workers->try_submit_blocking([&] {
        entered.fetch_add(1);
        while (!release.load()) release.wait(false);
    }));
    for (unsigned i = 0; i < 1000 && entered.load() != 2; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_EQ(entered.load(), 2u);
    bool full = false;
    for (unsigned i = 0; i < 4096; ++i) {
        if (!workers->try_submit_blocking([] {})) { full = true; break; }
    }
    EXPECT_TRUE(full);
    const RawResponse refused = do_request("GET", "/fixed", false, port);
    EXPECT_TRUE(refused.ok);
    EXPECT_EQ(refused.status, 503);
    EXPECT_FALSE(refused.truncated);
    EXPECT_FALSE(refused.chunked);
    EXPECT_EQ(refused.declared, static_cast<long long>(refused.body.size()));
    release.store(true);  // release on every assertion/timeout path, including mutants
    release.notify_all();
    RawResponse next;
    for (unsigned i = 0; i < 100; ++i) {
        next = do_request("GET", "/fixed", false, port);
        if (next.status == 200) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(next.ok);
    EXPECT_EQ(next.status, 200);
    EXPECT_EQ(next.body, "READY");
    server.stop();
    EXPECT_EQ(server.get_active_connections(), 0u);
    EXPECT_FALSE(workers->try_submit_blocking([] {}));
}
}  // namespace

namespace {
TEST(BlockingAdmission, ZeroBlockingWorkersNeverAcceptsCallback) {
    std::atomic<bool> executed{false};  // outlives queue-cell callback copies
    api::core::WorkerPoolConfig config;
    config.num_workers = 1;
    config.blocking_workers = 0;
    api::core::WorkerThreadPool workers(config);
    EXPECT_FALSE(workers.try_submit_blocking([&] { executed.store(true); }));
    workers.start();
    EXPECT_FALSE(workers.try_submit_blocking([&] { executed.store(true); }));
    workers.stop();
    EXPECT_FALSE(executed.load());
    EXPECT_FALSE(workers.try_submit_blocking([&] { executed.store(true); }));
}

constexpr std::size_t kAdmissionPublishers = 4;
constexpr std::size_t kAdmissionBacklog = 64;
constexpr std::size_t kAdmissionRaceIds = 64;
constexpr std::size_t kAdmissionLateIds = 16;
constexpr std::size_t kAdmissionStride = kAdmissionRaceIds + kAdmissionLateIds;
constexpr std::size_t kAdmissionTracked =
    1 + kAdmissionBacklog + kAdmissionPublishers * kAdmissionStride;

struct AdmissionLedger {
    std::array<std::atomic<unsigned>, kAdmissionTracked> executions{};
    std::array<bool, kAdmissionTracked> accepted{};  // one publisher per ID
    std::atomic<bool> entered{false}, release{false}, begin{false}, late{false};
    std::atomic<unsigned> ready{0};

    void submit(api::core::WorkerThreadPool& workers, std::size_t id) {
        accepted[id] = workers.try_submit_blocking([this, id] {
            executions[id].fetch_add(1);
        });
    }
};

void admission_publisher(api::core::WorkerThreadPool& workers,
        AdmissionLedger& ledger, std::size_t publisher) {
    const std::size_t base = 1 + kAdmissionBacklog + publisher * kAdmissionStride;
    ledger.ready.fetch_add(1);
    while (!ledger.begin.load()) ledger.begin.wait(false);
    for (std::size_t i = 0; i < kAdmissionRaceIds; ++i) ledger.submit(workers, base + i);
    while (!ledger.late.load()) ledger.late.wait(false);
    for (std::size_t i = 0; i < kAdmissionLateIds; ++i)
        ledger.submit(workers, base + kAdmissionRaceIds + i);
}

void check_concurrent_admission_stop(bool hold_backlog) {
    AdmissionLedger ledger;  // every callback and publisher capture outlives pool
    api::core::WorkerPoolConfig config;
    config.num_workers = 1;
    config.blocking_workers = 1;
    api::core::WorkerThreadPool workers(config);
    workers.start();
    ledger.accepted[0] = workers.try_submit_blocking([&ledger] {
        ledger.executions[0].fetch_add(1);
        ledger.entered.store(true);
        while (!ledger.release.load()) ledger.release.wait(false);
    });
    EXPECT_TRUE(ledger.accepted[0]);
    for (unsigned i = 0; i < 1000 && !ledger.entered.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(ledger.entered.load());
    for (std::size_t id = 1; id <= kAdmissionBacklog; ++id) {
        ledger.submit(workers, id);
        EXPECT_TRUE(ledger.accepted[id]);
        EXPECT_EQ(ledger.executions[id].load(), 0u);  // forced queued backlog
    }
    std::array<std::thread, kAdmissionPublishers> publishers;
    for (std::size_t i = 0; i < publishers.size(); ++i)
        publishers[i] = std::thread(admission_publisher, std::ref(workers),
                                     std::ref(ledger), i);
    std::thread stopper([&] {
        ledger.ready.fetch_add(1);
        while (!ledger.begin.load()) ledger.begin.wait(false);
        workers.stop();
    });
    for (unsigned i = 0; i < 1000 && ledger.ready.load() != kAdmissionPublishers + 1; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_EQ(ledger.ready.load(), kAdmissionPublishers + 1);
    ledger.begin.store(true);
    ledger.begin.notify_all();
    if (!hold_backlog) {
        ledger.release.store(true);  // let final drain race active publishers
        ledger.release.notify_all();
    }
    for (unsigned i = 0; i < 1000 && workers.is_running(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(workers.is_running());
    ledger.late.store(true);  // stop admission is closed before late attempts
    ledger.late.notify_all();
    for (auto& publisher : publishers) publisher.join();
    ledger.release.store(true);  // release on every assertion failure path
    ledger.release.notify_all();
    stopper.join();
    for (std::size_t id = 0; id < kAdmissionTracked; ++id)
        EXPECT_EQ(ledger.executions[id].load(), ledger.accepted[id] ? 1u : 0u)
            << "callback ID " << id;
    for (std::size_t publisher = 0; publisher < kAdmissionPublishers; ++publisher)
        for (std::size_t i = 0; i < kAdmissionLateIds; ++i)
            EXPECT_FALSE(ledger.accepted[1 + kAdmissionBacklog +
                publisher * kAdmissionStride + kAdmissionRaceIds + i]);
}

TEST(BlockingAdmission, ConcurrentStopDrainsEveryAcceptedCallbackExactlyOnce) {
    // Finite scheduling stress, not exhaustive SC-interleaving proof. Each round
    // forces queued work before stop and rejected attempts after stop begins.
    for (unsigned round = 0; round < 8; ++round) {
        SCOPED_TRACE(round);
        check_concurrent_admission_stop((round & 1u) == 0);
    }
}
}  // namespace
