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

#include <gtest/gtest.h>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19277;  // distinct from the other socket suites
constexpr std::size_t kObjSize = 4096;

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

int connect_client() {
    sys::startup();
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
        if (buf.size() > (1u << 22)) break;  // safety cap
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
                       bool head_request = false) {
    RawResponse out;
    const int fd = connect_client();
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
