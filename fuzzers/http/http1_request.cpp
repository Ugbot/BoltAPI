// http1_request.cpp — HTTP1Parser driven the way handle_http1_connection
// drives it: bytes arrive in reads of fuzzer-chosen size, parse() is retried
// on the whole buffer after every read, a complete request is dechunked in
// place and consumed, and the leftover is parsed again (pipelining).
//
// Input: byte 0 seeds the read splitter; the rest is the connection stream.

#include "boltapi/http/http1_parser.h"
#include "fuzz_util.h"

#include <algorithm>
#include <cstring>
#include <vector>

using bolt::api::http::HTTP1Parser;
using bolt::api::http::HTTP1Request;

namespace {

constexpr std::size_t kBufCap = 64 * 1024;   // server grows to max_body; bounded here
constexpr std::size_t kMaxRequests = 256;

void check_request(const HTTP1Request& r, const std::uint8_t* buf, std::size_t len,
                   std::size_t consumed) {
    FUZZ_CHECK(consumed <= len);
    FUZZ_CHECK(consumed > 0);
    FUZZ_CHECK(r.header_count <= HTTP1Request::MAX_HEADERS);
    FUZZ_CHECK(boltapi_fuzz::within(r.method_str, buf, consumed));
    FUZZ_CHECK(boltapi_fuzz::within(r.url, buf, consumed));
    FUZZ_CHECK(boltapi_fuzz::within(r.path, buf, consumed));
    FUZZ_CHECK(boltapi_fuzz::within(r.query, buf, consumed));
    FUZZ_CHECK(boltapi_fuzz::within(r.body, buf, consumed));
    for (std::size_t i = 0; i < r.header_count; ++i) {
        FUZZ_CHECK(boltapi_fuzz::within(r.headers[i].name, buf, consumed));
        FUZZ_CHECK(boltapi_fuzz::within(r.headers[i].value, buf, consumed));
    }
    if (r.has_content_length && !r.chunked) {
        FUZZ_CHECK(r.body.size() == r.content_length);
    }
    // Complete means the empty line that ends the field section was seen.
    const std::string_view head(reinterpret_cast<const char*>(buf), consumed - r.body.size());
    FUZZ_CHECK(head.size() >= 4 && head.substr(head.size() - 4) == "\r\n\r\n");
    // Both framings on one message is a smuggling vector; never accepted.
    FUZZ_CHECK(!(r.chunked && r.has_content_length));
    (void)r.get_header("host");
    (void)r.has_header("expect");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    boltapi_fuzz::Splitter split(data[0]);
    const std::uint8_t* in = data + 1;
    const std::size_t in_len = size - 1;

    std::vector<std::uint8_t> buf(kBufCap);
    std::size_t buf_len = 0;
    std::size_t in_off = 0;
    HTTP1Parser parser;
    std::size_t requests = 0;

    while (requests < kMaxRequests) {
        HTTP1Request req;
        std::size_t consumed = 0;
        int rc = buf_len > 0 ? parser.parse(buf.data(), buf_len, req, consumed) : -1;
        while (rc < 0 && in_off < in_len && buf_len < kBufCap) {
            const std::size_t n =
                split.chunk(std::min(in_len - in_off, kBufCap - buf_len));
            std::memcpy(buf.data() + buf_len, in + in_off, n);
            buf_len += n;
            in_off += n;
            rc = parser.parse(buf.data(), buf_len, req, consumed);
        }
        if (rc != 0) break;  // incomplete at EOF, buffer full, or 400
        check_request(req, buf.data(), buf_len, consumed);
        if (req.chunked) {
            const std::size_t off = static_cast<std::size_t>(
                reinterpret_cast<const std::uint8_t*>(req.body.data()) - buf.data());
            const std::size_t n = HTTP1Parser::dechunk_in_place(buf.data() + off,
                                                                req.body.size());
            FUZZ_CHECK(n <= req.body.size());
        }
        std::memmove(buf.data(), buf.data() + consumed, buf_len - consumed);
        buf_len -= consumed;
        parser.reset();
        ++requests;
    }
    return 0;
}
