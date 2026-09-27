// http1_chunked.cpp — HTTP1Parser::scan_chunked / dechunk_in_place against an
// independent RFC 9112 7.1 reference decoder. Accepting what the reference
// rejects (or decoding to different bytes) is a framing bug: the server and a
// proxy in front of it would disagree about where the body ends.

#include "boltapi/http/http1_parser.h"
#include "fuzz_util.h"

#include <cstring>
#include <vector>

using bolt::api::http::HTTP1Parser;

namespace {

int hexv(std::uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 0 = complete (raw_len, out set), -1 = incomplete, 1 = malformed.
int reference(const std::uint8_t* p, std::size_t n, std::size_t* raw_len,
              std::vector<std::uint8_t>* out) {
    std::size_t i = 0;
    for (;;) {
        std::uint64_t size = 0;
        std::size_t digits = 0;
        while (i < n && hexv(p[i]) >= 0) {
            if (++digits > 16) return 1;
            size = (size << 4) | static_cast<std::uint64_t>(hexv(p[i]));
            ++i;
        }
        if (i == n) return -1;
        if (digits == 0) return 1;
        const std::size_t line_start = i - digits;
        while (i < n && p[i] != '\r' && p[i] != '\n') {
            if (i - line_start >= 4096) return 1;
            ++i;
        }
        if (i == n) return -1;
        if (p[i] == '\n') return 1;
        if (i + 1 == n) return -1;
        if (p[i + 1] != '\n') return 1;
        i += 2;
        if (size == 0) break;
        if (size > n - i) return -1;
        if (n - i - size < 2) return -1;
        out->insert(out->end(), p + i, p + i + size);
        i += static_cast<std::size_t>(size);
        if (p[i] != '\r' || p[i + 1] != '\n') return 1;
        i += 2;
    }
    for (;;) {  // trailer fields, then the empty line
        const std::size_t start = i;
        while (i < n && p[i] != '\n') ++i;
        if (i == n) return -1;
        if (i == start || p[i - 1] != '\r') return 1;
        ++i;
        if (i - start == 2) {
            *raw_len = i;
            return 0;
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::size_t raw = 0;
    const int rc = HTTP1Parser::scan_chunked(data, size, &raw);
    std::size_t ref_raw = 0;
    std::vector<std::uint8_t> ref_out;
    const int ref_rc = reference(data, size, &ref_raw, &ref_out);
    FUZZ_CHECK(rc == ref_rc);
    if (rc != 0) return 0;
    FUZZ_CHECK(raw == ref_raw);
    FUZZ_CHECK(raw <= size);
    std::vector<std::uint8_t> copy(data, data + raw);
    const std::size_t n = HTTP1Parser::dechunk_in_place(copy.data(), raw);
    FUZZ_CHECK(n == ref_out.size());
    FUZZ_CHECK(n == 0 || std::memcmp(copy.data(), ref_out.data(), n) == 0);
    return 0;
}
