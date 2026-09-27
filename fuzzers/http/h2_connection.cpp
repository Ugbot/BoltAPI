// h2_connection.cpp — a server-side Http2Connection driven the way
// handle_http2_connection drives it: the client stream arrives in reads of at
// most 16 KiB (fuzzer-chosen sizes), every completed request is answered with
// send_response, and output is drained with partial commits. The bytes the
// server emits must themselves be well-formed frames.
//
// Input: byte 0 seeds the read splitter; byte 1 bit 0 = omit the client
// preface, bits 1..3 pick the response body size; the rest is client bytes.

#include "boltapi/http/http2_connection.h"
#include "fuzz_util.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

using namespace bolt::api;
using namespace bolt::api::http2;

namespace {

constexpr std::size_t kReadCap = 16384;  // handle_http2_connection's buffer
constexpr std::size_t kMaxReads = 4096;
constexpr std::size_t kBodySizes[8] = {0, 1, 100, 16384, 16385, 70000, 3, 200000};

// Walk the emitted byte stream frame by frame.
void check_output(const std::vector<std::uint8_t>& out, std::uint32_t max_frame) {
    std::size_t off = 0;
    bool first = true;
    for (std::size_t guard = 0; guard < out.size() && off + 9 <= out.size(); ++guard) {
        auto h = parse_frame_header(out.data() + off);
        FUZZ_CHECK(h.is_ok());
        if (first) FUZZ_CHECK(h.value().type == FrameType::SETTINGS);
        first = false;
        FUZZ_CHECK(h.value().length <= max_frame);
        off += 9 + h.value().length;
    }
    FUZZ_CHECK(off == out.size());  // never a torn frame at a drain boundary
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    boltapi_fuzz::Splitter split(data[0]);
    const bool raw = (data[1] & 1) != 0;
    const std::size_t body_size = kBodySizes[(data[1] >> 1) & 7];
    std::vector<std::uint8_t> client;
    if (!raw) client.assign(CONNECTION_PREFACE, CONNECTION_PREFACE + CONNECTION_PREFACE_LEN);
    client.insert(client.end(), data + 2, data + size);

    Http2Connection conn(true);
    std::vector<std::uint32_t> pending;
    conn.set_request_callback([&pending](Http2Stream* s) {
        FUZZ_CHECK(s != nullptr);
        for (const auto& [n, v] : s->request_headers()) {
            FUZZ_CHECK(n.size() + v.size() < (1u << 26));
        }
        (void)s->request_body();
        pending.push_back(s->id());
    });

    const std::string body(body_size, 'x');
    http::CoroResponseHeaders hdrs;
    hdrs.set("Content-Type", "text/plain");
    std::vector<std::uint8_t> emitted;
    std::size_t off = 0;
    for (std::size_t reads = 0; reads < kMaxReads && off < client.size(); ++reads) {
        const std::size_t n = split.chunk(std::min(kReadCap, client.size() - off));
        // Exact-size read buffer: over-reads past what arrived are visible.
        std::vector<std::uint8_t> rbuf(client.data() + off, client.data() + off + n);
        off += n;
        auto r = conn.process_input(rbuf.data(), rbuf.size());
        for (std::uint32_t id : pending) {
            (void)conn.send_response(id, 200, hdrs, body);
        }
        pending.clear();
        const std::uint8_t* p = nullptr;
        std::size_t plen = 0;
        for (std::size_t g = 0; g < 1u << 16 && conn.get_output(&p, &plen); ++g) {
            FUZZ_CHECK(plen > 0);
            const std::size_t take = split.chunk(plen);
            emitted.insert(emitted.end(), p, p + take);
            conn.commit_output(take);
        }
        if (r.is_err() || !conn.is_active()) break;
    }
    check_output(emitted, conn.remote_settings().max_frame_size);
    return 0;
}
