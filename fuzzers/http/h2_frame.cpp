// h2_frame.cpp — RFC 9113 frame codec. The 9-byte header comes from the
// input, the rest is the payload in an exact-size buffer (as the connection
// hands it over). Every parser is called with a payload whose length the
// header claims; every accepted frame is re-serialized with the matching
// writer and must parse back to the same values.

#include "boltapi/http/http2_frame.h"
#include "fuzz_util.h"

#include <cstring>
#include <string>
#include <vector>

using namespace bolt::api::http2;

namespace {

void fuzz_data(const FrameHeader& h, const std::vector<std::uint8_t>& p) {
    auto r = parse_data_frame(h, p.data(), p.size());
    if (r.is_err()) return;
    const std::string& d = r.value();
    FUZZ_CHECK(d.size() <= p.size());
    std::vector<std::uint8_t> out(9 + d.size());
    const std::size_t n = write_data_frame_to(out.data(), out.size(), h.stream_id,
                                              reinterpret_cast<const std::uint8_t*>(d.data()),
                                              d.size(), false);
    FUZZ_CHECK(n == out.size());
}

void fuzz_headers(const FrameHeader& h, const std::vector<std::uint8_t>& p) {
    PrioritySpec pr;
    std::vector<std::uint8_t> block;
    if (parse_headers_frame(h, p.data(), p.size(), &pr, block).is_err()) return;
    FUZZ_CHECK(block.size() <= p.size());
    std::vector<std::uint8_t> out(9 + 5 + block.size());
    const std::size_t n = write_headers_frame_to(out.data(), out.size(), 1, block.data(),
                                                 block.size(), false, true, &pr);
    FUZZ_CHECK(n > 0);
    auto hh = parse_frame_header(out.data());
    FUZZ_CHECK(hh.is_ok());
    PrioritySpec pr2;
    std::vector<std::uint8_t> block2;
    FUZZ_CHECK(parse_headers_frame(hh.value(), out.data() + 9, n - 9, &pr2, block2).is_ok());
    FUZZ_CHECK(block2 == block);
}

void fuzz_settings(const FrameHeader& h, const std::vector<std::uint8_t>& p) {
    auto r = parse_settings_frame(h, p.data(), p.size());
    if (r.is_err()) return;
    const auto& params = r.value();
    FUZZ_CHECK(params.size() * 6 == p.size());
    std::vector<std::uint8_t> out(9 + 6 * params.size() + 1);
    const std::size_t n = write_settings_frame_to(out.data(), out.size(), params.data(),
                                                  params.size(), false);
    FUZZ_CHECK(n == 9 + 6 * params.size());
    if (!params.empty()) FUZZ_CHECK(std::memcmp(out.data() + 9, p.data(), p.size()) == 0);
}

void fuzz_goaway(const std::vector<std::uint8_t>& p) {
    std::uint32_t last = 0;
    ErrorCode ec{};
    std::string dbg;
    if (parse_goaway_frame(p.data(), p.size(), last, ec, dbg).is_err()) return;
    FUZZ_CHECK(last <= 0x7FFFFFFFu);
    FUZZ_CHECK(dbg.size() + 8 == p.size());
}

void fuzz_push_promise(const FrameHeader& h, const std::vector<std::uint8_t>& p) {
    std::uint32_t promised = 0;
    std::vector<std::uint8_t> block;
    if (parse_push_promise_frame(h, p.data(), p.size(), promised, block).is_err()) return;
    FUZZ_CHECK(block.size() + 4 <= p.size());
    FUZZ_CHECK(promised <= 0x7FFFFFFFu);
}

void fuzz_fixed(const FrameHeader& h, const std::vector<std::uint8_t>& p) {
    // Fixed-size payloads: any other length is FRAME_SIZE_ERROR, never a read.
    const std::uint8_t* d = p.empty() ? nullptr : p.data();
    switch (h.type) {
    case FrameType::PRIORITY:
        FUZZ_CHECK(parse_priority_frame(d, p.size()).is_ok() == (p.size() == 5));
        break;
    case FrameType::RST_STREAM:
        FUZZ_CHECK(parse_rst_stream_frame(d, p.size()).is_ok() == (p.size() == 4));
        break;
    case FrameType::PING: {
        auto r = parse_ping_frame(d, p.size());
        FUZZ_CHECK(r.is_ok() == (p.size() == 8));
        if (r.is_ok()) {
            std::uint8_t out[17];
            FUZZ_CHECK(write_ping_frame_to(out, sizeof(out), r.value(), true) == 17);
            FUZZ_CHECK(std::memcmp(out + 9, p.data(), 8) == 0);
        }
        break;
    }
    case FrameType::WINDOW_UPDATE: {
        auto r = parse_window_update_frame(d, p.size());
        if (p.size() != 4) FUZZ_CHECK(r.is_err());
        if (r.is_ok()) FUZZ_CHECK(r.value() > 0 && r.value() <= 0x7FFFFFFFu);
        break;
    }
    default:
        break;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 9) return 0;
    auto hr = parse_frame_header(data);
    FUZZ_CHECK(hr.is_ok());
    FrameHeader h = hr.value();
    FUZZ_CHECK(h.length <= 0xFFFFFFu);
    FUZZ_CHECK(h.stream_id <= 0x7FFFFFFFu);
    std::uint8_t back[9];
    write_frame_header(h, back);
    FUZZ_CHECK(std::memcmp(back, data, 4) == 0);  // length + type round-trip
    std::vector<std::uint8_t> payload(data + 9, data + size);
    h.length = static_cast<std::uint32_t>(payload.size() & 0xFFFFFFu);
    if (payload.size() > 0xFFFFFFu) return 0;
    switch (h.type) {
    case FrameType::DATA: fuzz_data(h, payload); break;
    case FrameType::HEADERS: fuzz_headers(h, payload); break;
    case FrameType::SETTINGS: fuzz_settings(h, payload); break;
    case FrameType::GOAWAY: fuzz_goaway(payload); break;
    case FrameType::PUSH_PROMISE: fuzz_push_promise(h, payload); break;
    default: fuzz_fixed(h, payload); break;
    }
    return 0;
}
