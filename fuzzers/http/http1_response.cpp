// http1_response.cpp — the outbound client's ResponseParser fed an upstream
// response in reads of fuzzer-chosen size (byte 0 seeds the splitter).

#include "boltapi/http/client.h"
#include "fuzz_util.h"

using bolt::api::http::ResponseParser;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    boltapi_fuzz::Splitter split(data[0]);
    const char* in = reinterpret_cast<const char*>(data + 1);
    const std::size_t len = size - 1;
    ResponseParser p;
    p.reset();
    std::size_t off = 0;
    ResponseParser::State st = ResponseParser::State::NeedMore;
    while (off < len && st == ResponseParser::State::NeedMore) {
        const std::size_t n = split.chunk(len - off);
        st = p.consume(in + off, n);
        off += n;
    }
    if (st != ResponseParser::State::Complete) return 0;
    FUZZ_CHECK(p.status() >= 100 && p.status() <= 599);
    const std::string_view body = p.body();
    FUZZ_CHECK(body.size() == p.body_len());
    for (std::size_t i = 0; i < p.header_count(); ++i) {
        FUZZ_CHECK(p.header_name(i).size() <= len);
        FUZZ_CHECK(p.header_value(i).size() <= len);
    }
    return 0;
}
