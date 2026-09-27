// qpack — RFC 9204 decoder (field sections + encoder-stream instructions) and
// RFC 7541 Huffman decoding, with encoder round trips as an oracle: any header
// list the decoder accepts must re-encode and decode back to the same list.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "boltapi/http3/qpack.h"
#include "fuzz_input.h"

namespace h3 = bolt::api::http3;
using boltapi_fuzz::Input;

namespace {

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "qpack invariant failed: %s\n", what);
        std::abort();
    }
}

struct State {
    h3::QpackDecoder dec;
    h3::QpackHeader hdrs[h3::kQpackMaxHeaders];
    h3::QpackHeader back[h3::kQpackMaxHeaders];
    h3::QpackHeaderRef refs[h3::kQpackMaxHeaders];
    std::uint8_t enc_out[1 << 18];
    std::uint8_t huff[h3::kQpackMaxStringLen];
};

void round_trip(State& s, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        if (s.hdrs[i].name.empty()) return;  // encoder requires non-empty names
        s.refs[i] = {s.hdrs[i].name, s.hdrs[i].value};
    }
    h3::QpackEncoder enc;
    std::size_t w = 0;
    if (enc.encode_field_section(s.refs, count, s.enc_out, sizeof(s.enc_out), w) != 0)
        return;
    h3::QpackDecoder fresh;
    std::size_t got = 0;
    for (auto& b : s.back) { b.name.clear(); b.value.clear(); }
    check(fresh.decode_field_section(s.enc_out, w, s.back, got) == 0, "re-decode");
    check(got == count, "round trip header count");
    for (std::size_t i = 0; i < count; ++i)
        check(s.back[i].name == s.hdrs[i].name && s.back[i].value == s.hdrs[i].value,
              "round trip header value");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    Input in(data, size);
    static State* s = new State();
    s->dec.dynamic_table().clear();
    s->dec.dynamic_table().set_capacity(4096);
    for (std::size_t op = 0; op < 16 && !in.empty(); ++op) {
        const std::uint8_t kind = in.u8();
        std::size_t n = 0;
        const std::uint8_t* d = in.chunk(1 << 15, n);
        if (kind % 3 == 0) {
            (void)s->dec.decode_encoder_stream(d, n);
        } else if (kind % 3 == 1) {
            for (auto& h : s->hdrs) { h.name.clear(); h.value.clear(); }
            std::size_t count = 0;
            if (s->dec.decode_field_section(d, n, s->hdrs, count) == 0)
                round_trip(*s, count);
        } else {
            std::size_t out = 0;
            if (h3::qpack_huffman_decode(d, n, s->huff, sizeof(s->huff), out) == 0) {
                check(out <= sizeof(s->huff), "huffman out bound");
                std::uint8_t re[h3::kQpackMaxStringLen * 4];
                std::size_t rl = 0;
                check(h3::qpack_huffman_encode(s->huff, out, re, sizeof(re), rl) == 0,
                      "huffman re-encode");
                std::size_t out2 = 0;
                std::uint8_t again[h3::kQpackMaxStringLen];
                check(h3::qpack_huffman_decode(re, rl, again, sizeof(again), out2) == 0 &&
                          out2 == out && std::memcmp(again, s->huff, out) == 0,
                      "huffman round trip");
            }
        }
    }
    return 0;
}
