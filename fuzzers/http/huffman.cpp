// huffman.cpp — RFC 7541 Huffman codec: decode arbitrary bytes (never read or
// write out of bounds; accepted input must re-encode to itself modulo the
// padding the spec allows), and encode->decode round-trips any octets.

#include "boltapi/http/huffman.h"
#include "fuzz_util.h"

#include <cstring>
#include <vector>

using bolt::api::http::HuffmanDecoder;
using bolt::api::http::HuffmanEncoder;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;
    const std::size_t cap = static_cast<std::size_t>(data[0]) * 16 + 1;
    const std::uint8_t* in = data + 1;
    const std::size_t len = size - 1;

    // 1) decode arbitrary input into a buffer of fuzzer-chosen capacity.
    std::vector<std::uint8_t> out(cap);
    std::size_t dlen = 0;
    if (len > 0 && HuffmanDecoder::decode(in, len, out.data(), cap, dlen) == 0) {
        FUZZ_CHECK(dlen <= cap);
        std::vector<std::uint8_t> re(HuffmanEncoder::encoded_size(out.data(), dlen) + 1);
        std::size_t elen = 0;
        if (dlen > 0) {
            FUZZ_CHECK(HuffmanEncoder::encode(out.data(), dlen, re.data(), re.size(), elen) == 0);
            // Canonical: the only freedom is none — RFC 7541 5.2 pads with the
            // EOS prefix, so a valid encoding is unique.
            FUZZ_CHECK(elen == len);
            FUZZ_CHECK(std::memcmp(re.data(), in, len) == 0);
        }
    }

    // 2) round-trip the raw input as plaintext.
    if (len > 0) {
        const std::size_t need = HuffmanEncoder::encoded_size(in, len);
        std::vector<std::uint8_t> enc(need);
        std::size_t elen = 0;
        FUZZ_CHECK(HuffmanEncoder::encode(in, len, enc.data(), enc.size(), elen) == 0);
        FUZZ_CHECK(elen == need);
        std::vector<std::uint8_t> dec(len);
        std::size_t dl = 0;
        FUZZ_CHECK(HuffmanDecoder::decode(enc.data(), elen, dec.data(), dec.size(), dl) == 0);
        FUZZ_CHECK(dl == len);
        FUZZ_CHECK(std::memcmp(dec.data(), in, len) == 0);
    }
    return 0;
}
