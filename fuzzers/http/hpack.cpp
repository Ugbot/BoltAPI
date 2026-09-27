// hpack.cpp — HPACKDecoder over a sequence of header blocks sharing one
// dynamic table (as on a connection), plus a round-trip: every block the
// decoder accepts is re-encoded by a persistent HPACKEncoder and decoded by a
// persistent mirror decoder, which must reproduce the same header list.
//
// Input: records of [op][len_hi][len_lo][len bytes].
//   op & 3 == 0 : decode the bytes as one header block
//   op & 3 == 1 : SETTINGS_HEADER_TABLE_SIZE on the decoder (len = size)
//   op & 3 == 2 : SETTINGS_HEADER_TABLE_SIZE from the peer on the encoder

#include "boltapi/http/hpack.h"
#include "fuzz_util.h"

#include <string>
#include <utility>
#include <vector>

using bolt::api::http::HPACKDecoder;
using bolt::api::http::HPACKEncoder;
using bolt::api::http::HPACKHeader;

namespace {
constexpr std::size_t kMaxRecords = 64;
constexpr std::size_t kEncCap = 64 * 1024;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    HPACKDecoder dec;
    HPACKEncoder enc;
    HPACKDecoder mirror;
    std::vector<std::uint8_t> ebuf(kEncCap);
    std::size_t off = 0;
    for (std::size_t rec = 0; rec < kMaxRecords && off + 3 <= size; ++rec) {
        const std::uint8_t op = data[off];
        const std::size_t len = (static_cast<std::size_t>(data[off + 1]) << 8) | data[off + 2];
        off += 3;
        if ((op & 3) == 1) {
            dec.set_max_table_size(len);
            continue;
        }
        if ((op & 3) == 2) {
            enc.set_max_table_size(len);
            continue;
        }
        const std::size_t n = len < size - off ? len : size - off;
        // Exact-size copy: HEADERS payloads reach the decoder as their own buffer.
        std::vector<std::uint8_t> block(data + off, data + off + n);
        off += n;
        std::vector<HPACKHeader> out;
        const int rc = dec.decode(block.data(), block.size(), out);
        if (rc == HPACKDecoder::kCompressionError) break;  // ends the connection
        FUZZ_CHECK(out.size() <= 100);
        if (rc != HPACKDecoder::kOk) continue;
        std::vector<std::pair<std::string, std::string>> got;
        for (const auto& h : out) got.emplace_back(std::string(h.name), std::string(h.value));

        std::size_t written = 0;
        if (enc.encode(out.data(), out.size(), ebuf.data(), ebuf.size(), written) != 0) continue;
        FUZZ_CHECK(written <= ebuf.size());
        std::vector<std::uint8_t> eblock(ebuf.data(), ebuf.data() + written);
        std::vector<HPACKHeader> back;
        FUZZ_CHECK(mirror.decode(eblock.data(), eblock.size(), back) == 0);
        FUZZ_CHECK(back.size() == got.size());
        for (std::size_t i = 0; i < back.size(); ++i) {
            FUZZ_CHECK(back[i].name == got[i].first);
            FUZZ_CHECK(back[i].value == got[i].second);
        }
    }
    return 0;
}
