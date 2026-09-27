// packstream — the PackStream v2 decoder every Neo4j Bolt message goes
// through, plus a decode -> encode -> decode -> encode fixpoint check.
#include "fuzz_util.h"

#include "boltapi/proto/packstream.h"

#include <vector>

namespace ps = bolt::api::proto::packstream;

namespace {

constexpr std::size_t kArena = 1u << 20;
constexpr std::size_t kOut = 1u << 20;
constexpr std::uint32_t kMaxValues = 64;

void probe(const ps::PackValue& v) {
    if (v.type == ps::PackType::Dict) {
        (void)v.find("n");
        (void)v.find_str("scheme");
        (void)v.find_int("n", -1);
        for (std::uint32_t i = 0; i < v.len; ++i) {
            FUZZ_CHECK(v.pairs != nullptr);
            (void)v.pairs[i].key_view();
        }
    }
    (void)v.str();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static std::vector<std::uint8_t> arena_a(kArena), arena_b(kArena);
    static std::vector<std::uint8_t> out1(kOut), out2(kOut);
    if (size >= (std::size_t{1} << 31)) return 0;
    ps::PackArena a(arena_a.data(), arena_a.size());
    ps::PackReader r(data, size, a);
    for (std::uint32_t k = 0; k < kMaxValues && !r.at_end(); ++k) {
        ps::PackValue v{};
        const std::size_t before = r.offset();
        if (r.read(v) != ps::PackError::Ok) break;
        FUZZ_CHECK(r.offset() > before && r.offset() <= size);
        probe(v);

        ps::PackWriter w1(out1.data(), out1.size());
        if (w1.put_value(v) != ps::PackError::Ok || w1.overflowed()) continue;
        ps::PackArena b(arena_b.data(), arena_b.size());
        ps::PackReader r2(w1.data(), w1.size(), b);
        ps::PackValue v2{};
        const ps::PackError e2 = r2.read(v2);
        FUZZ_CHECK(e2 == ps::PackError::Ok || e2 == ps::PackError::OutOfMemory);
        if (e2 != ps::PackError::Ok) continue;
        FUZZ_CHECK(r2.at_end());
        ps::PackWriter w2(out2.data(), out2.size());
        FUZZ_CHECK(w2.put_value(v2) == ps::PackError::Ok);
        FUZZ_CHECK(w2.size() == w1.size());
        FUZZ_CHECK(std::memcmp(w1.data(), w2.data(), w1.size()) == 0);
    }
    return 0;
}
