// neo4j_values — Bolt graph + temporal structures (proto/neo4j_values.h).
//
// Byte 0 picks the dialect (bit 0: Bolt 4.4 / 5) and the mode (bit 1).
//   structured: the rest of the input drives a random value tree; it is
//     written, decoded, and must describe identically, re-encode to the same
//     bytes, and survive the other dialect minus element ids.
//   raw: the rest is decoded as PackStream; whatever write_value accepts must
//     decode, describe as the input did (element ids aside), and re-encode to
//     a fixpoint.
#include "fuzz_util.h"

#include "boltapi/proto/neo4j_values.h"
#include "boltapi/proto/packstream.h"
#include "neo4j_bolt_value_gen.h"

#include <string>
#include <vector>

namespace ps = bolt::api::proto::packstream;
namespace nv = bolt::api::proto::neo4j::values;

namespace {

constexpr std::size_t kArena = 1u << 20;
constexpr std::size_t kOut = 1u << 20;
constexpr std::uint32_t kMaxValues = 16;

struct Bufs {
    std::vector<std::uint8_t> a = std::vector<std::uint8_t>(kArena);
    std::vector<std::uint8_t> b = std::vector<std::uint8_t>(kArena);
    std::vector<std::uint8_t> o1 = std::vector<std::uint8_t>(kOut);
    std::vector<std::uint8_t> o2 = std::vector<std::uint8_t>(kOut);
};

// Encode `v`, decode it into `arena`, re-encode; returns false when the first
// write refused. Aborts on any inconsistency after an accepted write.
bool round_trip(Bufs& B, const ps::PackValue& v, std::uint8_t major, bool with_eid,
                const std::string* want) {
    ps::PackWriter w1(B.o1.data(), B.o1.size());
    if (nv::write_value(w1, v, major) != ps::PackError::Ok) return false;
    FUZZ_CHECK(!w1.overflowed());
    ps::PackArena ab(B.b.data(), B.b.size());
    ps::PackReader r(w1.data(), w1.size(), ab);
    ps::PackValue got{};
    const ps::PackError de = r.read(got);
    FUZZ_CHECK(de == ps::PackError::Ok || de == ps::PackError::OutOfMemory);
    if (de != ps::PackError::Ok) return true;
    FUZZ_CHECK(r.at_end());
    if (want != nullptr) {
        std::string have;
        FUZZ_CHECK(boltapi_test::describe(got, with_eid, have));
        if (have != *want) {
            std::fprintf(stderr, "want %s\nhave %s\n", want->c_str(), have.c_str());
            FUZZ_CHECK(have == *want);
        }
    }
    ps::PackWriter w2(B.o2.data(), B.o2.size());
    FUZZ_CHECK(nv::write_value(w2, got, major) == ps::PackError::Ok);
    FUZZ_CHECK(w2.size() == w1.size());
    FUZZ_CHECK(std::memcmp(w1.data(), w2.data(), w1.size()) == 0);
    return true;
}

void structured(Bufs& B, const std::uint8_t* d, std::size_t n, std::uint8_t major,
                std::uint8_t ctl) {
    ps::PackArena a(B.a.data(), B.a.size());
    boltapi_test::ByteSource src{d, n};
    boltapi_test::GenOptions o;
    std::int64_t ids = 0;
    o.id_seq = &ids;
    o.allow_zone_id = (major == 5);
    o.max_depth = 1u + ((ctl >> 2) & 3u);
    const ps::PackValue v = boltapi_test::gen_value(a, src, o, 0);
    std::string want, want_noeid;
    FUZZ_CHECK(boltapi_test::describe(v, true, want));
    FUZZ_CHECK(boltapi_test::describe(v, false, want_noeid));
    FUZZ_CHECK(round_trip(B, v, major, true, &want));
    // A Bolt 4 tree (no zone ids) has a form in both dialects; a Bolt 5 one
    // may carry a zone id, which Bolt 4 refuses.
    FUZZ_CHECK(round_trip(B, v, major == 5 ? 4 : 5, false, &want_noeid) || major == 5);
}

void raw(Bufs& B, const std::uint8_t* d, std::size_t n) {
    ps::PackArena a(B.a.data(), B.a.size());
    ps::PackReader r(d, n, a);
    for (std::uint32_t k = 0; k < kMaxValues && !r.at_end(); ++k) {
        ps::PackValue v{};
        if (r.read(v) != ps::PackError::Ok) return;
        std::string want;
        const bool describable = boltapi_test::describe(v, false, want);
        for (std::uint8_t major = 4; major <= 5; ++major) {
            (void)round_trip(B, v, major, false, describable ? &want : nullptr);
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static Bufs* B = new Bufs();
    if (size == 0 || size >= (std::size_t{1} << 24)) return 0;
    const std::uint8_t ctl = data[0];
    const std::uint8_t major = (ctl & 1u) ? 5 : 4;
    if ((ctl & 2u) == 0u) {
        structured(*B, data + 1, size - 1, major, ctl);
    } else {
        raw(*B, data + 1, size - 1);
    }
    return 0;
}
