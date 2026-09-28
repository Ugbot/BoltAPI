// tests/neo4j_values_test.cpp — Bolt graph + temporal structures, both dialects.
//
// Expected bytes come from the published Bolt structure spec
// (https://neo4j.com/docs/bolt/current/bolt/structure-semantics/): Bolt 4.4
// shapes without element ids and with the legacy DateTime, Bolt 5 shapes with
// them. "Bolt" is Neo4j's wire protocol, not extern/bolt.

#include "boltapi/proto/neo4j_values.h"
#include "boltapi/proto/packstream.h"
#include "neo4j_bolt_value_gen.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace ps = bolt::api::proto::packstream;
namespace nv = bolt::api::proto::neo4j::values;

namespace {

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        if (i) s.push_back(' ');
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xF]);
    }
    return s;
}

struct Fx {
    std::vector<std::uint8_t> mem = std::vector<std::uint8_t>(1u << 16);
    ps::PackArena a{mem.data(), mem.size()};
    std::uint8_t buf[512];

    std::string wire(const ps::PackValue& v, std::uint8_t major, ps::PackError* err = nullptr) {
        ps::PackWriter w(buf, sizeof(buf));
        const ps::PackError e = nv::write_value(w, v, major);
        if (err != nullptr) *err = e;
        return e == ps::PackError::Ok ? hex(w.data(), w.size()) : std::string("ERR");
    }

    ps::PackValue node(std::int64_t id) {
        ps::PackValue out{};
        EXPECT_EQ(nv::make_node(a, id, nullptr, 0, nullptr, 0, &out), ps::PackError::Ok);
        return out;
    }

    ps::PackValue ints(std::initializer_list<std::int64_t> xs, ps::PackValue* store) {
        std::uint32_t k = 0;
        for (std::int64_t x : xs) {
            store[k] = ps::PackValue{};
            store[k].type = ps::PackType::Int;
            store[k].i = x;
            ++k;
        }
        ps::PackValue l{};
        l.type = ps::PackType::List;
        l.items = store;
        l.len = k;
        return l;
    }
};

}  // namespace

TEST(Neo4jValues, NodeIsThreeFieldsOnBolt4AndCarriesElementIdOnBolt5) {
    Fx f;
    const std::string_view labels[] = {"Person"};
    ps::PackValue name{};
    name.type = ps::PackType::String;
    name.bytes = "Alice";
    name.len = 5;
    ps::PackPair props[1] = {{"name", 4, &name}};
    ps::PackValue n{};
    ASSERT_EQ(nv::make_node(f.a, 1, labels, 1, props, 1, &n), ps::PackError::Ok);
    EXPECT_EQ(f.wire(n, 4), "B3 4E 01 91 86 50 65 72 73 6F 6E A1 84 6E 61 6D 65 85 41 6C 69 63 65");
    EXPECT_EQ(f.wire(n, 5),
              "B4 4E 01 91 86 50 65 72 73 6F 6E A1 84 6E 61 6D 65 85 41 6C 69 63 65 81 31");
}

TEST(Neo4jValues, RelationshipCarriesThreeElementIdsOnBolt5) {
    Fx f;
    ps::PackValue r{};
    ASSERT_EQ(nv::make_relationship(f.a, 7, 1, 2, "KNOWS", nullptr, 0, &r), ps::PackError::Ok);
    EXPECT_EQ(f.wire(r, 4), "B5 52 07 01 02 85 4B 4E 4F 57 53 A0");
    EXPECT_EQ(f.wire(r, 5), "B8 52 07 01 02 85 4B 4E 4F 57 53 A0 81 37 81 31 81 32");
}

TEST(Neo4jValues, PathShapesItsNodesAndUnboundRelationships) {
    Fx f;
    ps::PackValue nodes[2] = {f.node(1), f.node(2)};
    ps::PackValue rels[1];
    ASSERT_EQ(nv::make_unbound_relationship(f.a, 7, "T", nullptr, 0, &rels[0]), ps::PackError::Ok);
    ps::PackValue idx_store[2];
    const ps::PackValue idx = f.ints({1, 1}, idx_store);
    ps::PackValue p{};
    ASSERT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, idx.items, 2, &p), ps::PackError::Ok);
    EXPECT_EQ(f.wire(p, 4),
              "B3 50 92 B3 4E 01 90 A0 B3 4E 02 90 A0 91 B3 72 07 81 54 A0 92 01 01");
    EXPECT_EQ(f.wire(p, 5),
              "B3 50 92 B4 4E 01 90 A0 81 31 B4 4E 02 90 A0 81 32 91 B4 72 07 81 54 A0 81 37"
              " 92 01 01");
}

TEST(Neo4jValues, PathIndicesMustWalkTheirOwnNodesAndRelationships) {
    Fx f;
    ps::PackValue nodes[2] = {f.node(1), f.node(2)};
    ps::PackValue rels[1];
    ASSERT_EQ(nv::make_unbound_relationship(f.a, 7, "T", nullptr, 0, &rels[0]), ps::PackError::Ok);
    ps::PackValue s[2];
    ps::PackValue p{};
    // relationship index 0 does not exist (they are 1-based)
    EXPECT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, f.ints({0, 1}, s).items, 2, &p),
              ps::PackError::Invalid);
    // relationship 2 does not exist
    EXPECT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, f.ints({-2, 1}, s).items, 2, &p),
              ps::PackError::Invalid);
    // node 2 does not exist
    EXPECT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, f.ints({1, 2}, s).items, 2, &p),
              ps::PackError::Invalid);
    // odd index list
    EXPECT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, f.ints({1}, s).items, 1, &p),
              ps::PackError::Invalid);
    // no nodes at all
    EXPECT_EQ(nv::make_path(f.a, nodes, 0, rels, 0, nullptr, 0, &p), ps::PackError::Invalid);
    // a backwards hop is valid
    EXPECT_EQ(nv::make_path(f.a, nodes, 2, rels, 1, f.ints({-1, 1}, s).items, 2, &p),
              ps::PackError::Ok);
}

TEST(Neo4jValues, TemporalBytesMatchTheSpec) {
    Fx f;
    ps::PackValue v{};
    ASSERT_EQ(nv::make_date(f.a, 19000, &v), ps::PackError::Ok);
    EXPECT_EQ(f.wire(v, 4), "B1 44 C9 4A 38");
    EXPECT_EQ(f.wire(v, 5), "B1 44 C9 4A 38");

    // one microsecond before the epoch: seconds floor to -1, nanos stay positive
    ASSERT_EQ(nv::make_local_date_time_from_micros(f.a, -1, &v), ps::PackError::Ok);
    EXPECT_EQ(f.wire(v, 5), "B2 64 FF CA 3B 9A C6 18");

    ASSERT_EQ(nv::make_time(f.a, 3600LL * 1000000000LL, -3600, &v), ps::PackError::Ok);
    EXPECT_EQ(f.wire(v, 5), "B2 54 CB 00 00 03 46 30 B8 A0 00 C9 F1 F0");

    ASSERT_EQ(nv::make_duration(f.a, 14, 16, 12, 0, &v), ps::PackError::Ok);
    EXPECT_EQ(f.wire(v, 4), "B4 45 0E 10 0C 00");
}

TEST(Neo4jValues, DateTimeIsLegacyLocalSecondsOnBolt4) {
    Fx f;
    ps::PackValue v{};
    ASSERT_EQ(nv::make_date_time(f.a, 1000, 5, 3600, &v), ps::PackError::Ok);
    EXPECT_EQ(f.wire(v, 5), "B3 49 C9 03 E8 05 C9 0E 10");
    EXPECT_EQ(f.wire(v, 4), "B3 46 C9 11 F8 05 C9 0E 10");

    ps::PackValue z{};
    ASSERT_EQ(nv::make_date_time_zone_id(f.a, 1000, 5, "UTC", &z), ps::PackError::Ok);
    EXPECT_EQ(f.wire(z, 5), "B3 69 C9 03 E8 05 83 55 54 43");
    ps::PackError e = ps::PackError::Ok;
    EXPECT_EQ(f.wire(z, 4, &e), "ERR");
    EXPECT_EQ(e, ps::PackError::Unsupported);

    // A legacy value handed to a Bolt 5 session is converted back to UTC.
    ps::PackValue* fl = f.a.alloc_n<ps::PackValue>(3);
    ASSERT_NE(fl, nullptr);
    ps::PackValue lg{};
    lg.type = ps::PackType::Struct;
    lg.signature = nv::kSigLegacyDateTime;
    lg.items = fl;
    lg.len = 3;
    f.ints({4600, 5, 3600}, fl);
    EXPECT_EQ(f.wire(lg, 5), "B3 49 C9 03 E8 05 C9 0E 10");
}

TEST(Neo4jValues, OutOfRangeTemporalsAreRefused) {
    Fx f;
    ps::PackValue v{};
    EXPECT_EQ(nv::make_local_date_time(f.a, 0, 1000000000, &v), ps::PackError::Invalid);
    EXPECT_EQ(nv::make_local_date_time(f.a, 0, -1, &v), ps::PackError::Invalid);
    EXPECT_EQ(nv::make_local_time(f.a, nv::kNanosPerDay, &v), ps::PackError::Invalid);
    EXPECT_EQ(nv::make_date_time(f.a, 0, 0, 19 * 3600, &v), ps::PackError::Invalid);
    EXPECT_EQ(nv::make_date_time_zone_id(f.a, 0, 0, "", &v), ps::PackError::Invalid);
}

TEST(Neo4jValues, MalformedStructuresAreRefusedNotForwarded) {
    Fx f;
    // a Node whose label is an integer
    ps::PackValue fields[3];
    ps::PackValue lbl[1];
    f.ints({1}, fields);
    const ps::PackValue l = f.ints({7}, lbl);
    fields[1] = l;
    fields[2] = ps::PackValue{};
    fields[2].type = ps::PackType::Dict;
    ps::PackValue bad{};
    bad.type = ps::PackType::Struct;
    bad.signature = nv::kSigNode;
    bad.items = fields;
    bad.len = 3;
    ps::PackError e = ps::PackError::Ok;
    EXPECT_EQ(f.wire(bad, 5, &e), "ERR");
    EXPECT_EQ(e, ps::PackError::Invalid);

    // the same node nested inside a list is refused too
    ps::PackValue list{};
    list.type = ps::PackType::List;
    list.items = &bad;
    list.len = 1;
    EXPECT_EQ(f.wire(list, 4, &e), "ERR");
    EXPECT_EQ(e, ps::PackError::Invalid);

    // an unknown structure signature is not a Bolt value
    ps::PackValue unk{};
    unk.type = ps::PackType::Struct;
    unk.signature = 0x13;
    unk.items = fields;
    unk.len = 1;
    EXPECT_EQ(f.wire(unk, 5, &e), "ERR");
    EXPECT_EQ(e, ps::PackError::Unsupported);
}

// Random trees round-trip through the decoder in both dialects and describe the
// same before and after, element ids included.
TEST(Neo4jValues, RandomValuesRoundTripInBothDialects) {
    std::vector<std::uint8_t> mem_a(1u << 20), mem_b(1u << 20), out(1u << 20);
    for (std::uint64_t seed = 1; seed <= 400; ++seed) {
        for (std::uint8_t major = 4; major <= 5; ++major) {
            ps::PackArena a(mem_a.data(), mem_a.size());
            boltapi_test::SplitMix rng{seed};
            boltapi_test::GenOptions o;
            std::int64_t ids = 0;
            o.id_seq = &ids;
            o.allow_zone_id = (major == 5);
            const ps::PackValue v = boltapi_test::gen_value(a, rng, o, 0);
            std::string want;
            ASSERT_TRUE(boltapi_test::describe(v, true, want)) << seed;
            ps::PackWriter w(out.data(), out.size());
            ASSERT_EQ(nv::write_value(w, v, major), ps::PackError::Ok) << seed << " " << want;
            ps::PackArena b(mem_b.data(), mem_b.size());
            ps::PackReader r(w.data(), w.size(), b);
            ps::PackValue got{};
            ASSERT_EQ(r.read(got), ps::PackError::Ok);
            EXPECT_TRUE(r.at_end());
            std::string have;
            ASSERT_TRUE(boltapi_test::describe(got, true, have)) << seed;
            EXPECT_EQ(have, want) << "seed " << seed << " bolt " << int(major);
        }
    }
}
