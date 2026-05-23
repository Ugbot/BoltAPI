// QPACK (RFC 9204) round-trip and conformance tests for bolt::api::http3.
//
// Covers: typical HTTP/3 GET request and response field sections, static-table
// indexed fields, literal-with-name-ref, Huffman strings, dynamic-table insert
// + reference round-trips (via encoder/decoder stream instructions), RFC 9204
// Appendix B worked examples, and randomized fuzz round-trips across multiple
// HTTP verbs / header sets.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "boltapi/http3/qpack.h"
#include "boltapi/http3/qpack_huffman.h"
#include "boltapi/http3/qpack_static_table.h"

namespace {

using bolt::api::http3::QpackDecoder;
using bolt::api::http3::QpackEncoder;
using bolt::api::http3::QpackHeader;
using bolt::api::http3::QpackHeaderRef;
using bolt::api::http3::QpackStaticTable;

// Encode `headers` then decode and assert the decoded set equals the input.
void RoundTrip(const std::vector<QpackHeaderRef>& headers, bool huffman) {
    QpackEncoder enc;
    enc.set_huffman(huffman);
    std::array<uint8_t, 8192> buf{};
    std::size_t enc_len = 0;
    ASSERT_EQ(enc.encode_field_section(headers.data(), headers.size(),
                                       buf.data(), buf.size(), enc_len),
              0);
    ASSERT_GT(enc_len, 0u);

    QpackDecoder dec;
    std::array<QpackHeader, 256> out{};
    std::size_t out_count = 0;
    ASSERT_EQ(dec.decode_field_section(buf.data(), enc_len, out.data(), out_count),
              0);
    ASSERT_EQ(out_count, headers.size());
    for (std::size_t i = 0; i < headers.size(); ++i) {
        EXPECT_EQ(out[i].name, std::string(headers[i].name)) << "idx " << i;
        EXPECT_EQ(out[i].value, std::string(headers[i].value)) << "idx " << i;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Static table sanity.
// ---------------------------------------------------------------------------
TEST(QpackStaticTable, KnownEntries) {
    EXPECT_EQ(QpackStaticTable::size(), 99u);
    const auto* m = QpackStaticTable::get(17);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->name, ":method");
    EXPECT_EQ(m->value, "GET");
    EXPECT_EQ(QpackStaticTable::find(":status", "200"), 25);
    EXPECT_EQ(QpackStaticTable::find(":path", "/"), 1);
    EXPECT_EQ(QpackStaticTable::find_name("content-type"), 44);
    EXPECT_EQ(QpackStaticTable::get(99), nullptr);
    EXPECT_EQ(QpackStaticTable::find("nonexistent", "x"),
              QpackStaticTable::kNotFound);
}

// ---------------------------------------------------------------------------
// Representative request: :method/:scheme/:authority/:path + a few headers.
// ---------------------------------------------------------------------------
TEST(QpackRoundTrip, GetRequest) {
    std::vector<QpackHeaderRef> headers = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {":path", "/index.html"},
        {"user-agent", "bolt-http3/1.0"},
        {"accept", "*/*"},
        {"accept-encoding", "gzip, deflate, br"},
    };
    RoundTrip(headers, /*huffman=*/false);
    RoundTrip(headers, /*huffman=*/true);
}

// ---------------------------------------------------------------------------
// Representative response: :status + content-type/length.
// ---------------------------------------------------------------------------
TEST(QpackRoundTrip, Response) {
    std::vector<QpackHeaderRef> headers = {
        {":status", "200"},
        {"content-type", "application/json"},
        {"content-length", "1234"},
        {"server", "bolt"},
        {"cache-control", "no-cache"},
    };
    RoundTrip(headers, /*huffman=*/false);
    RoundTrip(headers, /*huffman=*/true);
}

// Different verbs and status codes (POST/PUT/DELETE, 404/500/204).
TEST(QpackRoundTrip, MultipleVerbsAndStatuses) {
    RoundTrip({{":method", "POST"},
               {":scheme", "http"},
               {":authority", "api.test"},
               {":path", "/v1/items"},
               {"content-type", "application/x-www-form-urlencoded"}},
              true);
    RoundTrip({{":method", "DELETE"},
               {":path", "/v1/items/42"},
               {":status", "404"}},
              true);
    RoundTrip({{":status", "500"}, {"content-length", "0"}}, false);
    RoundTrip({{":status", "204"}}, true);
}

// ---------------------------------------------------------------------------
// Static indexed field: ":method GET" must encode as a single indexed line.
// ---------------------------------------------------------------------------
TEST(QpackEncode, StaticIndexedSingleByte) {
    QpackEncoder enc;
    enc.set_huffman(false);
    std::array<uint8_t, 64> buf{};
    std::size_t len = 0;
    QpackHeaderRef h[] = {{":method", "GET"}};
    ASSERT_EQ(enc.encode_field_section(h, 1, buf.data(), buf.size(), len), 0);
    // 2-byte prefix (RIC=0, base=0) + 1 indexed-field-line byte.
    EXPECT_EQ(len, 3u);
    // Indexed field line, static (T=1): 1 1 xxxxxx, index 17 => 0xC0|17 = 0xD1.
    EXPECT_EQ(buf[2], 0xC0u | 17u);
}

// ---------------------------------------------------------------------------
// Literal with name reference (static): name in table, novel value.
// ---------------------------------------------------------------------------
TEST(QpackRoundTrip, LiteralWithNameRef) {
    // "user-agent" is a name-only static entry (idx 95); value is novel.
    RoundTrip({{"user-agent", "CustomAgent/9.9 (test)"}}, false);
    RoundTrip({{"user-agent", "CustomAgent/9.9 (test)"}}, true);
    // ":authority" name ref (idx 0) + novel value.
    RoundTrip({{":authority", "host.invalid:8443"}}, true);
}

// ---------------------------------------------------------------------------
// Literal with literal name (neither name nor value in static table).
// ---------------------------------------------------------------------------
TEST(QpackRoundTrip, LiteralWithLiteralName) {
    RoundTrip({{"x-custom-header", "some-custom-value"},
               {"x-request-id", "abc-123-def-456"}},
              false);
    RoundTrip({{"x-custom-header", "some-custom-value"},
               {"x-request-id", "abc-123-def-456"}},
              true);
}

// ---------------------------------------------------------------------------
// Huffman string correctness at the codec level (encode->decode identity).
// ---------------------------------------------------------------------------
TEST(QpackHuffman, EncodeDecodeIdentity) {
    using bolt::api::http3::qpack_huffman_decode;
    using bolt::api::http3::qpack_huffman_encode;
    using bolt::api::http3::qpack_huffman_encoded_size;

    const std::vector<std::string> samples = {
        "www.example.com", "/sample/path/index.html", "no-cache",
        "Mozilla/5.0 (X11; Linux x86_64) bolt", "application/json",
        "custom-key", "a", "0123456789", "!@#$%^&*()_+-=[]{}",
    };
    for (const auto& s : samples) {
        std::array<uint8_t, 512> enc{};
        std::size_t enc_len = 0;
        const auto* sp = reinterpret_cast<const uint8_t*>(s.data());
        ASSERT_EQ(qpack_huffman_encode(sp, s.size(), enc.data(), enc.size(),
                                       enc_len),
                  0)
            << "encode failed for '" << s << "'";
        EXPECT_EQ(enc_len, qpack_huffman_encoded_size(sp, s.size()));

        std::array<uint8_t, 512> dec{};
        std::size_t dec_len = 0;
        ASSERT_EQ(qpack_huffman_decode(enc.data(), enc_len, dec.data(),
                                       dec.size(), dec_len),
                  0)
            << "decode failed for '" << s << "'";
        EXPECT_EQ(std::string(reinterpret_cast<char*>(dec.data()), dec_len), s);
    }
}

// RFC 7541 Appendix C.4.1 worked Huffman example: "www.example.com" ->
// f1e3 c2e5 f23a 6ba0 ab90 f4ff (12 bytes). Same code as QPACK.
TEST(QpackHuffman, Rfc7541WorkedExample) {
    using bolt::api::http3::qpack_huffman_encode;
    const std::string s = "www.example.com";
    const std::array<uint8_t, 12> expected = {0xf1, 0xe3, 0xc2, 0xe5,
                                              0xf2, 0x3a, 0x6b, 0xa0,
                                              0xab, 0x90, 0xf4, 0xff};
    std::array<uint8_t, 32> enc{};
    std::size_t enc_len = 0;
    ASSERT_EQ(qpack_huffman_encode(reinterpret_cast<const uint8_t*>(s.data()),
                                   s.size(), enc.data(), enc.size(), enc_len),
              0);
    ASSERT_EQ(enc_len, expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(enc[i], expected[i]) << "byte " << i;
    }
}

// ---------------------------------------------------------------------------
// Dynamic table: insert + size accounting + eviction.
// ---------------------------------------------------------------------------
TEST(QpackDynamicTable, InsertAndEvict) {
    bolt::api::http3::QpackDynamicTable t(120);  // small: forces eviction
    EXPECT_TRUE(t.insert("a", "1"));   // 1+1+32 = 34
    EXPECT_TRUE(t.insert("bb", "22")); // 2+2+32 = 36 -> total 70
    EXPECT_TRUE(t.insert("ccc", "333")); // 3+3+32=38 -> total 108
    EXPECT_EQ(t.count(), 3u);
    EXPECT_EQ(t.insert_count(), 3u);
    // Next insert (34) overflows 120 -> evict oldest ("a").
    EXPECT_TRUE(t.insert("d", "4"));
    EXPECT_EQ(t.drop_count(), 1u);
    std::string_view n, v;
    EXPECT_FALSE(t.get_absolute(0, n, v));  // evicted
    EXPECT_TRUE(t.get_absolute(1, n, v));
    EXPECT_EQ(n, "bb");
    EXPECT_EQ(v, "22");
}

// ---------------------------------------------------------------------------
// Dynamic table reference round-trip via encoder/decoder stream + indexed line.
// ---------------------------------------------------------------------------
TEST(QpackDynamic, InsertReferenceRoundTrip) {
    QpackEncoder enc;
    enc.set_huffman(false);

    // 1) Encoder inserts a header into its dynamic table, emits the encoder
    //    stream instruction (Insert With Name Reference, static name ":path").
    std::array<uint8_t, 256> es{};
    std::size_t es_len = 0;
    ASSERT_EQ(enc.encode_insert_with_name_ref(":path", "/dynamic/resource",
                                              es.data(), es.size(), es_len),
              0);
    EXPECT_EQ(enc.dynamic_table().count(), 1u);

    // 2) Decoder applies the same encoder stream -> identical dynamic table.
    QpackDecoder dec;
    ASSERT_EQ(dec.decode_encoder_stream(es.data(), es_len), 0);
    ASSERT_EQ(dec.dynamic_table().count(), 1u);
    std::string_view n, v;
    ASSERT_TRUE(dec.dynamic_table().get_absolute(0, n, v));
    EXPECT_EQ(n, ":path");
    EXPECT_EQ(v, "/dynamic/resource");

    // 3) Insert a literal-name entry too, replay on decoder.
    std::array<uint8_t, 256> es2{};
    std::size_t es2_len = 0;
    ASSERT_EQ(enc.encode_insert_literal_name("x-trace", "id-9001", es2.data(),
                                             es2.size(), es2_len),
              0);
    ASSERT_EQ(dec.decode_encoder_stream(es2.data(), es2_len), 0);
    ASSERT_EQ(dec.dynamic_table().count(), 2u);
    ASSERT_TRUE(dec.dynamic_table().get_absolute(1, n, v));
    EXPECT_EQ(n, "x-trace");
    EXPECT_EQ(v, "id-9001");
}

// Section Acknowledgment instruction (decoder stream output) shape check.
TEST(QpackDecoder, SectionAck) {
    QpackDecoder dec;
    std::array<uint8_t, 16> buf{};
    std::size_t len = 0;
    ASSERT_EQ(dec.encode_section_ack(5, buf.data(), buf.size(), len), 0);
    ASSERT_EQ(len, 1u);
    EXPECT_EQ(buf[0], 0x80u | 5u);  // 1 + 7-bit stream id
}

// ---------------------------------------------------------------------------
// Prefix integer codec edge cases (multi-byte continuation).
// ---------------------------------------------------------------------------
TEST(QpackInteger, PrefixCodecRoundTrip) {
    using bolt::api::http3::detail::qpack_decode_int;
    using bolt::api::http3::detail::qpack_encode_int;
    const uint64_t values[] = {0, 1, 30, 31, 62, 63, 127, 128, 1337, 100000};
    for (uint64_t val : values) {
        for (uint8_t pb : {uint8_t{5}, uint8_t{6}, uint8_t{7}, uint8_t{8}}) {
            std::array<uint8_t, 16> buf{};
            std::size_t w = qpack_encode_int(val, pb, 0x00, buf.data(),
                                             buf.size());
            ASSERT_GT(w, 0u);
            uint64_t got = 0;
            std::size_t consumed = 0;
            ASSERT_TRUE(qpack_decode_int(buf.data(), w, pb, got, consumed));
            EXPECT_EQ(got, val) << "val=" << val << " pb=" << int(pb);
            EXPECT_EQ(consumed, w);
        }
    }
}

// ---------------------------------------------------------------------------
// Randomized fuzz round-trip: random header sets across verbs, mixed static /
// novel names and values, both Huffman modes.
// ---------------------------------------------------------------------------
TEST(QpackFuzz, RandomizedRoundTrip) {
    std::mt19937 rng(0xB0117A91);
    const std::vector<std::string> verbs = {"GET",    "POST", "PUT",
                                            "DELETE", "HEAD", "OPTIONS"};
    const std::vector<std::string> names = {
        ":method",       ":scheme",    ":authority",  ":path",
        "content-type",  "user-agent", "x-custom",    "x-request-id",
        "accept",        "cookie",     "x-trace-id",  "referer"};
    auto rand_str = [&](std::size_t maxlen) {
        std::uniform_int_distribution<int> len_d(1, static_cast<int>(maxlen));
        std::uniform_int_distribution<int> ch_d(33, 126);
        std::string s;
        const int n = len_d(rng);
        for (int i = 0; i < n; ++i) s.push_back(static_cast<char>(ch_d(rng)));
        return s;
    };

    std::uniform_int_distribution<int> hcount_d(1, 12);
    for (int iter = 0; iter < 400; ++iter) {
        std::vector<std::pair<std::string, std::string>> store;
        const int hc = hcount_d(rng);
        store.reserve(hc);
        for (int i = 0; i < hc; ++i) {
            std::uniform_int_distribution<std::size_t> ni(0, names.size() - 1);
            std::string nm = names[ni(rng)];
            std::string val;
            if (nm == ":method") {
                std::uniform_int_distribution<std::size_t> vi(0,
                                                              verbs.size() - 1);
                val = verbs[vi(rng)];
            } else if (nm == ":scheme") {
                val = (rng() & 1) ? "https" : "http";
            } else {
                val = rand_str(40);
            }
            store.emplace_back(std::move(nm), std::move(val));
        }
        std::vector<QpackHeaderRef> headers;
        headers.reserve(store.size());
        for (auto& kv : store) headers.push_back({kv.first, kv.second});
        RoundTrip(headers, /*huffman=*/(iter & 1) != 0);
    }
}
