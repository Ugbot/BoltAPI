// tests/neo4j_bolt_packstream_test.cpp — golden wire vectors for PackStream v2.
//
// Every expected byte string below is fixed by the PUBLISHED PackStream
// specification (https://neo4j.com/docs/bolt/current/packstream/), not by what
// this implementation happens to emit. Encoding is asserted byte-for-byte and
// decoding is asserted value-for-value, in both directions, so a codec that
// agrees with itself but not with the spec fails here.
//
// "Bolt" throughout means Neo4j's client wire protocol, not extern/bolt.

#include "boltapi/proto/packstream.h"
#include "boltapi/proto/neo4j_bolt.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace ps = bolt::api::proto::packstream;
namespace nb = bolt::api::proto::neo4j;

namespace {

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 3);
    for (std::size_t i = 0; i < n; ++i) {
        if (i) s.push_back(' ');
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xF]);
    }
    return s;
}

std::vector<std::uint8_t> from_hex(const char* s) {
    std::vector<std::uint8_t> out;
    std::uint32_t acc = 0;
    int nib = 0;
    for (const char* p = s; *p; ++p) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else continue;
        acc = (acc << 4) | static_cast<std::uint32_t>(v);
        if (++nib == 2) {
            out.push_back(static_cast<std::uint8_t>(acc));
            acc = 0;
            nib = 0;
        }
    }
    EXPECT_EQ(nib, 0) << "odd hex digit count in vector";
    return out;
}

struct Enc {
    std::uint8_t buf[512];
    ps::PackWriter w{buf, sizeof(buf)};
    std::string as_hex() const { return hex(w.data(), w.size()); }
};

std::string expect_hex(const char* spec_bytes) {
    const std::vector<std::uint8_t> v = from_hex(spec_bytes);
    return hex(v.data(), v.size());
}

}  // namespace

// ---------------------------------------------------------------------------
// Encoding — bytes fixed by the spec.
// ---------------------------------------------------------------------------
TEST(PackStreamGolden, ScalarsMatchSpecBytes) {
    { Enc e; EXPECT_EQ(e.w.put_null(), ps::PackError::Ok);        EXPECT_EQ(e.as_hex(), expect_hex("C0")); }
    { Enc e; EXPECT_EQ(e.w.put_bool(false), ps::PackError::Ok);   EXPECT_EQ(e.as_hex(), expect_hex("C2")); }
    { Enc e; EXPECT_EQ(e.w.put_bool(true), ps::PackError::Ok);    EXPECT_EQ(e.as_hex(), expect_hex("C3")); }

    // TINY_INT covers -16..127 in one byte.
    { Enc e; EXPECT_EQ(e.w.put_int(0), ps::PackError::Ok);        EXPECT_EQ(e.as_hex(), expect_hex("00")); }
    { Enc e; EXPECT_EQ(e.w.put_int(1), ps::PackError::Ok);        EXPECT_EQ(e.as_hex(), expect_hex("01")); }
    { Enc e; EXPECT_EQ(e.w.put_int(-16), ps::PackError::Ok);      EXPECT_EQ(e.as_hex(), expect_hex("F0")); }
    { Enc e; EXPECT_EQ(e.w.put_int(127), ps::PackError::Ok);      EXPECT_EQ(e.as_hex(), expect_hex("7F")); }
    // Boundaries: one past TINY on each side.
    { Enc e; EXPECT_EQ(e.w.put_int(-17), ps::PackError::Ok);      EXPECT_EQ(e.as_hex(), expect_hex("C8 EF")); }
    { Enc e; EXPECT_EQ(e.w.put_int(-128), ps::PackError::Ok);     EXPECT_EQ(e.as_hex(), expect_hex("C8 80")); }
    { Enc e; EXPECT_EQ(e.w.put_int(128), ps::PackError::Ok);      EXPECT_EQ(e.as_hex(), expect_hex("C9 00 80")); }
    { Enc e; EXPECT_EQ(e.w.put_int(-129), ps::PackError::Ok);     EXPECT_EQ(e.as_hex(), expect_hex("C9 FF 7F")); }
    { Enc e; EXPECT_EQ(e.w.put_int(32767), ps::PackError::Ok);    EXPECT_EQ(e.as_hex(), expect_hex("C9 7F FF")); }
    { Enc e; EXPECT_EQ(e.w.put_int(32768), ps::PackError::Ok);    EXPECT_EQ(e.as_hex(), expect_hex("CA 00 00 80 00")); }
    { Enc e; EXPECT_EQ(e.w.put_int(-32769), ps::PackError::Ok);   EXPECT_EQ(e.as_hex(), expect_hex("CA FF FF 7F FF")); }
    { Enc e; EXPECT_EQ(e.w.put_int(2147483647LL), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("CA 7F FF FF FF")); }
    { Enc e; EXPECT_EQ(e.w.put_int(2147483648LL), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("CB 00 00 00 00 80 00 00 00")); }
    { Enc e; EXPECT_EQ(e.w.put_int(-9223372036854775807LL - 1), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("CB 80 00 00 00 00 00 00 00")); }

    // FLOAT_64 is IEEE-754 big-endian.
    { Enc e; EXPECT_EQ(e.w.put_float(1.1), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("C1 3F F1 99 99 99 99 99 9A")); }
    { Enc e; EXPECT_EQ(e.w.put_float(-1.1), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("C1 BF F1 99 99 99 99 99 9A")); }
    { Enc e; EXPECT_EQ(e.w.put_float(0.0), ps::PackError::Ok);
      EXPECT_EQ(e.as_hex(), expect_hex("C1 00 00 00 00 00 00 00 00")); }
}

TEST(PackStreamGolden, StringsMatchSpecBytes) {
    { Enc e; EXPECT_EQ(e.w.put_string(""), ps::PackError::Ok);  EXPECT_EQ(e.as_hex(), expect_hex("80")); }
    { Enc e; EXPECT_EQ(e.w.put_string("A"), ps::PackError::Ok); EXPECT_EQ(e.as_hex(), expect_hex("81 41")); }
    {
        Enc e;
        EXPECT_EQ(e.w.put_string("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ps::PackError::Ok);
        EXPECT_EQ(e.as_hex(), expect_hex("D0 1A 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51"
                                         " 52 53 54 55 56 57 58 59 5A"));
    }
    {
        // The spec's UTF-8 example: 14 characters, 18 bytes.
        Enc e;
        EXPECT_EQ(e.w.put_string("Gr\xc3\xb6\xc3\x9f" "enma\xc3\x9f" "st\xc3\xa4" "be"),
                  ps::PackError::Ok);
        EXPECT_EQ(e.as_hex(),
                  expect_hex("D0 12 47 72 C3 B6 C3 9F 65 6E 6D 61 C3 9F 73 74 C3 A4 62 65"));
    }
    {
        // 15 bytes is the last TINY_STRING; 16 must promote to STRING_8.
        Enc e15; EXPECT_EQ(e15.w.put_string(std::string(15, 'a')), ps::PackError::Ok);
        EXPECT_EQ(e15.w.data()[0], 0x8F);
        Enc e16; EXPECT_EQ(e16.w.put_string(std::string(16, 'a')), ps::PackError::Ok);
        EXPECT_EQ(e16.w.data()[0], 0xD0);
        EXPECT_EQ(e16.w.data()[1], 0x10);
    }
}

TEST(PackStreamGolden, ContainersMatchSpecBytes) {
    { Enc e; EXPECT_EQ(e.w.begin_list(0), ps::PackError::Ok); EXPECT_EQ(e.as_hex(), expect_hex("90")); }
    {
        Enc e;
        EXPECT_EQ(e.w.begin_list(3), ps::PackError::Ok);
        EXPECT_EQ(e.w.put_int(1), ps::PackError::Ok);
        EXPECT_EQ(e.w.put_int(2), ps::PackError::Ok);
        EXPECT_EQ(e.w.put_int(3), ps::PackError::Ok);
        EXPECT_EQ(e.as_hex(), expect_hex("93 01 02 03"));
    }
    { Enc e; EXPECT_EQ(e.w.begin_dict(0), ps::PackError::Ok); EXPECT_EQ(e.as_hex(), expect_hex("A0")); }
    {
        Enc e;
        EXPECT_EQ(e.w.begin_dict(1), ps::PackError::Ok);
        EXPECT_EQ(e.w.put_string("one"), ps::PackError::Ok);
        EXPECT_EQ(e.w.put_string("eins"), ps::PackError::Ok);
        EXPECT_EQ(e.as_hex(), expect_hex("A1 83 6F 6E 65 84 65 69 6E 73"));
    }
    {
        // A structure: marker B<n> then the signature byte. This is a Bolt
        // RUN message header (signature 0x10, three fields).
        Enc e;
        EXPECT_EQ(e.w.begin_struct(0x10, 3), ps::PackError::Ok);
        EXPECT_EQ(e.as_hex(), expect_hex("B3 10"));
    }
    {
        // 15 elements is the last TINY_LIST; 16 promotes to LIST_8.
        Enc a; EXPECT_EQ(a.w.begin_list(15), ps::PackError::Ok);
        EXPECT_EQ(a.w.data()[0], 0x9F);
        Enc b; EXPECT_EQ(b.w.begin_list(16), ps::PackError::Ok);
        EXPECT_EQ(b.w.data()[0], 0xD4);
        EXPECT_EQ(b.w.data()[1], 0x10);
        Enc c; EXPECT_EQ(c.w.begin_dict(16), ps::PackError::Ok);
        EXPECT_EQ(c.w.data()[0], 0xD8);
    }
}

// ---------------------------------------------------------------------------
// Decoding — the same spec bytes must produce the right VALUES.
// ---------------------------------------------------------------------------
namespace {
struct Dec {
    std::uint8_t   mem[8192];
    ps::PackArena  arena{mem, sizeof(mem)};
    ps::PackValue  v{};

    ps::PackError decode(const char* spec_bytes) {
        bytes = from_hex(spec_bytes);
        ps::PackReader r(bytes.data(), bytes.size(), arena);
        return r.read(v);
    }
    std::vector<std::uint8_t> bytes;
};
}  // namespace

TEST(PackStreamGolden, DecodesSpecBytesToValues) {
    { Dec d; ASSERT_EQ(d.decode("C0"), ps::PackError::Ok); EXPECT_EQ(d.v.type, ps::PackType::Null); }
    { Dec d; ASSERT_EQ(d.decode("C3"), ps::PackError::Ok); EXPECT_TRUE(d.v.b); }
    { Dec d; ASSERT_EQ(d.decode("C2"), ps::PackError::Ok); EXPECT_FALSE(d.v.b); }
    { Dec d; ASSERT_EQ(d.decode("F0"), ps::PackError::Ok); EXPECT_EQ(d.v.i, -16); }
    { Dec d; ASSERT_EQ(d.decode("FF"), ps::PackError::Ok); EXPECT_EQ(d.v.i, -1); }
    { Dec d; ASSERT_EQ(d.decode("7F"), ps::PackError::Ok); EXPECT_EQ(d.v.i, 127); }
    { Dec d; ASSERT_EQ(d.decode("C8 EF"), ps::PackError::Ok); EXPECT_EQ(d.v.i, -17); }
    { Dec d; ASSERT_EQ(d.decode("C9 FF 7F"), ps::PackError::Ok); EXPECT_EQ(d.v.i, -129); }
    { Dec d; ASSERT_EQ(d.decode("CA 00 00 80 00"), ps::PackError::Ok); EXPECT_EQ(d.v.i, 32768); }
    { Dec d; ASSERT_EQ(d.decode("CB 80 00 00 00 00 00 00 00"), ps::PackError::Ok);
      EXPECT_EQ(d.v.i, -9223372036854775807LL - 1); }
    { Dec d; ASSERT_EQ(d.decode("C1 3F F1 99 99 99 99 99 9A"), ps::PackError::Ok);
      EXPECT_DOUBLE_EQ(d.v.f, 1.1); }
    { Dec d; ASSERT_EQ(d.decode("81 41"), ps::PackError::Ok); EXPECT_EQ(d.v.str(), "A"); }
    {
        Dec d;
        ASSERT_EQ(d.decode("D0 12 47 72 C3 B6 C3 9F 65 6E 6D 61 C3 9F 73 74 C3 A4 62 65"),
                  ps::PackError::Ok);
        EXPECT_EQ(d.v.str(), std::string("Gr\xc3\xb6\xc3\x9f" "enma\xc3\x9f" "st\xc3\xa4" "be"));
        EXPECT_EQ(d.v.len, 18u);
    }
    {
        Dec d;
        ASSERT_EQ(d.decode("93 01 02 03"), ps::PackError::Ok);
        ASSERT_EQ(d.v.type, ps::PackType::List);
        ASSERT_EQ(d.v.len, 3u);
        EXPECT_EQ(d.v.items[0].i, 1);
        EXPECT_EQ(d.v.items[1].i, 2);
        EXPECT_EQ(d.v.items[2].i, 3);
    }
    {
        Dec d;
        ASSERT_EQ(d.decode("A1 83 6F 6E 65 84 65 69 6E 73"), ps::PackError::Ok);
        ASSERT_EQ(d.v.type, ps::PackType::Dict);
        ASSERT_EQ(d.v.len, 1u);
        EXPECT_EQ(d.v.find_str("one"), "eins");
        EXPECT_EQ(d.v.find("missing"), nullptr);
    }
    {
        // A real Bolt HELLO: B1 01 A1 8A user_agent 85 "hello".
        Dec d;
        ASSERT_EQ(d.decode("B1 01 A1 8A 75 73 65 72 5F 61 67 65 6E 74 85 68 65 6C 6C 6F"),
                  ps::PackError::Ok);
        ASSERT_EQ(d.v.type, ps::PackType::Struct);
        EXPECT_EQ(d.v.signature, static_cast<std::uint8_t>(nb::Signature::Hello));
        ASSERT_EQ(d.v.len, 1u);
        EXPECT_EQ(d.v.items[0].find_str("user_agent"), "hello");
    }
}

// ---------------------------------------------------------------------------
// Refusals — every bound is a named error, never a clamp or a guess.
// ---------------------------------------------------------------------------
TEST(PackStreamGolden, RefusesRatherThanGuesses) {
    { Dec d; EXPECT_EQ(d.decode("81"), ps::PackError::Truncated); }          // string, no payload
    { Dec d; EXPECT_EQ(d.decode("C9 00"), ps::PackError::Truncated); }       // int16, 1 byte
    { Dec d; EXPECT_EQ(d.decode("93 01 02"), ps::PackError::Truncated); }    // list of 3, 2 given
    { Dec d; EXPECT_EQ(d.decode("C4"), ps::PackError::BadMarker); }          // not a v2 marker
    { Dec d; EXPECT_EQ(d.decode("DC 01 10"), ps::PackError::Unsupported); }  // removed STRUCT_8
    { Dec d; EXPECT_EQ(d.decode("DD 00 01 10"), ps::PackError::Unsupported); }
    { Dec d; EXPECT_EQ(d.decode("A1 01 02"), ps::PackError::BadMarker); }    // dict key not a string

    // Nesting past kMaxDepth is refused, not silently flattened.
    {
        std::string deep;
        for (std::uint32_t k = 0; k < ps::kMaxDepth + 4; ++k) deep += "91";
        deep += "01";
        Dec d;
        EXPECT_EQ(d.decode(deep.c_str()), ps::PackError::DepthExceeded);
    }

    // Encoder overflow latches instead of writing past the caller's buffer.
    {
        std::uint8_t tiny[3];
        ps::PackWriter w(tiny, sizeof(tiny));
        EXPECT_EQ(w.put_string("abcdefgh"), ps::PackError::Overflow);
        EXPECT_TRUE(w.overflowed());
        EXPECT_LE(w.size(), sizeof(tiny));
    }

    // Arena exhaustion is OutOfMemory, and the value is NOT partially accepted.
    {
        std::uint8_t mem[8];
        ps::PackArena a(mem, sizeof(mem));
        const std::vector<std::uint8_t> b = from_hex("D0 20"
            "4141414141414141414141414141414141414141414141414141414141414141");
        ps::PackReader r(b.data(), b.size(), a);
        ps::PackValue v{};
        EXPECT_EQ(r.read(v), ps::PackError::OutOfMemory);
    }

    // A structure with more than 15 fields cannot be expressed in v2.
    {
        std::uint8_t buf[8];
        ps::PackWriter w(buf, sizeof(buf));
        EXPECT_EQ(w.begin_struct(0x10, 16), ps::PackError::TooLarge);
    }
}

// ---------------------------------------------------------------------------
// Round trip — a decoded value re-encodes to the same bytes.
// ---------------------------------------------------------------------------
TEST(PackStreamGolden, ReEncodeIsByteIdentical) {
    const char* vectors[] = {
        "C0", "C2", "C3", "01", "F0", "7F", "C8 EF", "C9 00 80",
        "CA 00 00 80 00", "CB 00 00 00 00 80 00 00 00",
        "C1 3F F1 99 99 99 99 99 9A",
        "80", "81 41", "D0 12 47 72 C3 B6 C3 9F 65 6E 6D 61 C3 9F 73 74 C3 A4 62 65",
        "90", "93 01 02 03", "A0", "A1 83 6F 6E 65 84 65 69 6E 73",
        "B1 01 A1 8A 75 73 65 72 5F 61 67 65 6E 74 85 68 65 6C 6C 6F",
        "92 93 01 02 03 A1 81 6B 81 76",
    };
    for (const char* hexs : vectors) {
        Dec d;
        ASSERT_EQ(d.decode(hexs), ps::PackError::Ok) << hexs;
        Enc e;
        ASSERT_EQ(e.w.put_value(d.v), ps::PackError::Ok) << hexs;
        EXPECT_EQ(e.as_hex(), expect_hex(hexs)) << "round trip drifted for " << hexs;
    }
}

// ---------------------------------------------------------------------------
// Handshake version negotiation — against the bytes the OFFICIAL neo4j Python
// driver 6.3.0 actually sends (captured from the wire, not assumed).
// ---------------------------------------------------------------------------
TEST(BoltHandshake, NegotiatesAgainstRealDriverProposals) {
    // Observed on the wire from neo4j-driver 6.3.0:
    //   60 60 b0 17 | 00 00 01 ff | 00 08 08 05 | 00 02 04 04 | 00 00 00 03
    // Entry 1 is the Bolt 5.7 handshake MANIFEST (major 0xFF) which we do not
    // implement; it must be skipped, not selected.
    const std::uint8_t real[16] = {0x00, 0x00, 0x01, 0xFF,
                                   0x00, 0x08, 0x08, 0x05,
                                   0x00, 0x02, 0x04, 0x04,
                                   0x00, 0x00, 0x00, 0x03};
    const nb::Version v = nb::negotiate(real);
    ASSERT_TRUE(v.valid());
    EXPECT_EQ(v.major, 5);
    EXPECT_EQ(v.minor, nb::kMaxBolt5Minor)
        << "must pick the highest 5.x we implement inside the offered range";
    EXPECT_TRUE(v.has_logon());

    // Manifest-only: nothing selectable, so the handshake must DECLINE.
    const std::uint8_t manifest_only[16] = {0x00, 0x00, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(nb::negotiate(manifest_only).valid());

    // Bolt 3.0 only: unsupported, decline rather than pretend.
    const std::uint8_t v3_only[16] = {0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(nb::negotiate(v3_only).valid());

    // A 4.x-only driver gets 4.4, and 4.4 predates LOGON so auth rides HELLO.
    const std::uint8_t v4_only[16] = {0x00, 0x02, 0x04, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const nb::Version v4 = nb::negotiate(v4_only);
    ASSERT_TRUE(v4.valid());
    EXPECT_EQ(v4.major, 4);
    EXPECT_EQ(v4.minor, 4);
    EXPECT_FALSE(v4.has_logon());

    // A range whose top is above what we implement must come DOWN to ours,
    // never select a version we cannot speak.
    const std::uint8_t v5_high[16] = {0x00, 0x00, 0x08, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(nb::negotiate(v5_high).valid())
        << "5.8 with range 0 offers only 5.8; we must decline, not downgrade silently";

    // Exact 5.0 (range 0) is supported.
    const std::uint8_t v50[16] = {0x00, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const nb::Version v50n = nb::negotiate(v50);
    ASSERT_TRUE(v50n.valid());
    EXPECT_EQ(v50n.minor, 0);
    EXPECT_FALSE(v50n.has_logon()) << "LOGON arrives at 5.1";
}
