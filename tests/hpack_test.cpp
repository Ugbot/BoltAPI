// hpack_test.cpp — RFC 7541 Appendix C vectors (with and without Huffman,
// including eviction at a 256-octet table) plus the G2ETL-130 regressions:
// large entries must enter the table, size updates are validated, and the
// encoder never folds an empty value into a static entry that has one.

#include "boltapi/http/hpack.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using bolt::api::http::HPACKDecoder;
using bolt::api::http::HPACKEncoder;
using bolt::api::http::HPACKHeader;

namespace {

using Fields = std::vector<std::pair<std::string, std::string>>;

std::vector<uint8_t> hex(const std::string& h) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    }
    return out;
}

Fields decode(HPACKDecoder& d, const std::string& block, int* rc = nullptr) {
    const auto bytes = hex(block);
    std::vector<HPACKHeader> out;
    const int r = d.decode(bytes.data(), bytes.size(), out);
    if (rc != nullptr) *rc = r;
    Fields f;
    for (const auto& h : out) f.emplace_back(std::string(h.name), std::string(h.value));
    return f;
}

const Fields kReq1 = {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                      {":authority", "www.example.com"}};
const Fields kReq2 = {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                      {":authority", "www.example.com"}, {"cache-control", "no-cache"}};
const Fields kReq3 = {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"},
                      {":authority", "www.example.com"}, {"custom-key", "custom-value"}};

TEST(Hpack, RequestsWithoutHuffmanC3) {
    HPACKDecoder d;
    EXPECT_EQ(decode(d, "828684410f7777772e6578616d706c652e636f6d"), kReq1);
    EXPECT_EQ(d.get_table_size(), 57u);
    EXPECT_EQ(decode(d, "828684be58086e6f2d6361636865"), kReq2);
    EXPECT_EQ(d.get_table_size(), 110u);
    EXPECT_EQ(decode(d, "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"), kReq3);
    EXPECT_EQ(d.get_table_size(), 164u);
}

TEST(Hpack, RequestsWithHuffmanC4) {
    HPACKDecoder d;
    EXPECT_EQ(decode(d, "828684418cf1e3c2e5f23a6ba0ab90f4ff"), kReq1);
    EXPECT_EQ(decode(d, "828684be5886a8eb10649cbf"), kReq2);
    EXPECT_EQ(decode(d, "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"), kReq3);
    EXPECT_EQ(d.get_table_size(), 164u);
}

TEST(Hpack, ResponsesWithEvictionC5) {
    HPACKDecoder d(256);
    const Fields r1 = {{":status", "302"}, {"cache-control", "private"},
                       {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                       {"location", "https://www.example.com"}};
    EXPECT_EQ(decode(d, "4803333032580770726976617465611d4d6f6e2c203231204f637420323031"
                        "332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d"
                        "706c652e636f6d"), r1);
    EXPECT_EQ(d.get_table_size(), 222u);
    Fields r2 = r1;
    r2[0].second = "307";
    EXPECT_EQ(decode(d, "4803333037c1c0bf"), r2);
    EXPECT_EQ(d.get_table_size(), 222u);
    const Fields r3 = {{":status", "200"}, {"cache-control", "private"},
                       {"date", "Mon, 21 Oct 2013 20:13:22 GMT"},
                       {"location", "https://www.example.com"}, {"content-encoding", "gzip"},
                       {"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"}};
    EXPECT_EQ(decode(d, "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54"
                        "c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541"
                        "585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31"), r3);
    EXPECT_EQ(d.get_table_size(), 215u);
}

TEST(Hpack, LargeEntryIsIndexedNotDropped) {
    // A 1000-byte cookie with incremental indexing, then referenced as 62:
    // the old fixed 256-byte slots refused it and 62 resolved elsewhere.
    const std::string value(1000, 'c');
    std::vector<uint8_t> block = {0x40, 0x06};
    block.insert(block.end(), {'c', 'o', 'o', 'k', 'i', 'e'});
    block.push_back(0x7f);  // length 1000 = 127 + 873 -> 0x7f 0xe9 0x06
    block.push_back(0xe9);
    block.push_back(0x06);
    block.insert(block.end(), value.begin(), value.end());
    block.push_back(0xbe);  // indexed 62
    HPACKDecoder d;
    std::vector<HPACKHeader> out;
    ASSERT_EQ(d.decode(block.data(), block.size(), out), HPACKDecoder::kOk);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[1].name, "cookie");
    EXPECT_EQ(out[1].value, value);
}

TEST(Hpack, SizeUpdateIsValidated) {
    HPACKDecoder d;  // advertised 4096
    int rc = 0;
    decode(d, "3fe11f82", &rc);  // update to 4096 at the start: fine
    EXPECT_EQ(rc, HPACKDecoder::kOk);
    decode(d, "3fe21f82", &rc);  // 4097 > SETTINGS_HEADER_TABLE_SIZE
    EXPECT_EQ(rc, HPACKDecoder::kCompressionError);
    HPACKDecoder d2;
    decode(d2, "8220", &rc);  // update after a field
    EXPECT_EQ(rc, HPACKDecoder::kCompressionError);
    HPACKDecoder d3;
    decode(d3, "80", &rc);  // index 0
    EXPECT_EQ(rc, HPACKDecoder::kCompressionError);
    decode(d3, "8288ff", &rc);  // truncated integer
    EXPECT_EQ(rc, HPACKDecoder::kCompressionError);
}

TEST(Hpack, EncoderRoundTripKeepsEmptyValuesAndAnnouncesShrink) {
    HPACKEncoder e;
    HPACKDecoder d;
    const HPACKHeader in[] = {{":status", "", false}, {"accept-encoding", "", false},
                              {"x-empty", "", false}, {":status", "200", false},
                              {"set-cookie", "secret", true}};
    e.set_max_table_size(0);  // peer shrank its table: must be announced
    uint8_t buf[256];
    size_t n = 0;
    ASSERT_EQ(e.encode(in, 5, buf, sizeof(buf), n), 0);
    EXPECT_EQ(buf[0], 0x20);  // size update to 0 leads the block
    std::vector<HPACKHeader> out;
    ASSERT_EQ(d.decode(buf, n, out), HPACKDecoder::kOk);
    ASSERT_EQ(out.size(), 5u);
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(out[i].name, in[i].name);
        EXPECT_EQ(out[i].value, in[i].value);
    }
    EXPECT_TRUE(out[4].sensitive);
}

}  // namespace
