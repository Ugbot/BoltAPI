// tests/flight_sql_codec_test.cpp — the Flight SQL byte codecs, no sockets.
// Real-client conformance is flight_sql_client_conformance.py.

#include "boltapi/proto/flight_sql_codec.h"

#include "bolt/bolt_arena.h"
#include "bolt/bolt_column.h"
#include "bolt/ingest/bolt_arrow_ipc.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace cd = bolt::api::proto::flightsql::codec;

TEST(FlightSqlCodec, VarintMatchesProtobufGoldenBytes) {
    std::string out;
    cd::pb_put_varint(&out, 1, 150);   // protobuf encoding guide's example
    EXPECT_EQ(out, std::string("\x08\x96\x01", 3));
    out.clear();
    cd::pb_put_int64(&out, 4, -1);     // negative int64 is a 10-byte varint
    ASSERT_EQ(out.size(), 11u);
    EXPECT_EQ(static_cast<unsigned char>(out.back()), 0x01u);
    out.clear();
    cd::pb_put_bytes(&out, 1000, "ab");   // FlightData.data_body tag
    EXPECT_EQ(out, std::string("\xC2\x3E\x02" "ab", 5));
}

TEST(FlightSqlCodec, ReaderSkipsUnknownFieldsAndRejectsGroups) {
    std::string m;
    cd::pb_put_varint(&m, 7, 42);
    m.append("\x39\x01\x02\x03\x04\x05\x06\x07\x08", 9);   // field 7 fixed64
    cd::pb_put_bytes(&m, 1, "SELECT 1");
    std::string_view q, txn;
    ASSERT_TRUE(cd::decode_statement_query(m, &q, &txn));
    EXPECT_EQ(q, "SELECT 1");
    EXPECT_TRUE(txn.empty());

    const std::string group("\x0B\x0C", 2);   // start/end group, field 1
    EXPECT_FALSE(cd::decode_statement_query(group, &q, &txn));
    const std::string truncated("\x0A\x05" "ab", 4);   // length past the end
    EXPECT_FALSE(cd::decode_statement_query(truncated, &q, &txn));
}

TEST(FlightSqlCodec, AnyRoundTripAndDescriptor) {
    std::string cmd_value;
    cd::pb_put_bytes(&cmd_value, 1, "SELECT 42");
    std::string any;
    cd::encode_any(&any, "CommandStatementQuery", cmd_value);
    std::string desc;
    cd::pb_put_varint(&desc, 1, 2);
    cd::pb_put_bytes(&desc, 2, any);

    cd::Descriptor d;
    ASSERT_TRUE(cd::decode_descriptor(desc, &d));
    EXPECT_EQ(d.type, 2u);
    cd::AnyMsg a;
    ASSERT_TRUE(cd::decode_any(d.cmd, &a));
    EXPECT_EQ(a.type_name, "arrow.flight.protocol.sql.CommandStatementQuery");
    std::string_view q, txn;
    ASSERT_TRUE(cd::decode_statement_query(a.value, &q, &txn));
    EXPECT_EQ(q, "SELECT 42");
}

TEST(FlightSqlCodec, GrpcFraming) {
    std::uint8_t p[5];
    cd::grpc_frame_prefix(p, 3);
    std::string buf(reinterpret_cast<char*>(p), 5);
    buf += "xyz";
    std::string_view msg;
    std::size_t used = 0;
    EXPECT_EQ(cd::grpc_unframe(buf.substr(0, 6), &msg, &used), cd::GrpcFrame::kIncomplete);
    ASSERT_EQ(cd::grpc_unframe(buf, &msg, &used), cd::GrpcFrame::kOk);
    EXPECT_EQ(msg, "xyz");
    EXPECT_EQ(used, 8u);
    buf[0] = 1;
    EXPECT_EQ(cd::grpc_unframe(buf, &msg, &used), cd::GrpcFrame::kCompressed);
    buf[0] = 2;
    EXPECT_EQ(cd::grpc_unframe(buf, &msg, &used), cd::GrpcFrame::kBad);
}

TEST(FlightSqlCodec, PercentEncodingAndBase64) {
    char out[64];
    const std::size_t n = cd::grpc_percent_encode("a%b\nc\xC3\xA9", out, sizeof(out));
    EXPECT_EQ(std::string(out, n), "a%25b%0Ac%C3%A9");

    char dec[64];
    std::size_t len = 0;
    ASSERT_TRUE(cd::base64_decode("dXNlcjpwYXNz", dec, sizeof(dec), &len));
    EXPECT_EQ(std::string(dec, len), "user:pass");
    EXPECT_FALSE(cd::base64_decode("dX*l", dec, sizeof(dec), &len));
    EXPECT_FALSE(cd::base64_decode("dXNlcjpwYXNz", dec, 3, &len));
}

TEST(FlightSqlCodec, SplitsABoltWrittenIpcStream) {
    auto* w = static_cast<bolt::ingest::ArrowIpcWriter*>(
        std::calloc(1, sizeof(bolt::ingest::ArrowIpcWriter)));
    auto* batch = static_cast<bolt::BoltBatch*>(std::calloc(1, sizeof(bolt::BoltBatch)));
    ASSERT_NE(w, nullptr);
    ASSERT_NE(batch, nullptr);
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    const bolt::BoltType ty[1] = {bolt::BoltType::Int64};
    const char* names[1] = {"v"};
    ASSERT_TRUE(bolt::ingest::arrow_ipc_open(w, f, ty, names, 1));
    std::int64_t vals[5] = {1, 2, 3, 4, 5};
    bolt::Arena arena;
    bolt::BoltBatch::init_empty(batch);
    ASSERT_TRUE(bolt::BoltBatch::alloc_columns(batch, &arena, 1));
    batch->num_rows = 5;
    batch->num_cols = 1;
    bolt::BoltColumn& c = batch->columns[batch->read_epoch][0];
    c.type = bolt::BoltType::Int64;
    c.format = bolt::ColumnFormat::Flat;
    c.length = 5;
    c.data = vals;
    c.type_size_bytes = 8;
    ASSERT_TRUE(bolt::ingest::arrow_ipc_write_batch(w, batch));
    ASSERT_TRUE(bolt::ingest::arrow_ipc_write_batch(w, batch));
    ASSERT_TRUE(bolt::ingest::arrow_ipc_close(w));
    std::fflush(f);
    const long size = std::ftell(f);
    std::rewind(f);
    std::string stream(static_cast<std::size_t>(size), '\0');
    ASSERT_EQ(std::fread(stream.data(), 1, stream.size(), f), stream.size());
    std::fclose(f);
    std::free(w);
    std::free(batch);

    std::size_t pos = 0;
    bool bad = false;
    cd::IpcMessage m;
    ASSERT_TRUE(cd::ipc_next_message(stream, &pos, &m, &bad));
    EXPECT_EQ(m.header_type, cd::kIpcHeaderSchema);
    EXPECT_TRUE(m.body.empty());
    EXPECT_EQ(m.encapsulated.size(), 8u + m.metadata.size());
    for (int i = 0; i < 2; ++i) {
        ASSERT_TRUE(cd::ipc_next_message(stream, &pos, &m, &bad));
        EXPECT_EQ(m.header_type, cd::kIpcHeaderRecordBatch);
        EXPECT_GE(m.body.size(), 40u);   // 5 x int64, 8-aligned
    }
    EXPECT_FALSE(cd::ipc_next_message(stream, &pos, &m, &bad));   // EOS
    EXPECT_FALSE(bad);
    EXPECT_EQ(pos + 8, stream.size());

    std::string cut = stream.substr(0, stream.size() - 20);   // truncated body
    pos = 0;
    ASSERT_TRUE(cd::ipc_next_message(cut, &pos, &m, &bad));
    ASSERT_TRUE(cd::ipc_next_message(cut, &pos, &m, &bad));
    EXPECT_FALSE(cd::ipc_next_message(cut, &pos, &m, &bad));
    EXPECT_TRUE(bad);
}
