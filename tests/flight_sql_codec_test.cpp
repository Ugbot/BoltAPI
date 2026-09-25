// tests/flight_sql_codec_test.cpp — the Flight SQL byte codecs, no sockets.
// Real-client conformance is flight_sql_client_conformance.py.

#include "boltapi/proto/flight_sql_arrow.h"
#include "boltapi/proto/flight_sql_codec.h"
#include "boltapi/proto/flight_sql_params.h"

#include "bolt/bolt_arena.h"
#include "bolt/bolt_column.h"
#include "bolt/ingest/bolt_arrow_ipc.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

namespace cd = bolt::api::proto::flightsql::codec;
namespace pm = bolt::api::proto::flightsql::params;

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

TEST(FlightSqlParams, PlaceholdersSkipStringsIdentifiersAndComments) {
    std::uint32_t n = 0;
    ASSERT_TRUE(pm::count_placeholders("SELECT ? , '?', \"?\", 'it''s ?' -- ?\n/* ? */ ?", &n));
    EXPECT_EQ(n, 2u);
    ASSERT_TRUE(pm::count_placeholders("SELECT E'\\'?' , ?", &n));   // E'' escapes
    EXPECT_EQ(n, 1u);
    ASSERT_TRUE(pm::count_placeholders("SELECT some'?'", &n));   // not an E'' string
    EXPECT_EQ(n, 0u);
    ASSERT_TRUE(pm::count_placeholders("SELECT '?", &n));   // unterminated literal
    EXPECT_EQ(n, 0u);
    std::string many = "SELECT ";
    for (int i = 0; i < 257; ++i) many += "?,";
    EXPECT_FALSE(pm::count_placeholders(many, &n));
}

TEST(FlightSqlParams, RendersAnsiLiterals) {
    pm::Value v[7];
    v[0].kind = pm::Kind::kInt;
    v[0].i = -5;
    v[1].kind = pm::Kind::kString;
    v[1].s = "o'k";
    v[2].kind = pm::Kind::kFloat;
    v[2].f = 3.0;
    v[3].kind = pm::Kind::kNull;
    v[4].kind = pm::Kind::kBool;
    v[4].b = false;
    v[5].kind = pm::Kind::kUInt;
    v[5].u = 18446744073709551615ull;
    v[6].kind = pm::Kind::kFloat;
    v[6].f = -0.25;
    std::string out;
    const char* err = nullptr;
    ASSERT_TRUE(pm::render("x-? = ? '?' ? ? ? ? ?", v, 7, 65536, &out, &err));
    EXPECT_EQ(out, "x-(-5) = 'o''k' '?' 3.0 NULL FALSE 18446744073709551615 (-0.25)");
    EXPECT_FALSE(pm::render("? ?", v, 1, 65536, &out, &err));   // too few values
    EXPECT_FALSE(pm::render("?", v, 2, 65536, &out, &err));     // too many
    pm::Value nan;
    nan.kind = pm::Kind::kFloat;
    nan.f = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(pm::render("?", &nan, 1, 65536, &out, &err));
    EXPECT_NE(std::string(err).find("NaN"), std::string::npos);
    EXPECT_FALSE(pm::render("SELECT ?", v + 1, 1, 8, &out, &err));   // past the cap
}

TEST(FlightSqlParams, HandleRoundTrip) {
    pm::Value v[3];
    v[0].kind = pm::Kind::kString;
    v[0].s = std::string_view("a\0b", 3);
    v[1].kind = pm::Kind::kInt;
    v[1].i = -9;
    v[2].kind = pm::Kind::kBool;
    v[2].b = true;
    std::string h;
    pm::encode_bound(&h, "SELECT ?, ?, ?", v, 3);
    std::string_view sql;
    bool bound = false;
    std::vector<pm::Value> row;
    ASSERT_TRUE(pm::decode_handle(h, &sql, &bound, &row));
    EXPECT_TRUE(bound);
    EXPECT_EQ(sql, "SELECT ?, ?, ?");
    ASSERT_EQ(row.size(), 3u);
    EXPECT_EQ(row[0].s, std::string_view("a\0b", 3));
    EXPECT_EQ(row[1].i, -9);
    EXPECT_TRUE(row[2].b);
    EXPECT_FALSE(pm::decode_handle(h.substr(0, h.size() - 1), &sql, &bound, &row));
    EXPECT_FALSE(pm::decode_handle("SELECT 1", &sql, &bound, &row));
    pm::encode_unbound(&h, "SELECT 1");
    ASSERT_TRUE(pm::decode_handle(h, &sql, &bound, &row));
    EXPECT_FALSE(bound);
    EXPECT_EQ(sql, "SELECT 1");
}

TEST(FlightSqlParams, DecodesABoltWrittenBatchAndTheAdvertisedSchema) {
    auto* w = static_cast<bolt::ingest::ArrowIpcWriter*>(
        std::calloc(1, sizeof(bolt::ingest::ArrowIpcWriter)));
    auto* batch = static_cast<bolt::BoltBatch*>(std::calloc(1, sizeof(bolt::BoltBatch)));
    ASSERT_NE(w, nullptr);
    ASSERT_NE(batch, nullptr);
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    const bolt::BoltType ty[2] = {bolt::BoltType::Int64, bolt::BoltType::Float64};
    const char* names[2] = {"a", "b"};
    ASSERT_TRUE(bolt::ingest::arrow_ipc_open(w, f, ty, names, 2));
    std::int64_t ints[2] = {7, -1};
    double dbls[2] = {0.5, 2.0};
    bolt::Arena arena;
    bolt::BoltBatch::init_empty(batch);
    ASSERT_TRUE(bolt::BoltBatch::alloc_columns(batch, &arena, 2));
    batch->num_rows = 2;
    batch->num_cols = 2;
    void* data[2] = {ints, dbls};
    for (int c = 0; c < 2; ++c) {
        bolt::BoltColumn& col = batch->columns[batch->read_epoch][c];
        col.type = ty[c];
        col.format = bolt::ColumnFormat::Flat;
        col.length = 2;
        col.data = data[c];
        col.type_size_bytes = 8;
    }
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
    cd::IpcMessage sch;
    cd::IpcMessage rb;
    ASSERT_TRUE(cd::ipc_next_message(stream, &pos, &sch, &bad));
    ASSERT_TRUE(cd::ipc_next_message(stream, &pos, &rb, &bad));
    EXPECT_EQ(pm::header_type(sch.metadata), cd::kIpcHeaderSchema);
    EXPECT_EQ(pm::header_type(rb.metadata), cd::kIpcHeaderRecordBatch);
    pm::Decoder dec;
    pm::Rows rows;
    const char* err = nullptr;
    ASSERT_TRUE(dec.schema(sch.metadata, &err)) << err;
    ASSERT_TRUE(dec.batch(rb.metadata, rb.body, &rows, &err)) << err;
    ASSERT_EQ(rows.n_rows, 2u);
    ASSERT_EQ(rows.n_cols, 2u);
    EXPECT_EQ(rows.values[0].i, 7);
    EXPECT_EQ(rows.values[1].f, 0.5);
    EXPECT_EQ(rows.values[2].i, -1);
    EXPECT_EQ(rows.values[3].f, 2.0);
    EXPECT_FALSE(dec.batch(rb.metadata, rb.body.substr(0, 8), &rows, &err));   // short body

    std::string params;
    bolt::api::proto::flightsql::arrow::write_parameter_schema(&params, 2, nullptr);
    pos = 0;
    ASSERT_TRUE(cd::ipc_next_message(params, &pos, &sch, &bad));
    pm::Decoder dec2;
    ASSERT_TRUE(dec2.schema(sch.metadata, &err)) << err;   // its own schema decodes
    EXPECT_FALSE(dec2.schema(rb.metadata, &err));          // a batch is not a schema

    // Typed placeholders (G2ETL-85): the typed schema decodes, and binds the
    // int64/float64 batch above column for column.
    using PT = bolt::api::proto::flightsql::ParamType;
    const PT types[2] = {PT::kInt64, PT::kFloat64};
    std::string typed;
    bolt::api::proto::flightsql::arrow::write_parameter_schema(&typed, 2, types);
    EXPECT_NE(typed, params);
    pos = 0;
    ASSERT_TRUE(cd::ipc_next_message(typed, &pos, &sch, &bad));
    pm::Decoder dec3;
    ASSERT_TRUE(dec3.schema(sch.metadata, &err)) << err;
    pm::Rows typed_rows;
    ASSERT_TRUE(dec3.batch(rb.metadata, rb.body, &typed_rows, &err)) << err;
    EXPECT_EQ(typed_rows.values[0].i, 7);
    EXPECT_EQ(typed_rows.values[1].f, 0.5);
    const PT all[4] = {PT::kUtf8, PT::kBool, PT::kUnknown, PT::kInt64};
    std::string mixed;
    bolt::api::proto::flightsql::arrow::write_parameter_schema(&mixed, 4, all);
    pos = 0;
    ASSERT_TRUE(cd::ipc_next_message(mixed, &pos, &sch, &bad));
    pm::Decoder dec4;
    EXPECT_TRUE(dec4.schema(sch.metadata, &err)) << err;
}
