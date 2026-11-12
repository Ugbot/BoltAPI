// tests/flight_sql_codec_test.cpp — the Flight SQL byte codecs, no sockets.
// Real-client conformance is flight_sql_client_conformance.py.

#include "boltapi/proto/flight_sql.h"
#include "boltapi/proto/flight_sql_arrow.h"
#include "boltapi/proto/flight_sql_codec.h"
#include "boltapi/proto/flight_sql_params.h"
#include "boltapi/proto/flight_sql_metadata.h"
#include "boltapi/boltapi_limits.h"

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
    for (int i = 0; i < 300; ++i) many += "?,";
    ASSERT_TRUE(pm::count_placeholders(many, &n));   // past the old fixed 256
    EXPECT_EQ(n, 300u);
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


namespace {
namespace fs = bolt::api::proto::flightsql;
class CatalogBoundsExecutor final : public fs::IQueryExecutor {
public:
    std::uint32_t tables = 1, visits = 0;
    std::uint16_t keys = 0;
    bool empty_name = false;
    bool execute(std::string_view, std::string*, std::int64_t*, fs::QueryFailure&) noexcept override {
        return false;
    }
    bool has_catalog() const noexcept override { return true; }
    std::uint32_t catalog_tables() noexcept override { return tables; }
    bool catalog_table(std::uint32_t i, fs::CatalogTable* out) noexcept override {
        ++visits;
        if (i >= tables || out == nullptr) return false;
        out->name = empty_name ? "" : "table";
        out->table_type = "TABLE";
        out->n_key_columns = keys;
        for (std::uint16_t k = 0; k < fs::kMaxKeyColumns; ++k) out->key_columns[k] = "key";
        return true;
    }
};

void expect_catalog(CatalogBoundsExecutor& exec, bool primary_keys,
                    fs::GrpcCode expected, std::int64_t expected_rows) {
    std::string out = "old output", value;
    if (primary_keys) cd::pb_put_bytes(&value, 3, "table");
    std::int64_t rows = -1;
    fs::QueryFailure failure;
    char message[256]{};
    const auto result = fs::metadata::build(primary_keys ?
        "arrow.flight.protocol.sql.CommandGetPrimaryKeys" :
        "arrow.flight.protocol.sql.CommandGetTables", value, exec, fs::Config{},
        &out, &rows, failure, message, sizeof(message));
    EXPECT_EQ(result, expected == fs::GrpcCode::kOk ?
        fs::metadata::Outcome::kOk : fs::metadata::Outcome::kFailed);
    EXPECT_EQ(rows, expected_rows);
    if (expected == fs::GrpcCode::kOk) EXPECT_FALSE(out.empty());
    else { EXPECT_EQ(failure.code, expected); EXPECT_TRUE(out.empty()); }
}
} // namespace

// Tables one GetTables/GetPrimaryKeys snapshot lists are the budget
// flight_sql_catalog_tables (was a fixed 4,096; JDBC/DBeaver browse warehouses
// with far more tables). Set small here so the test stays fast.
struct CatalogBudget {
    explicit CatalogBudget(std::uint64_t v) {
        bolt::LimitTable& t = bolt::api::boltapi_limits();
        i = static_cast<std::uint32_t>(bolt::api::boltapi_limits_id::flight_sql_catalog_tables);
        was = bolt::limits_value(t, i);
        EXPECT_TRUE(bolt::limits_set(&t, i, v, nullptr, 0));
    }
    ~CatalogBudget() { (void)bolt::limits_set(&bolt::api::boltapi_limits(), i, was, nullptr, 0); }
    std::uint32_t i = 0;
    std::uint64_t was = 0;
};

TEST(FlightSqlMetadata, CatalogBudgetDefaultListsAMillionTables) {
    const bolt::LimitTable& t = bolt::api::boltapi_limits();
    const auto i = static_cast<std::uint32_t>(bolt::api::boltapi_limits_id::flight_sql_catalog_tables);
    EXPECT_GE(t.descs[i].def, 1u << 20);
    EXPECT_STREQ(t.descs[i].env, "BOLTAPI_FLIGHT_SQL_CATALOG_TABLES");
}

TEST(FlightSqlMetadata, RejectsOversizedCatalogBeforeReadingEntries) {
    const CatalogBudget budget(64);
    CatalogBoundsExecutor exec;
    exec.tables = 65;
    std::string out, value;
    std::int64_t rows = -1;
    fs::QueryFailure failure;
    char message[256]{};
    (void)fs::metadata::build("arrow.flight.protocol.sql.CommandGetTables", value, exec,
                              fs::Config{}, &out, &rows, failure, message, sizeof(message));
    EXPECT_EQ(failure.code, fs::GrpcCode::kResourceExhausted);
    EXPECT_NE(std::string(failure.message).find("flight_sql_catalog_tables"), std::string::npos)
        << failure.message;
    EXPECT_EQ(exec.visits, 0u);
}

TEST(FlightSqlMetadata, RejectsInvalidEntriesBeforeSerializingKeys) {
    CatalogBoundsExecutor exec;
    exec.empty_name = true;
    expect_catalog(exec, false, fs::GrpcCode::kInternal, 0);
    exec.empty_name = false;
    exec.keys = fs::kMaxKeyColumns + 1;
    expect_catalog(exec, true, fs::GrpcCode::kInternal, 0);
}

TEST(FlightSqlMetadata, AcceptsExactTableAndKeyCapacity) {
    CatalogBoundsExecutor exec;
    exec.tables = 5000;   // past the old fixed 4,096, inside the default budget
    expect_catalog(exec, false, fs::GrpcCode::kOk, 5000);
    EXPECT_EQ(exec.visits, 5000u);
    {
        const CatalogBudget budget(64);
        exec.visits = 0;
        exec.tables = 64;
        expect_catalog(exec, false, fs::GrpcCode::kOk, 64);
        EXPECT_EQ(exec.visits, 64u);
    }
    exec.tables = 1;
    exec.keys = fs::kMaxKeyColumns;
    expect_catalog(exec, true, fs::GrpcCode::kOk, fs::kMaxKeyColumns);
}

// G2CHK-1009: DoPut parameter sets are a budget (flight_sql_doput_rows), not
// a fixed 4,096. One Int64 column of `n` rows, written by bolt's IPC writer.
namespace {
std::string int64_param_stream(std::uint32_t n) {
    auto* w = static_cast<bolt::ingest::ArrowIpcWriter*>(
        std::calloc(1, sizeof(bolt::ingest::ArrowIpcWriter)));
    auto* batch = static_cast<bolt::BoltBatch*>(std::calloc(1, sizeof(bolt::BoltBatch)));
    std::FILE* f = std::tmpfile();
    if (w == nullptr || batch == nullptr || f == nullptr) return {};
    const bolt::BoltType ty[1] = {bolt::BoltType::Int64};
    const char* names[1] = {"p"};
    std::vector<std::int64_t> vals(n);
    for (std::uint32_t i = 0; i < n; ++i) vals[i] = i;
    bolt::Arena arena;
    bolt::BoltBatch::init_empty(batch);
    bool ok = bolt::ingest::arrow_ipc_open(w, f, ty, names, 1) &&
              bolt::BoltBatch::alloc_columns(batch, &arena, 1);
    if (ok) {
        batch->num_rows = n;
        batch->num_cols = 1;
        bolt::BoltColumn& c = batch->columns[batch->read_epoch][0];
        c.type = bolt::BoltType::Int64;
        c.format = bolt::ColumnFormat::Flat;
        c.length = n;
        c.data = vals.data();
        c.type_size_bytes = 8;
        ok = bolt::ingest::arrow_ipc_write_batch(w, batch) && bolt::ingest::arrow_ipc_close(w);
    }
    std::fflush(f);
    const long size = std::ftell(f);
    std::rewind(f);
    std::string stream(ok && size > 0 ? static_cast<std::size_t>(size) : 0u, '\0');
    if (!stream.empty() && std::fread(stream.data(), 1, stream.size(), f) != stream.size()) {
        stream.clear();
    }
    std::fclose(f);
    std::free(w);
    std::free(batch);
    return stream;
}

bool decode_params(const std::string& stream, pm::Rows* rows, const char** err) {
    std::size_t pos = 0;
    bool bad = false;
    cd::IpcMessage sch;
    cd::IpcMessage rb;
    if (!cd::ipc_next_message(stream, &pos, &sch, &bad) ||
        !cd::ipc_next_message(stream, &pos, &rb, &bad)) {
        return false;
    }
    pm::Decoder dec;
    return dec.schema(sch.metadata, err) && dec.batch(rb.metadata, rb.body, rows, err);
}
}  // namespace

TEST(FlightSqlParams, DecodesMoreThan4096ParameterSets) {
    const std::string stream = int64_param_stream(5000);
    ASSERT_FALSE(stream.empty());
    pm::Rows rows;
    const char* err = nullptr;
    ASSERT_TRUE(decode_params(stream, &rows, &err)) << err;
    ASSERT_EQ(rows.n_rows, 5000u);
    EXPECT_EQ(rows.values[4999].i, 4999);
}

TEST(FlightSqlParams, ParameterSetsPastBudgetNameTheKnob) {
    bolt::LimitTable& t = bolt::api::boltapi_limits();
    const auto i = static_cast<std::uint32_t>(bolt::api::boltapi_limits_id::flight_sql_doput_rows);
    EXPECT_EQ(t.descs[i].def, 1u << 20);
    EXPECT_STREQ(t.descs[i].env, "BOLTAPI_FLIGHT_SQL_DOPUT_ROWS");
    const std::uint64_t was = bolt::limits_value(t, i);
    ASSERT_TRUE(bolt::limits_set(&t, i, 100, nullptr, 0));
    pm::Rows rows;
    const char* err = nullptr;
    EXPECT_FALSE(decode_params(int64_param_stream(101), &rows, &err));
    ASSERT_NE(err, nullptr);
    EXPECT_NE(std::string(err).find("flight_sql_doput_rows"), std::string::npos) << err;
    rows = pm::Rows{};
    EXPECT_TRUE(decode_params(int64_param_stream(100), &rows, &err)) << err;
    (void)bolt::limits_set(&t, i, was, nullptr, 0);
}

TEST(FlightSqlLimits, QueryTextDefaultsToGestaltMaxQueryBytes) {
    const bolt::LimitTable& t = bolt::api::boltapi_limits();
    const auto q = static_cast<std::uint32_t>(
        bolt::api::boltapi_limits_id::flight_sql_max_query_bytes);
    EXPECT_EQ(t.descs[q].def, 4u << 20);
    EXPECT_STREQ(t.descs[q].env, "BOLTAPI_FLIGHT_SQL_MAX_QUERY_BYTES");
    EXPECT_EQ(bolt::api::proto::flightsql::max_query_bytes(), 4u << 20);
    std::vector<pm::Value> row(1);
    row[0].kind = pm::Kind::kInt;
    row[0].i = 7;
    std::string out;
    const char* err = nullptr;
    const std::string sql = "SELECT " + std::string(100 * 1024, ' ') + "?";
    EXPECT_TRUE(pm::render(sql, row.data(), 1, bolt::api::proto::flightsql::max_query_bytes(),
                           &out, &err)) << err;
    EXPECT_FALSE(pm::render(sql, row.data(), 1, 1024, &out, &err));
    EXPECT_EQ(err, pm::kRenderTooLarge);
}

// G2CHK-1018 (boltapi): placeholders per statement are the flight_sql_params
// budget (was a fixed 256), Postgres's 65,535 by default.
TEST(FlightSqlParams, PlaceholdersAreABudgetNamingTheKnob) {
    bolt::LimitTable& t = bolt::api::boltapi_limits();
    const auto i = static_cast<std::uint32_t>(bolt::api::boltapi_limits_id::flight_sql_params);
    EXPECT_EQ(t.descs[i].def, 65535u);
    EXPECT_STREQ(t.descs[i].env, "BOLTAPI_FLIGHT_SQL_PARAMS");
    std::string sql = "SELECT ";
    for (int k = 0; k < 1000; ++k) sql += k == 0 ? "?" : ",?";
    std::uint32_t n = 0;
    ASSERT_TRUE(pm::count_placeholders(sql, &n));
    ASSERT_EQ(n, 1000u);
    std::vector<pm::Value> row(n);
    for (std::uint32_t k = 0; k < n; ++k) { row[k].kind = pm::Kind::kInt; row[k].i = k; }
    std::string handle, rendered;
    pm::encode_bound(&handle, sql, row.data(), n);
    std::string_view back;
    bool bound = false;
    std::vector<pm::Value> got;
    ASSERT_TRUE(pm::decode_handle(handle, &back, &bound, &got));
    ASSERT_TRUE(bound);
    ASSERT_EQ(got.size(), 1000u);
    EXPECT_EQ(got[999].i, 999);
    const char* err = nullptr;
    ASSERT_TRUE(pm::render(sql, got.data(), n, 1u << 20, &rendered, &err)) << err;
    EXPECT_NE(rendered.find(",999"), std::string::npos);
    const std::uint64_t was = bolt::limits_value(t, i);
    ASSERT_TRUE(bolt::limits_set(&t, i, 999, nullptr, 0));
    EXPECT_FALSE(pm::count_placeholders(sql, &n));
    EXPECT_FALSE(pm::decode_handle(handle, &back, &bound, &got));
    EXPECT_NE(std::string(pm::kTooManyParams).find("flight_sql_params"), std::string::npos);
    (void)bolt::limits_set(&t, i, was, nullptr, 0);
}

// A FlightDescriptor past 256 fields keeps its cmd (the loop stopped at 256).
TEST(FlightSqlCodec, DescriptorPast256FieldsKeepsItsCommand) {
    std::string desc;
    for (int k = 0; k < 300; ++k) cd::pb_put_varint(&desc, 9, 1);   // unknown field
    cd::pb_put_varint(&desc, 1, 2);
    cd::pb_put_bytes(&desc, 2, "cmd-bytes");
    cd::Descriptor d;
    ASSERT_TRUE(cd::decode_descriptor(desc, &d));
    EXPECT_EQ(d.type, 2u);
    EXPECT_EQ(d.cmd, "cmd-bytes");
}

// GetTables filtered by more than 256 table types (was refused).
TEST(FlightSqlMetadata, TableTypeFilterPast256Entries) {
    CatalogBoundsExecutor exec;
    exec.tables = 3;
    std::string value;
    for (int k = 0; k < 300; ++k) cd::pb_put_bytes(&value, 4, "VIEW");
    cd::pb_put_bytes(&value, 4, "TABLE");
    std::string out;
    std::int64_t rows = -1;
    fs::QueryFailure failure;
    char message[256]{};
    const auto result = fs::metadata::build("arrow.flight.protocol.sql.CommandGetTables", value,
        exec, fs::Config{}, &out, &rows, failure, message, sizeof(message));
    EXPECT_EQ(result, fs::metadata::Outcome::kOk) << failure.message;
    EXPECT_EQ(rows, 3);
}

// Concurrent HTTP/2 streams per Flight SQL connection: RFC 9113's >= 100.
TEST(FlightSqlLimits, MaxStreamsDefaultsToRfc9113) {
    const bolt::LimitTable& t = bolt::api::boltapi_limits();
    const auto i = static_cast<std::uint32_t>(bolt::api::boltapi_limits_id::flight_sql_max_streams);
    EXPECT_EQ(t.descs[i].def, 100u);
    EXPECT_STREQ(t.descs[i].env, "BOLTAPI_FLIGHT_SQL_MAX_STREAMS");
}
