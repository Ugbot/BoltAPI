// flight_params — the Arrow IPC parameter decoder behind a Flight SQL DoPut
// (Schema + RecordBatch flatbuffers and buffers, dense unions), then
// literal substitution and handle round-trip, as the server binds them.
// Input: an Arrow IPC stream.
#include "fuzz_util.h"

#include "boltapi/proto/flight_sql_codec.h"
#include "boltapi/proto/flight_sql_params.h"

#include <string>
#include <string_view>
#include <vector>

namespace cd = bolt::api::proto::flightsql::codec;
namespace pm = bolt::api::proto::flightsql::params;

namespace {

bool inside(std::string_view v, std::string_view buf) {
    return v.empty() ||
           (v.data() >= buf.data() && v.data() + v.size() <= buf.data() + buf.size());
}

constexpr char kSql[] = "SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE x = '?' -- ?\n";

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view stream(reinterpret_cast<const char*>(data), size);
    pm::Decoder dec;
    pm::Rows rows;
    std::size_t pos = 0;
    cd::IpcMessage m;
    bool bad = false;
    for (int guard = 0; guard < 256 && cd::ipc_next_message(stream, &pos, &m, &bad); ++guard) {
        const char* err = nullptr;
        if (m.header_type == cd::kIpcHeaderSchema && !dec.has_schema()) {
            if (!dec.schema(m.metadata, &err)) {
                FUZZ_CHECK(err != nullptr);
                break;
            }
        } else if (m.header_type == cd::kIpcHeaderRecordBatch && dec.has_schema()) {
            if (!dec.batch(m.metadata, m.body, &rows, &err)) {
                FUZZ_CHECK(err != nullptr);
                break;
            }
            FUZZ_CHECK(rows.values.size() ==
                       static_cast<std::size_t>(rows.n_rows) * rows.n_cols);
        }
    }
    for (const pm::Value& v : rows.values) {
        if (v.kind == pm::Kind::kString) FUZZ_CHECK(inside(v.s, stream));
    }
    std::uint32_t n = 0;
    FUZZ_CHECK(pm::count_placeholders(kSql, &n) && n == 8);
    for (std::uint32_t r = 0; r < rows.n_rows && r < 16; ++r) {
        const pm::Value* row = rows.values.data() + static_cast<std::size_t>(r) * rows.n_cols;
        std::string out;
        const char* err = nullptr;
        if (rows.n_cols == n && !pm::render(kSql, row, n, 1u << 20, &out, &err)) {
            FUZZ_CHECK(err != nullptr);
        }
        std::string h;
        pm::encode_bound(&h, kSql, row, rows.n_cols);
        std::string_view sql;
        bool bound = false;
        std::vector<pm::Value> back;
        FUZZ_CHECK(pm::decode_handle(h, &sql, &bound, &back));
        FUZZ_CHECK(bound && sql == kSql && back.size() == rows.n_cols);
    }
    return 0;
}
