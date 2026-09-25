// boltapi/proto/flight_sql_params.h — prepared-statement parameters for the
// Flight SQL endpoint (G2ETL-75): the `?` placeholder scan, the Arrow IPC
// decode of a DoPut parameter batch, SQL-literal substitution, and the
// stateless handle that carries a bound parameter set.
//
// Binding is by substitution: each `?` outside a string literal, quoted
// identifier or comment is replaced by the ANSI literal of its value
// (integers, doubles with a '.', '...' strings with '' doubling, TRUE/FALSE,
// NULL; negatives parenthesised so `x-?` never forms a `--` comment). The
// host's executor therefore only ever sees complete SQL text.
//
// Accepted parameter columns: Null, Int 8..64 signed/unsigned, Float32/64,
// Utf8, LargeUtf8, Bool, and a dense union of those (the type a
// parameter_schema advertises). Anything else is refused by name.
// Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api::proto::flightsql::params {

inline constexpr std::uint32_t kMaxParams = 256;      // placeholders per statement
inline constexpr std::uint32_t kMaxRows = 4096;       // parameter sets per DoPut

enum class Kind : std::uint8_t { kNull = 0, kInt = 1, kUInt = 2, kFloat = 3, kString = 4, kBool = 5 };

struct Value {
    Kind             kind = Kind::kNull;
    std::int64_t     i = 0;
    std::uint64_t    u = 0;
    double           f = 0.0;
    bool             b = false;
    std::string_view s;   // kString; points into the decoded buffer
};

namespace detail {
class Fb;
struct View;
}  // namespace detail

// Parameter sets, row-major: row r, column c is values[r * n_cols + c].
struct Rows {
    std::uint32_t      n_cols = 0;
    std::uint32_t      n_rows = 0;
    std::vector<Value> values;
};

// Decodes one IPC stream's worth of messages: a Schema, then RecordBatches
// appended to `out`. `metadata` is a Message flatbuffer (FlightData
// data_header). On failure `err` names the problem (static storage).
class Decoder {
public:
    bool schema(std::string_view metadata, const char** err);
    bool batch(std::string_view metadata, std::string_view body, Rows* out, const char** err);
    bool has_schema() const noexcept { return have_schema_; }
    // The last failure refused a well-formed but unsupported type or encoding.
    bool unsupported() const noexcept { return unsupported_; }

    struct Col {
        std::uint8_t  type = 0;       // Schema.fbs Type union id
        std::int32_t  bits = 0;       // Int bitWidth / FloatingPoint precision
        bool          is_signed = false;
        std::uint8_t  n_children = 0; // dense union members
        std::uint16_t child = 0;      // index of the first member in cols_
    };

private:
    enum class Field : std::uint8_t { kOk, kUnsupported, kMalformed };
    Field describe_top(detail::Fb& fb, std::size_t field, std::uint32_t k);
    bool  append_rows(const std::vector<detail::View>& views, std::int64_t length, Rows* out,
                      const char** err);

    bool have_schema_ = false;
    bool unsupported_ = false;
    const char* why_ = "";
    char        why_buf_[96] = {};
    std::uint32_t    n_top_ = 0;
    std::vector<Col> cols_;   // top-level fields, then union members
    std::vector<std::int32_t> codes_;   // type code of member cols_[n_top_ + i]
};

// MessageHeader type of an IPC Message flatbuffer (codec::kIpcHeader*),
// 0 when malformed.
std::uint8_t header_type(std::string_view metadata) noexcept;

// Number of `?` placeholders; false when there are more than kMaxParams.
bool count_placeholders(std::string_view sql, std::uint32_t* n) noexcept;

// `sql` with its placeholders replaced by the literals of `row[0..n)`.
// `n` must equal count_placeholders(sql). False (with `err`) on a value
// that has no SQL literal (NaN, infinity) or when the result exceeds `cap`.
bool render(std::string_view sql, const Value* row, std::uint32_t n, std::size_t cap,
            std::string* out, const char** err);

// Prepared-statement handles. Unbound: prefix + SQL. Bound: a second
// prefix, the SQL, then the one bound parameter set.
inline constexpr std::string_view kHandleMagic = "boltapi-fsql-ps1:";
inline constexpr std::string_view kBoundMagic = "boltapi-fsql-ps2:";

void encode_unbound(std::string* out, std::string_view sql);
void encode_bound(std::string* out, std::string_view sql, const Value* row, std::uint32_t n);
// False when `handle` was not issued by this endpoint. `row` receives the
// bound values (their strings point into `handle`); `*bound` tells which.
bool decode_handle(std::string_view handle, std::string_view* sql, bool* bound,
                   std::vector<Value>* row);

}  // namespace bolt::api::proto::flightsql::params
