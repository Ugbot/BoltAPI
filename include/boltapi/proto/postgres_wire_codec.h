// boltapi/proto/postgres_wire_codec.h — pure, allocation-free value codecs
// behind the Postgres wire Extended Query protocol (G2ETL-47).
//
// The wire layer is executor-agnostic: the host engine only ever sees plain
// SQL text. A Bind's parameters are therefore rendered into the statement as
// SQL literals here (the same approach PgBouncer-style proxies and every
// client-side interpolating driver take), and results the client asked for
// in BINARY format are encoded here from the executor's TEXT-format cells.
//
// Every function writes into a caller-owned bounded buffer and reports
// overflow / malformed input as `false` + a SQLSTATE, never a short result.
// Compiled ONLY under BOLTAPI_WITH_PG_WIRE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bolt::api::proto::pgwire {

// Well-known pg_type OIDs this codec understands.
namespace oid {
inline constexpr std::int32_t kUnspecified = 0;
inline constexpr std::int32_t kBool        = 16;
inline constexpr std::int32_t kBytea       = 17;
inline constexpr std::int32_t kName        = 19;
inline constexpr std::int32_t kInt8        = 20;
inline constexpr std::int32_t kInt2        = 21;
inline constexpr std::int32_t kInt4        = 23;
inline constexpr std::int32_t kText        = 25;
inline constexpr std::int32_t kOid         = 26;
inline constexpr std::int32_t kFloat4      = 700;
inline constexpr std::int32_t kFloat8      = 701;
inline constexpr std::int32_t kUnknown     = 705;
inline constexpr std::int32_t kBpchar      = 1042;
inline constexpr std::int32_t kVarchar     = 1043;
inline constexpr std::int32_t kDate        = 1082;
inline constexpr std::int32_t kNumeric     = 1700;
}  // namespace oid

// One bound parameter as it arrived in a Bind message.
struct BoundParam {
    std::string_view bytes;          // raw value bytes (text or binary form)
    std::int32_t     type_oid = 0;   // from Parse; 0 = unspecified
    bool             is_null  = false;
    bool             binary   = false;
};

// Failure detail shared by every codec entry point.
struct CodecError {
    const char* sqlstate = "22P02";
    const char* message  = "invalid parameter value";
};

// Decode a BINARY-format parameter to its TEXT form (int2/4/8, float4/8,
// bool, text-like, date, numeric). `out_len` receives the byte count.
bool binary_param_to_text(const BoundParam& p, char* out, std::size_t cap,
                          std::size_t& out_len, CodecError& err) noexcept;

// Render one TEXT-form value as a SQL literal for type `type_oid`: numerics
// validated and emitted bare (negatives parenthesised), bool as TRUE/FALSE,
// date as DATE '...', everything else as a standard-conforming quoted
// string. NULL renders as NULL. Appends at `out[pos]`, advancing `pos`.
bool render_literal(std::string_view text, bool is_null, std::int32_t type_oid,
                    char* out, std::size_t cap, std::size_t& pos,
                    CodecError& err) noexcept;

// Replace every `$n` placeholder OUTSIDE string literals, quoted
// identifiers, comments and dollar-quoted bodies with the rendered literal
// for params[n-1]. Binary params are decoded first. `$n` past `n_params` is
// refused (42P02).
bool substitute_params(std::string_view sql, const BoundParam* params,
                       std::uint32_t n_params, char* out, std::size_t cap,
                       std::size_t& out_len, CodecError& err) noexcept;

// Encode one TEXT-format result cell as the BINARY wire form of `type_oid`.
// Types without a binary encoder here are refused (0A000) — never guessed.
bool text_to_binary_result(std::string_view text, std::int32_t type_oid,
                           std::uint8_t* out, std::size_t cap,
                           std::size_t& out_len, CodecError& err) noexcept;

// Session-parameter statements drivers issue while connecting (pgJDBC's
// `SET extra_float_digits = 3` / `SET application_name = '...'`, psql's
// `SET client_encoding`). Handled by the wire layer, never the engine.
enum class SessionCommand : std::uint8_t {
    NotSession = 0,   // not SET/RESET: hand it to the executor
    Accepted   = 1,   // cosmetic, or already this server's value: tag "SET"/"RESET"
    Refused    = 2,   // a setting this server cannot honour: named 0A000
};

// Classify `sql`. `tag` receives "SET" or "RESET" for Accepted.
SessionCommand classify_session_command(std::string_view sql, const char*& tag,
                                        CodecError& err) noexcept;

// SHOW <setting>: answered by the wire layer from the values it already
// reports in ParameterStatus, as one text column named after the setting.
enum class ShowCommand : std::uint8_t {
    NotShow  = 0,   // not SHOW: hand it on
    Answered = 1,   // `column`/`value` hold the single-row result
    Refused  = 2,   // unknown setting (42704) or SHOW ALL (0A000)
};

struct ShowAnswer {
    const char*      column = nullptr;   // canonical setting name
    std::string_view value;              // static, or `server_version`
};

// Classify `sql`. `server_version` is this server's reported version.
ShowCommand classify_show_command(std::string_view sql, std::string_view server_version,
                                  ShowAnswer& out, CodecError& err) noexcept;

// Transaction-control statements. There are no transactions behind this
// wire layer (every statement is applied when it runs), so it answers these
// itself and tracks only the block status clients read from ReadyForQuery.
enum class TxCommand : std::uint8_t {
    None     = 0,   // not transaction control: hand it on
    Begin    = 1,   // BEGIN / START TRANSACTION [modes]
    Commit   = 2,   // COMMIT / END
    Rollback = 3,   // ROLLBACK / ABORT
    Refused  = 4,   // savepoints, two-phase, chaining, strict isolation
};

// Classify `sql`. `read_only` receives READ ONLY for Begin.
TxCommand classify_transaction_command(std::string_view sql, bool& read_only,
                                       CodecError& err) noexcept;

// Does the statement read (SELECT/WITH/VALUES/TABLE/SHOW/EXPLAIN, after
// leading whitespace, comments and parentheses)? Anything else is treated
// as a write.
bool is_query_shaped(std::string_view sql) noexcept;

// SQL-level cursors (psycopg named cursors, SQLAlchemy stream_results):
// DECLARE / FETCH / MOVE / CLOSE, answered by the wire layer over its own
// portals. Forward-only; the engine only ever sees the DECLAREd query.
inline constexpr std::size_t kMaxCursorName = 64;   // incl. the NUL

enum class CursorVerb : std::uint8_t {
    None    = 0,   // not a cursor statement: hand it on
    Declare = 1,
    Fetch   = 2,
    Move    = 3,
    Close   = 4,
    Refused = 5,   // a cursor statement this endpoint cannot honour
};

struct CursorCommand {
    CursorVerb       verb     = CursorVerb::None;
    char             name[kMaxCursorName] = {};   // case-folded unless quoted
    std::uint32_t    count    = 1;       // rows (FETCH/MOVE); ABSOLUTE position
    bool             all      = false;   // FETCH/MOVE ALL, CLOSE ALL
    bool             absolute = false;   // MOVE ABSOLUTE n
    bool             hold     = false;   // DECLARE ... WITH HOLD
    std::string_view query;              // DECLARE ... FOR <query>
};

// Classify `sql`. Refused carries the SQLSTATE in `err`.
CursorVerb classify_cursor_command(std::string_view sql, CursorCommand& out,
                                   CodecError& err) noexcept;

// Largest `$n` referenced outside literals/comments (0 if none) — used to
// infer the parameter count when Parse declares fewer types than it uses.
std::uint32_t max_param_ref(std::string_view sql) noexcept;

}  // namespace bolt::api::proto::pgwire
