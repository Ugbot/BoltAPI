// src/proto/postgres_wire_extended.h — per-worker Extended Query protocol
// state (prepared statements + portals). Private to boltapi. See the SCOPE
// note in boltapi/proto/postgres_wire.h. Compiled only under
// BOLTAPI_WITH_PG_WIRE.
#pragma once

#include "boltapi/proto/postgres_wire.h"
#include "boltapi/proto/postgres_wire_codec.h"
#include "postgres_wire_internal.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace bolt::api::proto::pgwire::detail {

inline constexpr std::uint32_t kMaxParams  = 256;   // per statement
inline constexpr std::size_t   kMaxNameLen = 64;    // statement/portal names

inline bool binary_result_supported(std::int32_t t) noexcept {
    switch (t) {
        case oid::kBool: case oid::kInt2: case oid::kInt4: case oid::kInt8:
        case oid::kOid: case oid::kFloat4: case oid::kFloat8: case oid::kDate:
        case oid::kNumeric: case oid::kText: case oid::kVarchar: case oid::kBpchar:
        case oid::kName: case oid::kUnknown:
            return true;
        default:
            return false;
    }
}

inline bool is_text_like(std::int32_t t) noexcept {
    return t == oid::kText || t == oid::kVarchar || t == oid::kBpchar ||
           t == oid::kName || t == oid::kUnknown;
}

class ExtendedSession {
public:
    explicit ExtendedSession(const Config& cfg) noexcept;

    // Forget every statement/portal: a new connection starts clean.
    void reset() noexcept;

    // Simple Query destroys the unnamed statement and portal.
    void on_simple_query() noexcept;

    // Transaction block status for ReadyForQuery: 'I', 'T' or 'E'.
    char tx_status() const noexcept { return tx_status_; }

    // Every ErrorResponse inside a block fails it (T -> E), as in Postgres.
    void tx_on_error() noexcept {
        if (tx_status_ == 'T') tx_status_ = 'E';
    }

    enum class TxStep : std::uint8_t { Pass, Tagged, Failed };

    // Answer transaction control here, and refuse everything else in a
    // failed block. Tagged: `tag` is the CommandComplete tag. Failed: `qf`
    // holds the error for the caller to send.
    TxStep tx_statement(std::string_view sql, int fd, MsgWriter& w,
                        const char*& tag, QueryFailure& qf) noexcept;

    // An engine statement about to run: refused if it writes inside a READ
    // ONLY block, otherwise counted when it writes inside a block.
    bool tx_admit(std::string_view sql, QueryFailure& qf) noexcept;

    enum class CursorStep : std::uint8_t { Pass, Tagged, Fetch, Failed };

    // SQL-level cursors. DECLARE/MOVE/CLOSE are answered here (Tagged, tag
    // written to `tag`); FETCH resolves to the cursor's portal (`cursor`,
    // `count` rows, UINT32_MAX = ALL) for the caller to stream.
    CursorStep cursor_statement(std::string_view sql, IQueryExecutor& exec, char* tag,
                                std::size_t tag_cap, std::int32_t& cursor,
                                std::uint32_t& count, QueryFailure& qf) noexcept;

    enum class Emit : std::uint8_t { Done, Suspended, Failed, Dead };

    // Simple-Query FETCH: RowDescription + DataRows + CommandComplete.
    Emit simple_fetch(std::int32_t cursor, std::uint32_t count, int fd, MsgWriter& w,
                      IQueryExecutor& exec, QueryFailure& qf) noexcept;

    // SHOW <setting>, answered from this server's reported values.
    ShowCommand show_statement(std::string_view sql, ShowAnswer& out,
                               QueryFailure& qf) const noexcept;

    // The executor is about to replace its buffered result.
    void displace() noexcept { current_ = -1; }

    // Handle one extended-protocol message ('P','B','D','E','C','H','S').
    // Returns false only when the socket write failed (connection is dead).
    bool handle(char type, const std::uint8_t* body, std::size_t len, int fd,
                MsgWriter& w, IQueryExecutor& exec) noexcept;

private:
    struct Statement {
        char          name[kMaxNameLen] = {};
        bool          used     = false;
        std::size_t   sql_off  = 0;
        std::size_t   sql_len  = 0;
        std::uint32_t n_params = 0;
        std::int32_t  param_types[kMaxParams] = {};
    };
    struct Portal {
        char          name[kMaxNameLen] = {};
        bool          used         = false;
        bool          empty_query  = false;
        bool          materialized = false;   // ran at least once
        bool          done         = false;
        const char*   session_tag  = nullptr;  // SET/RESET answered by the wire layer
        bool          show         = false;    // SHOW answered by the wire layer
        std::uint32_t show_len     = 0;
        char          show_value[kMaxNameLen] = {};
        std::size_t   sql_len      = 0;
        bool          cursor       = false;   // opened by DECLARE
        bool          holdable     = false;   // WITH HOLD: survives the block
        std::int32_t  fetch_from   = -1;      // FETCH portal: the cursor it drains
        std::uint32_t fetch_left   = 0;
        std::uint32_t fetch_sent   = 0;
        char          tag_buf[32]  = {};
        std::uint32_t next_row     = 0;
        std::uint32_t field_count  = 0;
        std::uint32_t n_formats    = 0;       // 0 = all text, 1 = all, else per column
        std::int16_t  formats[kMaxFields] = {};
        std::int32_t  oids[kMaxFields]    = {};
        char          names[kMaxFields][kMaxNameLen] = {};   // for re-Describe
    };

    bool on_parse(BodyReader& r, int fd, MsgWriter& w) noexcept;
    bool on_bind(BodyReader& r, int fd, MsgWriter& w) noexcept;
    bool on_describe(BodyReader& r, int fd, MsgWriter& w, IQueryExecutor& exec) noexcept;
    bool on_execute(BodyReader& r, int fd, MsgWriter& w, IQueryExecutor& exec) noexcept;
    bool on_close(BodyReader& r, int fd, MsgWriter& w) noexcept;

    bool fail(int fd, MsgWriter& w, const char* sqlstate, std::string_view msg) noexcept;
    bool materialize(std::int32_t pi, int fd, MsgWriter& w, IQueryExecutor& exec,
                     FieldDesc* fields, QueryFailure& qf) noexcept;
    TxStep tx_end(bool rollback, const char*& tag, QueryFailure& qf) noexcept;
    bool describe_statement(const Statement& st, int fd, MsgWriter& w,
                            IQueryExecutor& exec) noexcept;
    bool send_show(Portal& p, int fd, MsgWriter& w) noexcept;
    bool send_rows(Portal& p, std::int32_t max_rows, int fd, MsgWriter& w,
                   IQueryExecutor& exec) noexcept;
    Emit emit_rows(const Portal& fmt, std::uint32_t& next_row, std::uint64_t end_row,
                   std::int32_t max_rows, int fd, MsgWriter& w, IQueryExecutor& exec,
                   QueryFailure& qf) noexcept;
    CursorStep cursor_declare(const CursorCommand& cc, IQueryExecutor& exec,
                              QueryFailure& qf) noexcept;
    bool bind_fetch(std::int32_t pi, std::int32_t ci, std::uint32_t count,
                    QueryFailure& qf) noexcept;
    bool send_fetch(Portal& p, std::int32_t max_rows, int fd, MsgWriter& w,
                    IQueryExecutor& exec) noexcept;
    // FETCH portals read their cursor's buffered result.
    static std::int32_t result_owner(const Portal& p, std::int32_t pi) noexcept {
        return p.fetch_from > 0 ? p.fetch_from : pi;
    }
    bool describe_fetch(std::string_view sql, int fd, MsgWriter& w) noexcept;
    std::int16_t format_of(const Portal& p, std::uint32_t col) const noexcept;

    std::int32_t find_statement(std::string_view name) const noexcept;
    std::int32_t find_portal(std::string_view name) const noexcept;
    bool         store_sql(Statement& st, std::string_view sql) noexcept;
    void         close_statement(std::int32_t si) noexcept;
    void         close_portal(std::int32_t pi) noexcept;
    std::string_view statement_sql(const Statement& st) const noexcept;
    char*        portal_sql(std::int32_t pi) noexcept;

    const std::uint32_t    max_stmt_bytes_;
    const std::string_view server_version_;   // cfg outlives the session
    std::vector<Statement> stmts_;         // [0] = unnamed
    std::vector<Portal>    portals_;       // [0] = unnamed
    std::vector<char>      stmt_pool_;     // compacting text pool
    std::size_t            pool_used_ = 0;
    std::vector<char>      portal_sql_;    // [max_portals][max_statement_bytes]
    std::vector<char>      describe_sql_;  // Describe(statement) probe text
    std::int32_t           current_ = -1;  // portal whose rows the executor holds
    bool                   in_error_ = false;
    char                   tx_status_ = 'I';
    bool                   tx_read_only_ = false;
    std::uint32_t          tx_writes_ = 0;   // applied inside the open block
};

}  // namespace bolt::api::proto::pgwire::detail
