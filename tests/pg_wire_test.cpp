// tests/pg_wire_test.cpp — Postgres wire protocol: codec units + the
// Extended Query state machine driven by a hand-rolled raw-socket client.
// The real-driver half (psycopg 3 / pgJDBC) is pg_wire_driver_conformance.py.

#include "boltapi/proto/postgres_wire.h"
#include "boltapi/proto/postgres_wire_codec.h"
#include "pg_wire_echo_executor.h"

#include <gtest/gtest.h>

#include "boltapi/net/sys_compat.h"

#include <cstring>
#include <string>
#include <vector>

namespace pg = bolt::api::proto::pgwire;

namespace {

std::string subst(std::string_view sql, std::vector<pg::BoundParam> ps,
                  pg::CodecError* err_out = nullptr) {
    char out[4096];
    std::size_t n = 0;
    pg::CodecError err;
    const bool ok = pg::substitute_params(sql, ps.data(), static_cast<std::uint32_t>(ps.size()),
                                          out, sizeof(out), n, err);
    if (err_out != nullptr) *err_out = err;
    return ok ? std::string(out, n) : std::string("!") + err.sqlstate;
}

pg::BoundParam text(std::string_view v, std::int32_t oid = 0) {
    pg::BoundParam p;
    p.bytes = v;
    p.type_oid = oid;
    return p;
}

pg::BoundParam null_param() {
    pg::BoundParam p;
    p.is_null = true;
    return p;
}

}  // namespace

TEST(PgWireCodec, SubstitutesOutsideQuotesAndComments) {
    EXPECT_EQ(subst("select $1, '$1', \"$1\", $2 -- $1\n/* $2 */ $$ $1 $$",
                    {text("a'b"), text("7", pg::oid::kInt4)}),
              "select 'a''b', '$1', \"$1\", 7 -- $1\n/* $2 */ $$ $1 $$");
    EXPECT_EQ(subst("x$1 $tag$ $1 $tag$ $1", {text("v")}), "x$1 $tag$ $1 $tag$ 'v'");
    EXPECT_EQ(subst("E'\\' $1' $1", {text("q")}), "E'\\' $1' 'q'");
}

TEST(PgWireCodec, TypedLiterals) {
    EXPECT_EQ(subst("a - $1", {text("-5", pg::oid::kInt8)}), "a - (-5)");
    EXPECT_EQ(subst("$1", {text("1.25e3", pg::oid::kFloat8)}), "1.25e3");
    EXPECT_EQ(subst("$1", {text("yes", pg::oid::kBool)}), "TRUE");
    EXPECT_EQ(subst("$1", {text("2024-01-31", pg::oid::kDate)}), "DATE '2024-01-31'");
    EXPECT_EQ(subst("$1", {null_param()}), "NULL");
    EXPECT_EQ(subst("$1", {text("1; drop table t", pg::oid::kInt4)}), "!22P02");
    EXPECT_EQ(subst("$1", {text("maybe", pg::oid::kBool)}), "!22P02");
    EXPECT_EQ(subst("$2", {text("1")}), "!42P02");
    EXPECT_EQ(subst("$1", {text(std::string_view("a\0b", 3))}), "!22021");
}

TEST(PgWireCodec, BinaryParams) {
    const std::uint8_t i4[] = {0xff, 0xff, 0xff, 0xfe};           // -2
    const std::uint8_t d[] = {0x00, 0x00, 0x21, 0xf5};             // 2023-10-20 (8693)
    // numeric -1234.5670: ndigits 3, weight 0, sign neg, dscale 4, [1234,5670]
    const std::uint8_t num[] = {0, 2, 0, 0, 0x40, 0, 0, 4, 0x04, 0xd2, 0x16, 0x26};
    pg::BoundParam a; a.bytes = {reinterpret_cast<const char*>(i4), 4}; a.type_oid = pg::oid::kInt4; a.binary = true;
    pg::BoundParam b; b.bytes = {reinterpret_cast<const char*>(d), 4}; b.type_oid = pg::oid::kDate; b.binary = true;
    pg::BoundParam c; c.bytes = {reinterpret_cast<const char*>(num), sizeof(num)}; c.type_oid = pg::oid::kNumeric; c.binary = true;
    EXPECT_EQ(subst("$1 $2 $3", {a, b, c}), "(-2) DATE '2023-10-20' (-1234.5670)");
    pg::BoundParam bad; bad.bytes = "xyz"; bad.type_oid = 2950; bad.binary = true;   // uuid
    EXPECT_EQ(subst("$1", {bad}), "!0A000");
}

TEST(PgWireCodec, BinaryResults) {
    std::uint8_t out[64];
    std::size_t n = 0;
    pg::CodecError e;
    ASSERT_TRUE(pg::text_to_binary_result("-42", pg::oid::kInt8, out, sizeof(out), n, e));
    ASSERT_EQ(n, 8u);
    EXPECT_EQ(out[7], 0xd6);
    EXPECT_EQ(out[0], 0xff);
    ASSERT_TRUE(pg::text_to_binary_result("2024-02-29", pg::oid::kDate, out, sizeof(out), n, e));
    EXPECT_EQ(n, 4u);   // 8825 days after 2000-01-01
    EXPECT_EQ((out[2] << 8) | out[3], 8825);
    ASSERT_TRUE(pg::text_to_binary_result("-12.3450", pg::oid::kNumeric, out, sizeof(out), n, e));
    const std::uint8_t want[] = {0, 2, 0, 0, 0x40, 0, 0, 4, 0, 12, 0x0d, 0x7a};
    ASSERT_EQ(n, sizeof(want));
    EXPECT_EQ(std::memcmp(out, want, n), 0);
    EXPECT_FALSE(pg::text_to_binary_result("abc", pg::oid::kInt4, out, sizeof(out), n, e));
    EXPECT_FALSE(pg::text_to_binary_result("{}", 3802, out, sizeof(out), n, e));   // jsonb
    EXPECT_STREQ(e.sqlstate, "0A000");
}

// ---------------------------------------------------------------------------
// Raw-socket client.
// ---------------------------------------------------------------------------
namespace {

struct Msg {
    char type;
    std::string body;
};

class PgClient {
public:
    ~PgClient() { if (fd_ >= 0) bolt::api::net::sys::close_socket(fd_); }

    bool connect(std::uint16_t port) {
        bolt::api::net::sys::startup();
        fd_ = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        timeval tv{5, 0};
        (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        std::string body;
        put32(body, 196608);
        body += std::string("user\0t\0\0", 8);
        std::string pkt;
        put32(pkt, static_cast<std::int32_t>(body.size() + 4));
        pkt += body;
        if (!send_raw(pkt)) return false;
        return !read_until_ready().empty();
    }

    void msg(char type, const std::string& body) {
        out_ += type;
        put32(out_, static_cast<std::int32_t>(body.size() + 4));
        out_ += body;
    }
    void parse(const std::string& name, const std::string& sql, std::vector<std::int32_t> oids = {}) {
        std::string b = cstr(name) + cstr(sql);
        put16(b, static_cast<std::int16_t>(oids.size()));
        for (auto o : oids) put32(b, o);
        msg('P', b);
    }
    // params: nullptr-marked by `nulls`; fmt applies to all params; rfmt per result.
    void bind(const std::string& portal, const std::string& stmt,
              std::vector<std::string> params, std::int16_t fmt = 0,
              std::vector<std::int16_t> rfmt = {}) {
        std::string b = cstr(portal) + cstr(stmt);
        put16(b, 1);
        put16(b, fmt);
        put16(b, static_cast<std::int16_t>(params.size()));
        for (auto& p : params) {
            if (p == "<NULL>") { put32(b, -1); continue; }
            put32(b, static_cast<std::int32_t>(p.size()));
            b += p;
        }
        put16(b, static_cast<std::int16_t>(rfmt.size()));
        for (auto f : rfmt) put16(b, f);
        msg('B', b);
    }
    void describe(char kind, const std::string& name) { msg('D', std::string(1, kind) + cstr(name)); }
    void execute(const std::string& portal, std::int32_t max_rows = 0) {
        std::string b = cstr(portal);
        put32(b, max_rows);
        msg('E', b);
    }
    void close(char kind, const std::string& name) { msg('C', std::string(1, kind) + cstr(name)); }
    void sync() { msg('S', ""); }

    // Flush queued messages and read replies through ReadyForQuery.
    std::vector<Msg> roundtrip() {
        const bool sent = send_raw(out_);
        out_.clear();
        if (!sent) return {};
        return read_until_ready();
    }

    static std::string types(const std::vector<Msg>& ms) {
        std::string s;
        for (auto& m : ms) s += m.type;
        return s;
    }

    // DataRow column 0 as text.
    static std::string col0(const Msg& m) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(m.body.data());
        const std::int32_t len = (p[2] << 24) | (p[3] << 16) | (p[4] << 8) | p[5];
        return len < 0 ? "<NULL>" : m.body.substr(6, static_cast<std::size_t>(len));
    }
    static std::string sqlstate(const Msg& m) {
        const auto pos = m.body.find(std::string("\0C", 2));
        return pos == std::string::npos ? "" : m.body.substr(pos + 2, 5);
    }

private:
    static std::string cstr(const std::string& s) { return s + std::string(1, '\0'); }
    static void put16(std::string& s, std::int16_t v) {
        s += static_cast<char>((v >> 8) & 0xff);
        s += static_cast<char>(v & 0xff);
    }
    static void put32(std::string& s, std::int32_t v) {
        for (int k = 3; k >= 0; --k) s += static_cast<char>((v >> (8 * k)) & 0xff);
    }
    bool send_raw(const std::string& s) {
        std::size_t sent = 0;
        while (sent < s.size()) {
            const ssize_t w = bolt::api::net::sys::send_bytes(fd_, s.data() + sent, s.size() - sent);
            if (w <= 0) return false;
            sent += static_cast<std::size_t>(w);
        }
        return true;
    }
    bool recv_raw(void* p, std::size_t n) {
        auto* b = static_cast<std::uint8_t*>(p);
        std::size_t g = 0;
        while (g < n) {
            const ssize_t r = bolt::api::net::sys::recv_bytes(fd_, b + g, n - g);
            if (r <= 0) return false;
            g += static_cast<std::size_t>(r);
        }
        return true;
    }
    std::vector<Msg> read_until_ready() {
        std::vector<Msg> out;
        for (int i = 0; i < 10000; ++i) {
            std::uint8_t h[5];
            if (!recv_raw(h, 5)) return {};
            const std::int32_t len = (h[1] << 24) | (h[2] << 16) | (h[3] << 8) | h[4];
            std::string body(static_cast<std::size_t>(len - 4), '\0');
            if (len > 4 && !recv_raw(body.data(), body.size())) return {};
            out.push_back({static_cast<char>(h[0]), body});
            if (h[0] == 'Z') break;
        }
        return out;
    }

    int fd_ = -1;
    std::string out_;
};

class PgWire : public ::testing::Test {
protected:
    void SetUp() override {
        pg::Config cfg;
        cfg.port = 0;
        cfg.max_connections = 1;
        cfg.accept_poll_ms = 20;
        cfg.max_prepared_statements = 3;
        cfg.max_portals = 2;
        proto_ = std::make_unique<pg::Protocol>(cfg, factory_);
        ASSERT_FALSE(proto_->start_background().is_err());
        ASSERT_TRUE(c_.connect(proto_->local_port()));
    }
    void TearDown() override { proto_->stop(); }

    boltapi_test::PgEchoFactory factory_;
    std::unique_ptr<pg::Protocol> proto_;
    PgClient c_;
};

}  // namespace

TEST_F(PgWire, UnnamedParseBindDescribeExecute) {
    c_.parse("", "select $1, $2", {pg::oid::kInt4, 0});
    c_.bind("", "", {"5", "it's"});
    c_.describe('P', "");
    c_.execute("");
    c_.sync();
    const auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12TDCZ");
    EXPECT_EQ(PgClient::col0(r[3]), "select 5, 'it''s'");
    EXPECT_EQ(r[4].body, std::string("SELECT 1\0", 9));
}

TEST_F(PgWire, NamedStatementReusedAcrossBinds) {
    c_.parse("s1", "select $1", {pg::oid::kInt8});
    c_.describe('S', "s1");
    c_.sync();
    auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "1tTZ");   // ParameterDescription + RowDescription
    EXPECT_EQ(factory_.last->executes, 0);   // describe never Executes
    for (int k = 1; k <= 2; ++k) {
        c_.bind("", "s1", {std::to_string(k * 10)});
        c_.execute("");
        c_.sync();
        r = c_.roundtrip();
        ASSERT_EQ(PgClient::types(r), "2DCZ");
        EXPECT_EQ(PgClient::col0(r[1]), "select " + std::to_string(k * 10));
    }
    c_.close('S', "s1");
    c_.bind("", "s1", {"1"});
    c_.sync();
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "3EZ");
    EXPECT_EQ(PgClient::sqlstate(r[1]), "26000");
}

TEST_F(PgWire, DescribeStatementOfWriteIsNoData) {
    c_.parse("", "ddl insert into t values ($1)");
    c_.describe('S', "");
    c_.sync();
    const auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "1tnZ");
    EXPECT_EQ(factory_.last->executes + factory_.last->describes, 0);
}

TEST_F(PgWire, MaxRowsSuspendsAndResumes) {
    c_.parse("", "rows 5");
    c_.bind("", "", {});
    c_.execute("", 2);
    c_.execute("", 2);
    c_.execute("", 2);
    c_.sync();
    const auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12DDsDDsDCZ");
    EXPECT_EQ(PgClient::col0(r[8]), "5");
    EXPECT_EQ(factory_.last->executes, 1);
}

TEST_F(PgWire, ErrorDiscardsUntilSyncThenRecovers) {
    c_.parse("", "fail now");
    c_.bind("", "", {});
    c_.execute("");
    c_.parse("x", "select 1");   // must be skipped: still in the failed batch
    c_.sync();
    auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12EZ");
    EXPECT_EQ(PgClient::sqlstate(r[2]), "42601");
    c_.bind("", "x", {});
    c_.sync();
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "EZ");        // "x" was never created
    EXPECT_EQ(PgClient::sqlstate(r[0]), "26000");
    c_.parse("", "select 2");
    c_.bind("", "", {});
    c_.execute("");
    c_.sync();
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12DCZ");
}

TEST_F(PgWire, BinaryResultFormats) {
    c_.parse("", "types");
    c_.bind("", "", {}, 0, {1});   // all columns binary
    c_.describe('P', "");
    c_.execute("");
    c_.sync();
    const auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12TDCZ");
    const std::string& row = r[3].body;
    // int8 -42, 8 bytes big-endian.
    ASSERT_GE(row.size(), 14u);
    EXPECT_EQ(static_cast<std::uint8_t>(row[5]), 8u);
    EXPECT_EQ(static_cast<std::uint8_t>(row[13]), 0xd6u);
    // Last column is NULL (-1).
    EXPECT_EQ(row.substr(row.size() - 4), std::string("\xff\xff\xff\xff", 4));
}

TEST_F(PgWire, SlotExhaustionIsNamedNotEvicted) {
    c_.parse("a", "select 1");
    c_.parse("b", "select 2");
    c_.parse("c", "select 3");      // 3 slots incl. unnamed -> 2 named max
    c_.sync();
    auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "11EZ");
    EXPECT_EQ(PgClient::sqlstate(r[2]), "53000");
    c_.bind("", "a", {});
    c_.execute("");
    c_.sync();
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "2DCZ");
    EXPECT_EQ(PgClient::col0(r[1]), "select 1");
}

TEST_F(PgWire, DisplacedPortalIsRefused) {
    c_.parse("", "rows 4");
    c_.bind("p1", "", {});
    c_.execute("p1", 1);
    c_.parse("", "rows 3");
    c_.bind("", "", {});
    c_.execute("");
    c_.execute("p1", 1);
    c_.sync();
    const auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12Ds12DDDCEZ");
    EXPECT_EQ(PgClient::sqlstate(r[10]), "55000");
}

TEST_F(PgWire, SimpleQueryStillWorksAfterExtended) {
    c_.parse("", "select $1", {pg::oid::kText});
    c_.bind("", "", {"<NULL>"});
    c_.execute("");
    c_.sync();
    auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12DCZ");
    EXPECT_EQ(PgClient::col0(r[2]), "select NULL");
    c_.msg('Q', std::string("hello\0", 6));
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "TDCZ");
    EXPECT_EQ(PgClient::col0(r[1]), "hello");
}

TEST(PgWireCodec, SessionCommands) {
    const char* tag = nullptr;
    pg::CodecError e;
    EXPECT_EQ(pg::classify_session_command("SET extra_float_digits = 3", tag, e),
              pg::SessionCommand::Accepted);
    EXPECT_STREQ(tag, "SET");
    EXPECT_EQ(pg::classify_session_command("set application_name to 'x y'", tag, e),
              pg::SessionCommand::Accepted);
    EXPECT_EQ(pg::classify_session_command("SET TIME ZONE 'UTC'", tag, e),
              pg::SessionCommand::Accepted);
    EXPECT_EQ(pg::classify_session_command("SET TIME ZONE 'America/New_York'", tag, e),
              pg::SessionCommand::Refused);
    EXPECT_EQ(pg::classify_session_command("SET search_path = other", tag, e),
              pg::SessionCommand::Refused);
    EXPECT_STREQ(e.sqlstate, "0A000");
    EXPECT_EQ(pg::classify_session_command("RESET ALL;", tag, e), pg::SessionCommand::Accepted);
    EXPECT_EQ(pg::classify_session_command("select 1", tag, e), pg::SessionCommand::NotSession);
    EXPECT_EQ(pg::classify_session_command("settings", tag, e), pg::SessionCommand::NotSession);
}

TEST_F(PgWire, SetIsAnsweredByTheWireLayer) {
    c_.parse("", "SET application_name = 'x'");
    c_.bind("", "", {});
    c_.describe('P', "");
    c_.execute("");
    c_.sync();
    auto r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "12nCZ");
    EXPECT_EQ(r[3].body, std::string("SET\0", 4));
    EXPECT_EQ(factory_.last->executes, 0);
    c_.msg('Q', std::string("SET search_path = elsewhere\0", 28));
    r = c_.roundtrip();
    ASSERT_EQ(PgClient::types(r), "EZ");
    EXPECT_EQ(PgClient::sqlstate(r[0]), "0A000");
}
