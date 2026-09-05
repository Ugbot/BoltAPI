// tests/neo4j_bolt_wire_test.cpp — drive the Bolt server with a raw socket.
//
// This is the deterministic, dependency-free half of the acceptance. It speaks
// the wire by hand (handshake, chunk framing, PackStream) so the state machine
// is asserted on VALUES, and it pins the refusal behaviour a driver test cannot
// easily provoke: IGNORED after FAILURE, a declined handshake, an oversized
// message. The official-driver conformance run is the other half.
//
// "Bolt" here is Neo4j's client wire protocol, not extern/bolt.

#include "boltapi/proto/neo4j_bolt.h"
#include "neo4j_bolt_echo_executor.h"

#include <gtest/gtest.h>

#include "boltapi/net/sys_compat.h"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace ps = bolt::api::proto::packstream;
namespace nb = bolt::api::proto::neo4j;

namespace {

// A hand-rolled Bolt client: enough to exercise the server, nothing more.
class WireClient {
public:
    ~WireClient() { close(); }

    bool connect(std::uint16_t port) {
        bolt::api::net::sys::startup();
        fd_ = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd_ < 0) return false;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            close();
            return false;
        }
        timeval tv{5, 0};
        (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                           reinterpret_cast<const char*>(&tv), sizeof(tv));
        return true;
    }

    void close() {
        if (fd_ >= 0) { bolt::api::net::sys::close_socket(fd_); fd_ = -1; }
    }

    bool send_raw(const void* p, std::size_t n) {
        const auto* b = static_cast<const std::uint8_t*>(p);
        std::size_t s = 0;
        while (s < n) {
            const ssize_t w = bolt::api::net::sys::send_bytes(fd_, b + s, n - s);
            if (w <= 0) return false;
            s += static_cast<std::size_t>(w);
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

    // Send the 20-byte preamble; return the 4-byte reply as a Version.
    nb::Version handshake(const std::uint8_t proposals[16]) {
        std::uint8_t hs[20] = {0x60, 0x60, 0xB0, 0x17};
        std::memcpy(hs + 4, proposals, 16);
        if (!send_raw(hs, sizeof(hs))) return {};
        std::uint8_t r[4] = {0, 0, 0, 0};
        if (!recv_raw(r, 4)) return {};
        return nb::Version{r[3], r[2]};
    }

    bool send_message(const std::uint8_t* payload, std::size_t n) {
        std::uint8_t hdr[2] = {static_cast<std::uint8_t>(n >> 8),
                               static_cast<std::uint8_t>(n & 0xFF)};
        static const std::uint8_t end[2] = {0, 0};
        return send_raw(hdr, 2) && send_raw(payload, n) && send_raw(end, 2);
    }

    // Reassemble one message into `out`. Returns byte count or -1.
    std::int64_t recv_message(std::vector<std::uint8_t>& out) {
        out.clear();
        for (;;) {
            std::uint8_t hdr[2];
            if (!recv_raw(hdr, 2)) return -1;
            const std::size_t len = (static_cast<std::size_t>(hdr[0]) << 8) | hdr[1];
            if (len == 0) break;
            const std::size_t at = out.size();
            out.resize(at + len);
            if (!recv_raw(out.data() + at, len)) return -1;
        }
        return static_cast<std::int64_t>(out.size());
    }

private:
    int fd_ = -1;
};

// One decoded server message plus its arena.
struct Reply {
    std::vector<std::uint8_t> mem = std::vector<std::uint8_t>(1u << 18);
    std::vector<std::uint8_t> bytes;
    ps::PackValue v{};

    nb::Signature signature() const { return static_cast<nb::Signature>(v.signature); }

    bool read(WireClient& c) {
        if (c.recv_message(bytes) < 0) return false;
        // The arena OBJECT is a local, but the storage it bump-allocates from
        // is `mem`, a member — so every pointer inside `v` stays valid for as
        // long as this Reply does.
        ps::PackArena a(mem.data(), mem.size());
        ps::PackReader r(bytes.data(), bytes.size(), a);
        return r.read(v) == ps::PackError::Ok;
    }
};

struct Msg {
    std::uint8_t buf[4096];
    ps::PackWriter w{buf, sizeof(buf)};
    bool send(WireClient& c) { return c.send_message(w.data(), w.size()); }
};

// A protocol instance on an ephemeral port, torn down with the fixture.
class BoltServerFixture : public ::testing::Test {
protected:
    void SetUp() override {
        nb::Config cfg;
        cfg.bind.host = "127.0.0.1";
        cfg.bind.port = 0;
        cfg.max_connections = 2;
        cfg.message_buffer_bytes = 64 * 1024;
        cfg.write_buffer_bytes = 64 * 1024;
        cfg.value_arena_bytes = 256 * 1024;
        cfg.accept_poll_ms = 25;
        cfg.idle_timeout_ms = 5000;
        proto_ = std::make_unique<nb::Neo4jBoltProtocol>(cfg, factory_);
        const auto s = proto_->start_background();
        ASSERT_TRUE(s.is_ok());
        port_ = proto_->local_port();
        ASSERT_NE(port_, 0);
    }

    void TearDown() override {
        if (proto_) proto_->stop();
        proto_.reset();
    }

    // Handshake + HELLO (+ LOGON when the negotiated version needs it).
    nb::Version open_session(WireClient& c) {
        const std::uint8_t proposals[16] = {0x00, 0x00, 0x01, 0xFF,
                                            0x00, 0x08, 0x08, 0x05,
                                            0x00, 0x02, 0x04, 0x04,
                                            0x00, 0x00, 0x00, 0x03};
        const nb::Version v = c.handshake(proposals);
        if (!v.valid()) return v;
        Msg hello;
        (void)hello.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Hello), 1);
        (void)hello.w.begin_dict(1);
        (void)hello.w.put_string("user_agent");
        (void)hello.w.put_string("boltapi-wire-test/1.0");
        EXPECT_TRUE(hello.send(c));
        Reply r;
        EXPECT_TRUE(r.read(c));
        EXPECT_EQ(r.signature(), nb::Signature::Success);
        if (v.has_logon()) {
            Msg logon;
            (void)logon.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Logon), 1);
            (void)logon.w.begin_dict(1);
            (void)logon.w.put_string("scheme");
            (void)logon.w.put_string("none");
            EXPECT_TRUE(logon.send(c));
            Reply lr;
            EXPECT_TRUE(lr.read(c));
            EXPECT_EQ(lr.signature(), nb::Signature::Success);
        }
        return v;
    }

    boltapi_test::EchoFactory factory_;
    std::unique_ptr<nb::Neo4jBoltProtocol> proto_;
    std::uint16_t port_ = 0;
};

}  // namespace

TEST_F(BoltServerFixture, HandshakeSelectsAnImplementedVersion) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    const std::uint8_t proposals[16] = {0x00, 0x00, 0x01, 0xFF,
                                        0x00, 0x08, 0x08, 0x05,
                                        0x00, 0x02, 0x04, 0x04,
                                        0x00, 0x00, 0x00, 0x03};
    const nb::Version v = c.handshake(proposals);
    ASSERT_TRUE(v.valid());
    EXPECT_EQ(v.major, 5);
    EXPECT_EQ(v.minor, nb::kMaxBolt5Minor);
    EXPECT_TRUE(nb::is_supported(v));
}

TEST_F(BoltServerFixture, DeclinesUnsupportedVersionsWithZeroes) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    // Bolt 3.0 only: the server must answer 00 00 00 00 and close, NOT pick a
    // version it cannot speak.
    const std::uint8_t only3[16] = {0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const nb::Version v = c.handshake(only3);
    EXPECT_FALSE(v.valid());
    EXPECT_EQ(v.major, 0);
    EXPECT_EQ(v.minor, 0);
}

TEST_F(BoltServerFixture, RejectsABadPreamble) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    std::uint8_t junk[20] = {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P'};
    ASSERT_TRUE(c.send_raw(junk, sizeof(junk)));
    std::uint8_t r[4];
    // No Bolt framing exists yet, so the only correct answer is to close.
    EXPECT_FALSE(c.recv_raw(r, 4));
}

TEST_F(BoltServerFixture, RunPullReturnsTheEchoedValues) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());

    Msg run;
    (void)run.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)run.w.put_string("RETURN 1");
    (void)run.w.begin_dict(0);   // parameters
    (void)run.w.begin_dict(0);   // extra
    ASSERT_TRUE(run.send(c));

    Reply run_ok;
    ASSERT_TRUE(run_ok.read(c));
    ASSERT_EQ(run_ok.signature(), nb::Signature::Success);
    const ps::PackValue* fields = run_ok.v.items[0].find("fields");
    ASSERT_NE(fields, nullptr);
    ASSERT_EQ(fields->type, ps::PackType::List);
    ASSERT_EQ(fields->len, 4u);
    EXPECT_EQ(fields->items[0].str(), "query");
    EXPECT_EQ(fields->items[1].str(), "params");
    EXPECT_EQ(fields->items[2].str(), "index");
    EXPECT_EQ(fields->items[3].str(), "kinds");

    Msg pull;
    (void)pull.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Pull), 1);
    (void)pull.w.begin_dict(1);
    (void)pull.w.put_string("n");
    (void)pull.w.put_int(-1);
    ASSERT_TRUE(pull.send(c));

    Reply rec;
    ASSERT_TRUE(rec.read(c));
    ASSERT_EQ(rec.signature(), nb::Signature::Record);
    ASSERT_EQ(rec.v.len, 1u);
    const ps::PackValue& row = rec.v.items[0];
    ASSERT_EQ(row.type, ps::PackType::List);
    ASSERT_EQ(row.len, 4u);
    EXPECT_EQ(row.items[0].str(), "RETURN 1");
    EXPECT_EQ(row.items[2].i, 0);
    // The `kinds` column exercises every PackStream type the server emits.
    const ps::PackValue& kinds = row.items[3];
    ASSERT_EQ(kinds.type, ps::PackType::List);
    ASSERT_EQ(kinds.len, 7u);
    EXPECT_EQ(kinds.items[0].type, ps::PackType::Null);
    EXPECT_TRUE(kinds.items[1].b);
    EXPECT_EQ(kinds.items[2].i, -17);
    EXPECT_DOUBLE_EQ(kinds.items[3].f, 3.5);
    EXPECT_EQ(kinds.items[4].str(),
              std::string("Gr\xc3\xb6\xc3\x9f" "enma\xc3\x9f" "st\xc3\xa4" "be"));
    ASSERT_EQ(kinds.items[5].len, 3u);
    EXPECT_EQ(kinds.items[5].items[1].i, 2);
    EXPECT_EQ(kinds.items[6].find_str("k"), "v");

    Reply done;
    ASSERT_TRUE(done.read(c));
    EXPECT_EQ(done.signature(), nb::Signature::Success);
    EXPECT_EQ(done.v.items[0].find_str("type"), "r");
}

TEST_F(BoltServerFixture, PullNHonoursTheBatchSizeAndHasMore) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());

    Msg run;
    (void)run.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)run.w.put_string("stream please");
    (void)run.w.begin_dict(1);
    (void)run.w.put_string("n");
    (void)run.w.put_int(5);
    (void)run.w.begin_dict(0);
    ASSERT_TRUE(run.send(c));
    Reply run_ok;
    ASSERT_TRUE(run_ok.read(c));
    ASSERT_EQ(run_ok.signature(), nb::Signature::Success);

    // First PULL {n: 2} -> 2 RECORDs then SUCCESS{has_more:true}.
    Msg p1;
    (void)p1.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Pull), 1);
    (void)p1.w.begin_dict(1);
    (void)p1.w.put_string("n");
    (void)p1.w.put_int(2);
    ASSERT_TRUE(p1.send(c));
    for (int k = 0; k < 2; ++k) {
        Reply r;
        ASSERT_TRUE(r.read(c));
        ASSERT_EQ(r.signature(), nb::Signature::Record) << "record " << k;
        EXPECT_EQ(r.v.items[0].items[2].i, k);
    }
    Reply more;
    ASSERT_TRUE(more.read(c));
    ASSERT_EQ(more.signature(), nb::Signature::Success);
    const ps::PackValue* hm = more.v.items[0].find("has_more");
    ASSERT_NE(hm, nullptr);
    EXPECT_TRUE(hm->b);

    // Second PULL {n: -1} -> the remaining 3, then a terminal SUCCESS.
    Msg p2;
    (void)p2.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Pull), 1);
    (void)p2.w.begin_dict(1);
    (void)p2.w.put_string("n");
    (void)p2.w.put_int(-1);
    ASSERT_TRUE(p2.send(c));
    for (int k = 2; k < 5; ++k) {
        Reply r;
        ASSERT_TRUE(r.read(c));
        ASSERT_EQ(r.signature(), nb::Signature::Record) << "record " << k;
        EXPECT_EQ(r.v.items[0].items[2].i, k);
    }
    Reply fin;
    ASSERT_TRUE(fin.read(c));
    ASSERT_EQ(fin.signature(), nb::Signature::Success);
    EXPECT_EQ(fin.v.items[0].find("has_more"), nullptr);
    EXPECT_EQ(fin.v.items[0].find_str("type"), "r");
}

TEST_F(BoltServerFixture, FailureThenIgnoredThenResetRecovers) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());

    // The echo executor refuses an empty query, so this is a REAL failure path.
    Msg bad;
    (void)bad.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)bad.w.put_string("");
    (void)bad.w.begin_dict(0);
    (void)bad.w.begin_dict(0);
    ASSERT_TRUE(bad.send(c));
    Reply f;
    ASSERT_TRUE(f.read(c));
    ASSERT_EQ(f.signature(), nb::Signature::Failure);
    EXPECT_EQ(f.v.items[0].find_str("code"), "Neo.ClientError.Statement.SyntaxError");
    EXPECT_EQ(f.v.items[0].find_str("message"), "empty query");

    // In FAILED state every message but RESET/GOODBYE must be IGNORED -- an
    // explicit refusal, never a silent success with no rows.
    Msg after;
    (void)after.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)after.w.put_string("RETURN 1");
    (void)after.w.begin_dict(0);
    (void)after.w.begin_dict(0);
    ASSERT_TRUE(after.send(c));
    Reply ig;
    ASSERT_TRUE(ig.read(c));
    EXPECT_EQ(ig.signature(), nb::Signature::Ignored);

    // RESET clears it.
    Msg reset;
    (void)reset.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Reset), 0);
    ASSERT_TRUE(reset.send(c));
    Reply rr;
    ASSERT_TRUE(rr.read(c));
    ASSERT_EQ(rr.signature(), nb::Signature::Success);

    Msg good;
    (void)good.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)good.w.put_string("RETURN 1");
    (void)good.w.begin_dict(0);
    (void)good.w.begin_dict(0);
    ASSERT_TRUE(good.send(c));
    Reply ok;
    ASSERT_TRUE(ok.read(c));
    EXPECT_EQ(ok.signature(), nb::Signature::Success);
}

TEST_F(BoltServerFixture, TransactionsAreAcknowledgedNoOps) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());

    Msg begin;
    (void)begin.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Begin), 1);
    (void)begin.w.begin_dict(0);
    ASSERT_TRUE(begin.send(c));
    Reply br;
    ASSERT_TRUE(br.read(c));
    ASSERT_EQ(br.signature(), nb::Signature::Success);

    Msg run;
    (void)run.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)run.w.put_string("in a tx");
    (void)run.w.begin_dict(0);
    (void)run.w.begin_dict(0);
    ASSERT_TRUE(run.send(c));
    Reply rr;
    ASSERT_TRUE(rr.read(c));
    ASSERT_EQ(rr.signature(), nb::Signature::Success);

    Msg discard;
    (void)discard.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Discard), 1);
    (void)discard.w.begin_dict(1);
    (void)discard.w.put_string("n");
    (void)discard.w.put_int(-1);
    ASSERT_TRUE(discard.send(c));
    Reply dr;
    ASSERT_TRUE(dr.read(c));
    ASSERT_EQ(dr.signature(), nb::Signature::Success);

    Msg commit;
    (void)commit.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Commit), 0);
    ASSERT_TRUE(commit.send(c));
    Reply cr;
    ASSERT_TRUE(cr.read(c));
    EXPECT_EQ(cr.signature(), nb::Signature::Success);
}

TEST_F(BoltServerFixture, RouteFailsSoDriversFallBackToDirect) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());
    Msg route;
    (void)route.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Route), 3);
    (void)route.w.begin_dict(0);
    (void)route.w.begin_list(0);
    (void)route.w.begin_dict(0);
    ASSERT_TRUE(route.send(c));
    Reply r;
    ASSERT_TRUE(r.read(c));
    ASSERT_EQ(r.signature(), nb::Signature::Failure);
    EXPECT_EQ(r.v.items[0].find_str("code"), "Neo.ClientError.Procedure.ProcedureNotFound");
}

TEST_F(BoltServerFixture, OutOfOrderMessagesFailByName) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    const std::uint8_t proposals[16] = {0x00, 0x08, 0x08, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ASSERT_TRUE(c.handshake(proposals).valid());
    // RUN before HELLO: a named FAILURE, not a hang and not an empty result.
    Msg run;
    (void)run.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
    (void)run.w.put_string("RETURN 1");
    (void)run.w.begin_dict(0);
    (void)run.w.begin_dict(0);
    ASSERT_TRUE(run.send(c));
    Reply r;
    ASSERT_TRUE(r.read(c));
    ASSERT_EQ(r.signature(), nb::Signature::Failure);
    EXPECT_EQ(r.v.items[0].find_str("code"), "Neo.ClientError.Request.Invalid");
}

TEST_F(BoltServerFixture, GoodbyeClosesWithoutAReply) {
    WireClient c;
    ASSERT_TRUE(c.connect(port_));
    ASSERT_TRUE(open_session(c).valid());
    Msg bye;
    (void)bye.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Goodbye), 0);
    ASSERT_TRUE(bye.send(c));
    std::vector<std::uint8_t> out;
    EXPECT_LT(c.recv_message(out), 0) << "GOODBYE must close, not answer";
}

TEST_F(BoltServerFixture, ServesSeveralSequentialConnections) {
    for (int k = 0; k < 4; ++k) {
        WireClient c;
        ASSERT_TRUE(c.connect(port_)) << "connection " << k;
        ASSERT_TRUE(open_session(c).valid()) << "connection " << k;
        Msg run;
        (void)run.w.begin_struct(static_cast<std::uint8_t>(nb::Signature::Run), 3);
        (void)run.w.put_string("RETURN 1");
        (void)run.w.begin_dict(0);
        (void)run.w.begin_dict(0);
        ASSERT_TRUE(run.send(c));
        Reply r;
        ASSERT_TRUE(r.read(c));
        EXPECT_EQ(r.signature(), nb::Signature::Success) << "connection " << k;
    }
}

TEST(BoltProtocolSeam, RegistersIntoTheProtocolRegistry) {
    boltapi_test::EchoFactory factory;
    static nb::Config cfg;
    cfg.bind.port = 0;
    bolt::api::proto::ProtocolRegistry reg;
    EXPECT_FALSE(reg.has(bolt::api::proto::ProtocolId::Neo4jBolt));
    ASSERT_TRUE(nb::register_neo4j_bolt(reg, cfg, factory).is_ok());
    EXPECT_TRUE(reg.has(bolt::api::proto::ProtocolId::Neo4jBolt));
    auto p = reg.create(bolt::api::proto::ProtocolId::Neo4jBolt);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->id(), bolt::api::proto::ProtocolId::Neo4jBolt);
    EXPECT_EQ(p->transport_kind(), bolt::api::transport::TransportKind::Stream);
    EXPECT_STREQ(bolt::api::proto::protocol_name(bolt::api::proto::ProtocolId::Neo4jBolt),
                 "Neo4j-Bolt");

    // serve() must REFUSE a transport it was never bound to, rather than
    // downcasting blind (there is no RTTI in this build).
    nb::Neo4jBoltListener other({"127.0.0.1", 0});
    ASSERT_TRUE(other.start().is_ok());
    EXPECT_TRUE(p->serve(other).is_err());
    other.stop();
}
