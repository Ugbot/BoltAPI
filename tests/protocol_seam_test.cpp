// protocol_seam_test.cpp — M3 HTTP/3 + WebRTC seam tests.
//
// Exercises the ProtocolRegistry mechanism + the IProtocol/ITransport contract.
// FLAG-AWARE: every assertion that needs the real H3/WebRTC stubs is guarded by
// the matching compile flag, so this test passes in the DEFAULT (flags OFF)
// build using a dummy in-test protocol. It must NOT require the flags to be ON.

#include "boltapi/protocol.h"
#include "boltapi/transport.h"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

using bolt::api::proto::IProtocol;
using bolt::api::proto::ProtocolId;
using bolt::api::proto::ProtocolRegistry;
using bolt::api::proto::Status;
using bolt::api::transport::Endpoint;
using bolt::api::transport::ITransport;
using bolt::api::transport::TransportKind;

namespace {

// ---------------------------------------------------------------------------
// Test doubles: a dummy datagram transport + a dummy protocol that returns
// NotImplemented. These let us test the registry MECHANISM with flags OFF.
// ---------------------------------------------------------------------------

class DummyTransport final : public ITransport {
public:
    explicit DummyTransport(TransportKind k) : kind_(k) {}
    Status start() override { running_ = true; return bolt::api::transport::ok_status(); }
    void stop() noexcept override { running_ = false; }
    TransportKind kind() const noexcept override { return kind_; }
    const Endpoint& local_endpoint() const noexcept override { return ep_; }
    bool is_running() const noexcept override { return running_; }
private:
    TransportKind kind_;
    Endpoint ep_{"127.0.0.1", 9999};
    bool running_ = false;
};

class DummyProtocol final : public IProtocol {
public:
    explicit DummyProtocol(ProtocolId id) : id_(id) {}
    ProtocolId id() const noexcept override { return id_; }
    TransportKind transport_kind() const noexcept override { return TransportKind::Datagram; }
    Status serve(ITransport&) override { return bolt::api::proto::not_implemented(); }
    void stop() noexcept override {}
private:
    ProtocolId id_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Registry mechanism: register / has / create.
// ---------------------------------------------------------------------------
TEST(ProtocolSeam, RegistryStartsEmpty) {
    ProtocolRegistry reg;
    EXPECT_EQ(reg.size(), 0u);
    EXPECT_FALSE(reg.has(ProtocolId::Http3));
    EXPECT_FALSE(reg.has(ProtocolId::WebRtc));
    // create() on an empty slot returns nullptr (no crash).
    EXPECT_EQ(reg.create(ProtocolId::Http3), nullptr);
}

TEST(ProtocolSeam, RegisterHasCreate) {
    ProtocolRegistry reg;

    const Status s = reg.register_protocol(
        ProtocolId::Http3,
        []() -> std::unique_ptr<IProtocol> {
            return std::make_unique<DummyProtocol>(ProtocolId::Http3);
        });
    EXPECT_TRUE(s.is_ok());
    EXPECT_TRUE(reg.has(ProtocolId::Http3));
    EXPECT_EQ(reg.size(), 1u);

    std::unique_ptr<IProtocol> p = reg.create(ProtocolId::Http3);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->id(), ProtocolId::Http3);
    EXPECT_EQ(p->transport_kind(), TransportKind::Datagram);
}

// Independent factories for multiple ids; create() yields fresh instances.
TEST(ProtocolSeam, MultipleProtocolsIndependent) {
    ProtocolRegistry reg;
    reg.register_protocol(ProtocolId::Http3, []() -> std::unique_ptr<IProtocol> {
        return std::make_unique<DummyProtocol>(ProtocolId::Http3);
    });
    reg.register_protocol(ProtocolId::WebRtc, []() -> std::unique_ptr<IProtocol> {
        return std::make_unique<DummyProtocol>(ProtocolId::WebRtc);
    });
    EXPECT_EQ(reg.size(), 2u);
    EXPECT_TRUE(reg.has(ProtocolId::Http3));
    EXPECT_TRUE(reg.has(ProtocolId::WebRtc));

    auto a = reg.create(ProtocolId::Http3);
    auto b = reg.create(ProtocolId::Http3);
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    EXPECT_NE(a.get(), b.get());  // distinct instances
    EXPECT_EQ(reg.create(ProtocolId::WebRtc)->id(), ProtocolId::WebRtc);
}

// Re-registering replaces the factory (last wins) without growing size twice
// being a problem for has()/create() correctness.
TEST(ProtocolSeam, ReRegisterReplacesFactory) {
    ProtocolRegistry reg;
    reg.register_protocol(ProtocolId::Http3, []() -> std::unique_ptr<IProtocol> {
        return std::make_unique<DummyProtocol>(ProtocolId::Http3);
    });
    // Replace with a factory that yields WebRtc id (just to prove replacement).
    reg.register_protocol(ProtocolId::Http3, []() -> std::unique_ptr<IProtocol> {
        return std::make_unique<DummyProtocol>(ProtocolId::WebRtc);
    });
    auto p = reg.create(ProtocolId::Http3);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->id(), ProtocolId::WebRtc);  // replacement took effect
}

// Built-in protocols are reported as built-in (engine direct dispatch), and are
// NOT in the registry by default.
TEST(ProtocolSeam, BuiltinClassification) {
    EXPECT_TRUE(ProtocolRegistry::is_builtin(ProtocolId::Http11));
    EXPECT_TRUE(ProtocolRegistry::is_builtin(ProtocolId::Http2));
    EXPECT_FALSE(ProtocolRegistry::is_builtin(ProtocolId::Http3));
    EXPECT_FALSE(ProtocolRegistry::is_builtin(ProtocolId::WebRtc));

    ProtocolRegistry reg;
    EXPECT_FALSE(reg.has(ProtocolId::Http11));
    EXPECT_FALSE(reg.has(ProtocolId::Http2));
}

// ---------------------------------------------------------------------------
// IProtocol contract: a stub serve() returns the NotImplemented sentinel, and
// is recognized as such.
// ---------------------------------------------------------------------------
TEST(ProtocolSeam, StubServeReturnsNotImplemented) {
    DummyProtocol p(ProtocolId::Http3);
    DummyTransport t(TransportKind::Datagram);
    ASSERT_TRUE(t.start().is_ok());

    const Status s = p.serve(t);
    EXPECT_TRUE(s.is_err());
    EXPECT_TRUE(bolt::api::proto::is_not_implemented(s));
}

// ---------------------------------------------------------------------------
// ITransport contract sanity: stream vs datagram kinds.
// ---------------------------------------------------------------------------
TEST(ProtocolSeam, TransportKindReported) {
    DummyTransport stream(TransportKind::Stream);
    DummyTransport datagram(TransportKind::Datagram);
    EXPECT_EQ(stream.kind(), TransportKind::Stream);
    EXPECT_EQ(datagram.kind(), TransportKind::Datagram);
}

// ---------------------------------------------------------------------------
// Flag-gated: when built with the compile flags, the REAL stub factories
// register and create stubs that return NotImplemented. These blocks vanish in
// the default build, so the test still passes there.
// ---------------------------------------------------------------------------
#if defined(BOLTAPI_WITH_HTTP3)
TEST(ProtocolSeam, Http3StubFactoryRegisters) {
    ProtocolRegistry reg;
    const Status s = bolt::api::proto::register_http3(reg);
    EXPECT_TRUE(s.is_ok());
    ASSERT_TRUE(reg.has(ProtocolId::Http3));

    auto h3 = reg.create(ProtocolId::Http3);
    ASSERT_NE(h3, nullptr);
    EXPECT_EQ(h3->id(), ProtocolId::Http3);
    EXPECT_EQ(h3->transport_kind(), TransportKind::Datagram);

    // Drive serve() over the real (stub) UdpTransport: NotImplemented.
    bolt::api::transport::UdpTransport udp(Endpoint{"127.0.0.1", 4433});
    EXPECT_TRUE(bolt::api::proto::is_not_implemented(udp.start()));
    EXPECT_TRUE(bolt::api::proto::is_not_implemented(h3->serve(udp)));
}
#endif

#if defined(BOLTAPI_WITH_WEBRTC)
TEST(ProtocolSeam, WebRtcStubFactoryRegisters) {
    ProtocolRegistry reg;
    const Status s = bolt::api::proto::register_webrtc(reg);
    EXPECT_TRUE(s.is_ok());
    ASSERT_TRUE(reg.has(ProtocolId::WebRtc));

    auto rtc = reg.create(ProtocolId::WebRtc);
    ASSERT_NE(rtc, nullptr);
    EXPECT_EQ(rtc->id(), ProtocolId::WebRtc);
    EXPECT_EQ(rtc->transport_kind(), TransportKind::Datagram);

    bolt::api::transport::UdpTransport udp(Endpoint{"127.0.0.1", 5000});
    EXPECT_TRUE(bolt::api::proto::is_not_implemented(rtc->serve(udp)));
}
#endif
