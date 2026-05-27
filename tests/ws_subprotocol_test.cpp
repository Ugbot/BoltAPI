// ws_subprotocol_test.cpp — unit coverage for RFC 6455 §4.2.2 subprotocol
// selection in `HandshakeUtils::select_subprotocol`. The bug this regresses:
// browsers (notably Chrome) refuse the WS upgrade when they sent a non-empty
// `Sec-WebSocket-Protocol` and the server's 101 response omits it. With this
// helper wired into the server upgrade path, `mqtt` clients (mqtt.js,
// mosquitto_sub) get a 1st-class echo and other clients get the first token
// echoed back so the browser proceeds.

#include "boltapi/http/websocket_parser.h"

#include <gtest/gtest.h>

namespace ws = bolt::api::websocket;

TEST(WsSubprotocol, EmptyOfferReturnsEmpty) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol(""), "");
}

TEST(WsSubprotocol, WhitespaceOnlyReturnsEmpty) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("   ,  ,\t"), "");
}

TEST(WsSubprotocol, MqttExactWins) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("mqtt"), "mqtt");
}

TEST(WsSubprotocol, MqttInListWins) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("graphql-ws, mqtt, foo"),
              "mqtt");
}

TEST(WsSubprotocol, MqttWithSurroundingWhitespace) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("  mqtt  "), "mqtt");
}

TEST(WsSubprotocol, UnknownProtocolFirstTokenEchoed) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("v1.json, v2.binary"),
              "v1.json");
}

TEST(WsSubprotocol, MqttIsCaseSensitive) {
    // RFC 6455 says subprotocol names are case-sensitive tokens; mqtt.js +
    // browsers send lowercase. "MQTT" must NOT be selected as mqtt; it
    // falls through to the first-offered echo path.
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("MQTT, foo"), "MQTT");
    // (But the first-offered echo still happens — Chrome stays happy.)
}

TEST(WsSubprotocol, SingleNonMqttToken) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol("graphql-transport-ws"),
              "graphql-transport-ws");
}

TEST(WsSubprotocol, IgnoresEmptyTokens) {
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol(",  ,mqtt,"), "mqtt");
    EXPECT_EQ(ws::HandshakeUtils::select_subprotocol(",  ,foo,"), "foo");
}
