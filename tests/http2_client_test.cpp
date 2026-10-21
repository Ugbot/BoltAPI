#include "boltapi/http/http2_connection.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace bolt::api::http2;
using bolt::api::http::HPACKEncoder;
using bolt::api::http::HPACKHeader;
using Connection = Http2Connection;
using Kind = Connection::ResponseEventKind;
using Bytes = std::vector<uint8_t>;
using Fields = std::vector<HPACKHeader>;

const Fields kGet{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "local"}};

Bytes frame(FrameType type, uint32_t id, uint8_t flags, const Bytes& payload = {}) {
    Bytes out(9 + payload.size());
    write_frame_header(FrameHeader(static_cast<uint32_t>(payload.size()), type, flags, id), out.data());
    std::copy(payload.begin(), payload.end(), out.begin() + 9);
    return out;
}

Bytes block(const Fields& fields) {
    HPACKEncoder encoder;
    Bytes out(Connection::kMaxHeaderBlock);
    size_t n = 0;
    EXPECT_EQ(encoder.encode(fields.data(), fields.size(), out.data(), out.size(), n), 0);
    out.resize(n);
    return out;
}

bool feed(Connection& connection, const Bytes& bytes, size_t chunk = SIZE_MAX) {
    for (size_t off = 0; off < bytes.size();) {
        const size_t n = std::min(chunk, bytes.size() - off);
        auto r = connection.process_input(bytes.data() + off, n);
        if (r.is_err() || r.value() != n) return false;
        off += n;
    }
    return true;
}

Bytes take(Connection& connection) {
    const uint8_t* p = nullptr;
    size_t n = 0;
    if (!connection.get_output(&p, &n)) return {};
    Bytes out(p, p + n);
    connection.commit_output(n);
    return out;
}

bool transfer(Connection& from, Connection& to) { return feed(to, take(from)); }

void ready(Connection& client) {
    (void)take(client);
    EXPECT_TRUE(feed(client, frame(FrameType::SETTINGS, 0, 0)));
    (void)take(client);
}

bool headers(Connection& client, uint32_t id, const Fields& fields, bool end = false) {
    return feed(client, frame(FrameType::HEADERS, id,
        static_cast<uint8_t>(FrameFlags::HEADERS_END_HEADERS | (end ? FrameFlags::HEADERS_END_STREAM : 0)),
        block(fields)));
}

Bytes u32(uint32_t v) {
    return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}

Bytes setting(SettingsId id, uint32_t v) {
    Bytes out{0, static_cast<uint8_t>(id)};
    const auto value = u32(v);
    out.insert(out.end(), value.begin(), value.end());
    return frame(FrameType::SETTINGS, 0, 0, out);
}

Bytes goaway(uint32_t last, ErrorCode error = ErrorCode::NO_ERROR) {
    Bytes payload = u32(last);
    const auto code = u32(static_cast<uint32_t>(error));
    payload.insert(payload.end(), code.begin(), code.end());
    return frame(FrameType::GOAWAY, 0, 0, payload);
}

struct SavedEvent {
    Kind kind;
    uint32_t id;
    uint16_t status;
    ErrorCode error;
    std::string data;
    std::vector<std::pair<std::string, std::string>> fields;
    bool end_stream{false};
};

struct Events {
    std::vector<SavedEvent> items;
    void save(const Connection::ResponseEvent& event) {
        SavedEvent copy{event.kind, event.stream_id, event.status, event.error, std::string(event.data), {}, event.end_stream};
        for (size_t i = 0; i < event.header_count; ++i) {
            copy.fields.emplace_back(std::string(event.headers[i].name), std::string(event.headers[i].value));
        }
        items.push_back(std::move(copy));
    }
    size_t count(Kind kind) const {
        return static_cast<size_t>(std::count_if(items.begin(), items.end(),
            [kind](const SavedEvent& e) { return e.kind == kind; }));
    }
};

TEST(Http2Client, PrefaceOddIdsAndExistingServerInteroperate) {
    Events events;
    std::vector<uint32_t> requests;
    Connection client(false);
    Connection server;
    client.set_response_callback([&](const auto& e) { events.save(e); });
    server.set_request_callback([&](Http2Stream* stream) {
        requests.push_back(stream->id());
        EXPECT_EQ(stream->request_headers().at(":method"), "GET");
        EXPECT_TRUE(server.send_response(stream->id(), 200, {}, "hello").is_ok());
    });
    const Bytes startup = take(client);
    ASSERT_GE(startup.size(), CONNECTION_PREFACE_LEN + 9);
    EXPECT_EQ(std::memcmp(startup.data(), CONNECTION_PREFACE, CONNECTION_PREFACE_LEN), 0);
    const auto settings_header = parse_frame_header(startup.data() + CONNECTION_PREFACE_LEN).value();
    EXPECT_EQ(settings_header.type, FrameType::SETTINGS);
    bool disabled_push = false;
    for (size_t i = CONNECTION_PREFACE_LEN + 9; i + 6 <= startup.size(); i += 6) {
        if (startup[i] == 0 && startup[i + 1] == 2) {
            disabled_push = std::all_of(startup.begin() + static_cast<std::ptrdiff_t>(i + 2),
                                      startup.begin() + static_cast<std::ptrdiff_t>(i + 6),
                                      [](uint8_t b) { return b == 0; });
        }
    }
    EXPECT_TRUE(disabled_push);
    ASSERT_TRUE(feed(server, startup, 1));
    ASSERT_TRUE(transfer(server, client));
    const auto first = client.send_request(kGet.data(), kGet.size());
    const auto second = client.send_request(kGet.data(), kGet.size());
    ASSERT_TRUE(first.is_ok());
    ASSERT_TRUE(second.is_ok());
    EXPECT_EQ(first.value(), 1u);
    EXPECT_EQ(second.value(), 3u);
    ASSERT_TRUE(transfer(client, server));
    ASSERT_TRUE(transfer(server, client));
    EXPECT_EQ(requests, (std::vector<uint32_t>{1, 3}));
    EXPECT_EQ(events.count(Kind::Complete), 2u);
    EXPECT_EQ(events.count(Kind::Reset), 0u);
    EXPECT_EQ(client.open_stream_count(), 0u);
    ASSERT_EQ(events.items.size(), 6u);
    EXPECT_EQ(events.items[1].data, "hello");
    EXPECT_EQ(events.items[4].data, "hello");
}

TEST(Http2Client, DeliversBodyAndGrpcErrorTrailersWithoutMappingUncertainty) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}, {"content-type", "application/grpc"}}));
    ASSERT_TRUE(feed(client, frame(FrameType::DATA, 1, 0, {'a', 'b', 'c'})));
    ASSERT_TRUE(headers(client, 1, {{"grpc-status", "13"}, {"grpc-message", "chukonu: WriteUnconfirmed"}}, true));
    ASSERT_EQ(events.items.size(), 4u);
    EXPECT_EQ(events.items[0].kind, Kind::Headers);
    EXPECT_EQ(events.items[1].data, "abc");
    EXPECT_EQ(events.items[2].kind, Kind::Trailers);
    EXPECT_EQ(events.items[2].fields[0], (std::pair<std::string, std::string>{"grpc-status", "13"}));
    EXPECT_EQ(events.items[2].fields[1].second, "chukonu: WriteUnconfirmed");
    EXPECT_EQ(events.items[3].kind, Kind::Complete); // HTTP completion is not gRPC success.
    EXPECT_FALSE(events.items[0].end_stream);
    EXPECT_FALSE(events.items[1].end_stream);
    EXPECT_TRUE(events.items[2].end_stream);
    EXPECT_TRUE(events.items[3].end_stream);
}

TEST(Http2Client, HeadersExposeEndStreamForTrailersOnlySuccess) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}, {"grpc-status", "0"}}, true));
    ASSERT_EQ(events.items.size(), 2u);
    EXPECT_EQ(events.items[0].kind, Kind::Headers);
    EXPECT_TRUE(events.items[0].end_stream);
    EXPECT_EQ(events.items[1].kind, Kind::Complete);
    EXPECT_TRUE(events.items[1].end_stream);
}

TEST(Http2Client, NonterminalHeadersStayNonterminalThroughEmptyFinalData) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}, {"grpc-status", "0"}}));
    ASSERT_EQ(events.items.size(), 1u);
    EXPECT_FALSE(events.items[0].end_stream);
    ASSERT_TRUE(feed(client, frame(FrameType::DATA, 1, FrameFlags::DATA_END_STREAM)));
    ASSERT_EQ(events.items.size(), 2u);
    EXPECT_FALSE(events.items[0].end_stream);
    EXPECT_EQ(events.items[1].kind, Kind::Complete);
    EXPECT_TRUE(events.items[1].end_stream);
}

TEST(Http2Client, ReassemblesContinuationAndSingleByteReads) {
    Events events;
    const std::string value(20000, 'v');
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    const auto encoded = block({{":status", "200"}, {"x-large", value}});
    ASSERT_GT(encoded.size(), Connection::kLocalMaxFrameSize);
    const auto split = encoded.begin() + Connection::kLocalMaxFrameSize;
    ASSERT_TRUE(feed(client, frame(FrameType::HEADERS, 1, FrameFlags::HEADERS_END_STREAM,
                                  Bytes(encoded.begin(), split)), 1));
    EXPECT_TRUE(events.items.empty());
    ASSERT_TRUE(feed(client, frame(FrameType::CONTINUATION, 1, FrameFlags::CONTINUATION_END_HEADERS,
                                  Bytes(split, encoded.end())), 1));
    ASSERT_EQ(events.items.size(), 2u);
    EXPECT_EQ(events.items[0].fields[1].second, value);
    EXPECT_EQ(events.count(Kind::Complete), 1u);
}

TEST(Http2Client, InformationalHeadAndNotModifiedRepresentationLengths) {
    for (const auto status : {"200", "304", "204"}) {
        Events events;
        Connection client(false);
        client.set_response_callback([&](const auto& e) { events.save(e); });
        ready(client);
        Fields request = kGet;
        if (std::string_view(status) == "200") request[0].value = "HEAD";
        ASSERT_TRUE(client.send_request(request.data(), request.size()).is_ok());
        ASSERT_TRUE(headers(client, 1, {{":status", "103"}, {"link", "</style>"}}));
        Fields response{{":status", status}};
        if (std::string_view(status) != "204") response.push_back({"content-length", "1000"});
        ASSERT_TRUE(headers(client, 1, response, true));
        ASSERT_EQ(events.items.size(), 3u);
        EXPECT_EQ(events.items[0].status, 103u);
        EXPECT_EQ(events.count(Kind::Complete), 1u);
        EXPECT_EQ(events.count(Kind::Reset), 0u);
    }
}

TEST(Http2Client, RejectsMissingDuplicateAndRequestPseudoStatusFields) {
    const std::vector<Fields> malformed{
        {{"content-type", "text/plain"}}, {{":status", "200"}, {":status", "201"}},
        {{":method", "GET"}}, {{":status", "20a"}}, {{":status", "600"}},
        {{"x-first", "v"}, {":status", "200"}}, {{":status", "101"}},
        {{":status", "103"}, {"content-length", "0"}}, {{":status", "204"}, {"content-length", "0"}},
        {{":status", "200"}, {"Connection", "close"}}, {{":status", "200"}, {"connection", "close"}}};
    for (const auto& fields : malformed) {
        Events events;
        Connection client(false);
        client.set_response_callback([&](const auto& e) { events.save(e); });
        ready(client);
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
        EXPECT_TRUE(headers(client, 1, fields, true)); // stream error keeps connection usable
        EXPECT_EQ(events.count(Kind::Reset), 1u);
        EXPECT_EQ(events.count(Kind::Complete), 0u);
        EXPECT_EQ(client.open_stream_count(), 0u);
        EXPECT_TRUE(client.is_active());
    }
}

TEST(Http2Client, RejectsDataBeforeHeadersLengthMismatchAndBodylessData) {
    for (unsigned mode = 0; mode < 6; ++mode) {
        Events events;
        Connection client(false);
        client.set_response_callback([&](const auto& e) { events.save(e); });
        ready(client);
        Fields request = kGet;
        if (mode == 5) request[0].value = "HEAD";
        ASSERT_TRUE(client.send_request(request.data(), request.size()).is_ok());
        if (mode == 1) ASSERT_TRUE(headers(client, 1, {{":status", "200"}, {"content-length", "3"}}));
        if (mode == 2) ASSERT_TRUE(headers(client, 1, {{":status", "200"}, {"content-length", "1"}}));
        if (mode >= 3) ASSERT_TRUE(headers(client, 1, {{":status", mode == 3 ? "204" : mode == 4 ? "304" : "200"}}));
        EXPECT_TRUE(feed(client, frame(FrameType::DATA, 1, FrameFlags::DATA_END_STREAM, {'x', 'y'})));
        EXPECT_EQ(events.count(Kind::Reset), 1u);
        EXPECT_EQ(events.count(Kind::Complete), 0u);
        EXPECT_EQ(client.open_stream_count(), 0u);
    }
}

TEST(Http2Client, RejectsInvalidTrailersAndResponseBodyBudget) {
    for (unsigned mode = 0; mode < 4; ++mode) {
        Events events;
        Connection client(false);
        client.set_response_callback([&](const auto& e) { events.save(e); });
        ready(client);
        client.set_max_response_body(1);
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
        ASSERT_TRUE(headers(client, 1, {{":status", "200"}}));
        if (mode == 0) EXPECT_TRUE(headers(client, 1, {{"grpc-status", "0"}}, false));
        if (mode == 1) EXPECT_TRUE(headers(client, 1, {{":status", "200"}}, true));
        if (mode == 2) EXPECT_TRUE(headers(client, 1, {{"content-length", "0"}}, true));
        if (mode == 3) EXPECT_TRUE(feed(client, frame(FrameType::DATA, 1, 1, {'x', 'y'})));
        EXPECT_EQ(events.count(Kind::Reset), 1u);
        EXPECT_EQ(events.count(Kind::Complete), 0u);
    }
}

TEST(Http2Client, RefusesMalformedRequestsWithoutConsumingStreamIds) {
    Connection client(false);
    ready(client);
    const std::vector<Fields> malformed{
        {{":status", "200"}}, {{":method", "CONNECT"}, {":authority", "local"}},
        {{":method", ""}, {":scheme", "http"}, {":path", "/"}},
        {{":method", "G ET"}, {":scheme", "http"}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", ""}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", "1bad"}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"content-length", "1"}},
        {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"connection", "close"}},
        {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {"Upper", "v"}}};
    for (const auto& fields : malformed) EXPECT_TRUE(client.send_request(fields.data(), fields.size()).is_err());
    EXPECT_TRUE(client.send_request(nullptr, 0).is_err());
    EXPECT_TRUE(client.send_request(kGet.data(), Connection::kMaxRequestHeaders + 1).is_err());
    const std::string over_budget(Connection::kDefaultMaxRequestBody + 1, 'x');
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size(), over_budget).is_err());
    const auto accepted = client.send_request(kGet.data(), kGet.size());
    ASSERT_TRUE(accepted.is_ok());
    EXPECT_EQ(accepted.value(), 1u);
    Connection server;
    EXPECT_TRUE(server.send_request(kGet.data(), kGet.size()).is_err());
    EXPECT_TRUE(client.send_response(1, 200, {}, "").is_err());
}

TEST(Http2Client, RefusesRequestFieldWhitespaceWithoutPublishingBytesOrIds) {
    Connection client(false);
    ready(client);
    for (const auto value : {" leading", "trailing ", "\tleading", "trailing\t", " ", "\t"}) {
        Fields request = kGet;
        request.push_back({"x-value", value});
        EXPECT_TRUE(client.send_request(request.data(), request.size()).is_err());
        EXPECT_TRUE(take(client).empty());
        EXPECT_EQ(client.open_stream_count(), 0u);
    }
    Fields request = kGet;
    request.push_back({"x-value", "internal \t whitespace"});
    request.push_back({"x-empty", ""});
    request.push_back({"te", "trailers"});
    const auto accepted = client.send_request(request.data(), request.size());
    ASSERT_TRUE(accepted.is_ok());
    EXPECT_EQ(accepted.value(), 1u);
}

TEST(Http2Client, RejectsWhitespaceAndTeInResponseHeadersAndTrailers) {
    for (const bool trailers : {false, true}) {
        for (const auto value : {" leading", "trailing ", "\tleading", "trailing\t", "trailers"}) {
            Events events;
            Connection client(false);
            client.set_response_callback([&](const auto& e) { events.save(e); });
            ready(client);
            ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
            Fields response;
            if (trailers) ASSERT_TRUE(headers(client, 1, {{":status", "200"}}));
            else response.push_back({":status", "200"});
            response.push_back({std::string_view(value) == "trailers" ? "te" : "x-value", value});
            ASSERT_TRUE(headers(client, 1, response, true));
            EXPECT_EQ(events.count(Kind::Headers), trailers ? 1u : 0u);
            EXPECT_EQ(events.count(Kind::Trailers), 0u);
            EXPECT_EQ(events.count(Kind::Complete), 0u);
            ASSERT_EQ(events.count(Kind::Reset), 1u);
            EXPECT_EQ(events.items.back().error, ErrorCode::PROTOCOL_ERROR);
            EXPECT_EQ(client.open_stream_count(), 0u);
            EXPECT_TRUE(client.is_active());
            ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
            ASSERT_TRUE(headers(client, 3, {{":status", "204"}}, true));
            EXPECT_EQ(events.count(Kind::Complete), 1u);
        }
    }
}

TEST(Http2Client, BoundsConcurrencyAndReusesStartupSlotsWithMonotonicIds) {
    Connection client(false);
    ready(client);
    ASSERT_TRUE(feed(client, setting(SettingsId::MAX_CONCURRENT_STREAMS, 0)));
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    ASSERT_TRUE(feed(client, setting(SettingsId::MAX_CONCURRENT_STREAMS, 1)));
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}}, true));
    ASSERT_TRUE(feed(client, setting(SettingsId::MAX_CONCURRENT_STREAMS, 200)));
    for (size_t i = 0; i < Connection::kMaxConcurrentStreams; ++i) {
        const auto id = client.send_request(kGet.data(), kGet.size());
        ASSERT_TRUE(id.is_ok());
        EXPECT_EQ(id.value(), 3u + 2u * i);
    }
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    for (uint32_t id = 3; id < 203; id += 2) ASSERT_TRUE(headers(client, id, {{":status", "204"}}, true));
    EXPECT_EQ(client.open_stream_count(), 0u);
    const auto reused = client.send_request(kGet.data(), kGet.size());
    ASSERT_TRUE(reused.is_ok());
    EXPECT_EQ(reused.value(), 203u);
}

TEST(Http2Client, ExistingServerPacesUploadAndDownloadAcrossWindowUpdates) {
    Events events;
    const std::string upload(200000, 'u');
    const std::string download(180000, 'd');
    bool received = false;
    Connection client(false);
    Connection server;
    client.set_response_callback([&](const auto& e) { events.save(e); });
    server.set_request_callback([&](Http2Stream* stream) {
        EXPECT_EQ(stream->request_body_view(), upload);
        received = true;
        EXPECT_TRUE(server.send_response(stream->id(), 200, {}, download).is_ok());
    });
    ASSERT_TRUE(transfer(client, server));
    ASSERT_TRUE(transfer(server, client));
    Fields request = kGet;
    request[0].value = "POST";
    ASSERT_TRUE(client.send_request(request.data(), request.size(), upload).is_ok());
    EXPECT_EQ(client.connection_send_window(), 0);
    for (unsigned pass = 0; pass < 64 && events.count(Kind::Complete) == 0; ++pass) {
        ASSERT_TRUE(transfer(client, server));
        ASSERT_TRUE(transfer(server, client));
    }
    EXPECT_TRUE(received);
    EXPECT_EQ(events.count(Kind::Complete), 1u);
    EXPECT_EQ(events.count(Kind::Reset), 0u);
    std::string body;
    for (const auto& event : events.items) if (event.kind == Kind::Data) body += event.data;
    EXPECT_EQ(body, download);
}

TEST(Http2Client, UnreadUploadOutputIsBoundedAndResumesAfterCommit) {
    const std::string body(2 * Connection::kMaxControlBacklog, 'b');
    Connection client(false);
    ready(client);
    ASSERT_TRUE(feed(client, setting(SettingsId::INITIAL_WINDOW_SIZE, 4000000)));
    (void)take(client);
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 0, 0, u32(4000000))));
    (void)take(client);
    Fields request = kGet;
    request[0].value = "POST";
    ASSERT_TRUE(client.send_request(request.data(), request.size(), body).is_ok());
    size_t sent = 0;
    bool ended = false;
    for (unsigned pass = 0; pass < 8; ++pass) {
        const auto bytes = take(client);
        EXPECT_LE(bytes.size(), Connection::kClientOutputCapacity);
        if (bytes.empty()) break;
        for (size_t off = 0; off + 9 <= bytes.size();) {
            const auto h = parse_frame_header(bytes.data() + off).value();
            ASSERT_LE(off + 9 + h.length, bytes.size());
            if (h.type == FrameType::DATA) {
                sent += h.length;
                ended = ended || (h.flags & FrameFlags::DATA_END_STREAM) != 0;
            }
            off += 9 + h.length;
        }
    }
    EXPECT_EQ(sent, body.size());
    EXPECT_TRUE(ended);
}

TEST(Http2Client, ResetsAreTerminalAndEarlyResponseStopsBorrowingUpload) {
    Events events;
    std::string body(100000, 'u');
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size(), body).is_ok());
    ASSERT_TRUE(headers(client, 1, {{":status", "413"}}, true));
    EXPECT_EQ(events.count(Kind::Complete), 1u);
    body.clear(); // terminal event ended the borrowed upload lifetime
    (void)take(client);
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 0, 0, u32(100000))));
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 1, 0, u32(100000))));
    EXPECT_TRUE(take(client).empty());
    const auto second = client.send_request(kGet.data(), kGet.size());
    ASSERT_TRUE(second.is_ok());
    ASSERT_TRUE(feed(client, frame(FrameType::RST_STREAM, second.value(), 0,
                                  u32(static_cast<uint32_t>(ErrorCode::CANCEL)))));
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.items.back().error, ErrorCode::CANCEL);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    Bytes goaway = u32(0);
    const auto no_error = u32(0);
    goaway.insert(goaway.end(), no_error.begin(), no_error.end());
    ASSERT_TRUE(feed(client, frame(FrameType::GOAWAY, 0, 0, goaway)));
    EXPECT_EQ(events.count(Kind::Reset), 2u);
    EXPECT_EQ(events.count(Kind::Complete), 1u);
    EXPECT_TRUE(client.wants_close());
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
}

TEST(Http2Client, RejectsReentryAndInvalidServerFirstFrameOrPushSettings) {
    bool called = false;
    Connection client(false);
    client.set_response_callback([&](const auto&) {
        called = true;
        EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
        EXPECT_TRUE(client.send_rst_stream(1, ErrorCode::CANCEL).is_err());
        EXPECT_TRUE(client.send_goaway(ErrorCode::NO_ERROR).is_err());
        EXPECT_TRUE(client.process_input(nullptr, 0).is_err());
        client.commit_output(0); // safe refusal, no recursive pump
        client.set_response_callback({}); // safe refusal while callback is live
    });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}}, true));
    EXPECT_TRUE(called);
    EXPECT_EQ(client.open_stream_count(), 0u);
    for (unsigned mode = 0; mode < 3; ++mode) {
        Events errors;
        Connection malformed(false);
        malformed.set_response_callback([&](const auto& e) { errors.save(e); });
        ASSERT_TRUE(malformed.send_request(kGet.data(), kGet.size()).is_ok());
        if (mode == 0) EXPECT_FALSE(feed(malformed, frame(FrameType::PING, 0, 0, Bytes(8))));
        if (mode == 1) EXPECT_FALSE(feed(malformed, frame(FrameType::SETTINGS, 0, FrameFlags::SETTINGS_ACK)));
        if (mode == 2) EXPECT_FALSE(feed(malformed, setting(SettingsId::ENABLE_PUSH, 0)));
        EXPECT_EQ(malformed.last_error(), ErrorCode::PROTOCOL_ERROR);
        EXPECT_EQ(errors.count(Kind::Reset), 1u);
        EXPECT_EQ(errors.count(Kind::Complete), 0u);
    }
}

TEST(Http2Client, GracefulGoawayDrainsAcceptedStreamsAndLowersCutoff) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    for (unsigned i = 0; i < 3; ++i) {
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    }
    (void)take(client);
    ASSERT_TRUE(headers(client, 1, {{":status", "200"}}));
    ASSERT_TRUE(feed(client, goaway(0x7FFFFFFFu), 1));
    EXPECT_EQ(events.count(Kind::Reset), 0u);
    EXPECT_EQ(client.open_stream_count(), 3u);
    EXPECT_FALSE(client.wants_close());
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    ASSERT_TRUE(feed(client, goaway(3)));
    ASSERT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.items.back().id, 5u);
    EXPECT_EQ(events.items.back().error, ErrorCode::NO_ERROR);
    EXPECT_EQ(client.open_stream_count(), 2u);
    ASSERT_TRUE(feed(client, goaway(3))); // repeated notice is not another terminal event
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    ASSERT_TRUE(feed(client, frame(FrameType::DATA, 1, FrameFlags::DATA_END_STREAM, {'x'})));
    EXPECT_FALSE(client.wants_close());
    ASSERT_TRUE(headers(client, 3, {{":status", "204"}}, true));
    EXPECT_EQ(events.count(Kind::Complete), 2u);
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_TRUE(client.wants_close());
    EXPECT_EQ(client.last_error(), ErrorCode::NO_ERROR);
}

TEST(Http2Client, GracefulGoawayKeepsAcceptedUploadPacedAndReleasesExcludedBody) {
    Events events;
    const std::string accepted_body(100000, 'a');
    std::string excluded_body(100000, 'x');
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size(), accepted_body).is_ok());
    EXPECT_EQ(client.connection_send_window(), 0);
    (void)take(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size(), excluded_body).is_ok());
    (void)take(client);
    ASSERT_TRUE(feed(client, goaway(1)));
    ASSERT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.items.back().id, 3u);
    excluded_body.clear(); // Reset has ended this borrowed body's lifetime.
    EXPECT_FALSE(client.wants_close());
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 0, 0, u32(100000))));
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 1, 0, u32(100000))));
    ASSERT_TRUE(feed(client, frame(FrameType::WINDOW_UPDATE, 3, 0, u32(100000))));
    const auto output = take(client);
    size_t sent = 0;
    bool ended = false;
    for (size_t off = 0; off + 9 <= output.size();) {
        const auto h = parse_frame_header(output.data() + off).value();
        ASSERT_LE(off + 9 + h.length, output.size());
        ASSERT_EQ(h.type, FrameType::DATA);
        EXPECT_EQ(h.stream_id, 1u);
        sent += h.length;
        ended = ended || (h.flags & FrameFlags::DATA_END_STREAM) != 0;
        off += 9 + h.length;
    }
    EXPECT_EQ(sent, accepted_body.size() - 65535);
    EXPECT_TRUE(ended);
    ASSERT_TRUE(headers(client, 1, {{":status", "204"}}, true));
    EXPECT_EQ(events.count(Kind::Complete), 1u);
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_TRUE(client.wants_close());
}

TEST(Http2Client, GracefulGoawayAndFinalResponseInOneReadCompleteNormally) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    Bytes input = goaway(1);
    const auto response = frame(FrameType::HEADERS, 1,
        FrameFlags::HEADERS_END_HEADERS | FrameFlags::HEADERS_END_STREAM, block({{":status", "204"}}));
    input.insert(input.end(), response.begin(), response.end());
    ASSERT_TRUE(feed(client, input));
    EXPECT_EQ(events.count(Kind::Complete), 1u);
    EXPECT_EQ(events.count(Kind::Reset), 0u);
    EXPECT_EQ(client.open_stream_count(), 0u);
    EXPECT_TRUE(client.wants_close());
}

TEST(Http2Client, FatalGoawayAfterGracefulNoticeResetsRemainingStreamsOnce) {
    Events events;
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    ASSERT_TRUE(feed(client, goaway(0x7FFFFFFFu)));
    EXPECT_EQ(events.count(Kind::Reset), 0u);
    ASSERT_TRUE(feed(client, goaway(1, ErrorCode::INTERNAL_ERROR)));
    ASSERT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.items.back().error, ErrorCode::INTERNAL_ERROR);
    ASSERT_TRUE(feed(client, goaway(1, ErrorCode::INTERNAL_ERROR)));
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.count(Kind::Complete), 0u);
    EXPECT_TRUE(client.wants_close());
}

TEST(Http2Client, MalformedGoawayRemainsAConnectionError) {
    for (const bool invalid_stream : {false, true}) {
        Events events;
        Connection client(false);
        client.set_response_callback([&](const auto& e) { events.save(e); });
        ready(client);
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
        EXPECT_FALSE(feed(client, frame(FrameType::GOAWAY, invalid_stream ? 1u : 0u, 0,
                                         Bytes(invalid_stream ? 8u : 7u)), 1));
        EXPECT_EQ(client.last_error(), invalid_stream ? ErrorCode::PROTOCOL_ERROR : ErrorCode::FRAME_SIZE_ERROR);
        EXPECT_EQ(events.count(Kind::Reset), 1u);
        EXPECT_EQ(events.count(Kind::Complete), 0u);
        EXPECT_TRUE(client.wants_close());
    }
}

TEST(Http2Client, ClientGoawayReportsNoPeerInitiatedStreams) {
    for (unsigned mode = 0; mode < 2; ++mode) {
        Connection client(false);
        ready(client);
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
        (void)take(client);
        if (mode == 0) ASSERT_TRUE(client.send_goaway(ErrorCode::NO_ERROR).is_ok());
        else EXPECT_FALSE(headers(client, 2, {{":status", "200"}}, true));
        const auto output = take(client);
        ASSERT_GE(output.size(), 17u);
        const auto h = parse_frame_header(output.data()).value();
        EXPECT_EQ(h.type, FrameType::GOAWAY);
        EXPECT_EQ((Bytes(output.begin() + 9, output.begin() + 13)), u32(0));
        EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    }
}

TEST(Http2Server, FirstGoawayReportsAcceptedStreamsInsteadOfRefusedIds) {
    for (const bool accepted : {false, true}) {
        Connection client(false), server;
        uint32_t requests = 0;
        server.set_request_callback([&](Http2Stream*) { ++requests; });
        ASSERT_TRUE(transfer(client, server));
        (void)take(server);
        if (accepted) ASSERT_TRUE(headers(server, 1, kGet, true));
        const uint32_t refused = accepted ? 3u : 1u;
        ASSERT_TRUE(headers(server, refused, {{":method", "GET"}}, true));
        EXPECT_EQ(take(server), frame(FrameType::RST_STREAM, refused, 0,
                                     u32(static_cast<uint32_t>(ErrorCode::PROTOCOL_ERROR))));
        ASSERT_TRUE(server.send_goaway(ErrorCode::NO_ERROR).is_ok());
        EXPECT_EQ(take(server), goaway(accepted ? 1u : 0u));
        EXPECT_EQ(requests, accepted ? 1u : 0u);
        EXPECT_EQ(server.open_stream_count(), accepted ? 1u : 0u);
    }
}

TEST(Http2Server, RepeatedGoawayKeepsCutoffAndDrainsAcceptedStream) {
    for (const size_t chunk : {size_t{1}, SIZE_MAX}) {
        Connection client(false), server;
        Events events;
        uint32_t requests = 0;
        server.set_request_callback([&](Http2Stream*) { ++requests; });
        client.set_response_callback([&](const auto& event) { events.save(event); });
        ASSERT_TRUE(transfer(client, server));
        ASSERT_TRUE(transfer(server, client));
        ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
        ASSERT_TRUE(transfer(client, server));
        ASSERT_TRUE(server.send_goaway(ErrorCode::NO_ERROR).is_ok());
        const Bytes first = take(server);
        ASSERT_EQ(first, goaway(1));
        ASSERT_TRUE(feed(client, first, chunk));
        EXPECT_FALSE(server.wants_close());

        Bytes indexed = block(kGet);
        // Incremental literal x-drain:yes inserts dynamic index62 on refused3.
        const Bytes entry{0x40, 7, 'x', '-', 'd', 'r', 'a', 'i', 'n', 3, 'y', 'e', 's'};
        indexed.insert(indexed.end(), entry.begin(), entry.end());
        Bytes referenced = block(kGet);
        referenced.push_back(0xBE); // dynamic index62 must still decode on refused5
        Bytes input = frame(FrameType::HEADERS, 3, 0x5, indexed);
        const Bytes next = frame(FrameType::HEADERS, 5, 0x5, referenced);
        input.insert(input.end(), next.begin(), next.end());
        ASSERT_TRUE(feed(server, input, chunk));
        Bytes expected = frame(FrameType::RST_STREAM, 3, 0,
                               u32(static_cast<uint32_t>(ErrorCode::REFUSED_STREAM)));
        const Bytes reset = frame(FrameType::RST_STREAM, 5, 0,
                                  u32(static_cast<uint32_t>(ErrorCode::REFUSED_STREAM)));
        expected.insert(expected.end(), reset.begin(), reset.end());
        EXPECT_EQ(take(server), expected);
        ASSERT_TRUE(server.send_goaway(ErrorCode::NO_ERROR).is_ok());
        const Bytes repeated = take(server);
        ASSERT_EQ(repeated, goaway(1));
        ASSERT_TRUE(feed(client, repeated, chunk));
        EXPECT_EQ(requests, 1u);
        EXPECT_EQ(server.open_stream_count(), 1u);
        ASSERT_TRUE(server.send_response(1, 200, {}, "accepted").is_ok());
        ASSERT_TRUE(transfer(server, client));
        EXPECT_EQ(events.count(Kind::Complete), 1u);
        EXPECT_EQ(events.count(Kind::Reset), 0u);
        ASSERT_EQ(events.items.size(), 3u);
        EXPECT_EQ(events.items[1].data, "accepted");
        EXPECT_TRUE(server.wants_close());
        EXPECT_TRUE(client.wants_close());
    }
}

TEST(Http2Server, FatalAndConnectionErrorGoawayPreserveSentCutoff) {
    for (const size_t chunk : {size_t{1}, SIZE_MAX}) {
        for (const bool explicit_fatal : {false, true}) {
            Connection client(false), server;
            uint32_t requests = 0;
            server.set_request_callback([&](Http2Stream*) { ++requests; });
            ASSERT_TRUE(transfer(client, server));
            (void)take(server);
            ASSERT_TRUE(headers(server, 1, kGet, true));
            ASSERT_TRUE(server.send_goaway(ErrorCode::NO_ERROR).is_ok());
            ASSERT_EQ(take(server), goaway(1));
            Bytes input = frame(FrameType::HEADERS, 3, 0x5, block(kGet));
            const ErrorCode error = explicit_fatal ? ErrorCode::INTERNAL_ERROR : ErrorCode::FRAME_SIZE_ERROR;
            if (explicit_fatal) {
                ASSERT_TRUE(feed(server, input, chunk));
                ASSERT_TRUE(server.send_goaway(error).is_ok());
            } else {
                const Bytes malformed = frame(FrameType::PING, 0, 0, Bytes(7));
                input.insert(input.end(), malformed.begin(), malformed.end());
                EXPECT_FALSE(feed(server, input, chunk));
            }
            Bytes expected = frame(FrameType::RST_STREAM, 3, 0,
                                   u32(static_cast<uint32_t>(ErrorCode::REFUSED_STREAM)));
            const Bytes fatal = goaway(1, error);
            expected.insert(expected.end(), fatal.begin(), fatal.end());
            EXPECT_EQ(take(server), expected);
            EXPECT_EQ(server.last_error(), error);
            EXPECT_TRUE(server.wants_close());
            EXPECT_EQ(requests, 1u);
            EXPECT_TRUE(server.send_goaway(ErrorCode::NO_ERROR).is_err());
        }
    }
}

TEST(Http2Client, HeaderBudgetsAndUnreadControlFloodFailExplicitly) {
    Events events;
    const std::string oversized(Connection::kMaxHeaderListSize, 'h');
    Connection client(false);
    client.set_response_callback([&](const auto& e) { events.save(e); });
    ready(client);
    Fields large = kGet;
    large.push_back({"x-large", oversized});
    EXPECT_TRUE(client.send_request(large.data(), large.size()).is_err());
    ASSERT_TRUE(feed(client, setting(SettingsId::MAX_HEADER_LIST_SIZE, 1)));
    EXPECT_TRUE(client.send_request(kGet.data(), kGet.size()).is_err());
    ASSERT_TRUE(feed(client, setting(SettingsId::MAX_HEADER_LIST_SIZE, Connection::kMaxHeaderListSize)));
    ASSERT_TRUE(client.send_request(kGet.data(), kGet.size()).is_ok());
    (void)take(client);
    const auto ping = frame(FrameType::PING, 0, 0, Bytes(8));
    bool refused = false;
    for (size_t i = 0; i < Connection::kMaxControlBacklog / 17 + 4; ++i) {
        if (!feed(client, ping)) { refused = true; break; }
    }
    EXPECT_TRUE(refused);
    EXPECT_EQ(client.last_error(), ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(events.count(Kind::Reset), 1u);
    EXPECT_EQ(events.count(Kind::Complete), 0u);
    const uint8_t* output = nullptr;
    size_t n = 0;
    ASSERT_TRUE(client.get_output(&output, &n));
    EXPECT_LE(n, Connection::kClientOutputCapacity);
}

} // namespace
