// json_test.cpp — coverage for Bolt API's JSON facility (boltapi/json.h),
// which wraps Bolt's own parser "fionn" (bolt::parse::json). No simdjson, no
// nlohmann — this is the canonical JSON path. See docs/JSON.md.
//
// Two layers:
//   1. UNIT — parse objects/arrays/scalars/nested directly via json::parse():
//      string/int/double/bool/null extraction, object member + array iteration,
//      missing keys, type mismatches, and MALFORMED input -> ok()==false (no
//      throw / no crash, since the whole stack is -fno-exceptions / noexcept).
//   2. INTEGRATION — a real App on an ephemeral cleartext HTTP/1.1 port, driven
//      by a raw client socket (mirrors app_integration_test). A route reads
//      req.json(), pulls typed fields, and replies; randomized JSON bodies.

#include "boltapi/json.h"
#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"
#include "util/http_fuzz.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace json = bolt::api::json;
namespace api  = bolt::api;
namespace core = bolt::api::core;
namespace sys  = bolt::api::net::sys;
namespace bt   = boltapi::test;

// ===========================================================================
// UNIT TESTS — facility in isolation.
// ===========================================================================

TEST(JsonFacility, ParsesObjectScalars) {
    const std::string body =
        R"({"name":"alice","age":30,"score":98.5,"active":true,"absent":null})";
    json::Document doc = json::parse(body);
    ASSERT_TRUE(doc.ok());

    json::Value root = doc.root();
    EXPECT_TRUE(root.is_object());
    EXPECT_EQ(root.size(), 5);

    EXPECT_EQ(doc["name"].as_string(), "alice");
    EXPECT_EQ(doc["age"].as_int(), 30);
    EXPECT_DOUBLE_EQ(doc["score"].as_double(), 98.5);
    EXPECT_TRUE(doc["active"].as_bool());
    EXPECT_TRUE(doc["absent"].is_null());

    // Typed getters report success/failure without throwing.
    std::string_view s; int64_t i; double d; bool b;
    EXPECT_TRUE(doc["name"].get_string(&s));
    EXPECT_EQ(s, "alice");
    EXPECT_TRUE(doc["age"].get_int(&i));
    EXPECT_EQ(i, 30);
    EXPECT_TRUE(doc["score"].get_double(&d));
    EXPECT_DOUBLE_EQ(d, 98.5);
    EXPECT_TRUE(doc["active"].get_bool(&b));
    EXPECT_TRUE(b);
}

TEST(JsonFacility, TypeMismatchesAndMissingKeysAreSafe) {
    const std::string body = R"({"name":"bob","age":7})";
    json::Document doc = json::parse(body);
    ASSERT_TRUE(doc.ok());

    // Missing key -> invalid value, fallbacks returned, no crash.
    EXPECT_FALSE(doc["nope"].valid());
    EXPECT_EQ(doc["nope"].as_string("DEF"), "DEF");
    EXPECT_EQ(doc["nope"].as_int(-1), -1);
    EXPECT_FALSE(doc["nope"].as_bool(false));

    // Wrong-type extraction fails cleanly.
    int64_t i; std::string_view s;
    EXPECT_FALSE(doc["name"].get_int(&i));   // string, not int
    EXPECT_FALSE(doc["age"].get_string(&s)); // int, not string
    EXPECT_EQ(doc["age"].as_string("fb"), "fb");
}

TEST(JsonFacility, IntReadAsDouble) {
    json::Document doc = json::parse(R"({"n":42})");
    ASSERT_TRUE(doc.ok());
    // An integer token is also readable as a double (is_double()==true).
    EXPECT_TRUE(doc["n"].is_int());
    EXPECT_TRUE(doc["n"].is_double());
    EXPECT_DOUBLE_EQ(doc["n"].as_double(), 42.0);
    EXPECT_DOUBLE_EQ(doc["n"].as_double(), 42.0);
}

TEST(JsonFacility, NegativeAndExponentNumbers) {
    json::Document doc =
        json::parse(R"({"neg":-12345,"exp":6.022e23,"frac":-0.001})");
    ASSERT_TRUE(doc.ok());
    EXPECT_EQ(doc["neg"].as_int(), -12345);
    EXPECT_DOUBLE_EQ(doc["exp"].as_double(), 6.022e23);
    EXPECT_DOUBLE_EQ(doc["frac"].as_double(), -0.001);
}

TEST(JsonFacility, NestedObjectsAndArrays) {
    const std::string body = R"({
        "user": { "id": 1001, "tags": ["a","bb","ccc"] },
        "nums": [10, 20, 30, 40],
        "meta": { "inner": { "deep": "value" } }
    })";
    json::Document doc = json::parse(body);
    ASSERT_TRUE(doc.ok());

    json::Value user = doc["user"];
    EXPECT_TRUE(user.is_object());
    EXPECT_EQ(user["id"].as_int(), 1001);

    json::Value tags = user["tags"];
    ASSERT_TRUE(tags.is_array());
    EXPECT_EQ(tags.size(), 3);
    EXPECT_EQ(tags.at(0).as_string(), "a");
    EXPECT_EQ(tags.at(1).as_string(), "bb");
    EXPECT_EQ(tags.at(2).as_string(), "ccc");
    EXPECT_FALSE(tags.at(3).valid());  // out of range

    json::Value nums = doc["nums"];
    ASSERT_TRUE(nums.is_array());
    EXPECT_EQ(nums.size(), 4);
    int64_t sum = 0;
    for (auto e = nums.first_element(); e.valid(); e = e.next()) {
        sum += e.value().as_int();
    }
    EXPECT_EQ(sum, 100);

    // Deep nesting reachable by chained member().
    EXPECT_EQ(doc["meta"]["inner"]["deep"].as_string(), "value");
}

TEST(JsonFacility, ObjectMemberIteration) {
    json::Document doc = json::parse(R"({"x":1,"y":2,"z":3})");
    ASSERT_TRUE(doc.ok());
    int64_t sum = 0;
    int count = 0;
    std::string keys;
    for (auto m = doc.root().first_member(); m.valid(); m = m.next()) {
        keys += m.key();
        sum += m.value().as_int();
        ++count;
    }
    EXPECT_EQ(count, 3);
    EXPECT_EQ(keys, "xyz");
    EXPECT_EQ(sum, 6);
}

TEST(JsonFacility, ArrayOfObjects) {
    const std::string body =
        R"([{"k":"first","v":1},{"k":"second","v":2},{"k":"third","v":3}])";
    json::Document doc = json::parse(body);
    ASSERT_TRUE(doc.ok());
    json::Value root = doc.root();
    ASSERT_TRUE(root.is_array());
    EXPECT_EQ(root.size(), 3);
    EXPECT_EQ(root.at(0)["k"].as_string(), "first");
    EXPECT_EQ(root.at(1)["v"].as_int(), 2);
    EXPECT_EQ(root.at(2)["k"].as_string(), "third");

    int idx = 0;
    int64_t vsum = 0;
    for (auto e = root.first_element(); e.valid(); e = e.next()) {
        vsum += e.value()["v"].as_int();
        ++idx;
    }
    EXPECT_EQ(idx, 3);
    EXPECT_EQ(vsum, 6);
}

TEST(JsonFacility, MalformedInputReturnsErrorNoThrow) {
    const char* bad[] = {
        R"({"unterminated":)",        // truncated
        R"({"k": })",                  // missing value
        R"({"k" "v"})",               // missing colon
        R"([1,2,)",                    // truncated array
        R"({"a":1} trailing)",        // trailing junk
        R"(not json at all)",
        R"({)",
        R"("a":1})",                   // bare junk after string
    };
    for (const char* s : bad) {
        json::Document doc = json::parse(s);
        EXPECT_FALSE(doc.ok()) << "should have failed: " << s;
        // Navigating a failed document is safe (invalid root).
        EXPECT_FALSE(doc.root().valid());
        EXPECT_EQ(doc["anything"].as_int(-7), -7);
    }
    // is_valid() probe agrees.
    EXPECT_TRUE(json::is_valid(R"({"ok":true})"));
    EXPECT_FALSE(json::is_valid(R"({"ok":)"));
}

TEST(JsonFacility, EmptyContainers) {
    json::Document a = json::parse(R"({})");
    ASSERT_TRUE(a.ok());
    EXPECT_TRUE(a.root().is_object());
    EXPECT_EQ(a.root().size(), 0);
    EXPECT_FALSE(a.root().first_member().valid());

    json::Document b = json::parse(R"([])");
    ASSERT_TRUE(b.ok());
    EXPECT_TRUE(b.root().is_array());
    EXPECT_EQ(b.root().size(), 0);
    EXPECT_FALSE(b.root().first_element().valid());
}

TEST(JsonFacility, ParseCheckedResult) {
    auto good = json::parse_checked(R"({"a":1})");
    ASSERT_TRUE(good.is_ok());
    EXPECT_EQ(good.value()["a"].as_int(), 1);

    auto bad = json::parse_checked(R"({"a":)");
    EXPECT_TRUE(bad.is_err());
    EXPECT_EQ(bad.error(), core::error_code::parse_error);
}

TEST(JsonFacility, RandomizedRoundTripFields) {
    // Build randomized {"id":N,"name":"...","ratio":F,"flag":B} objects and
    // confirm every field parses back to the value we serialized.
    bt::FuzzRng rng{0x5EED1234u};
    for (int it = 0; it < 200; ++it) {
        const int64_t id   = rng.in_range(0, 1000000);
        const int     nlen = static_cast<int>(rng.in_range(1, 16));
        std::string name;
        for (int i = 0; i < nlen; ++i) {
            name += static_cast<char>('a' + static_cast<int>(rng.in_range(0, 25)));
        }
        const bool flag = (rng.in_range(0, 1) == 1);
        // A clean decimal ratio that round-trips through strtod exactly enough
        // for EXPECT_DOUBLE_EQ on a /1000 grid.
        const double ratio = static_cast<double>(rng.in_range(0, 100000)) / 1000.0;

        std::string body = "{\"id\":" + std::to_string(id) +
                           ",\"name\":\"" + name + "\"" +
                           ",\"ratio\":" + std::to_string(ratio) +
                           ",\"flag\":" + (flag ? "true" : "false") + "}";

        json::Document doc = json::parse(body);
        ASSERT_TRUE(doc.ok()) << body;
        EXPECT_EQ(doc["id"].as_int(), id) << body;
        EXPECT_EQ(doc["name"].as_string(), name) << body;
        EXPECT_TRUE(doc["flag"].is_bool());
        EXPECT_EQ(doc["flag"].as_bool(), flag) << body;
        // ratio printed by to_string (6 dp) and re-parsed; compare via string
        // re-extraction to avoid float formatting drift.
        EXPECT_NEAR(doc["ratio"].as_double(), ratio, 1e-6) << body;
    }
}

// ===========================================================================
// INTEGRATION — real App + real socket. Mirrors app_integration_test's client.
// ===========================================================================

namespace {

constexpr uint16_t kPort = 19233;  // distinct from other suites

struct HttpResponse {
    int status = 0;
    std::string headers_block;
    std::string body;
    bool ok = false;
};

std::string header_value_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");
    if (pos == std::string::npos) return {};
    pos += 2;
    while (pos < headers.size()) {
        std::size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (char& c : key) c = static_cast<char>(std::tolower((unsigned char)c));
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                std::size_t b = 0, e = val.size();
                while (b < e && (val[b] == ' ' || val[b] == '\t')) ++b;
                while (e > b && (val[e - 1] == ' ' || val[e - 1] == '\t')) --e;
                return val.substr(b, e - b);
            }
        }
        pos = eol + 2;
    }
    return {};
}

HttpResponse do_request(const std::string& raw) {
    HttpResponse out;
    sys::startup();
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return out;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return out;
    }
    std::size_t sent = 0;
    while (sent < raw.size()) {
        ssize_t n = sys::send_bytes(fd, raw.data() + sent, raw.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }
    std::string buf;
    char tmp[4096];
    std::size_t header_end = std::string::npos;
    long long content_length = -1;
    for (;;) {
        if (header_end != std::string::npos) {
            const std::size_t have_body = buf.size() - (header_end + 4);
            if (content_length >= 0 &&
                have_body >= static_cast<std::size_t>(content_length)) break;
            if (content_length < 0) break;
        }
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers_block = buf.substr(0, header_end);
                std::string cl = header_value_ci(out.headers_block, "Content-Length");
                if (!cl.empty()) content_length = std::stoll(cl);
            }
        }
        if (buf.size() > (1u << 20)) break;
    }
    sys::close_socket(fd);
    if (header_end == std::string::npos) return out;
    {
        const std::string& h = out.headers_block;
        std::size_t sp1 = h.find(' ');
        if (sp1 != std::string::npos) out.status = std::atoi(h.c_str() + sp1 + 1);
    }
    out.body = buf.substr(header_end + 4);
    if (content_length >= 0 &&
        out.body.size() > static_cast<std::size_t>(content_length)) {
        out.body.resize(static_cast<std::size_t>(content_length));
    }
    out.ok = true;
    return out;
}

std::string make_post(const std::string& target, const std::string& body) {
    std::string r = "POST ";
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ";
    r += std::to_string(body.size());
    r += "\r\n\r\n";
    r += body;
    return r;
}

class JsonIntegration : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();

        // POST /sum: read req.json(), add two integer fields, reply with JSON.
        app_->post("/sum", [](api::Request& req, api::Response& res) {
            auto doc = req.json();  // views alias req.body() (alive this handler)
            if (!doc.ok()) { res.bad_request().text("bad json"); return; }
            int64_t a = doc["a"].as_int(0);
            int64_t b = doc["b"].as_int(0);
            res.ok().json("{\"sum\":" + std::to_string(a + b) + "}");
        });

        // POST /profile: extract mixed-type + nested fields, echo a summary.
        app_->post("/profile", [](api::Request& req, api::Response& res) {
            auto doc = req.json();
            if (!doc.ok()) { res.bad_request().text("bad json"); return; }
            std::string_view name = doc["name"].as_string("?");
            int64_t age = doc["age"].as_int(-1);
            // nested: address.city
            std::string_view city = doc["address"]["city"].as_string("?");
            // array: roles -> count
            int roles = doc["roles"].size();
            std::string out = "{\"name\":\"" + std::string(name) +
                              "\",\"age\":" + std::to_string(age) +
                              ",\"city\":\"" + std::string(city) +
                              "\",\"roles\":" + std::to_string(roles) + "}";
            res.ok().json(out);
        });

        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }

    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }

    static api::App* app_;
};

api::App* JsonIntegration::app_ = nullptr;

TEST_F(JsonIntegration, SumRoute) {
    HttpResponse r = do_request(make_post("/sum", R"({"a":40,"b":2})"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "{\"sum\":42}");
    EXPECT_EQ(header_value_ci(r.headers_block, "Content-Type"), "application/json");
}

TEST_F(JsonIntegration, ProfileNestedAndArray) {
    const std::string body =
        R"({"name":"carol","age":29,"address":{"city":"berlin"},"roles":["admin","ops","dev"]})";
    HttpResponse r = do_request(make_post("/profile", body));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body,
              R"({"name":"carol","age":29,"city":"berlin","roles":3})");
}

TEST_F(JsonIntegration, MalformedBodyIs400) {
    HttpResponse r = do_request(make_post("/sum", R"({"a":1,"b":)"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 400);
}

TEST_F(JsonIntegration, RandomizedSumBodies) {
    bt::FuzzRng rng{0xA11CE001u};
    constexpr int kIters = 60;
    int ok_count = 0;
    for (int i = 0; i < kIters; ++i) {
        const int64_t a = rng.in_range(0, 500000);
        const int64_t b = rng.in_range(0, 500000);
        std::string body = "{\"a\":" + std::to_string(a) +
                           ",\"b\":" + std::to_string(b) + "}";
        HttpResponse r = do_request(make_post("/sum", body));
        ASSERT_TRUE(r.ok) << "iter " << i;
        EXPECT_EQ(r.status, 200);
        const std::string expect = "{\"sum\":" + std::to_string(a + b) + "}";
        EXPECT_EQ(r.body, expect) << body;
        if (r.status == 200 && r.body == expect) ++ok_count;
    }
    EXPECT_EQ(ok_count, kIters);
}

}  // namespace
