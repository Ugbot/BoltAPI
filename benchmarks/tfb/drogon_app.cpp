// drogon_app.cpp — Drogon equivalent of the BoltAPI bench server, for a
// TechEmpower-style head-to-head. Same two pure-framework endpoints:
//   GET /plaintext -> "Hello, World!" (text/plain)        [TFB Plaintext]
//   GET /json      -> {"message":"Hello, World!"}         [TFB JSON]
// Listens on 0.0.0.0:8080 with one thread per core (Drogon's standard TFB shape).
// DB-backed TFB tests are intentionally omitted: BoltAPI dropped PostgreSQL, so
// this is a fair PURE-FRAMEWORK comparison (routing + serialization + I/O).

#include <drogon/drogon.h>

#include <thread>

int main() {
    using namespace drogon;

    app().registerHandler(
        "/plaintext",
        [](const HttpRequestPtr&,
           std::function<void(const HttpResponsePtr&)>&& callback) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody("Hello, World!");
            callback(resp);
        },
        {Get});

    app().registerHandler(
        "/json",
        [](const HttpRequestPtr&,
           std::function<void(const HttpResponsePtr&)>&& callback) {
            Json::Value json;
            json["message"] = "Hello, World!";
            auto resp = HttpResponse::newHttpJsonResponse(json);
            callback(resp);
        },
        {Get});

    unsigned int threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;

    app()
        .addListener("0.0.0.0", 8080)
        .setThreadNum(threads)
        .run();
    return 0;
}
