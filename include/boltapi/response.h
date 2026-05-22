// boltapi/response.h — fluent builder writing into the engine's CoroHttpResponse.
//
// bolt::api::Response is a thin chainable view over a CoroHttpResponse the
// dispatcher owns on its stack frame. All setters return *this by reference so
// handlers read like: res.status(201).content_type("application/json").send(j);
//
// This is the Gestalt-compatible surface: status/content_type/header/send/json/
// text/html/body plus the named-status helpers ok()/created()/.../internal_error().
//
// Design rules (TigerStyle): no recursion, bounded, assert >= 2 invariants in the
// non-trivial setters, and we never own the response buffer (the dispatcher does).
#pragma once

#include "boltapi/server/coro_unified_server.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api {

class Response {
public:
    using CoroHttpResponse = http::CoroHttpResponse;

    explicit Response(CoroHttpResponse& out) noexcept : out_(out) {
        assert(out_.status >= 100 || out_.status == 0);
        assert(&out_ != nullptr);  // reference-validity guard (TigerStyle >=2)
    }

    Response(const Response&)            = delete;
    Response& operator=(const Response&) = delete;

    // --- Core chainable setters ---
    Response& status(int code) & noexcept {
        assert(code >= 100 && code <= 599);
        out_.status = static_cast<uint16_t>(code);
        out_.status_message = reason_phrase(out_.status);
        return *this;
    }

    Response& content_type(std::string_view ct) & {
        assert(!ct.empty());
        assert(ct.size() < 256);
        out_.headers["Content-Type"] = std::string(ct);
        return *this;
    }

    Response& header(std::string_view key, std::string_view value) & {
        assert(!key.empty());
        assert(key.size() < 256);
        out_.headers[std::string(key)] = std::string(value);
        return *this;
    }

    // Set the body (no content-type change). Aliased by body()/send().
    Response& send(std::string_view payload) & {
        assert(payload.size() <= (1u << 30));  // 1 GiB sanity cap
        assert(out_.status >= 100);
        out_.body.assign(payload.data(), payload.size());
        return *this;
    }

    Response& body(std::string_view payload) & {
        return send(payload);
    }

    // JSON: sets content-type application/json + body.
    Response& json(std::string_view payload) & {
        assert(payload.size() <= (1u << 30));
        assert(out_.status >= 100);
        out_.headers["Content-Type"] = "application/json";
        out_.body.assign(payload.data(), payload.size());
        return *this;
    }

    // Plain text.
    Response& text(std::string_view payload) & {
        assert(payload.size() <= (1u << 30));
        assert(out_.status >= 100);
        out_.headers["Content-Type"] = "text/plain; charset=utf-8";
        out_.body.assign(payload.data(), payload.size());
        return *this;
    }

    // HTML.
    Response& html(std::string_view payload) & {
        assert(payload.size() <= (1u << 30));
        assert(out_.status >= 100);
        out_.headers["Content-Type"] = "text/html; charset=utf-8";
        out_.body.assign(payload.data(), payload.size());
        return *this;
    }

    // --- Named-status helpers (set status + canonical reason phrase) ---
    Response& ok()            & noexcept { return status(200); }
    Response& created()       & noexcept { return status(201); }
    Response& no_content()    & noexcept { return status(204); }
    Response& bad_request()   & noexcept { return status(400); }
    Response& unauthorized()  & noexcept { return status(401); }
    Response& forbidden()     & noexcept { return status(403); }
    Response& not_found()     & noexcept { return status(404); }
    Response& internal_error()& noexcept { return status(500); }

    // --- Introspection ---
    uint16_t status_code() const noexcept { return out_.status; }
    const std::string& body_ref() const noexcept { return out_.body; }
    CoroHttpResponse& raw() noexcept { return out_; }

    // Canonical HTTP reason phrase for a status code. Total + noexcept.
    static const char* reason_phrase(uint16_t code) noexcept {
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            case 415: return "Unsupported Media Type";
            case 422: return "Unprocessable Entity";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default:  return "OK";
        }
    }

private:
    CoroHttpResponse& out_;
};

}  // namespace bolt::api
