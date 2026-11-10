// gRPC server mode on the boltapi reactor (Config::reactor): one
// CoroUnifiedServer on the cleartext port; every gRPC call runs on a blocking
// worker and streams its responses through an H2StreamWriter, while the
// connection's reader keeps serving WINDOW_UPDATE, RST_STREAM and other
// calls. The thread-per-connection server stays for TLS and Unix sockets.
#ifdef BOLTAPI_WITH_FLIGHT_SQL

#include "grpc_reactor.h"

#include "boltapi/proto/flight_sql_codec.h"
#include "boltapi/server/coro_unified_server.h"

#include <cassert>
#include <cstdio>
#include <string>

namespace bolt::api::proto::grpc {

namespace cd = ::bolt::api::proto::flightsql::codec;

namespace {

std::int64_t timeout_ms(std::string_view v) noexcept {
    if (v.size() < 2 || v.size() > 9) return -1;
    std::int64_t n = 0;
    for (std::size_t i = 0; i + 1 < v.size(); ++i) {
        if (v[i] < '0' || v[i] > '9') return -1;
        n = n * 10 + (v[i] - '0');
    }
    switch (v.back()) {
        case 'H': return n * 3600000;
        case 'M': return n * 60000;
        case 'S': return n * 1000;
        case 'm': return n;
        case 'u': return n / 1000;
        case 'n': return n / 1000000;
        default: return -1;
    }
}

void base64(std::string* out, std::string_view in) {
    static const char* k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        const auto a = static_cast<unsigned char>(in[i]), b = static_cast<unsigned char>(in[i + 1]),
                   c = static_cast<unsigned char>(in[i + 2]);
        out->push_back(k[a >> 2]);
        out->push_back(k[((a & 3) << 4) | (b >> 4)]);
        out->push_back(k[((b & 15) << 2) | (c >> 6)]);
        out->push_back(k[c & 63]);
    }
    if (in.size() - i == 1) {
        const auto a = static_cast<unsigned char>(in[i]);
        out->push_back(k[a >> 2]);
        out->push_back(k[(a & 3) << 4]);
    } else if (in.size() - i == 2) {
        const auto a = static_cast<unsigned char>(in[i]), b = static_cast<unsigned char>(in[i + 1]);
        out->push_back(k[a >> 2]);
        out->push_back(k[((a & 3) << 4) | (b >> 4)]);
        out->push_back(k[(b & 15) << 2]);
    }
}

class WriterResponder final : public Responder {
public:
    explicit WriterResponder(http::H2StreamWriter& w) noexcept : w_(w) {}
    bool send(std::string_view message) noexcept override {
        if (finished_ || !head()) return false;
        frame_.clear();
        const auto n = static_cast<std::uint32_t>(message.size());
        frame_.push_back('\0');
        for (int s = 24; s >= 0; s -= 8) frame_.push_back(static_cast<char>((n >> s) & 0xFF));
        frame_.append(message.data(), message.size());
        return w_.data(frame_);
    }
    void finish(Code code, std::string_view message) noexcept override {
        finish_with_details(code, message, {});
    }
    void finish_with_details(Code code, std::string_view message,
                             std::string_view details) noexcept override {
        if (finished_) return;
        finished_ = true;
        if (!head()) return;
        http::CoroResponseHeaders t;
        char num[8];
        std::snprintf(num, sizeof(num), "%u", static_cast<unsigned>(code));
        t.append("grpc-status", num);
        if (!message.empty()) {
            char enc[2048];
            const std::size_t n = cd::grpc_percent_encode(message, enc, sizeof(enc));
            t.append("grpc-message", std::string_view(enc, n));
        }
        if (!details.empty() && details.size() <= 8192) {
            std::string b64;
            base64(&b64, details);
            t.append("grpc-status-details-bin", b64);
        }
        (void)w_.trailers(t);
    }
    bool cancelled() const noexcept override { return w_.cancelled(); }
    void poll() noexcept override {}   // the connection's reader runs concurrently
    bool finished() const noexcept { return finished_; }

private:
    bool head() {
        if (head_sent_) return true;
        head_sent_ = true;
        http::CoroResponseHeaders h;
        h.append("content-type", "application/grpc");
        return w_.head(200, h);
    }
    http::H2StreamWriter& w_;
    std::string frame_;
    bool head_sent_ = false;
    bool finished_ = false;
};

}  // namespace

ReactorHost::ReactorHost(const Config& cfg, IServiceFactory& factory) noexcept
    : cfg_(cfg), factory_(factory) {}

ReactorHost::~ReactorHost() { stop(); }

Status ReactorHost::start() noexcept {
    if (cfg_.port == 0 || cfg_.tls_enabled() || !cfg_.unix_path.empty()) {
        return Status(core::error_code::invalid_state);
    }
    http::CoroUnifiedServerConfig sc;
    sc.enable_tls = false;
    sc.enable_http1_cleartext = true;
    sc.enable_h2c = true;
    sc.host = cfg_.host;
    sc.http1_port = cfg_.port;
    sc.num_io_threads = 1;
    sc.num_workers = 2;
    // One blocking worker per concurrent call: a session's long ExecutePlan
    // and its Interrupt / ReleaseExecute each hold one while they run.
    sc.num_streaming_workers = static_cast<std::size_t>(cfg_.max_connections) * 4u;
    sc.stack_size_bytes = cfg_.worker_stack_bytes;
    sc.max_body_size = cfg_.max_request_bytes;
    sc.enable_signal_handlers = false;
    server_ = std::make_unique<http::CoroUnifiedServer>(sc);
    server_->set_handler([](const http::CoroHttpRequest&) -> http::dispatch_task<http::CoroHttpResponse> {
        http::CoroHttpResponse r;
        r.status = 415;
        r.status_message = "Unsupported Media Type";
        r.body = "gRPC over HTTP/2 only";
        co_return r;
    });
    server_->set_h2_stream_handler(
        [](const http::CoroHttpRequest& r) {
            return r.method == "POST" && r.find_header("content-type").substr(0, 16) == "application/grpc";
        },
        [this](const http::CoroHttpRequest& r, http::H2StreamWriter& w) { serve(r, w); });
    if (server_->start_background() != 0) {
        server_.reset();
        return Status(core::error_code::internal_error);
    }
    return Status();
}

void ReactorHost::serve(const http::CoroHttpRequest& r, http::H2StreamWriter& w) noexcept {
    Call call;
    call.method = r.path;
    call.authorization = r.find_header("authorization");
    call.user_agent = r.find_header("user-agent");
    call.timeout_ms = timeout_ms(r.find_header("grpc-timeout"));
    call.body = r.body;
    WriterResponder out(w);
    IService* svc = factory_.create();
    if (svc == nullptr) {
        out.finish(Code::kResourceExhausted, "no service instance");
        return;
    }
    svc->handle(call, out);
    factory_.destroy(svc);
    if (!out.finished()) out.finish(Code::kInternal, "handler returned without a status");
}

void ReactorHost::stop() noexcept {
    if (server_ != nullptr) server_->stop();
    server_.reset();
}

}  // namespace bolt::api::proto::grpc

#endif  // BOLTAPI_WITH_FLIGHT_SQL
