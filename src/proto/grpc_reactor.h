// gRPC calls hosted on the boltapi reactor (grpc::Config::reactor).
#pragma once
#ifdef BOLTAPI_WITH_FLIGHT_SQL

#include "boltapi/proto/grpc_server.h"

#include <memory>

namespace bolt::api::http {
class CoroUnifiedServer;
struct CoroHttpRequest;
class H2StreamWriter;
}  // namespace bolt::api::http

namespace bolt::api::proto::grpc {

class ReactorHost {
public:
    ReactorHost(const Config& cfg, IServiceFactory& factory) noexcept;
    ~ReactorHost();
    Status start() noexcept;
    void stop() noexcept;

private:
    void serve(const http::CoroHttpRequest& r, http::H2StreamWriter& w) noexcept;
    const Config&                            cfg_;
    IServiceFactory&                         factory_;
    std::unique_ptr<http::CoroUnifiedServer> server_;
};

}  // namespace bolt::api::proto::grpc

#endif  // BOLTAPI_WITH_FLIGHT_SQL
