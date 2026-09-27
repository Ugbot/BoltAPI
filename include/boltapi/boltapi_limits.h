// boltapi/boltapi_limits.h — boltapi's entries in the bolt Limits registry.
//
// Each value is derived from the constant that enforces it. Kind A today;
// the limits review turns the wire-door caps into streamed encoders.

#pragma once

#include <cstdint>

#include "bolt/bolt_limits.h"
#include "boltapi/proto/postgres_wire.h"
#include "boltapi/router.h"

#define BOLTAPI_LIMITS(X)                                                       \
    X(pgwire_max_fields, kInvariant, "columns",                                 \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields, nullptr, nullptr,                 \
      "columns in one Postgres RowDescription")                                 \
    X(router_max_params, kInvariant, "params", ::bolt::api::kMaxParams,          \
      ::bolt::api::kMaxParams, ::bolt::api::kMaxParams, nullptr, nullptr,       \
      "path parameters captured per route match")

namespace bolt::api {

BOLT_LIMITS_TABLE(boltapi_limits, "boltapi", BOLTAPI_LIMITS)

}  // namespace bolt::api
