// src/proto/flight_sql_server_put.inc — prepared-statement parameters and
// DoPut (updates, parameter binding) for flight_sql_server.cpp (G2ETL-75).
// Included inside that file's anonymous namespace, after class Conn.

// The executable text of a prepared-statement handle: the statement itself,
// or with its bound parameter set substituted (into bound_).
bool Conn::bound_sql(Stream& s, std::string_view handle, std::string_view* sql) noexcept {
    assert(sql != nullptr);
    bool bound = false;
    if (!pm::decode_handle(handle, sql, &bound, &handle_row_)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "prepared_statement_handle was not issued by this endpoint");
        return false;
    }
    std::uint32_t n = 0;
    if (!pm::count_placeholders(*sql, &n)) {
        respond_error(s, GrpcCode::kInvalidArgument, "statement has more than 256 parameters");
        return false;
    }
    if (n == 0) return true;
    if (!bound) {
        std::snprintf(fail_buf_, sizeof(fail_buf_),
                      "prepared statement has %u parameter(s) and none are bound: DoPut "
                      "them, then use the handle DoPutPreparedStatementResult returns",
                      static_cast<unsigned>(n));
        respond_error(s, GrpcCode::kInvalidArgument, fail_buf_);
        return false;
    }
    const char* err = nullptr;
    if (handle_row_.size() != n ||
        !pm::render(*sql, handle_row_.data(), n, kMaxQueryBytes, &bound_, &err)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      err != nullptr ? err : "bound parameters do not match the statement");
        return false;
    }
    *sql = bound_;
    assert(!bound_.empty());
    return true;
}

// ActionCreatePreparedStatementResult{prepared_statement_handle=1,
// dataset_schema=2, parameter_schema=3}. A parameterless query is run once
// to describe it. A query with parameters is run once only when the host
// types every placeholder, with a typed stand-in for each; otherwise no
// stand-in is safe for every placeholder position and it answers no
// dataset_schema. An update is never run here; its missing dataset_schema
// is how clients tell updates from queries.
void Conn::create_prepared(Stream& s, std::string_view sql) noexcept {
    std::uint32_t n = 0;
    if (sql.empty() || sql.size() > kMaxQueryBytes || !pm::count_placeholders(sql, &n)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "statement is empty, exceeds 65536 bytes or has more than 256 parameters");
        return;
    }
    std::string handle;
    pm::encode_unbound(&handle, sql);
    std::string result;
    cd::pb_put_bytes(&result, 1, handle);
    if (n == 0 && exec_.is_query(sql)) {
        std::int64_t rows = 0;
        cd::IpcMessage schema;
        if (!run_query(s, sql, &rows, &schema)) return;
        cd::pb_put_bytes(&result, 2, schema.encapsulated);
    }
    if (n > 0) {
        std::vector<ParamType> types(n, ParamType::kUnknown);
        ipc_.clear();
        if (!exec_.describe_parameters(sql, n, types.data(), &ipc_)) {
            std::fill(types.begin(), types.end(), ParamType::kUnknown);
            ipc_.clear();
        }
        if (exec_.is_query(sql)) {
            if (ipc_.empty()) describe_typed(sql, types.data(), n);
            put_leading_schema(&result);
        }
        scratch_.clear();
        arrow::write_parameter_schema(&scratch_, n, types.data());
        cd::pb_put_bytes(&result, 3, scratch_);
    }
    std::string wrapped;
    cd::encode_any(&wrapped, "ActionCreatePreparedStatementResult", result);
    msg_.clear();
    cd::pb_put_bytes(&msg_, 1, wrapped);   // Result{body}
    if (!send_response_headers(s) || !send_message(s, msg_)) return;
    (void)send_trailers(s, GrpcCode::kOk, {}, false);
}

// Runs a query whose placeholders are all typed once, with typed
// stand-ins, into ipc_. Best effort: any failure leaves ipc_ empty.
void Conn::describe_typed(std::string_view sql, const ParamType* types,
                          std::uint32_t n) noexcept {
    assert(types != nullptr);
    assert(n > 0 && n <= pm::kMaxParams);
    ipc_.clear();
    std::vector<pm::Value> stand_in(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        switch (types[i]) {
            case ParamType::kInt64:   stand_in[i].kind = pm::Kind::kInt; break;
            case ParamType::kFloat64: stand_in[i].kind = pm::Kind::kFloat; break;
            case ParamType::kUtf8:    stand_in[i].kind = pm::Kind::kString; break;
            case ParamType::kBool:    stand_in[i].kind = pm::Kind::kBool; break;
            default: return;
        }
    }
    const char* err = nullptr;
    if (!pm::render(sql, stand_in.data(), n, kMaxQueryBytes, &bound_, &err)) return;
    QueryFailure f;
    std::int64_t rows = 0;
    if (!exec_.execute(bound_, &ipc_, &rows, f)) ipc_.clear();
}

// dataset_schema (field 2) from ipc_'s leading Schema message, if any.
void Conn::put_leading_schema(std::string* result) noexcept {
    assert(result != nullptr);
    if (ipc_.empty()) return;
    std::size_t pos = 0;
    bool bad = false;
    cd::IpcMessage schema;
    if (!cd::ipc_next_message(ipc_, &pos, &schema, &bad) ||
        schema.header_type != cd::kIpcHeaderSchema) {
        return;
    }
    assert(!schema.encapsulated.empty());
    cd::pb_put_bytes(result, 2, schema.encapsulated);
}

bool Conn::send_put_result(Stream& s, std::string_view app_metadata) noexcept {
    msg_.clear();
    cd::pb_put_bytes(&msg_, 1, app_metadata);   // PutResult{app_metadata}
    if (!send_response_headers(s) || !send_message(s, msg_)) return false;
    return send_trailers(s, GrpcCode::kOk, {}, false);
}

// Runs `sql` once, or once per parameter set, and answers DoPutUpdateResult.
bool Conn::put_update(Stream& s, std::string_view sql, const pm::Rows& rows,
                      const std::vector<pm::Value>& handle_row, bool bound) noexcept {
    std::uint32_t n = 0;
    if (sql.empty() || sql.size() > kMaxQueryBytes || !pm::count_placeholders(sql, &n)) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "statement is empty, exceeds 65536 bytes or has more than 256 parameters");
        return false;
    }
    const bool use_handle = n > 0 && rows.n_rows == 0 && bound;
    if (n > 0 && rows.n_rows == 0 && !bound) {
        std::snprintf(fail_buf_, sizeof(fail_buf_),
                      "update has %u parameter(s) and the DoPut carried no parameter rows",
                      static_cast<unsigned>(n));
        respond_error(s, GrpcCode::kInvalidArgument, fail_buf_);
        return false;
    }
    if (n > 0 && !use_handle && rows.n_cols != n) {
        std::snprintf(fail_buf_, sizeof(fail_buf_),
                      "statement has %u parameter(s) but the bound batch has %u column(s)",
                      static_cast<unsigned>(n), static_cast<unsigned>(rows.n_cols));
        respond_error(s, GrpcCode::kInvalidArgument, fail_buf_);
        return false;
    }
    const std::uint32_t sets = (n == 0 || use_handle) ? 1u : rows.n_rows;
    std::int64_t total = 0;
    for (std::uint32_t r = 0; r < sets; ++r) {                // bounded by kMaxRows
        std::string_view text = sql;
        if (n > 0) {
            const pm::Value* row = use_handle ? handle_row.data()
                                              : &rows.values[static_cast<std::size_t>(r) * n];
            const char* err = nullptr;
            if (!pm::render(sql, row, n, kMaxQueryBytes, &bound_, &err)) {
                respond_error(s, GrpcCode::kInvalidArgument, err);
                return false;
            }
            text = bound_;
        }
        QueryFailure f;
        std::int64_t affected = 0;
        if (!exec_.execute_update(text, &affected, f)) {
            respond_error(s, f.code, f.message != nullptr ? f.message : "update failed");
            return false;
        }
        total = (total < 0 || affected < 0) ? -1 : total + affected;
    }
    std::string result;
    cd::pb_put_int64(&result, 1, total);   // DoPutUpdateResult{record_count}
    return send_put_result(s, result);
}

// DoPut's FlightData messages: the first carries the descriptor, the rest
// an optional IPC stream of parameter sets.
bool Conn::read_put(Stream& s, std::string_view* descriptor, pm::Rows* rows) noexcept {
    assert(descriptor != nullptr && rows != nullptr);
    const std::string_view body(reinterpret_cast<const char*>(s.body), s.body_len);
    pm::Decoder dec;
    std::size_t pos = 0;
    for (std::size_t k = 0; k < kMaxPutMessages && pos < body.size(); ++k) {
        std::string_view msg;
        std::size_t used = 0;
        const cd::GrpcFrame fr = cd::grpc_unframe(body.substr(pos), &msg, &used);
        if (fr == cd::GrpcFrame::kCompressed) {
            respond_error(s, GrpcCode::kUnimplemented,
                          "compressed gRPC messages are not supported (identity only)");
            return false;
        }
        cd::FlightDataMsg fd;
        if (fr != cd::GrpcFrame::kOk || !cd::decode_flight_data(msg, &fd)) {
            respond_error(s, GrpcCode::kInvalidArgument, "malformed FlightData in DoPut");
            return false;
        }
        pos += used;
        if (k == 0) *descriptor = fd.descriptor;
        if (fd.data_header.empty()) continue;
        const char* err = "unexpected IPC message in DoPut";
        const std::uint8_t ht = pm::header_type(fd.data_header);
        const bool ok = !dec.has_schema() ? dec.schema(fd.data_header, &err)
                        : ht == cd::kIpcHeaderRecordBatch
                            ? dec.batch(fd.data_header, fd.data_body, rows, &err)
                            : false;
        if (!ok) {
            const bool unsupported = dec.unsupported() || ht == cd::kIpcHeaderDictionaryBatch;
            respond_error(s, unsupported ? GrpcCode::kUnimplemented : GrpcCode::kInvalidArgument,
                          ht == cd::kIpcHeaderDictionaryBatch
                              ? "dictionary-encoded parameters are not supported" : err);
            return false;
        }
    }
    if (pos != body.size()) {
        respond_error(s, GrpcCode::kResourceExhausted, "too many FlightData messages in DoPut");
        return false;
    }
    if (descriptor->empty()) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "DoPut: the first FlightData carries no FlightDescriptor");
        return false;
    }
    return true;
}

// Binds one parameter set to a prepared query: answers
// DoPutPreparedStatementResult with a handle that carries it.
void Conn::put_bind(Stream& s, std::string_view handle, std::string_view sql,
                    const pm::Rows& rows) noexcept {
    std::uint32_t n = 0;
    if (!pm::count_placeholders(sql, &n) || rows.n_rows > 1 ||
        (rows.n_rows == 1 && rows.n_cols != n)) {
        std::snprintf(fail_buf_, sizeof(fail_buf_),
                      "a query binds exactly one parameter set of %u value(s); got %u "
                      "row(s) of %u column(s)", static_cast<unsigned>(n),
                      static_cast<unsigned>(rows.n_rows), static_cast<unsigned>(rows.n_cols));
        respond_error(s, GrpcCode::kInvalidArgument, fail_buf_);
        return;
    }
    std::string next(handle);
    if (rows.n_rows == 1) pm::encode_bound(&next, sql, rows.values.data(), n);
    std::string result;
    cd::pb_put_bytes(&result, 1, next);   // DoPutPreparedStatementResult
    (void)send_put_result(s, result);
}

void Conn::rpc_do_put(Stream& s) noexcept {
    std::string_view descriptor;
    pm::Rows rows;
    if (!read_put(s, &descriptor, &rows)) return;
    std::string_view cmd;
    if (!command_from_descriptor(s, descriptor, &cmd)) return;
    cd::AnyMsg any;
    if (!cd::decode_any(cmd, &any)) {
        respond_error(s, GrpcCode::kInvalidArgument, "FlightDescriptor.cmd is not a google.protobuf.Any");
        return;
    }
    if (is_sql(any.type_name, "CommandStatementUpdate")) {
        std::string_view sql;
        std::string_view txn;
        if (!cd::decode_statement_query(any.value, &sql, &txn)) {
            respond_error(s, GrpcCode::kInvalidArgument, "malformed CommandStatementUpdate");
            return;
        }
        if (!txn.empty()) {
            respond_error(s, GrpcCode::kUnimplemented, "transactions are not supported");
            return;
        }
        std::uint32_t n = 0;
        if (pm::count_placeholders(sql, &n) && n > 0) {
            respond_error(s, GrpcCode::kInvalidArgument,
                          "CommandStatementUpdate cannot bind parameters; prepare the statement");
            return;
        }
        (void)put_update(s, sql, pm::Rows{}, {}, false);
        return;
    }
    std::string_view handle;
    std::string_view sql;
    bool bound = false;
    const bool prepared = is_sql(any.type_name, "CommandPreparedStatementUpdate") ||
                          is_sql(any.type_name, "CommandPreparedStatementQuery");
    if (prepared && (!cd::decode_single_bytes(any.value, &handle) ||
                     !pm::decode_handle(handle, &sql, &bound, &handle_row_))) {
        respond_error(s, GrpcCode::kInvalidArgument,
                      "prepared_statement_handle was not issued by this endpoint");
        return;
    }
    if (is_sql(any.type_name, "CommandPreparedStatementUpdate")) {
        (void)put_update(s, sql, rows, handle_row_, bound);
        return;
    }
    if (is_sql(any.type_name, "CommandPreparedStatementQuery")) {
        put_bind(s, handle, sql, rows);
        return;
    }
    const std::string_view name = any.type_name.substr(0, 160);
    std::snprintf(fail_buf_, sizeof(fail_buf_),
                  "DoPut of %.*s is not supported by this endpoint",
                  static_cast<int>(name.size()), name.data());
    respond_error(s, GrpcCode::kUnimplemented, fail_buf_);
}
