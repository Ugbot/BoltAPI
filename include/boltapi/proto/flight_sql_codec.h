// boltapi/proto/flight_sql_codec.h — the byte-level codecs behind
// proto/flight_sql.h: a minimal protobuf reader/writer for the handful of
// Flight / Flight SQL messages the endpoint speaks, gRPC message framing,
// and an Arrow IPC stream splitter. Hand-rolled from the specs (protobuf
// encoding guide, gRPC-over-HTTP2 PROTOCOL-HTTP2.md, arrow/format/Flight.proto,
// FlightSql.proto, Message.fbs) — see flight_sql.h "WHY HAND-ROLLED".
//
// Split out of the server TU so the codecs are unit-testable without a
// socket. Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::proto::flightsql::codec {

// ---------------------------------------------------------------------------
// Protobuf wire format (proto3). Wire types: 0 varint, 1 fixed64,
// 2 length-delimited, 5 fixed32. Groups (3/4) are refused.
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kWireVarint = 0;
inline constexpr std::uint32_t kWireFixed64 = 1;
inline constexpr std::uint32_t kWireBytes = 2;
inline constexpr std::uint32_t kWireFixed32 = 5;

struct PbField {
    std::uint32_t    number = 0;
    std::uint32_t    wire = 0;
    std::uint64_t    varint = 0;    // wire 0 / 1 / 5 value
    std::string_view bytes;         // wire 2 payload
};

// Sequential field reader over one message. next() returns false at the end
// of the buffer or on malformed input (then ok() is false).
class PbReader {
public:
    explicit PbReader(std::string_view buf) noexcept : buf_(buf) {}
    bool next(PbField* out) noexcept;
    bool ok() const noexcept { return ok_; }

private:
    std::string_view buf_;
    std::size_t      pos_ = 0;
    bool             ok_ = true;
};

// Reads one raw varint at `*pos` (packed repeated fields).
bool pb_read_varint(std::string_view buf, std::size_t* pos, std::uint64_t* out) noexcept;

// Appenders. Each writes one complete field (tag + value) to `out`.
void pb_put_varint_raw(std::string* out, std::uint64_t v);
void pb_put_varint(std::string* out, std::uint32_t field, std::uint64_t v);
void pb_put_int64(std::string* out, std::uint32_t field, std::int64_t v);
void pb_put_bytes(std::string* out, std::uint32_t field, std::string_view v);

// ---------------------------------------------------------------------------
// The Flight / Flight SQL messages the endpoint decodes.
// ---------------------------------------------------------------------------
inline constexpr std::string_view kTypeUrlPrefix =
    "type.googleapis.com/arrow.flight.protocol.sql.";

// google.protobuf.Any{type_url=1, value=2}. `type_name` is the part after
// the last '/', e.g. "arrow.flight.protocol.sql.CommandStatementQuery".
struct AnyMsg {
    std::string_view type_name;
    std::string_view value;
};
bool decode_any(std::string_view buf, AnyMsg* out) noexcept;
void encode_any(std::string* out, std::string_view short_name,
                std::string_view value);

// FlightDescriptor{type=1 (enum, CMD=2), cmd=2, path=3}.
struct Descriptor {
    std::uint64_t    type = 0;
    std::string_view cmd;
};
bool decode_descriptor(std::string_view buf, Descriptor* out) noexcept;

// The single-string-field Flight SQL payloads:
// CommandStatementQuery{query=1, transaction_id=2},
// TicketStatementQuery{statement_handle=1}, Ticket{ticket=1}.
bool decode_statement_query(std::string_view buf, std::string_view* query,
                            std::string_view* transaction_id) noexcept;
bool decode_single_bytes(std::string_view buf, std::string_view* out) noexcept;

// FlightInfo{schema=1, flight_descriptor=2, endpoint=3, total_records=4,
// total_bytes=5}. `ticket` is the opaque Ticket.ticket bytes of the one
// endpoint (no locations: "retrieve from this same server").
void encode_flight_info(std::string* out, std::string_view schema_ipc,
                        std::string_view descriptor_raw,
                        std::string_view ticket, std::int64_t total_records);

// FlightData{flight_descriptor=1, data_header=2, app_metadata=3,
// data_body=1000}, as a DoPut stream sends it.
struct FlightDataMsg {
    std::string_view descriptor;    // raw FlightDescriptor, first message only
    std::string_view data_header;   // an IPC Message flatbuffer, or empty
    std::string_view data_body;
};
bool decode_flight_data(std::string_view buf, FlightDataMsg* out) noexcept;

// FlightData{data_header=2, data_body=1000}.
void encode_flight_data(std::string* out, std::string_view data_header,
                        std::string_view data_body);

// ---------------------------------------------------------------------------
// gRPC length-prefixed message framing: 1-byte compressed flag + 4-byte
// big-endian length + payload.
// ---------------------------------------------------------------------------
enum class GrpcFrame : std::uint8_t { kOk, kIncomplete, kCompressed, kBad };
GrpcFrame grpc_unframe(std::string_view buf, std::string_view* msg,
                       std::size_t* consumed) noexcept;
void grpc_frame_prefix(std::uint8_t out[5], std::uint32_t len) noexcept;

// gRPC's grpc-message percent-encoding (PROTOCOL-HTTP2.md): bytes outside
// 0x20..0x7E, and '%', become %XX. Bounded by `cap` output bytes.
std::size_t grpc_percent_encode(std::string_view in, char* out,
                                std::size_t cap) noexcept;

// RFC 4648 base64 decode (for "authorization: Basic ..."). Returns false on
// malformed input or when the output would exceed `cap`.
bool base64_decode(std::string_view in, char* out, std::size_t cap,
                   std::size_t* out_len) noexcept;

// ---------------------------------------------------------------------------
// Arrow IPC stream splitting. An encapsulated message is
// [0xFFFFFFFF][int32 metadata_len][Message flatbuffer][body of bodyLength].
// ---------------------------------------------------------------------------
struct IpcMessage {
    std::string_view encapsulated;   // continuation + length + metadata
    std::string_view metadata;       // the Message flatbuffer (padded)
    std::string_view body;
    std::uint8_t     header_type = 0;   // Message.fbs MessageHeader
};
inline constexpr std::uint8_t kIpcHeaderSchema = 1;
inline constexpr std::uint8_t kIpcHeaderDictionaryBatch = 2;
inline constexpr std::uint8_t kIpcHeaderRecordBatch = 3;

// Reads the message at `*pos` and advances past it. Returns false at the
// end-of-stream marker, the end of the buffer, or on malformed input
// (`*malformed` distinguishes the last case).
bool ipc_next_message(std::string_view stream, std::size_t* pos,
                      IpcMessage* out, bool* malformed) noexcept;

}  // namespace bolt::api::proto::flightsql::codec
