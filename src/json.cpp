// json.cpp — Bolt API JSON facade translation unit.
//
// The facility in include/boltapi/json.h is header-only (everything inline so
// the cursor walks stay in the caller's TU and inline well). This TU exists to:
//   1. Anchor the bolt::parse (fionn) link dependency in a single object so the
//      symbols are pulled in deterministically.
//   2. Force a standalone compile of json.h (catches header self-sufficiency
//      regressions in the library build, not just in tests).
//   3. Host one non-inline helper that other TUs can call without dragging the
//      whole header in (validity check used by middleware / app glue later).
//
// No exceptions, no allocation beyond the Document's own arena.
#include "boltapi/json.h"

namespace bolt::api::json {

// Cheap "is this body valid JSON?" probe. Parses and discards. Useful for
// content negotiation / 400 short-circuits without materialising fields.
bool is_valid(std::string_view input) noexcept {
    Document doc = parse(input);
    return doc.ok();
}

}  // namespace bolt::api::json
