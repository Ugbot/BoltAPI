// compression.cpp — gzip codec implementation behind the BOLTAPI_HAVE_GZIP seam.
//
// STOPGAP: zlib backend. See compression.h for the Bolt-native-codec TODO. The
// Accept-Encoding parser is backend-independent and always compiled.

#include "boltapi/compression.h"

#include <cassert>
#include <cctype>

#if BOLTAPI_HAVE_GZIP
#include <zlib.h>
#endif

namespace bolt::api {
namespace compression {

namespace {

// Case-insensitive single-char compare (ASCII).
inline char lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Case-insensitive prefix match of `tok` against `s` starting at `pos`.
inline bool token_is(std::string_view s, std::size_t pos,
                     std::string_view tok) noexcept {
    if (pos + tok.size() > s.size()) return false;
    for (std::size_t i = 0; i < tok.size(); ++i) {
        if (lower_ascii(s[pos + i]) != lower_ascii(tok[i])) return false;
    }
    return true;
}

}  // namespace

bool accepts_gzip(std::string_view ae) noexcept {
    // Walk comma-separated codings. Accept "gzip" or "*" unless followed by
    // ";q=0" (with optional decimal zeros). Allocation-free, bounded by length.
    std::size_t i = 0;
    const std::size_t n = ae.size();
    while (i < n) {
        // Skip leading whitespace / commas.
        while (i < n && (ae[i] == ' ' || ae[i] == '\t' || ae[i] == ',')) ++i;
        if (i >= n) break;

        const std::size_t tok_start = i;
        // Find end of this coding element (next comma).
        std::size_t elem_end = i;
        while (elem_end < n && ae[elem_end] != ',') ++elem_end;

        // Coding token ends at ';' or whitespace or elem_end.
        std::size_t coding_end = tok_start;
        while (coding_end < elem_end && ae[coding_end] != ';' &&
               ae[coding_end] != ' ' && ae[coding_end] != '\t') {
            ++coding_end;
        }

        const bool is_gzip = (coding_end - tok_start == 4) &&
                             token_is(ae, tok_start, "gzip");
        const bool is_star = (coding_end - tok_start == 1) && ae[tok_start] == '*';

        if (is_gzip || is_star) {
            // Scan params for an explicit q=0 that would disable this coding.
            bool q_zero = false;
            std::size_t p = coding_end;
            while (p < elem_end) {
                if (ae[p] == 'q' || ae[p] == 'Q') {
                    // Find '=' then the value.
                    std::size_t eq = p + 1;
                    while (eq < elem_end && (ae[eq] == ' ' || ae[eq] == '\t')) ++eq;
                    if (eq < elem_end && ae[eq] == '=') {
                        std::size_t v = eq + 1;
                        while (v < elem_end && (ae[v] == ' ' || ae[v] == '\t')) ++v;
                        // q=0, q=0.0, q=0.00, q=0.000 all disable.
                        if (v < elem_end && ae[v] == '0') {
                            bool nonzero_digit = false;
                            std::size_t w = v + 1;
                            if (w < elem_end && ae[w] == '.') {
                                ++w;
                                while (w < elem_end && ae[w] >= '0' && ae[w] <= '9') {
                                    if (ae[w] != '0') nonzero_digit = true;
                                    ++w;
                                }
                            }
                            if (!nonzero_digit) q_zero = true;
                        }
                    }
                }
                ++p;
            }
            if (!q_zero) return true;
        }

        i = elem_end;  // advance past this element (loop skips the comma)
    }
    return false;
}

#if BOLTAPI_HAVE_GZIP

std::string gzip_encode(std::string_view input, bool& ok) {
    ok = false;
    std::string out;

    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree  = Z_NULL;
    zs.opaque = Z_NULL;

    // windowBits = 15 (max window) | 16 (gzip wrapper, RFC 1952).
    constexpr int kWindowBitsGzip = 15 | 16;
    const int rc = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                                kWindowBitsGzip, 8 /*memLevel*/,
                                Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) {
        return out;
    }

    zs.next_in =
        reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    zs.avail_in = static_cast<uInt>(input.size());

    // Reserve a sensible upper bound to avoid repeated reallocation.
    out.resize(deflateBound(&zs, static_cast<uLong>(input.size())));
    zs.next_out  = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());

    const int drc = deflate(&zs, Z_FINISH);
    if (drc != Z_STREAM_END) {
        deflateEnd(&zs);
        out.clear();
        return out;
    }

    out.resize(out.size() - zs.avail_out);
    deflateEnd(&zs);
    ok = true;
    return out;
}

#else  // BOLTAPI_HAVE_GZIP == 0 : identity / unavailable

std::string gzip_encode(std::string_view /*input*/, bool& ok) {
    // No backend compiled in. Report unavailable; caller falls back to identity.
    ok = false;
    return std::string{};
}

#endif  // BOLTAPI_HAVE_GZIP

}  // namespace compression
}  // namespace bolt::api
