// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * search_bytes.cpp - the `byte_search` table (canonical cross-tool byte-pattern
 * search — conforms to the idasql reference shape), plus the
 * `search_first(pattern)` scalar (first match address, or NULL).
 *
 * Pattern syntax (FlexHex; whitespace between bytes is optional):
 *   - "48 8B 05"     exact bytes (hex)
 *   - "48 ?? 05"     ?? = any byte
 *   - "4?" / "?F"    single-nibble wildcard (4? matches 0x40-0x4F)
 *
 * Canonical schema — visible: addr, matched_hex, matched_bytes (BLOB), size;
 * hidden inputs: pattern (REQUIRED), start_addr, end_addr, max_results. A bare
 * `SELECT * FROM byte_search` errors (matched_hex is an output column, not the
 * search input). Two equivalent calling conventions:
 *   SELECT addr, matched_hex FROM byte_search WHERE pattern = '48 8B ?? 00';
 *   SELECT addr FROM byte_search('4? 89') LIMIT 10;                  -- positional TVF
 *   SELECT addr FROM byte_search('48 8B', 0x140001000, 0x140002000); -- range-limited
 *   SELECT printf('0x%X', search_first('CC CC CC'));                 -- scalar
 *
 * Implementation note: the search reads the initialized segment bytes directly
 * (bv->GetSegments() + bv->ReadBuffer(), the same source and the same
 * initialized check the `bytes` table uses)
 * and matches a parsed byte+mask pattern. It deliberately does NOT use
 * BinaryView::Search(): that (ABS/FlexHex) path yields zero matches on a headless
 * raw-binary session, whereas the segment bytes are always readable here.
 */

#include "core_common.hpp"   // BN SDK (via bn_headers.hpp PCH) + core::get_bv()
#include <xsql/database.hpp>
#include <xsql/functions.hpp>

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cctype>
#include <cstdint>
#include <algorithm>
#include <limits>
#include <optional>

namespace bnsql {
namespace search {

using namespace BinaryNinja;

// ============================================================================
// Search Result Row
// ============================================================================

struct SearchResult {
    uint64_t address = 0;
    std::vector<uint8_t> matched_bytes;
    std::string matched_hex;
};

namespace detail {

// One byte of a FlexHex pattern: a match requires (data & mask) == (value & mask).
struct PatternByte {
    uint8_t value = 0;
    uint8_t mask = 0;
};

// Parse a FlexHex string into byte specs. Whitespace between bytes is ignored, so
// "48 8B", "488B", and "48 ?? 00" all parse. '?' is a nibble wildcard: "??" = any
// byte, "4?" = high nibble fixed, "?F" = low nibble fixed. Returns false on any
// invalid character or an odd nibble count.
inline bool parse_pattern(const std::string& pattern, std::vector<PatternByte>& out) {
    out.clear();
    std::string s;
    for (char c : pattern) {
        if (!std::isspace(static_cast<unsigned char>(c))) s += c;
    }
    if (s.empty() || (s.size() % 2) != 0) return false;

    auto nibble = [](char c, uint8_t& v, bool& any) -> bool {
        if (c == '?') { any = true; v = 0; return true; }
        if (c >= '0' && c <= '9') { any = false; v = static_cast<uint8_t>(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { any = false; v = static_cast<uint8_t>(10 + c - 'a'); return true; }
        if (c >= 'A' && c <= 'F') { any = false; v = static_cast<uint8_t>(10 + c - 'A'); return true; }
        return false;
    };

    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        bool hany = false, lany = false;
        if (!nibble(s[i], hi, hany) || !nibble(s[i + 1], lo, lany)) return false;
        PatternByte pb;
        pb.value = static_cast<uint8_t>((hi << 4) | lo);
        pb.mask = static_cast<uint8_t>((hany ? 0x00 : 0xF0) | (lany ? 0x00 : 0x0F));
        out.push_back(pb);
    }
    return !out.empty();
}

// Space-separated lowercase 2-digit hex, matching idasql/r2sql matched_hex.
inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) hex << ' ';
        hex << std::setw(2) << static_cast<int>(data[i]);
    }
    return hex.str();
}

constexpr size_t kSearchPageCandidates = 32 * 1024;

struct SearchRegion {
    uint64_t start = 0;
    uint64_t end_inclusive = 0;  // inclusive candidate-start address
};

struct InitializedSpan {
    uint64_t start = 0;
    uint64_t end_inclusive = 0;
};

// Lazy bounded-page scanner. Each read owns at most 32 Ki candidate starts plus
// pattern_length-1 overlap bytes. SQL LIMIT therefore stops future reads, and a
// large mapped segment (or a wildcard-heavy pattern) never becomes one segment-
// sized allocation followed by an allocation for every match.
class SearchBytesScanGenerator : public xsql::Generator<SearchResult> {
    Ref<BinaryView> bv_;
    std::vector<PatternByte> pattern_;
    size_t max_results_ = 0;
    size_t emitted_ = 0;

    std::vector<SearchRegion> regions_;
    size_t region_index_ = 0;
    uint64_t cursor_ = 0;
    bool cursor_valid_ = false;

    std::vector<uint8_t> page_;
    uint64_t page_start_ = 0;
    size_t page_candidate_index_ = 0;
    size_t page_candidate_count_ = 0;
    SearchResult current_;

    void advance_candidates(size_t count) {
        const auto& region = regions_[region_index_];
        const uint64_t distance = region.end_inclusive - cursor_;
        if (count == 0 || static_cast<uint64_t>(count - 1) >= distance) {
            ++region_index_;
            cursor_valid_ = false;
        } else {
            cursor_ += static_cast<uint64_t>(count);
        }
    }

    bool load_next_page() {
        page_.clear();
        page_candidate_index_ = 0;
        page_candidate_count_ = 0;

        while (region_index_ < regions_.size()) {
            const auto& region = regions_[region_index_];
            if (!cursor_valid_) {
                cursor_ = region.start;
                cursor_valid_ = true;
            }

            const uint64_t distance = region.end_inclusive - cursor_;
            const size_t requested_candidates =
                distance >= static_cast<uint64_t>(kSearchPageCandidates - 1)
                    ? kSearchPageCandidates
                    : static_cast<size_t>(distance + 1);
            const size_t requested_bytes =
                requested_candidates + pattern_.size() - 1;
            page_start_ = cursor_;

            DataBuffer buf = bv_->ReadBuffer(page_start_, requested_bytes);
            const auto* data = static_cast<const uint8_t*>(buf.GetData());
            const size_t length = buf.GetLength();
            if (!data || length != requested_bytes) {
                std::ostringstream error;
                error << "byte_search: short read at 0x" << std::hex
                      << page_start_ << " (requested " << std::dec
                      << requested_bytes << " bytes, got " << length << ")";
                xsql::set_vtab_error(error.str());
                regions_.clear();
                return false;
            }

            page_.assign(data, data + length);
            page_candidate_count_ = requested_candidates;
            advance_candidates(requested_candidates);
            return true;
        }
        return false;
    }

public:
    // `windows` are inclusive ranges of candidate START addresses, searched in
    // the order given (the caller passes them in SQL order). A match must fit
    // inside one initialized span; it may run past its window's upper end.
    SearchBytesScanGenerator(Ref<BinaryView> bv, std::vector<PatternByte> pattern,
                             const std::vector<xsql::U64Span>& windows,
                             size_t max_results = 0)
        : bv_(std::move(bv)),
          pattern_(std::move(pattern)),
          max_results_(max_results) {
        if (!bv_ || pattern_.empty() || windows.empty()) return;
        const uint64_t plen = static_cast<uint64_t>(pattern_.size());

        auto segments = bv_->GetSegments();
        std::sort(segments.begin(), segments.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return lhs->GetStart() < rhs->GetStart();
                  });
        std::vector<InitializedSpan> spans;
        spans.reserve(segments.size());
        for (auto& seg : segments) {
            const uint64_t segment_start = seg->GetStart();
            // Only initialized bytes are searched: file data and data memory
            // regions (whose segment reports data length 0), not a BSS tail
            // or an unbacked segment (core::segment_initialized_length).
            const uint64_t initialized = core::segment_initialized_length(bv_, seg);
            if (initialized == 0) continue;
            if (initialized - 1 >
                std::numeric_limits<uint64_t>::max() - segment_start) {
                xsql::set_vtab_error("byte_search: segment address range overflows uint64");
                regions_.clear();
                return;
            }
            const InitializedSpan span{
                segment_start, segment_start + initialized - 1};
            if (spans.empty() ||
                (spans.back().end_inclusive !=
                     std::numeric_limits<uint64_t>::max() &&
                 span.start > spans.back().end_inclusive + 1)) {
                spans.push_back(span);
            } else if (span.end_inclusive > spans.back().end_inclusive) {
                spans.back().end_inclusive = span.end_inclusive;
            }
        }

        // Search the union of initialized virtual addresses. Adjacent segments
        // are one readable span, so a pattern starting at the end of one segment
        // may legitimately finish in the next -- including across 2^63, which is
        // no boundary to Binary Ninja. A match belongs to the window its START
        // falls in, so the last candidate of a region is min(window end, span
        // end - (pattern length - 1)): widening by the pattern length never
        // steps past the span, and so never past the top of the space.
        const uint64_t pattern_tail = plen - 1;
        for (const xsql::U64Span& window : windows) {
            for (const auto& span : spans) {
                if (span.end_inclusive - span.start < pattern_tail) continue;
                const uint64_t region_start = std::max(span.start, window.lo);
                const uint64_t region_end = std::min(
                    span.end_inclusive - pattern_tail, window.hi);
                if (region_end < region_start) continue;
                regions_.push_back({region_start, region_end});
            }
        }
    }

    bool next() override {
        if (max_results_ != 0 && emitted_ >= max_results_) return false;

        for (;;) {
            while (page_candidate_index_ < page_candidate_count_) {
                const size_t i = page_candidate_index_++;
                bool matched = true;
                for (size_t j = 0; j < pattern_.size(); ++j) {
                    if (static_cast<uint8_t>(page_[i + j] & pattern_[j].mask) !=
                        static_cast<uint8_t>(pattern_[j].value & pattern_[j].mask)) {
                        matched = false;
                        break;
                    }
                }
                if (!matched) continue;

                current_.address = page_start_ + static_cast<uint64_t>(i);
                current_.matched_bytes.assign(
                    page_.begin() + static_cast<std::ptrdiff_t>(i),
                    page_.begin() + static_cast<std::ptrdiff_t>(
                        i + pattern_.size()));
                current_.matched_hex = bytes_to_hex(
                    current_.matched_bytes.data(), current_.matched_bytes.size());
                ++emitted_;
                return true;
            }
            if (!load_next_page()) return false;
        }
    }
    const SearchResult& current() const override { return current_; }
    int64_t rowid() const override {
        return static_cast<int64_t>(current_.address);
    }
};

// Column indices for the byte_search table; keep in sync with
// define_byte_search_table(). Visible columns first (canonical idasql order), then
// hidden inputs.
enum SearchColumn {
    kAddr = 0,
    kMatchedHex = 1,
    kMatchedBytes = 2,
    kSize = 3,
    kPattern = 4,      // hidden: the FlexHex pattern (first positional TVF arg)
    kStartAddr = 5,    // hidden: optional range start
    kEndAddr = 6,      // hidden: optional range end
    kMaxResults = 7,   // hidden: optional result cap
};

inline std::unique_ptr<xsql::Generator<SearchResult>>
make_search_generator(const std::vector<xsql::GeneratorConstraintArg>& args) {
    // Every constraint is omit=1. The hidden inputs take a value only when a
    // native column of their type would equal it (pattern = NULL, start_addr =
    // 4096.5 and max_results = 1.5 request nothing), and the addr bounds are
    // compared the way SQLite compares the INTEGER addr column.
    //
    // start_addr / end_addr are unsigned scan bounds (a match starts at or
    // after start_addr and before end_addr), bit-cast from SQL like every
    // address. The addr window is walked as its unsigned spans in SQL order
    // (xsql::Int64KeyRange::unsigned_spans): an address >= 2^63 is a negative
    // INTEGER, so the part of the window at or above 2^63 is searched first
    // and the plan's ORDER BY addr claim holds.
    std::string pattern;
    uint64_t scan_lo = 0;
    uint64_t scan_hi = std::numeric_limits<uint64_t>::max();  // inclusive
    bool scan_empty = false;
    size_t max_results = 0;
    xsql::Int64KeyRange addr_range;
    for (const auto& arg : args) {
        if (arg.column_index == kAddr) {
            if (arg.op == xsql::ConstraintOp::Like) continue;
            addr_range.constrain(arg.op, arg.value);
            continue;
        }
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        if (arg.column_index == kPattern) {
            std::optional<std::string> text = xsql::exact_text(arg.value);
            if (!text) return nullptr;
            pattern = std::move(*text);
            continue;
        }
        if (arg.column_index != kStartAddr && arg.column_index != kEndAddr &&
            arg.column_index != kMaxResults) {
            continue;
        }
        const std::optional<int64_t> value = xsql::exact_int64(arg.value);
        if (!value) return nullptr;
        if (arg.column_index == kStartAddr) {
            scan_lo = std::max(scan_lo, static_cast<uint64_t>(*value));
        } else if (arg.column_index == kEndAddr) {
            const uint64_t end = static_cast<uint64_t>(*value);  // exclusive
            if (end == 0) scan_empty = true;
            else scan_hi = std::min(scan_hi, end - 1);
        } else if (*value > 0) {
            max_results = static_cast<size_t>(*value);
        }
    }

    std::vector<xsql::U64Span> windows;
    if (!scan_empty && scan_lo <= scan_hi) {
        for (const xsql::U64Span& span : addr_range.unsigned_spans()) {
            const uint64_t lo = std::max(span.lo, scan_lo);
            const uint64_t hi = std::min(span.hi, scan_hi);
            if (lo <= hi) windows.push_back({lo, hi});
        }
    }

    std::vector<PatternByte> parsed;
    if (!parse_pattern(pattern, parsed)) {
        xsql::set_vtab_error("byte_search: invalid byte pattern");
        parsed.clear();
    } else if (parsed.size() >
        std::numeric_limits<size_t>::max() - kSearchPageCandidates + 1) {
        xsql::set_vtab_error("byte_search: pattern is too large");
        parsed.clear();
    }
    return std::make_unique<SearchBytesScanGenerator>(
        core::get_bv(), std::move(parsed), windows, max_results);
}

} // namespace detail

// ============================================================================
// Table definition
// ============================================================================

xsql::GeneratorTableDef<SearchResult> define_byte_search_table() {
    using namespace detail;
    return xsql::generator_table<SearchResult>("byte_search")
        .estimate_rows([]() -> size_t { return 64; })
        // Canonical visible order: addr, matched_hex, matched_bytes, size.
        .column_int64("addr", [](const SearchResult& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text("matched_hex", [](const SearchResult& r) -> std::string {
            return r.matched_hex;
        })
        .column_blob("matched_bytes", [](const SearchResult& r) -> std::vector<uint8_t> {
            return r.matched_bytes;
        })
        .column_int("size", [](const SearchResult& r) -> int {
            return static_cast<int>(r.matched_bytes.size());
        })
        // Hidden inputs bound by positional TVF args or WHERE predicates:
        // byte_search(pattern[, start_addr, end_addr, max_results]).
        .hidden_column_text("pattern")
        .hidden_column_int64("start_addr")
        .hidden_column_int64("end_addr")
        .hidden_column_int("max_results")
        .full_scan_error(
            "byte_search requires WHERE pattern = '<FlexHex byte pattern>'; "
            "matched_hex is an output column, not the search input")
        .constraint_filter(
            {xsql::required_eq("pattern",
                 "byte_search requires WHERE pattern = '<FlexHex byte pattern>'"),
             xsql::optional_eq("start_addr"),
             xsql::optional_eq("end_addr"),
             xsql::optional_eq("max_results"),
             xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            make_search_generator, 1.0, 64.0)
        .order_by_consumed("addr")
        .build();
}

// ============================================================================
// search_first(pattern) scalar
// ============================================================================

static void sql_search_first_1(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) { ctx.result_error("search_first requires pattern argument"); return; }
    const char* pattern = argv[0].as_c_str();
    if (!pattern) { ctx.result_error("Invalid pattern"); return; }

    auto bv = core::get_bv();
    if (!bv) { ctx.result_error("No BinaryView context"); return; }

    std::vector<detail::PatternByte> parsed;
    if (!detail::parse_pattern(pattern, parsed)) { ctx.result_error("Invalid byte pattern"); return; }

    // The lowest match in unsigned address order: one window over the whole
    // space (SQL order does not apply to a scalar).
    detail::SearchBytesScanGenerator gen(
        bv, std::move(parsed),
        {xsql::U64Span{0, std::numeric_limits<uint64_t>::max()}}, 1);
    if (gen.next()) ctx.result_int64(static_cast<int64_t>(gen.current().address));
    else ctx.result_null();
}

// ============================================================================
// Registration
// ============================================================================

bool register_search_bytes(xsql::Database& db) {
    // The def outlives the DB (SQLite holds a pointer); a function-local static is
    // process-lifetime and thread-safe to initialize, so the table needs no
    // CoreRegistry member.
    static xsql::GeneratorTableDef<SearchResult> def = define_byte_search_table();
    db.register_generator_table("byte_search", &def);
    db.create_table("byte_search", "byte_search");
    db.register_function("search_first", 1, xsql::ScalarFn(sql_search_first_1));
    return true;
}

} // namespace search
} // namespace bnsql
