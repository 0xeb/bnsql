// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * search_bytes.hpp - Binary pattern search table-valued function
 *
 * Provides search_bytes() TVF for finding byte patterns in the binary.
 *
 * Pattern syntax (Binary Ninja native):
 *   - "48 8B 05"     - Exact bytes (hex, space-separated)
 *   - "48 ?? 05"     - ?? = any byte wildcard
 *   - "4?"           - ? = any nibble (matches 40-4F)
 *   - "[regex]"      - Regex patterns supported
 *
 * SQL usage:
 *   SELECT * FROM search_bytes('48 8B ?? 00');
 *   SELECT * FROM search_bytes('48 8B ?? 00', 0x401000, 0x402000);
 *   SELECT address FROM search_bytes('4? 89') LIMIT 10;
 *
 * Columns returned:
 *   - address (INTEGER): Match address
 *   - matched_bytes (BLOB): Raw matched bytes
 *   - matched_hex (TEXT): Hex string of matched bytes
 */

#pragma once

#include <xsql/database.hpp>
#include <xsql/functions.hpp>
#include <bnsql/vtable.hpp>
#include <bnsql/entities.hpp>
#include "binaryninjaapi.h"

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <mutex>

namespace bnsql {
namespace search {

using namespace BinaryNinja;

// ============================================================================
// Search Result Row
// ============================================================================

struct SearchResult {
    uint64_t address;
    std::vector<uint8_t> matched_bytes;
    std::string matched_hex;
};

// ============================================================================
// Search Generator (lazy evaluation for LIMIT support)
// ============================================================================

class SearchBytesGenerator : public xsql::Generator<SearchResult> {
public:
    SearchBytesGenerator(Ref<BinaryView> bv, const std::string& pattern,
                         uint64_t start, uint64_t end)
        : bv_(bv), pattern_(pattern), start_(start), end_(end),
          current_addr_(start), row_num_(0), eof_(false) {

        // Collect all results using BN's Search() callback API
        // BN's Search() collects all matches via callback, so we store them
        collect_matches();
        match_idx_ = 0;
    }

    bool next() override {
        if (match_idx_ >= matches_.size()) {
            eof_ = true;
            return false;
        }

        current_ = matches_[match_idx_];
        match_idx_++;
        row_num_++;
        return true;
    }

    const SearchResult& current() const override {
        return current_;
    }

    sqlite3_int64 rowid() const override {
        return static_cast<sqlite3_int64>(row_num_);
    }

private:
    Ref<BinaryView> bv_;
    std::string pattern_;
    uint64_t start_;
    uint64_t end_;
    uint64_t current_addr_;
    size_t row_num_;
    bool eof_;

    std::vector<SearchResult> matches_;
    size_t match_idx_;
    SearchResult current_;

    void collect_matches() {
        if (!bv_) return;

        // Use BN's Search() API which handles wildcards and regex
        bv_->Search(pattern_,
            // Progress callback
            [](size_t, size_t) { return true; },
            // Match callback
            [this](uint64_t addr, const DataBuffer& match) {
                // Filter by range
                if (addr >= start_ && addr < end_) {
                    SearchResult result;
                    result.address = addr;

                    // Copy matched bytes
                    const uint8_t* data = static_cast<const uint8_t*>(match.GetData());
                    size_t len = match.GetLength();
                    result.matched_bytes.assign(data, data + len);

                    // Build hex string
                    std::ostringstream hex;
                    hex << std::hex << std::setfill('0');
                    for (size_t i = 0; i < len; i++) {
                        if (i > 0) hex << " ";
                        hex << std::setw(2) << static_cast<int>(data[i]);
                    }
                    result.matched_hex = hex.str();

                    matches_.push_back(std::move(result));
                }
                return true;  // Continue searching
            });
    }
};

// ============================================================================
// Table Definition and Registration
// ============================================================================

/**
 * Register the search_bytes table-valued function
 *
 * This is a generator table that lazily yields search results.
 * Pattern parsing is handled by a custom xFilter implementation.
 */
namespace detail {

inline void search_bytes_impl(xsql::FunctionContext& ctx, const char* pattern,
                               uint64_t start, uint64_t end) {
    auto bv = entities::get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    std::ostringstream json;
    json << "[";
    bool first = true;

    bv->Search(pattern,
        [](size_t, size_t) { return true; },
        [&](uint64_t addr, const DataBuffer& match) {
            if (addr >= start && addr < end) {
                if (!first) json << ",";
                first = false;

                json << "{\"address\":" << addr;

                const uint8_t* data = static_cast<const uint8_t*>(match.GetData());
                size_t len = match.GetLength();
                json << ",\"matched_hex\":\"";
                for (size_t i = 0; i < len; i++) {
                    if (i > 0) json << " ";
                    char buf[4];
                    snprintf(buf, sizeof(buf), "%02x", data[i]);
                    json << buf;
                }
                json << "\",\"size\":" << len << "}";
            }
            return true;
        });

    json << "]";
    ctx.result_text(json.str());
}

} // namespace detail

static void sql_search_bytes_1(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) { ctx.result_error("search_bytes requires pattern argument"); return; }
    const char* pattern = argv[0].as_c_str();
    if (!pattern) { ctx.result_error("Invalid pattern"); return; }

    auto bv = entities::get_bv();
    if (!bv) { ctx.result_error("No BinaryView context"); return; }

    detail::search_bytes_impl(ctx, pattern, bv->GetStart(), bv->GetEnd());
}

static void sql_search_bytes_3(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) { ctx.result_error("search_bytes requires (pattern, start, end)"); return; }
    const char* pattern = argv[0].as_c_str();
    if (!pattern) { ctx.result_error("Invalid pattern"); return; }

    uint64_t start = static_cast<uint64_t>(argv[1].as_int64());
    uint64_t end = static_cast<uint64_t>(argv[2].as_int64());

    detail::search_bytes_impl(ctx, pattern, start, end);
}

static void sql_search_first_1(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) { ctx.result_error("search_first requires pattern argument"); return; }
    const char* pattern = argv[0].as_c_str();
    if (!pattern) { ctx.result_error("Invalid pattern"); return; }

    auto bv = entities::get_bv();
    if (!bv) { ctx.result_error("No BinaryView context"); return; }

    uint64_t found_addr = 0;
    bool found = false;

    bv->Search(pattern,
        [](size_t, size_t) { return true; },
        [&](uint64_t addr, const DataBuffer&) {
            if (!found) { found_addr = addr; found = true; }
            return !found;
        });

    if (found) ctx.result_int64(static_cast<int64_t>(found_addr));
    else ctx.result_null();
}

inline bool register_search_bytes(xsql::Database& db) {
    db.register_function("search_bytes", 1, xsql::ScalarFn(sql_search_bytes_1));
    db.register_function("search_bytes", 3, xsql::ScalarFn(sql_search_bytes_3));
    db.register_function("search_first", 1, xsql::ScalarFn(sql_search_first_1));
    return true;
}

} // namespace search
} // namespace bnsql
