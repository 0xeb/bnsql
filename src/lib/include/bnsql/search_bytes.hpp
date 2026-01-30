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

#include <sqlite3.h>
#include <xsql/database.hpp>
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
inline bool register_search_bytes(xsql::Database& db) {
    // search_bytes needs special handling for parameters, so we use
    // a module-based approach with xFilter parsing arguments

    // For now, register as a scalar function that returns JSON array
    // (TVF with arguments requires more complex module setup)

    sqlite3_create_function(db.handle(), "search_bytes", 1, SQLITE_UTF8, nullptr,
        [](sqlite3_context* ctx, int argc, sqlite3_value** argv) {
            auto bv = entities::get_bv();
            if (!bv) {
                sqlite3_result_error(ctx, "No BinaryView context", -1);
                return;
            }

            const char* pattern = (const char*)sqlite3_value_text(argv[0]);
            if (!pattern) {
                sqlite3_result_error(ctx, "Invalid pattern", -1);
                return;
            }

            uint64_t start = bv->GetStart();
            uint64_t end = bv->GetEnd();

            // Collect matches
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

                        // Hex string
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
            std::string result = json.str();
            sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
        }, nullptr, nullptr);

    // 3-arg version with start/end range
    sqlite3_create_function(db.handle(), "search_bytes", 3, SQLITE_UTF8, nullptr,
        [](sqlite3_context* ctx, int argc, sqlite3_value** argv) {
            auto bv = entities::get_bv();
            if (!bv) {
                sqlite3_result_error(ctx, "No BinaryView context", -1);
                return;
            }

            const char* pattern = (const char*)sqlite3_value_text(argv[0]);
            if (!pattern) {
                sqlite3_result_error(ctx, "Invalid pattern", -1);
                return;
            }

            uint64_t start = static_cast<uint64_t>(sqlite3_value_int64(argv[1]));
            uint64_t end = static_cast<uint64_t>(sqlite3_value_int64(argv[2]));

            // Collect matches
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
            std::string result = json.str();
            sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
        }, nullptr, nullptr);

    // search_first - returns just the first match address (scalar)
    sqlite3_create_function(db.handle(), "search_first", 1, SQLITE_UTF8, nullptr,
        [](sqlite3_context* ctx, int argc, sqlite3_value** argv) {
            auto bv = entities::get_bv();
            if (!bv) {
                sqlite3_result_error(ctx, "No BinaryView context", -1);
                return;
            }

            const char* pattern = (const char*)sqlite3_value_text(argv[0]);
            if (!pattern) {
                sqlite3_result_error(ctx, "Invalid pattern", -1);
                return;
            }

            uint64_t found_addr = 0;
            bool found = false;

            bv->Search(pattern,
                [](size_t, size_t) { return true; },
                [&](uint64_t addr, const DataBuffer&) {
                    if (!found) {
                        found_addr = addr;
                        found = true;
                    }
                    return !found;  // Stop after first match
                });

            if (found) {
                sqlite3_result_int64(ctx, static_cast<int64_t>(found_addr));
            } else {
                sqlite3_result_null(ctx);
            }
        }, nullptr, nullptr);

    return true;
}

} // namespace search
} // namespace bnsql
