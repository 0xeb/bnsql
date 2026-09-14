// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * database.hpp - BNSQL API
 *
 * Main API for using bnsql. Similar to idasql's database.hpp for compatibility.
 *
 * Usage patterns:
 *
 * 1. QueryEngine (for plugins with existing BinaryView):
 *    bnsql::QueryEngine qe(bv);
 *    auto result = qe.query("SELECT name FROM funcs LIMIT 10");
 *
 * 2. Free functions (quick one-liners with context already set):
 *    bnsql::query("SELECT * FROM segments");
 *
 * 3. Loading binaries with auto-save:
 *    auto bv = bnsql::load_binary("program.exe");  // Creates program.bndb
 */

#pragma once

#include <xsql/database.hpp>
#include <xsql/runtime_settings.hpp>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <sys/stat.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>

#include "binaryninjaapi.h"
#include <bnsql/fwd.hpp>
#include <bnsql/runtime_settings.hpp>

namespace bnsql {

using namespace BinaryNinja;

// ============================================================================
// Result Types (compatible with idasql)
// ============================================================================

/**
 * Single row from a query result
 */
struct Row {
    std::vector<std::string> values;

    const std::string& operator[](size_t i) const { return values[i]; }
    size_t size() const { return values.size(); }
};

/**
 * Query result set
 */
struct QueryResult {
    std::vector<std::string> columns;
    std::vector<Row> rows;
    std::string error;
    bool success = false;
    bool timed_out = false;
    double elapsed_ms = 0.0;
    std::vector<std::string> warnings;

    size_t row_count() const { return rows.size(); }
    size_t column_count() const { return columns.size(); }
    bool empty() const { return rows.empty(); }

    std::string scalar() const {
        return (!empty() && rows[0].size() > 0) ? rows[0][0] : "";
    }

    auto begin() { return rows.begin(); }
    auto end() { return rows.end(); }
    auto begin() const { return rows.begin(); }
    auto end() const { return rows.end(); }

    std::string to_string() const {
        if (!success) return error;
        if (empty()) return "(0 rows)";

        std::string result;
        // Header
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += " | ";
            result += columns[i];
        }
        result += "\n";
        // Separator
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += "-+-";
            result += std::string(columns[i].size(), '-');
        }
        result += "\n";
        // Rows
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0) result += " | ";
                result += row[i];
            }
            result += "\n";
        }
        result += "(" + std::to_string(row_count()) + " rows)";
        return result;
    }
};

// ============================================================================
// QueryEngine - SQL interface to a BinaryView
// ============================================================================

/**
 * QueryEngine provides SQL access to a Binary Ninja BinaryView.
 *
 * Example:
 *   Ref<BinaryView> bv = ...;
 *   bnsql::QueryEngine qe(bv);
 *   auto result = qe.query("SELECT name, addr FROM funcs LIMIT 10");
 *   for (const auto& row : result) {
 *       LogInfo("%s: %s", row[0].c_str(), row[1].c_str());
 *   }
 */
class QueryEngine {
public:
    explicit QueryEngine(Ref<BinaryView> bv);

    // Out-of-line: the registry members are unique_ptr to types that are only
    // complete inside database.cpp (where the per-table/registry headers live).
    ~QueryEngine();

    // Moveable but not copyable (defaulted out-of-line for the same reason).
    QueryEngine(QueryEngine&&) noexcept;
    QueryEngine& operator=(QueryEngine&&) noexcept;
    QueryEngine(const QueryEngine&) = delete;
    QueryEngine& operator=(const QueryEngine&) = delete;

    /**
     * Execute SQL and return results
     */
    QueryResult query(const std::string& sql) {
        return query(sql.c_str());
    }

    QueryResult query(const char* sql) {
        QueryResult result;

        if (!db_.is_open()) {
            result.error = "QueryEngine not initialized";
            return result;
        }

        // Intercept PRAGMA bnsql.* statements
        if (handle_runtime_pragma(sql, result)) {
            return result;
        }

        // Set context for this query
        core::set_context(context_.get());

        // Configure timeout via libxsql's QueryOptions (libxsql installs a
        // progress handler internally and surfaces timed_out in the Result).
        xsql::QueryOptions options;
        options.timeout_ms = runtime_settings().query_timeout_ms();

        xsql::Result raw = db_.query(sql, options);

        // Translate xsql::Result -> bnsql::QueryResult. xsql::Row already
        // holds std::vector<std::string> values, same shape as bnsql::Row.
        // `raw` is dead after this block, so move instead of copying cells.
        result.columns = std::move(raw.columns);
        result.rows.reserve(raw.rows.size());
        for (auto& xr : raw.rows) {
            Row row;
            row.values = std::move(xr.values);
            result.rows.push_back(std::move(row));
        }
        result.elapsed_ms = static_cast<double>(raw.elapsed_ms);
        result.timed_out = raw.timed_out;
        result.success = raw.error.empty();
        if (!result.success) {
            if (result.timed_out) {
                result.error = "Query timed out after " +
                    std::to_string(options.timeout_ms) + " ms";
            } else {
                result.error = raw.error;
            }
        }

        // Append query hints (decompiler table warnings, etc.)
        append_query_hints(sql, result);

        return result;
    }

    /**
     * Execute SQL, ignore results
     */
    bool execute(const char* sql) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            return false;
        }
        core::set_context(context_.get());
        xsql::Status rc = db_.exec(sql);
        if (rc != xsql::Status::ok) {
            error_ = db_.last_error();
            return false;
        }
        return true;
    }

    /**
     * Get single value
     */
    std::string scalar(const std::string& sql) {
        return scalar(sql.c_str());
    }

    std::string scalar(const char* sql) {
        auto result = query(sql);
        if (result.success && !result.empty()) {
            return result.rows[0].values[0];
        }
        return "";
    }

    const std::string& error() const { return error_; }
    bool is_valid() const { return db_.is_open(); }
    Ref<BinaryView> binaryView() { return bv_; }

private:
    Ref<BinaryView> bv_;
    xsql::Database db_;
    std::string error_;

    std::unique_ptr<core::BNContext> context_;
    std::unique_ptr<core::CoreRegistry> core_;
    std::unique_ptr<decompiler::DecompilerTableRegistry> decompiler_;
    std::unique_ptr<types::TypesRegistry> types_;


    static inline QueryResult make_pragma_result(const std::string& name, const std::string& value) {
        QueryResult result;
        result.success = true;
        result.columns = {"name", "value"};
        Row row;
        row.values = {name, value};
        result.rows.push_back(std::move(row));
        return result;
    }

    static inline QueryResult make_pragma_error(const std::string& error) {
        QueryResult result;
        result.success = false;
        result.error = error;
        return result;
    }

    bool handle_runtime_pragma(const char* sql, QueryResult& out) {
        const auto request = xsql::runtime::parse_runtime_pragma(sql, "bnsql");
        if (!request.matched) return false;

        // Clean break: only the two imperative timeout verbs remain PRAGMAs. Value
        // settings (the common keys + enable_python / python_output_max) are read
        // via SELECT and changed via UPDATE runtime_settings.
        if (request.key == "timeout_push" || request.key == "timeout_pop") {
            auto& settings = runtime_settings();
            const auto common = xsql::runtime::handle_common_runtime_pragma(
                request, "bnsql", settings.common_settings());
            out = common.success
                ? make_pragma_result(common.name, common.value)
                : make_pragma_error(common.error);
            return true;
        }

        out = make_pragma_error(xsql::runtime::unknown_runtime_pragma_error("bnsql"));
        return true;
    }

    // True when the active view is backed by an on-disk .bndb, so user mutations
    // survive a save(). A raw-binary view is not database-backed; see issue #4.
    bool view_is_database_backed() const {
        if (!bv_) return false;
        auto file = bv_->GetFile();
        return file && file->IsBackedByDatabase();
    }

    void append_query_hints(const char* sql, QueryResult& result) const {
        if (!runtime_settings().hints_enabled()) return;
        if (!sql) return;

        const std::string lower = xsql::runtime::to_lower_copy(sql);

        // bnsql issue #4: mutations on a raw-binary-backed view succeed in-memory
        // but do not persist (and some BN write APIs apply lossily) — unlike a
        // .bndb-backed view which round-trips. When a write ran successfully on a
        // view with no on-disk database backing, warn and steer the caller to a
        // .bndb / explicit save() so a "success" is never mistaken for durable.
        const bool is_mutation =
            lower.find("update ") != std::string::npos ||
            lower.find("insert ") != std::string::npos ||
            lower.find("delete ") != std::string::npos;
        if (is_mutation && result.success && !view_is_database_backed()) {
            const std::string warning =
                "This session is backed by a raw binary, not a .bndb: mutations "
                "may not persist (and some writes apply lossily). Open/save a "
                ".bndb (SELECT save();) for durable, lossless edits.";
            bool exists = false;
            for (const auto& w : result.warnings) {
                if (w == warning) { exists = true; break; }
            }
            if (!exists) result.warnings.push_back(warning);
        }

        const bool touches_decompiler_table =
            lower.find("pseudocode") != std::string::npos ||
            lower.find("hlil_vars") != std::string::npos ||
            lower.find("hlil_calls") != std::string::npos ||
            lower.find("_hlil_ast") != std::string::npos;
        const bool has_func_filter = lower.find("func_addr") != std::string::npos;

        auto add_warning_once = [&result](const std::string& warning) {
            for (const auto& existing : result.warnings) {
                if (existing == warning) return;
            }
            result.warnings.push_back(warning);
        };

        if (touches_decompiler_table && !has_func_filter) {
            add_warning_once(
                "Decompiler tables are expensive without func_addr filtering; "
                "add WHERE func_addr = <addr> and LIMIT.");
        }
        if (result.timed_out && touches_decompiler_table) {
            add_warning_once(
                "Decompiler query timed out; resolve candidate functions first, "
                "then query per function.");
        }
    }

    // Defined out-of-line in database.cpp (constructs + registers every
    // registry; needs the complete per-table/registry definitions).
    void init();
};

// ============================================================================
// Convenience wrappers
// ============================================================================

/**
 * Create a QueryEngine for a BinaryView
 */
inline std::unique_ptr<QueryEngine> create_engine(Ref<BinaryView> bv) {
    return std::make_unique<QueryEngine>(bv);
}

// ============================================================================
// Binary Loader Utilities
// ============================================================================

namespace loader {

/**
 * Check if file exists
 */
inline bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

/**
 * Case-insensitive suffix check
 */
inline bool ends_with_icase(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
}

/**
 * Replace file extension
 */
inline std::string replace_extension(const std::string& path, const std::string& new_ext) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return path + new_ext;
    return path.substr(0, dot) + new_ext;
}

/**
 * Check if path is a Binary Ninja database
 */
inline bool is_bndb(const std::string& path) {
    return ends_with_icase(path, ".bndb");
}

/**
 * Get the .bndb path for any input file
 */
inline std::string get_bndb_path(const std::string& path) {
    return is_bndb(path) ? path : replace_extension(path, ".bndb");
}

/**
 * Result of load_binary operation
 */
struct LoadResult {
    Ref<BinaryView> bv;          // The loaded BinaryView
    std::string loaded_path;     // Path that was actually loaded
    std::string bndb_path;       // Path to .bndb (may differ from loaded_path)
    bool created_bndb = false;   // True if we created a new .bndb
    bool save_needed = false;    // True if save is pending
    std::string error;           // Error message if bv is null

    explicit operator bool() const { return bv != nullptr; }
};

/**
 * Options for load_binary
 */
struct LoadOptions {
    bool auto_save = true;       // Save .bndb after analyzing executable
    bool wait_for_analysis = true;
    std::function<void(const std::string&)> log;  // Optional logging callback
};

/**
 * Load a binary or database with smart .bndb handling
 *
 * Behavior:
 * - If path is .bndb: loads it directly
 * - If path is executable and sibling .bndb exists: loads the .bndb
 * - If path is executable and no .bndb: analyzes, optionally saves .bndb
 *
 * Example:
 *   auto result = bnsql::loader::load_binary("program.exe");
 *   if (result) {
 *       bnsql::QueryEngine qe(result.bv);
 *       // Use qe...
 *   }
 */
inline LoadResult load_binary(const std::string& path, const LoadOptions& opts = {}) {
    LoadResult result;
    result.bndb_path = get_bndb_path(path);

    bool input_is_bndb = is_bndb(path);

    // Determine what to load
    if (input_is_bndb) {
        // Direct .bndb load
        result.loaded_path = path;
        if (opts.log) opts.log("Loading: " + path);
    } else if (file_exists(result.bndb_path)) {
        // Sibling .bndb exists - use it
        result.loaded_path = result.bndb_path;
        if (opts.log) opts.log("Found existing database: " + result.bndb_path);
    } else {
        // Need to analyze from scratch
        result.loaded_path = path;
        result.save_needed = opts.auto_save;
        if (opts.log) {
            opts.log("Analyzing: " + path);
            if (opts.auto_save) opts.log("Will save to: " + result.bndb_path);
        }
    }

    // Load
    result.bv = Load(result.loaded_path);
    if (!result.bv) {
        result.error = "Failed to load " + result.loaded_path;
        return result;
    }

    // Wait for analysis if needed
    if (opts.wait_for_analysis) {
        auto progress = result.bv->GetAnalysisProgress();
        if (progress.state != IdleState) {
            if (opts.log) opts.log("Waiting for analysis...");
            result.bv->UpdateAnalysisAndWait();
        }
    }

    // Save if we analyzed from scratch
    if (result.save_needed) {
        if (opts.log) opts.log("Saving database...");
        if (result.bv->CreateDatabase(result.bndb_path)) {
            result.created_bndb = true;
        } else if (opts.log) {
            opts.log("Warning: Failed to save " + result.bndb_path);
        }
        result.save_needed = false;
    }

    return result;
}

} // namespace loader

} // namespace bnsql
