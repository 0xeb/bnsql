// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

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

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <sys/stat.h>
#include <algorithm>
#include <cctype>

#include "binaryninjaapi.h"
#include <bnsql/entities.hpp>
#include <bnsql/functions.hpp>

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
 *   auto result = qe.query("SELECT name, address FROM funcs LIMIT 10");
 *   for (const auto& row : result) {
 *       LogInfo("%s: %s", row[0].c_str(), row[1].c_str());
 *   }
 */
class QueryEngine {
public:
    explicit QueryEngine(Ref<BinaryView> bv) : bv_(bv) {
        init();
    }

    ~QueryEngine() {
        // Restore previous context if we changed it
        if (context_ && entities::g_context == context_.get()) {
            entities::set_context(nullptr);
        }
    }

    // Moveable but not copyable
    QueryEngine(QueryEngine&&) noexcept = default;
    QueryEngine& operator=(QueryEngine&&) noexcept = default;
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

        // Set context for this query
        entities::set_context(context_.get());

        struct QueryData {
            QueryResult* result;
            bool first_row;
        } qd = { &result, true };

        auto callback = [](void* data, int argc, char** argv, char** cols) -> int {
            auto* qd = static_cast<QueryData*>(data);

            if (qd->first_row) {
                for (int i = 0; i < argc; i++) {
                    qd->result->columns.push_back(cols[i] ? cols[i] : "");
                }
                qd->first_row = false;
            }

            Row row;
            row.values.reserve(argc);
            for (int i = 0; i < argc; i++) {
                row.values.push_back(argv[i] ? argv[i] : "NULL");
            }
            qd->result->rows.push_back(std::move(row));

            return 0;
        };

        int rc = exec(sql, callback, &qd);
        result.success = (rc == SQLITE_OK);
        if (!result.success && result.error.empty()) {
            result.error = sqlite3_errmsg(db_.handle());
        }

        return result;
    }

    /**
     * Execute SQL with callback
     */
    int exec(const char* sql, sqlite3_callback callback, void* data) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            return SQLITE_ERROR;
        }

        // Set context
        entities::set_context(context_.get());

        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_.handle(), sql, callback, data, &err_msg);
        if (err_msg) {
            error_ = err_msg;
            sqlite3_free(err_msg);
        }
        return rc;
    }

    /**
     * Execute SQL, ignore results
     */
    bool execute(const char* sql) {
        return exec(sql, nullptr, nullptr) == SQLITE_OK;
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
    sqlite3* handle() { return db_.handle(); }
    Ref<BinaryView> binaryView() { return bv_; }

private:
    Ref<BinaryView> bv_;
    xsql::Database db_;
    std::string error_;

    std::unique_ptr<entities::BNContext> context_;
    std::unique_ptr<entities::TableRegistry> entities_;

    void init() {
        // Create context for this BinaryView
        context_ = std::make_unique<entities::BNContext>(bv_);
        entities::set_context(context_.get());

        // Register all virtual tables
        entities_ = std::make_unique<entities::TableRegistry>();
        entities_->register_all(db_);

        // Register SQL functions
        functions::register_sql_functions(db_);
    }
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
