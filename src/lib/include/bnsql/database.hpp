// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <sys/stat.h>
#include <algorithm>
#include <cctype>
#include <chrono>

#include "binaryninjaapi.h"
#include <bnsql/entities.hpp>
#include <bnsql/functions.hpp>
#include <bnsql/decompiler.hpp>
#include <bnsql/types.hpp>
#include <bnsql/search_bytes.hpp>
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

        // Intercept PRAGMA bnsql.* statements
        if (handle_runtime_pragma(sql, result)) {
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

        auto t0 = std::chrono::steady_clock::now();
        int rc = exec(sql, callback, &qd);
        auto t1 = std::chrono::steady_clock::now();
        result.elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        if (rc == SQLITE_INTERRUPT) {
            result.success = false;
            result.timed_out = true;
            result.error = "Query timed out after " +
                std::to_string(runtime_settings().query_timeout_ms()) + " ms";
        } else {
            result.success = (rc == SQLITE_OK);
            if (!result.success && result.error.empty()) {
                result.error = sqlite3_errmsg(db_.handle());
            }
        }

        // Append query hints (decompiler table warnings, etc.)
        append_query_hints(sql, result);

        return result;
    }

    /**
     * Execute SQL with callback, enforcing query timeout via sqlite3_progress_handler.
     */
    int exec(const char* sql, sqlite3_callback callback, void* data) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            return SQLITE_ERROR;
        }

        // Set context
        entities::set_context(context_.get());

        // Install timeout progress handler
        struct TimeoutState {
            std::chrono::steady_clock::time_point deadline;
            bool timed_out = false;
        };

        int timeout_ms = runtime_settings().query_timeout_ms();
        TimeoutState timeout_state;
        if (timeout_ms > 0) {
            timeout_state.deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(timeout_ms);
            sqlite3_progress_handler(db_.handle(), 1000,
                [](void* ctx) -> int {
                    auto* state = static_cast<TimeoutState*>(ctx);
                    if (std::chrono::steady_clock::now() >= state->deadline) {
                        state->timed_out = true;
                        return 1;  // non-zero aborts
                    }
                    return 0;
                }, &timeout_state);
        }

        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_.handle(), sql, callback, data, &err_msg);

        // Clear progress handler
        if (timeout_ms > 0) {
            sqlite3_progress_handler(db_.handle(), 0, nullptr, nullptr);
        }

        if (err_msg) {
            error_ = err_msg;
            sqlite3_free(err_msg);
        }

        // Map interrupt caused by timeout to SQLITE_INTERRUPT
        if (timeout_state.timed_out && rc != SQLITE_OK) {
            return SQLITE_INTERRUPT;
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
    std::unique_ptr<decompiler::DecompilerTableRegistry> decompiler_;
    std::unique_ptr<types::TypesRegistry> types_;

    // ================================================================
    // PRAGMA helpers
    // ================================================================

    static inline std::string trim_copy(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    static inline std::string to_lower_copy(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    static inline std::string strip_optional_quotes(const std::string& s) {
        if (s.size() >= 2) {
            char first = s.front(), last = s.back();
            if ((first == '\'' && last == '\'') || (first == '"' && last == '"')) {
                return s.substr(1, s.size() - 2);
            }
        }
        return s;
    }

    static inline bool parse_int_value(const std::string& s, int& out) {
        try {
            size_t pos = 0;
            long val = std::stol(s, &pos);
            if (pos != s.size()) return false;
            out = static_cast<int>(val);
            return true;
        } catch (...) {
            return false;
        }
    }

    static inline bool parse_bool_value(const std::string& s, bool& out) {
        std::string lower = to_lower_copy(s);
        if (lower == "1" || lower == "true" || lower == "on" || lower == "yes") {
            out = true;
            return true;
        }
        if (lower == "0" || lower == "false" || lower == "off" || lower == "no") {
            out = false;
            return true;
        }
        return false;
    }

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
        if (sql == nullptr) return false;

        std::string text = trim_copy(sql);
        if (text.empty()) return false;
        if (text.back() == ';') {
            text.pop_back();
            text = trim_copy(text);
        }

        std::string lower = to_lower_copy(text);
        const std::string pragma_prefix = "pragma";
        if (lower.rfind(pragma_prefix, 0) != 0) return false;

        std::string body = trim_copy(text.substr(pragma_prefix.size()));
        std::string body_lower = to_lower_copy(body);
        const std::string bnsql_prefix = "bnsql.";
        if (body_lower.rfind(bnsql_prefix, 0) != 0) return false;

        std::string key_expr = trim_copy(body.substr(bnsql_prefix.size()));
        std::string value_expr;
        size_t eq_pos = key_expr.find('=');
        if (eq_pos != std::string::npos) {
            value_expr = trim_copy(key_expr.substr(eq_pos + 1));
            key_expr = trim_copy(key_expr.substr(0, eq_pos));
            value_expr = strip_optional_quotes(value_expr);
        }

        const std::string key = to_lower_copy(key_expr);
        auto& settings = runtime_settings();

        if (key == "query_timeout_ms") {
            if (value_expr.empty()) {
                out = make_pragma_result("query_timeout_ms",
                    std::to_string(settings.query_timeout_ms()));
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms) ||
                !settings.set_query_timeout_ms(timeout_ms)) {
                out = make_pragma_error("Invalid bnsql.query_timeout_ms value");
                return true;
            }
            out = make_pragma_result("query_timeout_ms",
                std::to_string(settings.query_timeout_ms()));
            return true;
        }

        if (key == "queue_admission_timeout_ms") {
            if (value_expr.empty()) {
                out = make_pragma_result("queue_admission_timeout_ms",
                    std::to_string(settings.queue_admission_timeout_ms()));
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms) ||
                !settings.set_queue_admission_timeout_ms(timeout_ms)) {
                out = make_pragma_error("Invalid bnsql.queue_admission_timeout_ms value");
                return true;
            }
            out = make_pragma_result("queue_admission_timeout_ms",
                std::to_string(settings.queue_admission_timeout_ms()));
            return true;
        }

        if (key == "max_queue") {
            if (value_expr.empty()) {
                out = make_pragma_result("max_queue",
                    std::to_string(settings.max_queue()));
                return true;
            }
            int queue_limit = 0;
            if (!parse_int_value(value_expr, queue_limit) || queue_limit < 0 ||
                !settings.set_max_queue(static_cast<size_t>(queue_limit))) {
                out = make_pragma_error("Invalid bnsql.max_queue value");
                return true;
            }
            out = make_pragma_result("max_queue",
                std::to_string(settings.max_queue()));
            return true;
        }

        if (key == "hints_enabled") {
            if (value_expr.empty()) {
                out = make_pragma_result("hints_enabled",
                    settings.hints_enabled() ? "1" : "0");
                return true;
            }
            bool enabled = false;
            if (!parse_bool_value(value_expr, enabled)) {
                out = make_pragma_error("Invalid bnsql.hints_enabled value");
                return true;
            }
            settings.set_hints_enabled(enabled);
            out = make_pragma_result("hints_enabled",
                settings.hints_enabled() ? "1" : "0");
            return true;
        }

        if (key == "timeout_push") {
            if (value_expr.empty()) {
                out = make_pragma_error("bnsql.timeout_push requires a timeout value");
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms)) {
                out = make_pragma_error("Invalid bnsql.timeout_push value");
                return true;
            }
            int effective_timeout = 0;
            if (!settings.timeout_push(timeout_ms, &effective_timeout)) {
                out = make_pragma_error("Invalid bnsql.timeout_push value");
                return true;
            }
            out = make_pragma_result("query_timeout_ms",
                std::to_string(effective_timeout));
            return true;
        }

        if (key == "timeout_pop") {
            int effective_timeout = 0;
            if (!settings.timeout_pop(&effective_timeout)) {
                out = make_pragma_error("bnsql.timeout_pop stack is empty");
                return true;
            }
            out = make_pragma_result("query_timeout_ms",
                std::to_string(effective_timeout));
            return true;
        }

        out = make_pragma_error("Unknown bnsql pragma key");
        return true;
    }

    void append_query_hints(const char* sql, QueryResult& result) const {
        if (!runtime_settings().hints_enabled()) return;
        if (!sql) return;

        const std::string lower = to_lower_copy(sql);
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

    void init() {
        // Create context for this BinaryView
        context_ = std::make_unique<entities::BNContext>(bv_);
        entities::set_context(context_.get());

        // Register all virtual tables
        entities_ = std::make_unique<entities::TableRegistry>();
        entities_->register_all(db_);

        // Register decompiler tables
        decompiler_ = std::make_unique<decompiler::DecompilerTableRegistry>();
        decompiler_->register_all(db_);

        // Register type intelligence tables
        types_ = std::make_unique<types::TypesRegistry>();
        types_->register_all(db_);

        // Register SQL functions
        functions::register_sql_functions(db_);

        // Register search functions
        search::register_search_bytes(db_);
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
