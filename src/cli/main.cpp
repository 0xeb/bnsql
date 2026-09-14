// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * main.cpp - BNSQL command-line SQL interface to Binary Ninja databases
 *
 * Usage:
 *   bnsql database.bndb -c "SELECT * FROM funcs"          # Local query
 *   bnsql database.bndb -i                                # Local interactive
 *   bnsql database.bndb --http [port]                     # HTTP server
 *   bnsql database.bndb --mcp [port]                      # MCP server
 */
 
// Windows compatibility
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

#include <bnsql/bnsql.hpp>
#include <bnsql/config.hpp>
#include "binaryninjaapi.h"

#include "bnsql_version.hpp"
#include "bnsql_commands.hpp"

#ifdef BNSQL_HAS_MCP
#include "mcp_server.hpp"
#endif

#ifdef BNSQL_HAS_HTTP
#include <xsql/thinclient/http_query_server.hpp>
#include "bnsql_http_routes.hpp"
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <csignal>
#include <thread>
#include <filesystem>
#include <cstdlib>

using namespace BinaryNinja;
namespace fs = std::filesystem;

static const char* g_version = BNSQL_VERSION_STRING;
static const char* g_copyright = BNSQL_COPYRIGHT_STRING;

// ============================================================================
// Utilities
// ============================================================================

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Cannot open file: " + path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// ============================================================================
// Table Printer
// ============================================================================

class TablePrinter {
    std::vector<std::string> columns_;
    std::vector<std::vector<std::string>> rows_;
    std::vector<size_t> widths_;

public:
    void set_columns(const std::vector<std::string>& cols) {
        columns_ = cols;
        widths_.assign(cols.size(), 0);
        for (size_t i = 0; i < cols.size(); i++) {
            widths_[i] = cols[i].length();
        }
    }

    void add_row(const std::vector<std::string>& row) {
        for (size_t i = 0; i < row.size() && i < widths_.size(); i++) {
            widths_[i] = std::max(widths_[i], row[i].length());
        }
        rows_.push_back(row);
    }

    void print() const {
        if (columns_.empty()) return;

        // Build separator
        std::string sep = "+";
        for (size_t w : widths_) sep += std::string(w + 2, '-') + "+";

        // Header
        std::cout << sep << "\n| ";
        for (size_t i = 0; i < columns_.size(); i++) {
            std::cout << std::left << std::setw(widths_[i]) << columns_[i] << " | ";
        }
        std::cout << "\n" << sep << "\n";

        // Rows
        for (const auto& row : rows_) {
            std::cout << "| ";
            for (size_t i = 0; i < row.size(); i++) {
                std::cout << std::left << std::setw(widths_[i]) << row[i] << " | ";
            }
            std::cout << "\n";
        }
        std::cout << sep << "\n";
        std::cout << rows_.size() << " row(s)\n";
    }

    size_t row_count() const { return rows_.size(); }
};

// Global quit flag for signal-driven shutdown (MCP standalone, HTTP REPL, etc.)
static std::atomic<bool> g_quit_requested{false};

static void quit_signal_handler(int) {
    g_quit_requested.store(true);
}

// ============================================================================
// HTTP Server Mode (REST API)
// ============================================================================

#ifdef BNSQL_HAS_HTTP
static xsql::thinclient::http_query_server* g_http_server = nullptr;
static std::unique_ptr<xsql::thinclient::http_query_server> g_repl_http_server;

// Set by the SIGINT/SIGBREAK handler. The handler must do nothing but set this
// flag: calling http_query_server::stop() from signal context can self-deadlock
// (stop() -> drain_pending_commands() locks queue_mutex_, which the interrupted
// main thread may already hold in process_one_command_internal), and locking a
// std::mutex in a signal handler is not async-signal-safe. run_until_stopped()
// polls this via set_interrupt_check() and stops from the main thread instead.
static volatile std::sig_atomic_t g_http_interrupt = 0;

static void http_signal_handler(int) {
    g_http_interrupt = 1;
}

// Build the single-statement executor that fills a ScriptStatementResult from
// the BN QueryEngine. Shared by the CLI --http server, the REPL `.http` server,
// and the plugin server so the three cannot drift.
static xsql::thinclient::http_query_server_config::statement_executor_t
make_statement_executor(bnsql::QueryEngine& qe) {
    return [&qe](const std::string& stmt, xsql::ScriptStatementResult& out) {
        auto r = qe.query(stmt);
        out.columns = std::move(r.columns);
        out.rows.reserve(r.rows.size());
        for (auto& row : r.rows) out.rows.push_back(std::move(row.values));
        out.elapsed_ms = r.elapsed_ms;
        out.success = r.success;
        out.error = std::move(r.error);
    };
}

// Build the /status extra-fields callback: tool name, cached function count, and
// the full runtime settings snapshot. The function count is queried once now (on
// the calling thread, before the server serves) and cached, because status_fn
// runs on a worker thread where touching the non-concurrency-safe engine would
// race /query. Shared by all three servers so /status is uniform everywhere.
static xsql::thinclient::http_query_server_config::status_fn_t
make_status_fn(bnsql::QueryEngine& qe) {
    std::string func_count;
    {
        auto r = qe.query("SELECT COUNT(*) FROM funcs");
        if (r.success && !r.empty()) func_count = r.rows[0][0];
    }
    return [func_count]() { return bnsql::status_extra_json(func_count); };
}

// Wire HTTP callbacks for .http REPL command
static void setup_http_callbacks(bnsql::CommandCallbacks& callbacks, bnsql::QueryEngine& qe) {
    callbacks.http_start = [&qe]() -> std::string {
        if (g_repl_http_server && g_repl_http_server->is_running()) {
            return "HTTP server already running on port " + std::to_string(g_repl_http_server->port());
        }

        xsql::thinclient::http_query_server_config cfg;
        cfg.tool_name = "bnsql";
        cfg.help_text = bnsql::http_help_text();
        cfg.port = 0;  // Random port
        cfg.bind_address = "127.0.0.1";
        // Background server (no main-thread queue), so serialize requests:
        // BN's QueryEngine is not concurrency-safe. The serialize path now honors
        // the same admission limits as the queue path (503/408), so wire the
        // runtime-settings callbacks just like run_http_mode.
        cfg.use_queue = false;
        cfg.serialize_requests = true;
        cfg.queue_admission_timeout_ms_fn = []() {
            return bnsql::runtime_settings().queue_admission_timeout_ms();
        };
        cfg.max_queue_fn = []() { return bnsql::runtime_settings().max_queue(); };
        cfg.statement_executor = make_statement_executor(qe);
        cfg.status_fn = make_status_fn(qe);
        cfg.status_requires_auth = true;
        cfg.extra_routes = [](httplib::Server& svr) {
            svr.Get("/settings", [](const httplib::Request&, httplib::Response& res) {
                res.set_content(bnsql::settings_to_json(bnsql::runtime_settings().snapshot()),
                                "application/json");
            });
        };

        g_repl_http_server = std::make_unique<xsql::thinclient::http_query_server>(cfg);
        int port = g_repl_http_server->start();
        if (port < 0) {
            g_repl_http_server.reset();
            return "Failed to start HTTP server";
        }
        return "HTTP server started on port " + std::to_string(port) + "\n"
               "  curl http://127.0.0.1:" + std::to_string(port) + "/help\n"
               "  curl -X POST http://127.0.0.1:" + std::to_string(port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"";
    };

    callbacks.http_stop = []() -> std::string {
        if (!g_repl_http_server || !g_repl_http_server->is_running()) {
            return "HTTP server is not running";
        }
        int port = g_repl_http_server->port();
        g_repl_http_server->stop();
        g_repl_http_server.reset();
        return "HTTP server stopped (was on port " + std::to_string(port) + ")";
    };

    callbacks.http_status = [&callbacks]() -> std::string {
        if (g_repl_http_server && g_repl_http_server->is_running()) {
            int port = g_repl_http_server->port();
            return "HTTP server is RUNNING on port " + std::to_string(port) + "\n"
                   "  curl http://127.0.0.1:" + std::to_string(port) + "/help";
        }
        // Auto-start if not running
        if (callbacks.http_start) {
            return callbacks.http_start();
        }
        return "HTTP server is STOPPED";
    };
}

static int run_http_mode(bnsql::QueryEngine& qe, int port, const std::string& bind_addr, const std::string& auth_token) {
    // Always announce a non-loopback bind; only the no-auth exposure warning is
    // gated on the token being absent. (Previously the whole notice was gated on
    // auth_token.empty(), so a non-loopback bind WITH a token printed nothing.)
    const bool non_loopback = !bind_addr.empty() && bind_addr != "127.0.0.1"
                           && bind_addr != "localhost";
    if (non_loopback) {
        std::cerr << "NOTICE: Binding to non-loopback address " << bind_addr << "\n";
        if (auth_token.empty()) {
            std::cerr << "WARNING: No authentication token set. Server is accessible without authentication.\n";
            std::cerr << "         Consider using --token <secret> for remote access.\n";
        }
    }

    xsql::thinclient::http_query_server_config cfg;
    cfg.tool_name = "bnsql";
    cfg.help_text = bnsql::http_help_text();
    cfg.port = port;
    cfg.bind_address = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    if (!auth_token.empty()) cfg.auth_token = auth_token;
    // BN's QueryEngine is not concurrency-safe; serialize on the main thread
    // via the thinclient queue (also provides admission timeout + max_queue).
    cfg.use_queue = true;
    cfg.queue_admission_timeout_ms_fn = []() {
        return bnsql::runtime_settings().queue_admission_timeout_ms();
    };
    cfg.max_queue_fn = []() { return bnsql::runtime_settings().max_queue(); };
    cfg.statement_executor = make_statement_executor(qe);
    cfg.status_fn = make_status_fn(qe);
    cfg.status_requires_auth = true;
    // Preserve bnsql's auth-gated GET /settings (thinclient extra routes are raw).
    cfg.extra_routes = [auth_token](httplib::Server& svr) {
        svr.Get("/settings", [auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string tok;
                if (req.has_header("X-XSQL-Token")) tok = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto a = req.get_header_value("Authorization");
                    if (a.rfind("Bearer ", 0) == 0) tok = a.substr(7);
                }
                if (tok != auth_token) {
                    res.status = 401;
                    res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
                    return;
                }
            }
            res.set_content(bnsql::settings_to_json(bnsql::runtime_settings().snapshot()),
                            "application/json");
        });
    };

    auto server = std::make_unique<xsql::thinclient::http_query_server>(cfg);
    g_http_server = server.get();

    // Signal-safe shutdown: the handler only sets g_http_interrupt; the main
    // thread's run_until_stopped() loop polls it and calls stop() itself.
    g_http_interrupt = 0;
    server->set_interrupt_check([]() { return g_http_interrupt != 0; });

    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    auto old_break_handler = std::signal(SIGBREAK, http_signal_handler);
#endif

    int actual_port = server->start();
    if (actual_port < 0) {
        std::cerr << "Error: Failed to start HTTP server\n";
        g_http_server = nullptr;
        return 1;
    }

    std::cout << "HTTP server listening on http://" << cfg.bind_address << ":" << actual_port << "\n";
    std::cout << "Endpoints: /help /query /status /settings /shutdown\n";
    std::cout << "  curl -X POST http://localhost:" << actual_port << "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
    std::cout << "\nPress Ctrl+C to stop.\n\n";
    std::cout.flush();

    // Process the query queue on this (main) thread until stopped.
    server->run_until_stopped();
    server->stop();

    std::signal(SIGINT, old_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, old_break_handler);
#endif
    g_http_server = nullptr;
    std::cout << "\nHTTP server stopped.\n";
    return 0;
}
#endif // BNSQL_HAS_HTTP

// ============================================================================
// Query Execution Helper
// ============================================================================

static void execute_and_print(bnsql::QueryEngine& qe, const std::string& sql, bool timing = true) {
    auto start = std::chrono::high_resolution_clock::now();
    auto result = qe.query(sql);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start);

    if (!result.success) {
        std::cerr << "Error: " << result.error << "\n";
        return;
    }

    if (result.empty()) {
        if (timing) std::cout << "OK (" << elapsed.count() << " ms)\n";
        return;
    }

    TablePrinter tp;
    tp.set_columns(result.columns);
    for (const auto& row : result) {
        tp.add_row(row.values);
    }
    tp.print();
    if (timing) std::cout << "(" << elapsed.count() << " ms)\n";
}

// ============================================================================
// REPL Commands
// ============================================================================

static void print_repl_help() {
    std::cout << R"(
Commands:
  .help              Show this help
  .tables            List available tables
  .schema TABLE      Show table schema
  .quit              Exit

Tables: binary, capabilities, runtime_settings, funcs, segments, blocks, cfg_edges,
        switch_tables, function_frames, data_items, dominators, post_dominators,
        loops, instructions, instruction_operands, bytes, byte_search, entries,
        imports, names, comments, bookmarks, xrefs, strings, patches, pseudocode,
        hlil_vars, hlil_calls, mlil, mlil_operands, _hlil_ast, types, type_members,
        type_enum_values, func_signatures

IR Views: ir_ops, ir_operands, ir_maturities, ir_v_calls, ir_v_mem_reads,
          ir_v_mem_writes, ir_v_branches, ir_v_arith

SQL Functions: disasm(addr), name_at(addr), func_at(addr), hex(val), xrefs_to(addr),
               decompile(addr), search_first(pattern), save()
Bounded bytes: SELECT addr,value FROM bytes WHERE start_addr=<addr> AND n=<count>;

Writable Tables (SELECT save() to persist analysis edits):
  funcs (create/delete; name/prototype/comment), segments, names, comments,
  bookmarks, patches, pseudocode.comment, hlil_vars (name/type/comment/delete-clear),
  types, type_members, type_enum_values; runtime_settings.value is session-only

Examples:
  SELECT COUNT(*) FROM funcs;
  SELECT hex(addr), name, size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT content FROM strings WHERE content LIKE '%error%';
  SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC;
  UPDATE pseudocode SET comment='check bounds' WHERE func_addr=0x401000 AND line_num=12;
)";
}

static std::string resolve_bn_bundled_plugin_dir() {
    // Prefer explicit BN install root in env for out-of-tree builds.
    if (const char* bn_install_dir = std::getenv("BN_INSTALL_DIR")) {
        fs::path install_path = bn_install_dir;
        fs::path plugins_path = install_path / "plugins";
        std::error_code ec;
        if (fs::exists(plugins_path, ec) && !ec) {
            return plugins_path.string();
        }
    }
    return GetBundledPluginDirectory();
}

// Pin the INSTALL-dir binaryninjacore.dll before the first Binary Ninja call.
//
// bnsql.exe delay-loads the core, so the instance is chosen at the first BN API
// call by the default search order -- application directory first. If a copied
// core sits beside the executable, the exe binds that copy while Binary Ninja's
// Python side (_binaryninjacore.py) always binds the install-dir core by
// absolute ctypes path: TWO same-basename modules from different paths load as
// two instances (the Windows loader does not dedupe this), each with its own
// provider registry -- and the Python scripting provider registers into the one
// this process never reads, making headless bnsql_python() silently
// unavailable. Loading the install-dir core by full path first means every
// later by-name resolution (delay-load included) binds this same instance, so
// the process holds exactly one core in ANY layout.
static void pin_install_core() {
#ifdef _WIN32
    if (const char* bn_install_dir = std::getenv("BN_INSTALL_DIR")) {
        fs::path core_path = fs::path(bn_install_dir) / "binaryninjacore.dll";
        std::error_code ec;
        if (fs::exists(core_path, ec) && !ec)
            LoadLibraryW(core_path.wstring().c_str());
    }
#endif
}

static void show_tables(bnsql::QueryEngine& qe) {
    auto result = qe.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    if (result.success) {
        std::cout << "Tables:\n";
        for (const auto& row : result) std::cout << "  " << row[0] << "\n";
    }
}

static void show_schema(bnsql::QueryEngine& qe, const std::string& table) {
    auto result = qe.query("PRAGMA table_info(" + table + ")");
    if (result.success && !result.empty()) {
        TablePrinter tp;
        tp.set_columns({"cid", "name", "type", "notnull", "dflt", "pk"});
        for (const auto& row : result) tp.add_row(row.values);
        tp.print();
    } else {
        std::cout << "Unknown table: " << table << "\n";
    }
}

// ============================================================================
// Interactive Mode
// ============================================================================

static void run_interactive(bnsql::QueryEngine& qe) {
    std::string line, query;

    // Set up command callbacks for interactive mode
    bnsql::CommandCallbacks callbacks;
    callbacks.get_tables = [&qe]() -> std::string {
        auto result = qe.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
        std::stringstream ss;
        ss << "Tables:\n";
        for (const auto& row : result) {
            if (row.size() > 0) ss << "  " << row[0] << "\n";
        }
        return ss.str();
    };
    callbacks.get_schema = [&qe](const std::string& table) -> std::string {
        auto result = qe.query("PRAGMA table_info(" + table + ")");
        if (!result.success || result.empty()) {
            return "Unknown table: " + table;
        }
        std::stringstream ss;
        for (const auto& row : result) {
            if (row.size() >= 3) ss << "  " << row.values[1] << " " << row.values[2] << "\n";
        }
        return ss.str();
    };

#ifdef BNSQL_HAS_HTTP
    setup_http_callbacks(callbacks, qe);
#endif

    std::cout << "bnsql interactive mode. Type .help for help, .quit to exit.\n\n";

    while (true) {
        std::cout << (query.empty() ? "bnsql> " : "   ...> ") << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::string trimmed = trim(line);
        if (trimmed.empty()) continue;

        // Dot commands (only when not accumulating)
        if (query.empty() && trimmed[0] == '.') {
            std::string output;
            auto result = bnsql::handle_command(trimmed, callbacks, output);

            switch (result) {
                case bnsql::CommandResult::QUIT:
                    goto exit_interactive;
                case bnsql::CommandResult::HANDLED:
                    if (!output.empty()) {
                        std::cout << output;
                        if (output.back() != '\n') std::cout << "\n";
                    }
                    continue;
                case bnsql::CommandResult::NOT_HANDLED:
                    break;
            }
            continue;
        }

        // Accumulate SQL until ;
        query += (query.empty() ? "" : "\n") + line;

        if (trimmed.back() == ';') {
            execute_and_print(qe, query);
            query.clear();
            std::cout << "\n";
        }
    }
    exit_interactive:;

#ifdef BNSQL_HAS_HTTP
    // Stop HTTP server if it was started during this session
    if (g_repl_http_server) {
        g_repl_http_server->stop();
        g_repl_http_server.reset();
    }
#endif
}

// ============================================================================
// Usage
// ============================================================================

static void print_usage(const char* prog) {
    std::cout << "bnsql v" << g_version << " - SQL interface for Binary Ninja" << std::endl;
    std::cout << g_copyright << std::endl << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << prog << " <file>                                 Interactive mode" << std::endl;
    std::cout << "  " << prog << " <file> -c <query>                      Execute query and exit" << std::endl;
    std::cout << "  " << prog << " <file> -f <file.sql>                   Execute SQL file" << std::endl;
    std::cout << "  " << prog << " <file> --http [port]                   Start HTTP REST server (default: 8080)" << std::endl;
    std::cout << "  " << prog << " <file> --mcp [port]                    Start MCP server (default: 9998)" << std::endl;
    std::cout << std::endl;
    std::cout << "  <file> is a Binary Ninja database (.bndb) OR a raw binary" << std::endl;
    std::cout << "  (.exe/.dll/firmware/etc.). Raw binaries trigger fresh BN analysis;" << std::endl;
    std::cout << "  the resulting .bndb is auto-saved next to the source on clean exit." << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --source <path>    Binary Ninja database (.bndb) OR raw binary" << std::endl;
    std::cout << "                         (.exe/.dll/firmware/etc.) — raw binaries trigger" << std::endl;
    std::cout << "                         fresh BN analysis (auto-saved next to source)" << std::endl;
    std::cout << "  -c, --command <sql>    SQL query to execute" << std::endl;
    std::cout << "  -f, --file <path>      SQL file to execute" << std::endl;
    std::cout << "  -i, --interactive      Interactive SQL mode (default)" << std::endl;
    std::cout << "  --http [port]          Start HTTP REST server (default: 8080)" << std::endl;
    std::cout << "  --mcp [port]           Start MCP server for Claude Desktop, etc. (default: 9998)" << std::endl;
    std::cout << "  --bind <addr>          Bind address for server (default: 127.0.0.1)" << std::endl;
    std::cout << "  --token <token>        Auth token for HTTP/MCP mode" << std::endl;
    std::cout << "  -q, --quiet            Suppress banner" << std::endl;
    std::cout << "  --log-file <path>      Write Binary Ninja log output (Info+) to a file" << std::endl;
    std::cout << "  -V, --verbose          Raise log level to Debug and echo to stdout" << std::endl;
    std::cout << "  -h, --help             Show this help" << std::endl;
    std::cout << "  -v, --version          Show version" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << prog << " sample.bndb -c \"SELECT name, size FROM funcs LIMIT 10\"" << std::endl;
    std::cout << "  " << prog << " sample.bndb --http 8080" << std::endl;
    std::cout << "  " << prog << " sample.exe --http 8080       # raw PE: BN auto-analyzes, then serves SQL" << std::endl;
    std::cout << "  " << prog << " firmware.bin -c \"SELECT COUNT(*) FROM funcs\"" << std::endl;
}

#ifdef _WIN32
// Return true when the Binary Ninja core DLL is discoverable before the
// delay-loaded imports are triggered. It resolves if it sits in BN_INSTALL_DIR,
// next to bnsql.exe (the documented "install next to Binary Ninja" layout), or
// anywhere on the standard search path (PATH). This is the actual precondition
// for loading — the old check required BN_INSTALL_DIR even when the DLL was
// already reachable next to the executable or on PATH.
static bool bn_core_dll_discoverable() {
    constexpr const char* kCoreDll = "binaryninjacore.dll";
    std::error_code ec;

    if (const char* dir = std::getenv(bnsql::ENV_BN_INSTALL_DIR)) {
        if (fs::exists(fs::path(dir) / kCoreDll, ec)) {
            return true;
        }
    }

    wchar_t exe_buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe_buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        if (fs::exists(fs::path(exe_buf).parent_path() / kCoreDll, ec)) {
            return true;
        }
    }

    char found[MAX_PATH];
    if (SearchPathA(nullptr, kCoreDll, nullptr, MAX_PATH, found, nullptr) > 0) {
        return true;
    }
    return false;
}
#endif

// ============================================================================
// Main
// ============================================================================

static int run_cli(int argc, char* argv[]) {
#ifdef _WIN32
    // The BN core DLL must be discoverable before delay-loaded imports fire.
    if (!bn_core_dll_discoverable()) {
        std::cerr << "Error: Binary Ninja core library (binaryninjacore.dll) was not found.\n\n"
                  << "Make it discoverable in any one of these ways:\n"
                  << "  - install bnsql next to Binary Ninja (bnsql.exe beside binaryninjacore.dll)\n"
                  << "  - add the Binary Ninja directory to PATH\n"
                  << "  - set " << bnsql::ENV_BN_INSTALL_DIR << "=C:\\Program Files\\Binary Ninja\n";
        return 1;
    }

    // Enable UTF-8 console output on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Enable virtual terminal processing for ANSI escape sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif

    std::string database, query, query_file, auth_token, bind_addr, log_file_path;
    int http_port = 8080, mcp_port = 9998;
    bool interactive = false, quiet = false, http_mode = false, mcp_mode = false, verbose = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        if (arg == "-v" || arg == "--version") { std::cout << "bnsql v" << g_version << std::endl << g_copyright << std::endl; return 0; }
        if (arg == "-q" || arg == "--quiet") { quiet = true; continue; }
        if (arg == "-i" || arg == "--interactive") { interactive = true; continue; }
        if ((arg == "-s" || arg == "--source") && i + 1 < argc) { database = argv[++i]; continue; }
        if ((arg == "-c" || arg == "--command") && i + 1 < argc) { query = argv[++i]; continue; }
        if ((arg == "-f" || arg == "--file") && i + 1 < argc) { query_file = argv[++i]; continue; }
        if (arg == "--http") {
            http_mode = true;
            // Optional port argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                try {
                    http_port = std::stoi(argv[++i]);
                    if (http_port < 0 || http_port > 65535) throw std::runtime_error("invalid");
                } catch (...) {
                    std::cerr << "Error: Invalid HTTP port" << std::endl;
                    return 1;
                }
            }
            continue;
        }
        if (arg == "--mcp") {
            mcp_mode = true;
            // Optional port argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                try {
                    mcp_port = std::stoi(argv[++i]);
                    if (mcp_port < 0 || mcp_port > 65535) throw std::runtime_error("invalid");
                } catch (...) {
                    std::cerr << "Error: Invalid MCP port" << std::endl;
                    return 1;
                }
            }
            continue;
        }
        if (arg == "--bind" && i + 1 < argc) { bind_addr = argv[++i]; continue; }
        if (arg == "--token" && i + 1 < argc) { auth_token = argv[++i]; continue; }
        if (arg == "--log-file" && i + 1 < argc) { log_file_path = argv[++i]; continue; }
        if (arg == "-V" || arg == "--verbose") { verbose = true; continue; }

        // Positional argument = database
        if (arg[0] != '-' && database.empty()) { database = arg; continue; }

        std::cerr << "Unknown option: " << arg << std::endl;
        return 1;
    }

    // Validate mutual exclusivity
    int mode_count = (http_mode ? 1 : 0) + (mcp_mode ? 1 : 0);
    if (mode_count > 1) {
        std::cerr << "Error: Cannot use multiple modes (--http, --mcp)\n";
        return 1;
    }

    // Require database
    if (database.empty()) {
        std::cerr << "Error: No database specified. Use -s <database.bndb>\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Must precede every BN API call (LogToFile below is the first): the core
    // instance is fixed at the first delay-load resolution.
    pin_install_core();

    // Route Binary Ninja log output. Wired BEFORE InitPlugins() so plugin-load
    // messages (e.g. the headless "plugin skipped" line) are captured. --verbose
    // raises the level to Debug and echoes to stdout; --log-file writes Info+ (Debug
    // with --verbose) to a file. Nothing is routed when neither flag is given.
    BNLogLevel log_level = verbose ? DebugLog : InfoLog;
    bool log_file_opened = false;
    if (!log_file_path.empty()) {
        log_file_opened = LogToFile(log_level, log_file_path, /*append=*/false);
        if (!log_file_opened)
            std::cerr << "warning: could not open log file: " << log_file_path << "\n";
    }
    if (verbose)
        LogToStdout(log_level);
    // Flush/close BN log files on every exit path (normal, error, /shutdown, Ctrl+C,
    // exception) via a main-scope RAII guard.
    struct LogGuard { bool active; ~LogGuard() { if (active) CloseLogs(); } } log_guard{ log_file_opened };

    // Initialize Binary Ninja
    SetBundledPluginDirectory(resolve_bn_bundled_plugin_dir());
    InitPlugins();

    // Load binary with auto-save support
    if (!quiet) std::cout << "bnsql v" << g_version << "\n" << g_copyright << "\n";

    bnsql::loader::LoadOptions load_opts;
    load_opts.auto_save = true;
    load_opts.wait_for_analysis = true;
    if (!quiet) {
        load_opts.log = [](const std::string& msg) { std::cout << msg << "\n"; };
    }

    auto load_result = bnsql::loader::load_binary(database, load_opts);
    if (!load_result) {
        std::cerr << "Error: " << load_result.error << "\n";
        return 1;
    }

    Ref<BinaryView> bv = load_result.bv;

    if (!quiet) {
        std::cout << "Ready. " << bv->GetAnalysisFunctionList().size() << " functions.\n\n";
    }

    // Create query engine
    bnsql::QueryEngine qe(bv);

    // Load SQL from file if specified
    if (!query_file.empty()) {
        try {
            query = read_file(query_file);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
    }

    // Execute based on mode
#ifdef BNSQL_HAS_HTTP
    if (http_mode) {
        return run_http_mode(qe, http_port, bind_addr, auth_token);
    }
#else
    if (http_mode) {
        std::cerr << "Error: HTTP mode not available. Rebuild with -DBNSQL_WITH_HTTP=ON\n";
        return 1;
    }
#endif

#ifdef BNSQL_HAS_MCP
    if (mcp_mode) {
        if (bind_addr.empty()) bind_addr = "127.0.0.1";
        std::string url = "http://" + bind_addr + ":" + std::to_string(mcp_port);

        if (!quiet) {
            std::cout << "Starting MCP server on " << url << "..." << std::endl;
        }

        bnsql::MCPServer mcp_server;

        bnsql::QueryCallback query_cb = [&qe](const std::string& sql) -> bnsql::MCPQueryOutcome {
            auto result = qe.query(sql);
            if (!result.success) {
                return {"Error: " + result.error, false};
            }
            return {result.to_string(), true};
        };

        int actual_port = mcp_server.start(mcp_port, query_cb, bind_addr);
        if (actual_port <= 0) {
            std::cerr << "Error: Failed to start MCP server on port " << mcp_port << std::endl;
            return 1;
        }
        url = "http://" + bind_addr + ":" + std::to_string(actual_port);

        size_t func_count = 0;
        auto count_result = qe.query("SELECT COUNT(*) FROM funcs");
        if (count_result.success && !count_result.rows.empty()) {
            try { func_count = std::stoul(count_result.rows[0][0]); } catch (...) {}
        }

        std::cout << bnsql::format_mcp_info(database, func_count, url) << std::endl;
        std::cout << "Press Ctrl+C to stop MCP server." << std::endl;

        g_quit_requested.store(false);
        auto old_handler = std::signal(SIGINT, quit_signal_handler);
#ifdef _WIN32
        auto old_break_handler = std::signal(SIGBREAK, quit_signal_handler);
#endif
        mcp_server.set_interrupt_check([]() {
            return g_quit_requested.load();
        });

        mcp_server.wait();

        std::signal(SIGINT, old_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, old_break_handler);
#endif

        std::cout << "MCP server stopped." << std::endl;
        return 0;
    }
#else
    if (mcp_mode) {
        std::cerr << "Error: MCP mode not available. Rebuild with -DBNSQL_WITH_MCP=ON\n";
        return 1;
    }
#endif

    if (!query.empty()) {
        auto result = qe.query(query);
        if (!result.success) {
            std::cerr << "Error: " << result.error << "\n";
            return 1;
        }
        std::cout << result.to_string() << "\n";
        return 0;
    }

    run_interactive(qe);

    return 0;
}

int main(int argc, char* argv[]) {
    int rc = run_cli(argc, argv);
    // On x86_64 Linux, Binary Ninja's core hangs (deadlocks in a static
    // destructor tearing down its Rust runtime) when the process exits normally.
    // All CLI work — including any --write save — has completed by here, so exit
    // immediately with the real status instead of hanging on teardown.
    std::fflush(nullptr);
    std::_Exit(rc);
}
