// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

#include "bnsql_commands.hpp"

#ifdef BNSQL_HAS_MCP
#include "mcp_server.hpp"
#endif

#ifdef BNSQL_HAS_HTTP
#include <xsql/thinclient/server.hpp>
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

static const char* g_version = "0.0.10";

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
static xsql::thinclient::server* g_http_server = nullptr;
static std::unique_ptr<xsql::thinclient::server> g_repl_http_server;

static void http_signal_handler(int) {
    if (g_http_server) {
        g_http_server->stop();
    }
}

// Wire HTTP callbacks for .http REPL command
static void setup_http_callbacks(bnsql::CommandCallbacks& callbacks, bnsql::QueryEngine& qe) {
    callbacks.http_start = [&qe]() -> std::string {
        if (g_repl_http_server && g_repl_http_server->is_running()) {
            return "HTTP server already running on port " + std::to_string(g_repl_http_server->port());
        }

        xsql::thinclient::server_config cfg;
        cfg.port = 0;  // Random port
        cfg.bind_address = "127.0.0.1";
        cfg.setup_routes = [&qe](httplib::Server& svr) {
            bnsql::setup_http_routes(svr,
                [&qe](const std::string& sql) { return qe.query(sql); },
                "", 0);
        };

        g_repl_http_server = std::make_unique<xsql::thinclient::server>(cfg);
        g_repl_http_server->run_async();

        if (!g_repl_http_server->is_running()) {
            g_repl_http_server.reset();
            return "Failed to start HTTP server";
        }

        int port = g_repl_http_server->port();
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
    xsql::thinclient::server_config cfg;
    cfg.port = port;
    cfg.bind_address = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    if (!auth_token.empty()) {
        cfg.auth_token = auth_token;
    }
    if (!bind_addr.empty() && bind_addr != "127.0.0.1" && bind_addr != "localhost") {
        cfg.allow_insecure_no_auth = auth_token.empty();
        std::cerr << "WARNING: Binding to non-loopback address " << bind_addr << "\n";
        if (auth_token.empty()) {
            std::cerr << "WARNING: No authentication token set. Server is accessible without authentication.\n";
            std::cerr << "         Consider using --token <secret> for remote access.\n";
        }
    }

    cfg.setup_routes = [&qe, &auth_token, port](httplib::Server& svr) {
        bnsql::setup_http_routes(svr,
            [&qe](const std::string& sql) { return qe.query(sql); },
            auth_token, port);
    };

    xsql::thinclient::server http_server(cfg);
    g_http_server = &http_server;

    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, http_signal_handler);
#endif

    http_server.run_async();
    int actual_port = http_server.port();

    std::cout << "HTTP server listening on http://" << cfg.bind_address << ":" << actual_port << "\n";
    std::cout << "Endpoints:\n";
    std::cout << "  GET  /help     - API documentation\n";
    std::cout << "  POST /query    - Execute SQL (body = raw SQL)\n";
    std::cout << "  GET  /status   - Health check\n";
    std::cout << "  POST /shutdown - Stop server\n";
    std::cout << "\nExamples:\n";
    std::cout << "  curl http://localhost:" << actual_port << "/help\n";
    std::cout << "  curl -X POST http://localhost:" << actual_port << "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
    std::cout << "\nPress Ctrl+C to stop.\n\n";
    std::cout.flush();

    // Block until server stops (via signal or /shutdown)
    while (http_server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::signal(SIGINT, old_handler);
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

Tables: funcs, segments, names, entries, strings, xrefs, blocks, imports, instructions, comments, db_info, pseudocode, hlil_vars, hlil_calls

SQL Functions: disasm(addr), bytes(addr,n), name_at(addr), func_at(addr), hex(val), xrefs_to(addr), decompile(addr)

Writable Columns:
  funcs.name, funcs.prototype, names.name
  pseudocode.comment, pseudocode.comment_placement
  hlil_vars.name, hlil_vars.type

Examples:
  SELECT COUNT(*) FROM funcs;
  SELECT hex(address), name, size FROM funcs ORDER BY size DESC LIMIT 10;
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
    std::cout << "bnsql v" << g_version << " - SQL interface for Binary Ninja" << std::endl << std::endl;
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
    std::cout << "  -h, --help             Show this help" << std::endl;
    std::cout << "  -v, --version          Show version" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << prog << " sample.bndb -c \"SELECT name, size FROM funcs LIMIT 10\"" << std::endl;
    std::cout << "  " << prog << " sample.bndb --http 8080" << std::endl;
    std::cout << "  " << prog << " sample.exe --http 8080       # raw PE: BN auto-analyzes, then serves SQL" << std::endl;
    std::cout << "  " << prog << " firmware.bin -c \"SELECT COUNT(*) FROM funcs\"" << std::endl;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Check for BN_INSTALL_DIR before delay-loaded DLLs are triggered
    if (!std::getenv(bnsql::ENV_BN_INSTALL_DIR)) {
        std::cerr << "Error: " << bnsql::ENV_BN_INSTALL_DIR << " environment variable not set.\n\n"
                  << "Please set it to your Binary Ninja installation directory:\n"
                  << "  set " << bnsql::ENV_BN_INSTALL_DIR << "=C:\\Program Files\\Binary Ninja\n"
                  << "  set PATH=%" << bnsql::ENV_BN_INSTALL_DIR << "%;%PATH%\n";
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

    std::string database, query, query_file, auth_token, bind_addr;
    int http_port = 8080, mcp_port = 9998;
    bool interactive = false, quiet = false, http_mode = false, mcp_mode = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        if (arg == "-v" || arg == "--version") { std::cout << "bnsql v" << g_version << std::endl; return 0; }
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

    // Initialize Binary Ninja
    SetBundledPluginDirectory(resolve_bn_bundled_plugin_dir());
    InitPlugins();

    // Load binary with auto-save support
    if (!quiet) std::cout << "bnsql v" << g_version << "\n";

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

        bnsql::QueryCallback query_cb = [&qe](const std::string& sql) -> std::string {
            auto result = qe.query(sql);
            if (!result.success) {
                return "Error: " + result.error;
            }
            return result.to_string();
        };

        int actual_port = mcp_server.start(mcp_port, query_cb, bind_addr);
        if (actual_port <= 0) {
            std::cerr << "Error: Failed to start MCP server on port " << mcp_port << std::endl;
            return 1;
        }
        url = "http://" + bind_addr + ":" + std::to_string(actual_port);

        size_t func_count = 0;
        auto count_result = qe.query("SELECT COUNT(*) FROM functions");
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
