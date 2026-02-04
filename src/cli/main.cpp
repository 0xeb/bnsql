// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * main.cpp - BNSQL command-line SQL interface to Binary Ninja databases
 *
 * Usage:
 *   bnsql database.bndb -c "SELECT * FROM funcs"          # Local query
 *   bnsql database.bndb -i                                # Local interactive
 *   bnsql database.bndb --agent                           # Agent mode (AI)
 *   bnsql --remote localhost:13337 -c "SELECT * FROM funcs"  # Remote query
 *   bnsql --remote localhost:13337 -i                     # Remote interactive
 */

// Socket includes MUST come before Windows.h
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
#include <xsql/socket/client.hpp>
#include <xsql/socket/server.hpp>
#include "binaryninjaapi.h"

#include "bnsql_commands.hpp"

#ifdef BNSQL_HAS_AI_AGENT
#include "ai_agent.hpp"
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

using namespace BinaryNinja;

static const char* g_version = "1.0.0";
static const int DEFAULT_PORT = 13337;

// ============================================================================
// Utilities
// ============================================================================

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
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

// ============================================================================
// Remote Mode Helpers
// ============================================================================

static void print_remote_result(const xsql::socket::RemoteResult& qr) {
    if (qr.rows.empty() && qr.columns.empty()) {
        std::cout << "OK" << std::endl;
        return;
    }
    TablePrinter tp;
    tp.set_columns(qr.columns);
    for (const auto& row : qr.rows) {
        tp.add_row(row.values);
    }
    tp.print();
}

static void run_remote_interactive(xsql::socket::Client& client) {
    std::string line, stmt;
    std::cout << "bnsql remote mode. Type .help for help, .quit to exit." << std::endl << std::endl;

    while (true) {
        std::cout << (stmt.empty() ? "bnsql> " : "   ...> ") << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::string trimmed = line;
        while (!trimmed.empty() && (trimmed[0] == ' ' || trimmed[0] == '	'))
            trimmed = trimmed.substr(1);
        while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '	'))
            trimmed.pop_back();

        if (trimmed.empty()) continue;

        if (stmt.empty() && trimmed[0] == '.') {
            if (trimmed == ".quit" || trimmed == ".exit" || trimmed == ".q") break;
            if (trimmed == ".tables") {
                auto qr = client.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
                if (qr.success) {
                    std::cout << "Tables:" << std::endl;
                    for (const auto& r : qr.rows) std::cout << "  " << r[0] << std::endl;
                }
                continue;
            }
            if (trimmed == ".help") {
                std::cout << std::endl << "Commands: .tables, .quit, .help" << std::endl << std::endl;
                continue;
            }
            std::cout << "Unknown command" << std::endl;
            continue;
        }

        stmt += line + " ";
        if (trimmed.back() == ';') {
            auto qr = client.query(stmt);
            if (qr.success) print_remote_result(qr);
            else std::cerr << "Error: " << qr.error << std::endl;
            stmt.clear();
            std::cout << std::endl;
        }
    }
}

// Helper to convert RemoteResult to string for agent
static std::string remote_result_to_string(const xsql::socket::RemoteResult& qr) {
    if (!qr.success) {
        return "Error: " + qr.error;
    }
    if (qr.rows.empty() && qr.columns.empty()) {
        return "OK (no results)";
    }
    std::stringstream ss;
    // Header
    for (size_t i = 0; i < qr.columns.size(); ++i) {
        if (i > 0) ss << " | ";
        ss << qr.columns[i];
    }
    ss << "\n";
    // Separator
    for (size_t i = 0; i < qr.columns.size(); ++i) {
        if (i > 0) ss << "-+-";
        ss << std::string(qr.columns[i].size(), '-');
    }
    ss << "\n";
    // Rows
    for (const auto& row : qr.rows) {
        for (size_t i = 0; i < row.values.size(); ++i) {
            if (i > 0) ss << " | ";
            ss << row.values[i];
        }
        ss << "\n";
    }
    ss << "(" << qr.rows.size() << " row" << (qr.rows.size() != 1 ? "s" : "") << ")";
    return ss.str();
}

// Global quit flag for signal-driven shutdown (MCP standalone, HTTP REPL, etc.)
static std::atomic<bool> g_quit_requested{false};

static void quit_signal_handler(int) {
    g_quit_requested.store(true);
}

#ifdef BNSQL_HAS_AI_AGENT
// Forward declarations for signal handling - shared by run_remote_agent and run_agent
static bnsql::AIAgent* g_agent = nullptr;

static void signal_handler(int sig) {
    (void)sig;
    g_quit_requested.store(true);
    if (g_agent) {
        g_agent->request_quit();
    }
}

static void run_remote_agent(xsql::socket::Client& client, bool verbose = false,
                             const std::string& provider_override = "",
                             int timeout_override = 0) {
    // Create SQL executor that uses remote client
    auto executor = [&client](const std::string& sql) -> std::string {
        auto result = client.query(sql);
        return remote_result_to_string(result);
    };

    // Load settings and apply overrides
    bnsql::AgentSettings settings = bnsql::LoadAgentSettings();
    if (!provider_override.empty()) {
        try {
            settings.default_provider = bnsql::ParseProviderType(provider_override);
            if (verbose) {
                std::cerr << "[AGENT] Provider override: " << provider_override << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }
    }

    if (timeout_override > 0) {
        settings.response_timeout_ms = timeout_override;
        if (verbose) {
            std::cerr << "[AGENT] Timeout override: " << timeout_override << " ms" << std::endl;
        }
    }

    // Create and start agent with settings
    bnsql::AIAgent agent(executor, settings, verbose);
    g_agent = &agent;

    // Install signal handler for Ctrl-C
    auto old_handler = std::signal(SIGINT, signal_handler);

    agent.start();

    std::cout << "Remote Agent mode - Connected to server, AI runs locally." << std::endl;
    std::cout << "Type SQL directly, or ask questions in natural language." << std::endl;
    std::cout << "Commands: .help, .clear, .quit" << std::endl;
    std::cout << std::endl;

    // Set up command callbacks using remote client
    bnsql::CommandCallbacks callbacks;
    callbacks.get_tables = [&client]() -> std::string {
        auto result = client.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
        std::stringstream ss;
        for (const auto& row : result.rows) {
            if (!row.values.empty()) ss << row.values[0] << "\n";
        }
        return ss.str();
    };
    callbacks.get_schema = [&client](const std::string& table) -> std::string {
        auto result = client.query("SELECT sql FROM sqlite_master WHERE name='" + table + "'");
        if (!result.rows.empty() && !result.rows[0].values.empty()) {
            return result.rows[0].values[0];
        }
        return "Table not found: " + table;
    };
    callbacks.clear_session = [&agent]() -> std::string {
        agent.reset_session();
        return "Session cleared (conversation history reset)";
    };

    std::string line;
    while (!agent.quit_requested()) {
        std::cout << "bnsql> " << std::flush;
        if (!std::getline(std::cin, line)) break;

        line = trim(line);
        if (line.empty()) continue;

        // Handle .sql command specially (switches to SQL-only remote mode)
        if (to_lower(line) == ".sql") {
            std::cout << "Switching to SQL mode..." << std::endl << std::endl;
            agent.stop();
            g_agent = nullptr;
            std::signal(SIGINT, old_handler);
            run_remote_interactive(client);
            return;
        }

        // Use unified command handler
        if (!line.empty() && line[0] == '.') {
            std::string output;
            auto result = bnsql::handle_command(line, callbacks, output);

            switch (result) {
                case bnsql::CommandResult::QUIT:
                    goto exit_remote_agent;
                case bnsql::CommandResult::HANDLED:
                    if (!output.empty()) {
                        std::cout << output;
                        if (output.back() != '\n') std::cout << "\n";
                    }
                    continue;
                case bnsql::CommandResult::NOT_HANDLED:
                    break;
            }
        }

        // Process query through AI agent
        std::string response = agent.query(line);
        if (!response.empty()) {
            std::cout << response << std::endl;
        }
        std::cout << std::endl;
    }
    exit_remote_agent:;

    agent.stop();
    g_agent = nullptr;
    std::signal(SIGINT, old_handler);
}
#endif // BNSQL_HAS_AI_AGENT

// ============================================================================
// Server Mode
// ============================================================================

static xsql::socket::Server* g_server = nullptr;

static void server_signal_handler(int) {
    if (g_server) {
        g_server->stop();
    }
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

    std::cout << "HTTP server listening on http://" << cfg.bind_address << ":" << port << "\n";
    std::cout << "Endpoints:\n";
    std::cout << "  GET  /help     - API documentation\n";
    std::cout << "  POST /query    - Execute SQL (body = raw SQL)\n";
    std::cout << "  GET  /status   - Health check\n";
    std::cout << "  POST /shutdown - Stop server\n";
    std::cout << "\nExamples:\n";
    std::cout << "  curl http://localhost:" << port << "/help\n";
    std::cout << "  curl -X POST http://localhost:" << port << "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
    std::cout << "\nPress Ctrl+C to stop.\n\n";
    std::cout.flush();

    http_server.run();  // Blocking

    std::signal(SIGINT, old_handler);
    g_http_server = nullptr;
    std::cout << "\nHTTP server stopped.\n";
    return 0;
}
#endif // BNSQL_HAS_HTTP

// ============================================================================
// Raw TCP Server Mode
// ============================================================================

static int run_server_mode(bnsql::QueryEngine& qe, int port, const std::string& auth_token) {
    xsql::socket::Server server;
    g_server = &server;

    xsql::socket::ServerConfig cfg;
    cfg.port = port;
    cfg.verbose = false;  // We'll print our own messages
    if (!auth_token.empty()) {
        cfg.auth_token = auth_token;
    }
    server.set_config(cfg);

    server.set_query_handler([&qe](const std::string& sql) -> xsql::socket::QueryResult {
        auto result = qe.query(sql);

        xsql::socket::QueryResult qr;
        qr.success = result.success;
        qr.error = result.error;
        qr.columns = result.columns;
        for (const auto& row : result) {
            qr.rows.push_back(row.values);
        }
        return qr;
    });

    // Install signal handler for Ctrl+C
    auto old_handler = std::signal(SIGINT, server_signal_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, server_signal_handler);
#endif

    // Start server asynchronously to get actual port (useful when port=0)
    if (!server.run_async(port)) {
        std::cerr << "Failed to start server on port " << port << "\n";
        std::signal(SIGINT, old_handler);
        g_server = nullptr;
        return 1;
    }

    int actual_port = server.port();
    std::cout << "PORT=" << actual_port << "\n";  // Machine-readable for scripts
    std::cerr << "bnsql server listening on port " << actual_port << "\n";
    std::cerr << "Connect with: bnsql --remote localhost:" << actual_port << " -c \"SELECT * FROM funcs\"\n";
    std::cerr << "Press Ctrl+C to stop.\n\n";
    std::cerr.flush();
    std::cout.flush();

    // Wait for server to stop (Ctrl+C or external signal)
    while (server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cerr << "\nServer stopped.\n";
    std::signal(SIGINT, old_handler);
    g_server = nullptr;
    return 0;
}

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

Tables: funcs, segments, names, entries, strings, xrefs, blocks, imports, instructions, comments, db_info

SQL Functions: disasm(addr), bytes(addr,n), name_at(addr), func_at(addr), hex(val), xrefs_to(addr)

Examples:
  SELECT COUNT(*) FROM funcs;
  SELECT hex(address), name, size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT content FROM strings WHERE content LIKE '%error%';
  SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC;
)";
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
// Agent Mode (Natural Language -> SQL via AI)
// ============================================================================

#ifdef BNSQL_HAS_AI_AGENT
// Note: g_agent and signal_handler are defined earlier with run_remote_agent

static void run_agent(bnsql::QueryEngine& qe, const std::string& prompt = "",
                      bool verbose = false, const std::string& provider_override = "",
                      int timeout_override = 0) {
    // Create SQL executor that returns formatted results
    auto executor = [&qe](const std::string& sql) -> std::string {
        auto result = qe.query(sql);
        if (!result.success) {
            return "Error: " + result.error;
        }
        return result.to_string();
    };

    // Load settings and apply overrides
    bnsql::AgentSettings settings = bnsql::LoadAgentSettings();
    if (!provider_override.empty()) {
        try {
            settings.default_provider = bnsql::ParseProviderType(provider_override);
            if (verbose) {
                std::cerr << "[AGENT] Provider override: " << provider_override << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }
    }

    if (timeout_override > 0) {
        settings.response_timeout_ms = timeout_override;
        if (verbose) {
            std::cerr << "[AGENT] Timeout override: " << timeout_override << " ms" << std::endl;
        }
    }

    // Create and start agent with settings
    bnsql::AIAgent agent(executor, settings, verbose);
    g_agent = &agent;

    // Install signal handler for Ctrl-C
    auto old_handler = std::signal(SIGINT, signal_handler);

    agent.start();

    bool one_shot = !prompt.empty();

    if (one_shot) {
        // One-shot mode: process single query
        std::string response = agent.query(prompt);
        std::cout << response << std::endl;

        // Print session ID for reference
        std::string session_id = agent.get_session_id();
        if (!session_id.empty()) {
            std::cout << "\n[Session: " << session_id << "]" << std::endl;
        }
    } else {
        // Interactive mode
        std::cout << "Agent mode - Natural language queries powered by AI." << std::endl;
        std::cout << "Type SQL directly, or ask questions in natural language." << std::endl;
        std::cout << "Commands: .help, .clear, .sql (SQL mode), .quit" << std::endl;
        std::cout << std::endl;

        // Set up command callbacks
        bnsql::CommandCallbacks callbacks;
        callbacks.get_tables = [&qe]() -> std::string {
            auto result = qe.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
            std::stringstream ss;
            for (const auto& row : result) {
                if (row.size() > 0) ss << row[0] << "\n";
            }
            return ss.str();
        };
        callbacks.get_schema = [&qe](const std::string& table) -> std::string {
            auto result = qe.query("SELECT sql FROM sqlite_master WHERE name='" + table + "'");
            if (!result.empty() && result.rows[0].size() > 0) {
                return result.rows[0][0];
            }
            return "Table not found: " + table;
        };
        callbacks.clear_session = [&agent]() -> std::string {
            agent.reset_session();
            return "Session cleared (conversation history reset)";
        };

#ifdef BNSQL_HAS_HTTP
        setup_http_callbacks(callbacks, qe);
#endif

        std::string line;
        while (!agent.quit_requested()) {
            std::cout << "bnsql> " << std::flush;
            if (!std::getline(std::cin, line)) break;

            line = trim(line);
            if (line.empty()) continue;

            // Handle .sql command specially (switches mode)
            if (to_lower(line) == ".sql") {
                std::cout << "Switching to SQL mode..." << std::endl << std::endl;
                agent.stop();
                g_agent = nullptr;
                std::signal(SIGINT, old_handler);
                run_interactive(qe);
                return;
            }

            // Use unified command handler
            if (!line.empty() && line[0] == '.') {
                std::string output;
                auto result = bnsql::handle_command(line, callbacks, output);

                switch (result) {
                    case bnsql::CommandResult::QUIT:
                        goto exit_agent;
                    case bnsql::CommandResult::HANDLED:
                        if (!output.empty()) {
                            std::cout << output;
                            if (output.back() != '\n') std::cout << "\n";
                        }
                        continue;
                    case bnsql::CommandResult::NOT_HANDLED:
                        break;
                }
            }

            // Process query through AI agent
            std::string response = agent.query(line);
            if (!response.empty()) {
                std::cout << response << std::endl;
            }
            std::cout << std::endl;
        }
        exit_agent:;
    }

    agent.stop();
    g_agent = nullptr;
    std::signal(SIGINT, old_handler);

#ifdef BNSQL_HAS_HTTP
    if (g_repl_http_server) {
        g_repl_http_server->stop();
        g_repl_http_server.reset();
    }
#endif
}

#else // !BNSQL_HAS_AI_AGENT

// Fallback when AI agent is not available
static void run_agent(bnsql::QueryEngine& qe, const std::string& prompt = "",
                      bool verbose = false, const std::string& provider_override = "",
                      int timeout_override = 0) {
    (void)prompt;
    (void)verbose;
    (void)provider_override;
    (void)timeout_override;
    std::cerr << "Error: Agent mode requires building with -DBNSQL_WITH_AI_AGENT=ON" << std::endl;
    std::cerr << "Falling back to interactive SQL mode..." << std::endl << std::endl;
    run_interactive(qe);
}

static void run_remote_agent(xsql::socket::Client& client, bool verbose = false,
                             const std::string& provider_override = "",
                             int timeout_override = 0) {
    (void)verbose;
    (void)provider_override;
    (void)timeout_override;
    std::cerr << "Error: Agent mode requires building with -DBNSQL_WITH_AI_AGENT=ON" << std::endl;
    std::cerr << "Falling back to interactive SQL mode..." << std::endl << std::endl;
    run_remote_interactive(client);
}

#endif // BNSQL_HAS_AI_AGENT

// ============================================================================
// Usage
// ============================================================================

static void print_usage(const char* prog) {
    std::cout << "bnsql v" << g_version << " - SQL interface for Binary Ninja" << std::endl << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << prog << " <database.bndb>                        Interactive mode" << std::endl;
    std::cout << "  " << prog << " <database.bndb> -c <query>             Execute query and exit" << std::endl;
    std::cout << "  " << prog << " <database.bndb> -f <file.sql>          Execute SQL file" << std::endl;
    std::cout << "  " << prog << " <database.bndb> --agent                Agent mode (AI-powered)" << std::endl;
    std::cout << "  " << prog << " <database.bndb> --prompt <text>        One-shot agent query" << std::endl;
    std::cout << "  " << prog << " <database.bndb> --server [port]        Start TCP server (default: " << DEFAULT_PORT << ")" << std::endl;
    std::cout << "  " << prog << " <database.bndb> --http [port]          Start HTTP REST server (default: 8080)" << std::endl;
    std::cout << "  " << prog << " <database.bndb> --mcp [port]           Start MCP server (default: 9998)" << std::endl;
    std::cout << "  " << prog << " --remote <host:port>                   Connect to remote TCP server" << std::endl;
    std::cout << "  " << prog << " --remote <host:port> --agent           Remote agent mode (AI client, SQL server)" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --source <path>    Binary Ninja database (.bndb)" << std::endl;
    std::cout << "  -c, --command <sql>    SQL query to execute" << std::endl;
    std::cout << "  -f, --file <path>      SQL file to execute" << std::endl;
    std::cout << "  -i, --interactive      Interactive SQL mode (default)" << std::endl;
    std::cout << "  --agent                AI-powered natural language agent mode" << std::endl;
    std::cout << "  --prompt <text>        One-shot natural language query" << std::endl;
    std::cout << "  --provider <name>      AI provider: claude or copilot" << std::endl;
    std::cout << "  --timeout <ms>         Response timeout in milliseconds" << std::endl;
    std::cout << "  --config [path] [val]  View/set agent configuration" << std::endl;
    std::cout << "  --server [port]        Start TCP server on port (default: " << DEFAULT_PORT << ")" << std::endl;
    std::cout << "  --http [port]          Start HTTP REST server (default: 8080)" << std::endl;
    std::cout << "  --mcp [port]           Start MCP server for Claude Desktop, etc. (default: 9998)" << std::endl;
    std::cout << "  --bind <addr>          Bind address for server (default: 127.0.0.1)" << std::endl;
    std::cout << "  --token <token>        Auth token for server/http mode" << std::endl;
    std::cout << "  --remote <host:port>   Connect to BNSQL TCP server" << std::endl;
    std::cout << "  --verbose              Verbose output (agent mode)" << std::endl;
    std::cout << "  -q, --quiet            Suppress banner" << std::endl;
    std::cout << "  -h, --help             Show this help" << std::endl;
    std::cout << "  -v, --version          Show version" << std::endl;
#ifdef BNSQL_HAS_AI_AGENT
    std::cout << std::endl;
    std::cout << "Agent settings: " << bnsql::GetSettingsPath() << std::endl;
#endif
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

    std::string database, query, query_file, prompt, remote_spec, provider_override, auth_token, bind_addr;
    int timeout_override = 0, server_port = DEFAULT_PORT, http_port = 8080, mcp_port = 9998;
    bool interactive = false, agent = false, quiet = false, verbose = false, server_mode = false, http_mode = false, mcp_mode = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        if (arg == "-v" || arg == "--version") { std::cout << "bnsql v" << g_version << std::endl; return 0; }
        if (arg == "-q" || arg == "--quiet") { quiet = true; continue; }
        if (arg == "-i" || arg == "--interactive") { interactive = true; continue; }
        if (arg == "--agent") { agent = true; continue; }
        if (arg == "--verbose") { verbose = true; continue; }

        if ((arg == "-s" || arg == "--source") && i + 1 < argc) { database = argv[++i]; continue; }
        if ((arg == "-c" || arg == "--command") && i + 1 < argc) { query = argv[++i]; continue; }
        if ((arg == "-f" || arg == "--file") && i + 1 < argc) { query_file = argv[++i]; continue; }
        if (arg == "--prompt" && i + 1 < argc) { prompt = argv[++i]; agent = true; continue; }
        if (arg == "--provider" && i + 1 < argc) { provider_override = argv[++i]; continue; }
        if (arg == "--timeout" && i + 1 < argc) {
            try {
                timeout_override = std::stoi(argv[++i]);
                if (timeout_override < 0) throw std::runtime_error("invalid");
            } catch (...) {
                std::cerr << "Error: Invalid timeout value (must be positive integer in milliseconds)" << std::endl;
                return 1;
            }
            continue;
        }
        if (arg == "--remote" && i + 1 < argc) { remote_spec = argv[++i]; continue; }
        if (arg == "--server") {
            server_mode = true;
            // Optional port argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                try {
                    server_port = std::stoi(argv[++i]);
                    if (server_port < 0 || server_port > 65535) throw std::runtime_error("invalid");
                } catch (...) {
                    std::cerr << "Error: Invalid server port" << std::endl;
                    return 1;
                }
            }
            continue;
        }
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

        // --config [path] [value] - handle immediately and exit
        if (arg == "--config") {
#ifdef BNSQL_HAS_AI_AGENT
            std::string config_path = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            std::string config_value = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            auto [ok, output, code] = bnsql::handle_config_command(config_path, config_value);
            std::cout << output;
            return code;
#else
            std::cerr << "Error: AI agent not compiled in. Rebuild with -DBNSQL_WITH_AI_AGENT=ON\n";
            return 1;
#endif
        }

        // Positional argument = database
        if (arg[0] != '-' && database.empty()) { database = arg; continue; }

        std::cerr << "Unknown option: " << arg << std::endl;
        return 1;
    }

    // Validate mutual exclusivity
    int mode_count = (server_mode ? 1 : 0) + (http_mode ? 1 : 0) + (mcp_mode ? 1 : 0) + (!remote_spec.empty() ? 1 : 0);
    if (mode_count > 1) {
        std::cerr << "Error: Cannot use multiple modes (--server, --http, --mcp, --remote)\n";
        return 1;
    }

    // Remote mode - connect to server instead of loading database
    if (!remote_spec.empty()) {
        std::string host = "127.0.0.1";
        int port = 13337;
        auto colon = remote_spec.find(':');
        if (colon != std::string::npos) {
            host = remote_spec.substr(0, colon);
            try {
                port = std::stoi(remote_spec.substr(colon + 1));
                if (port < 1 || port > 65535) throw std::runtime_error("invalid");
            } catch (...) {
                std::cerr << "Error: Invalid port in --remote" << std::endl;
                return 1;
            }
        } else {
            host = remote_spec;
        }

        if (!quiet) std::cerr << "Connecting to " << host << ":" << port << "..." << std::endl;
        xsql::socket::Client client;
        if (!client.connect(host, port)) {
            std::cerr << "Error: " << client.error() << std::endl;
            return 1;
        }
        if (!quiet) std::cerr << "Connected." << std::endl << std::endl;

        if (!query.empty()) {
            auto qr = client.query(query);
            if (qr.success) print_remote_result(qr);
            else { std::cerr << "Error: " << qr.error << std::endl; return 1; }
        } else if (agent) {
            // Agent mode with remote SQL execution
            run_remote_agent(client, verbose, provider_override, timeout_override);
        } else {
            run_remote_interactive(client);
        }
        return 0;
    }

    // Require database
    if (database.empty()) {
        std::cerr << "Error: No database specified. Use -s <database.bndb> or --remote <host:port>\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Initialize Binary Ninja
    SetBundledPluginDirectory(GetBundledPluginDirectory());
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
    if (server_mode) {
        return run_server_mode(qe, server_port, auth_token);
    }

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

#ifdef BNSQL_HAS_AI_AGENT
    if (mcp_mode) {
        // Start MCP server
        if (bind_addr.empty()) bind_addr = "127.0.0.1";
        std::string url = "http://" + bind_addr + ":" + std::to_string(mcp_port);

        if (!quiet) {
            std::cout << "Starting MCP server on " << url << "..." << std::endl;
        }

        bnsql::MCPServer mcp_server;

        // SQL query callback - direct SQL execution
        bnsql::QueryCallback query_cb = [&qe](const std::string& sql) -> std::string {
            auto result = qe.query(sql);
            if (!result.success) {
                return "Error: " + result.error;
            }
            return result.to_string();
        };

        // Agent ask callback - natural language query
        // Create AI agent for NL queries
        bnsql::AgentSettings settings = bnsql::LoadAgentSettings();
        auto executor = [&qe](const std::string& sql) -> std::string {
            auto result = qe.query(sql);
            if (!result.success) {
                return "Error: " + result.error;
            }
            return result.to_string();
        };
        bnsql::AIAgent ai_agent(executor, settings, verbose);
        ai_agent.start();

        bnsql::AskCallback ask_cb = [&ai_agent](const std::string& question) -> std::string {
            return ai_agent.query(question);
        };

        int actual_port = mcp_server.start(mcp_port, query_cb, ask_cb, bind_addr);
        if (actual_port <= 0) {
            std::cerr << "Error: Failed to start MCP server on port " << mcp_port << std::endl;
            return 1;
        }
        url = "http://" + bind_addr + ":" + std::to_string(actual_port);

        // Print MCP server info
        size_t func_count = 0;
        auto count_result = qe.query("SELECT COUNT(*) FROM functions");
        if (count_result.success && !count_result.rows.empty()) {
            try { func_count = std::stoul(count_result.rows[0][0]); } catch (...) {}
        }

        std::cout << bnsql::format_mcp_info(database, func_count, url, true) << std::endl;
        std::cout << "Press Ctrl+C to stop MCP server." << std::endl;

        // Install signal handler for clean shutdown
        g_quit_requested.store(false);
        auto old_handler = std::signal(SIGINT, quit_signal_handler);
#ifdef _WIN32
        auto old_break_handler = std::signal(SIGBREAK, quit_signal_handler);
#endif
        mcp_server.set_interrupt_check([]() {
            return g_quit_requested.load();
        });

        // Wait for shutdown (Ctrl+C)
        mcp_server.wait();

        // Restore signal handlers
        std::signal(SIGINT, old_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, old_break_handler);
#endif
        ai_agent.stop();

        std::cout << "MCP server stopped." << std::endl;
        return 0;
    }
#else
    if (mcp_mode) {
        std::cerr << "Error: MCP mode not available. Rebuild with -DBNSQL_WITH_AI_AGENT=ON\n";
        return 1;
    }
#endif

    if (!query.empty() && !agent) {
        // Single query mode
        auto result = qe.query(query);
        if (!result.success) {
            std::cerr << "Error: " << result.error << "\n";
            return 1;
        }
        std::cout << result.to_string() << "\n";
        return 0;
    }

    if (agent) {
        run_agent(qe, prompt, verbose, provider_override, timeout_override);
    } else {
        run_interactive(qe);
    }

    return 0;
}
