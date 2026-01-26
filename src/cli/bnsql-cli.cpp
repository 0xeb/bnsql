// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * bnsql-cli - Command-line SQL interface to Binary Ninja databases
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
#pragma comment(lib, "ws2_32.lib")
#endif

#include <bnsql/bnsql.hpp>
#include <xsql/socket/client.hpp>
#include "binaryninjaapi.h"

#ifdef BNSQL_HAS_AI_AGENT
#include "ai_agent.hpp"
#include "bnsql_commands.hpp"
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

using namespace BinaryNinja;

static const char* g_version = "1.0.0";

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

    std::cout << "bnsql interactive mode. Type .help for help, .quit to exit.\n\n";

    while (true) {
        std::cout << (query.empty() ? "bnsql> " : "   ...> ") << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::string trimmed = trim(line);
        if (trimmed.empty()) continue;

        // Dot commands (only when not accumulating)
        if (query.empty() && trimmed[0] == '.') {
            std::string cmd = to_lower(trimmed);
            if (cmd == ".quit" || cmd == ".exit" || cmd == ".q") break;
            if (cmd == ".help" || cmd == ".h") { print_repl_help(); continue; }
            if (cmd == ".tables") { show_tables(qe); continue; }
            if (cmd.rfind(".schema", 0) == 0) {
                show_schema(qe, trim(trimmed.substr(7)));
                continue;
            }
            std::cout << "Unknown command. Try .help\n";
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
}

// ============================================================================
// Agent Mode (Natural Language -> SQL via AI)
// ============================================================================

#ifdef BNSQL_HAS_AI_AGENT

static bnsql::AIAgent* g_agent = nullptr;

static void signal_handler(int sig) {
    if (g_agent) {
        g_agent->request_quit();
    }
}

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
    } else {
        // Interactive mode
        std::cout << "Agent mode - Natural language queries powered by AI." << std::endl;
        std::cout << "Type SQL directly, or ask questions in natural language." << std::endl;
        std::cout << "Commands: .help, .agent help, .sql (SQL mode), .quit" << std::endl;
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

        std::string line;
        while (!agent.quit_requested()) {
            std::cout << "agent> " << std::flush;
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
            std::string response = agent.query_streaming(line, [](const std::string& delta) {
                std::cout << delta << std::flush;
            });
            std::cout << std::endl << std::endl;
        }
        exit_agent:;
    }

    agent.stop();
    g_agent = nullptr;
    std::signal(SIGINT, old_handler);
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
    std::cout << "  " << prog << " <database.bndb> --provider <name>      Override AI provider" << std::endl;
    std::cout << "  " << prog << " --remote <host:port>                   Connect to remote server" << std::endl;
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
    std::cout << "  --remote <host:port>   Connect to BNSQL server" << std::endl;
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
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::string database, query, query_file, prompt, remote_spec, provider_override;
    int timeout_override = 0;
    bool interactive = false, agent = false, quiet = false, verbose = false;

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
