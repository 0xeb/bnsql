// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <functional>
#include <string>

#include <xsql/thinclient/clipboard.hpp>

namespace bnsql {

/**
 * Command handler result
 */
enum class CommandResult {
    NOT_HANDLED,  // Not a command, process as query
    HANDLED,      // Command executed successfully
    QUIT          // User requested quit
};

/**
 * Command handler callbacks
 *
 * These callbacks allow different environments (CLI, plugin) to extend
 * command behavior.
 */
struct CommandCallbacks {
    std::function<std::string()> get_tables;      // Return table list
    std::function<std::string(const std::string&)> get_schema;  // Return schema for table
    std::function<std::string()> get_info;        // Return database info
    std::function<std::string()> clear_session;   // Clear/reset session (agent, UI, etc.)

#ifdef BNSQL_HAS_HTTP
    // HTTP server callbacks (optional)
    std::function<std::string()> http_status;     // Get HTTP server status
    std::function<std::string()> http_start;      // Start HTTP server
    std::function<std::string()> http_stop;       // Stop HTTP server
#endif
};

/**
 * Handle dot commands (.tables, .schema, .help, .quit, etc.)
 *
 * @param input User input line
 * @param callbacks Callbacks to execute commands
 * @param output Output string (filled if command produces output)
 * @return CommandResult indicating how to proceed
 */
inline CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output)
{
    if (input.empty() || input[0] != '.') {
        return CommandResult::NOT_HANDLED;
    }

    if (input == ".quit" || input == ".exit" || input == ".q") {
        return CommandResult::QUIT;
    }

    if (input == ".tables") {
        if (callbacks.get_tables) {
            output = callbacks.get_tables();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".info") {
        if (callbacks.get_info) {
            output = callbacks.get_info();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".clear" || input == ".reset") {
        if (callbacks.clear_session) {
            output = callbacks.clear_session();
        } else {
            output = "Session cleared";
        }
        return CommandResult::HANDLED;
    }

    if (input == ".help" || input == ".h") {
        output = "BNSQL Commands:\n"
                 "  .tables         List all tables\n"
                 "  .schema <table> Show table schema\n"
                 "  .info           Show database info\n"
                 "  .clear          Clear/reset session\n"
                 "  .quit / .exit   Exit\n"
                 "  .help           Show this help\n"
#ifdef BNSQL_HAS_HTTP
                 "\n"
                 "HTTP Server:\n"
                 "  .http           Show status or start if not running\n"
                 "  .http start     Start HTTP server\n"
                 "  .http stop      Stop HTTP server\n"
                 "  .http help      Show HTTP help\n"
#endif
                 "\n"
                 "SQL:\n"
                 "  SELECT * FROM funcs LIMIT 10;\n"
                 "  SELECT name, size FROM funcs ORDER BY size DESC;\n"
                 ;
        return CommandResult::HANDLED;
    }

    // .http commands (HTTP server control)
    if (input.rfind(".http", 0) == 0) {
#ifdef BNSQL_HAS_HTTP
        std::string subargs = input.length() > 5 ? input.substr(5) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        if (subargs.empty()) {
            // .http - show status, start if not running
            if (callbacks.http_status) {
                output = callbacks.http_status();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "start") {
            if (callbacks.http_start) {
                output = callbacks.http_start();
                std::string host;
                int actual_port = 0;
                if (xsql::thinclient::extract_http_start_endpoint(output, host, actual_port)) {
                    const std::string clipboard_text =
                        xsql::thinclient::build_http_clipboard_payload("bnsql", host, actual_port);
                    (void)xsql::thinclient::try_copy_text_to_clipboard_windows(clipboard_text);
                }
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "stop") {
            if (callbacks.http_stop) {
                output = callbacks.http_stop();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "help") {
            output = "HTTP Server Commands:\n"
                     "  .http            Show status, start if not running\n"
                     "  .http start      Start HTTP server on random port\n"
                     "  .http stop       Stop HTTP server\n"
                     "  .http help       Show this help\n"
                     "\n"
                     "Endpoints:\n"
                     "  GET  /help       API documentation\n"
                     "  POST /query      Execute SQL (body = raw SQL)\n"
                     "  GET  /status     Health check\n"
                     "  POST /shutdown   Stop server\n"
                     "\n"
                     "Example:\n"
                     "  curl -X POST http://127.0.0.1:<port>/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
        }
        else {
            output = "Unknown HTTP command: " + subargs + "\nUse '.http help' for available commands.";
        }
#else
        output = "HTTP server not compiled in. Rebuild with -DBNSQL_WITH_HTTP=ON";
#endif
        return CommandResult::HANDLED;
    }

    if (input.rfind(".schema", 0) == 0) {
        std::string table = input.length() > 8 ? input.substr(8) : "";
        // Trim leading whitespace
        size_t start = table.find_first_not_of(" \t");
        if (start != std::string::npos) {
            table = table.substr(start);
            // Trim trailing whitespace
            size_t end = table.find_last_not_of(" \t");
            if (end != std::string::npos) {
                table = table.substr(0, end + 1);
            }
        } else {
            table.clear();
        }

        if (table.empty()) {
            output = "Usage: .schema <table_name>";
        } else if (callbacks.get_schema) {
            output = callbacks.get_schema(table);
        }
        return CommandResult::HANDLED;
    }

    output = "Unknown command: " + input;
    return CommandResult::HANDLED;
}

} // namespace bnsql
