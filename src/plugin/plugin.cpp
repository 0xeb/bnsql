// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * plugin.cpp - Binary Ninja plugin for bnsql
 *
 * Registers bnsql functionality with Binary Ninja:
 *   - Menu commands for SQL queries
 *   - HTTP server for remote queries
 *   - Plugin command integration
 */

// Socket includes MUST come before binaryninjaapi.h (which includes windows.h)
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <bnsql/bnsql.hpp>
#ifdef BNSQL_HAS_HTTP
#include <xsql/thinclient/http_query_server.hpp>
#include "bnsql_http_routes.hpp"
#endif
#include "binaryninjaapi.h"

#include <memory>
#include <mutex>
#include <atomic>

using namespace BinaryNinja;

// Defined in ui_context_capture.cpp — installs the live BN-Python UIContext
// capture into the shared library's get_ui_context_json() provider slot.
namespace bnsql { void install_ui_context_capture(); }

// ============================================================================
// Plugin Commands
// ============================================================================

static void RunSQLQuery(BinaryView* bv) {
    std::string query;
    if (!GetTextLineInput(query, "SQL Query", "Enter SQL query:")) return;
    if (query.empty()) return;

    // Plugin commands run on the GUI thread. Execute SQL on a worker so long
    // analysis queries keep the UI responsive and Python-backed UI-context
    // capture can marshal to the main thread without a cyclic wait.
    Ref<BinaryView> view = bv;
    WorkerEnqueue([view, query]() {
        bnsql::QueryEngine qe(view);
        auto result = qe.query(query);
        const bool success = result.success;
        std::string error = result.error;
        std::string output = success ? result.to_string() : std::string();
        const size_t row_count = result.row_count();

        ExecuteOnMainThread(
            [success, error = std::move(error), output = std::move(output),
             row_count]() {
                if (!success) {
                    LogError("SQL Error: %s", error.c_str());
                    ShowMessageBox(
                        "SQL Error", error.c_str(), OKButtonSet, ErrorIcon);
                    return;
                }

                LogInfo("%s", output.c_str());
                if (row_count <= 50) {
                    ShowMessageBox(
                        "SQL Result", output.c_str(), OKButtonSet,
                        InformationIcon);
                } else {
                    LogInfo(
                        "SQL Result (%zu rows) - see Log window", row_count);
                }
            });
    }, "BNSQL SQL query");
}

static void ShowTables(BinaryView* bv) {
    bnsql::QueryEngine qe(bv);
    auto result = qe.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    if (!result.success) { LogError("Error: %s", result.error.c_str()); return; }
    std::string tables = "Available tables:\n\n";
    for (const auto& row : result) tables += "  " + row[0] + "\n";
    ShowMessageBox("BNSQL Tables", tables.c_str(), OKButtonSet, InformationIcon);
}

// ============================================================================
// HTTP Server Commands
// ============================================================================

#ifdef BNSQL_HAS_HTTP
static std::unique_ptr<xsql::thinclient::http_query_server> g_http_server;
static std::mutex g_http_server_mutex;
static Ref<BinaryView> g_http_server_bv;
static bool g_http_server_stopping = false;

static void StartHTTPServer(BinaryView* bv) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    if (g_http_server_stopping) {
        ShowMessageBox(
            "BNSQL HTTP Server", "HTTP server is still stopping",
            OKButtonSet, InformationIcon);
        return;
    }
    if (g_http_server && g_http_server->is_running()) {
        std::string msg = "HTTP server already running on port " + std::to_string(g_http_server->port());
        ShowMessageBox("BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
        return;
    }

    // Accept "port" or "host:port". The CLI has --bind and --token; the plugin
    // prompt used to hardcode loopback, so a GUI user had no way to expose the
    // server to another machine (or to protect it if they could). One field keeps
    // the common case a single keystroke.
    std::string input;
    if (!GetTextLineInput(input, "HTTP Server Port",
                          "Enter port, or host:port to bind elsewhere\n"
                          "(0 = random port, default: 8080, default host: 127.0.0.1):"))
        return;

    int port = 8080;
    std::string bind_address = "127.0.0.1";
    if (!input.empty()) {
        std::string port_part = input;
        // Rightmost colon splits host from port, so IPv6 literals in brackets
        // ("[::1]:8080") and bare "0.0.0.0:8080" both parse.
        const std::string::size_type colon = input.rfind(':');
        if (colon != std::string::npos) {
            bind_address = input.substr(0, colon);
            port_part = input.substr(colon + 1);
            if (bind_address.size() >= 2 && bind_address.front() == '[' && bind_address.back() == ']')
                bind_address = bind_address.substr(1, bind_address.size() - 2);
            if (bind_address.empty()) bind_address = "127.0.0.1";
        }
        try { port = std::stoi(port_part); if (port < 0 || port > 65535) throw 0; }
        catch (...) { ShowMessageBox("Error", "Invalid port", OKButtonSet, ErrorIcon); return; }
    }

    // A non-loopback bind exposes a SQL endpoint that can execute Python (once
    // enable_python is set) to anything that can reach it. The CLI prints a
    // warning for this; in the GUI the equivalent is to offer the token up front
    // and make an unauthenticated exposure an explicit, confirmed choice.
    std::string auth_token;
    const bool non_loopback = bind_address != "127.0.0.1" && bind_address != "localhost"
                           && bind_address != "::1";
    if (non_loopback) {
        GetTextLineInput(auth_token, "Auth Token",
                         "Binding to " + bind_address + " (reachable off this machine).\n"
                         "Enter an auth token, or leave empty for no authentication:");
        if (auth_token.empty()) {
            if (!ShowMessageBox("BNSQL HTTP Server",
                                ("No authentication token set.\n\n"
                                 "The server on " + bind_address + " will accept queries from "
                                 "anyone who can reach it, with no credentials. Continue?").c_str(),
                                YesNoButtonSet, WarningIcon))
                return;
        }
    }

    g_http_server_bv = bv;

    xsql::thinclient::http_query_server_config cfg;
    cfg.tool_name = "bnsql";
    cfg.help_text = bnsql::http_help_text();
    cfg.port = port;
    cfg.bind_address = bind_address;
    if (!auth_token.empty()) cfg.auth_token = auth_token;
    // Background server (no main-thread queue); serialize concurrent requests
    // since a per-request QueryEngine over the shared BinaryView isn't
    // concurrency-safe (matches the prior timed_mutex behavior).
    cfg.use_queue = false;
    cfg.serialize_requests = true;
    // The serialize path honors these admission limits (503/408), same as the
    // CLI servers — previously the plugin server dropped queue backpressure.
    cfg.queue_admission_timeout_ms_fn = []() {
        return bnsql::runtime_settings().queue_admission_timeout_ms();
    };
    cfg.max_queue_fn = []() { return bnsql::runtime_settings().max_queue(); };
    // Capture the BinaryView by value into the executor. The lambda runs on
    // httplib worker threads; reading the non-atomic g_http_server_bv global at
    // call time would race StopHTTPServer() nulling it. A captured Ref keeps the
    // view alive for the executor's lifetime regardless of the global.
    cfg.statement_executor =
        [view = g_http_server_bv](const std::string& stmt, xsql::ScriptStatementResult& out) {
        if (!view) {
            out.success = false;
            out.error = "No binary loaded";
            return;
        }
        bnsql::QueryEngine qe(view);
        auto r = qe.query(stmt);
        out.columns = std::move(r.columns);
        out.rows.reserve(r.rows.size());
        for (auto& row : r.rows) out.rows.push_back(std::move(row.values));
        out.elapsed_ms = r.elapsed_ms;
        out.success = r.success;
        out.error = std::move(r.error);
    };
    // /status must carry `functions` + `settings` like the CLI servers. Cache the
    // function count once now (serialize mode means no /query runs concurrently
    // during startup) so status_fn never touches the engine on a worker thread.
    {
        std::string func_count;
        if (g_http_server_bv) {
            bnsql::QueryEngine qe(g_http_server_bv);
            auto r = qe.query("SELECT COUNT(*) FROM funcs");
            if (r.success && !r.empty()) func_count = r.rows[0][0];
        }
        cfg.status_fn = [func_count]() { return bnsql::status_extra_json(func_count); };
    }
    cfg.status_requires_auth = true;
    cfg.extra_routes = [](httplib::Server& svr) {
        svr.Get("/settings", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(bnsql::settings_to_json(bnsql::runtime_settings().snapshot()),
                            "application/json");
        });
    };

    g_http_server = std::make_unique<xsql::thinclient::http_query_server>(cfg);
    int actual_port_check = g_http_server->start();
    if (actual_port_check < 0) {
        g_http_server.reset();
        g_http_server_bv = nullptr;
        ShowMessageBox("Error", "Failed to start HTTP server", OKButtonSet, ErrorIcon);
        return;
    }

    int actual_port = g_http_server->port();
    // Echo the ACTUAL bind address in the examples. Hardcoding 127.0.0.1 handed a
    // user who bound elsewhere a copy-pasteable command that cannot work.
    const std::string host_for_url =
        (bind_address == "0.0.0.0" || bind_address == "::") ? "127.0.0.1" : bind_address;
    const std::string auth_hdr = auth_token.empty()
        ? std::string()
        : " -H \"Authorization: Bearer " + auth_token + "\"";
    std::string msg = "HTTP server started on " + bind_address + ":" + std::to_string(actual_port) +
        (auth_token.empty() ? "" : "\nAuth: bearer token required") +
        "\n\nEndpoints:\n"
        "  GET  /help     - API documentation\n"
        "  POST /query    - Execute SQL\n"
        "  GET  /status   - Health check\n"
        "  GET  /settings - Runtime settings\n"
        "  POST /shutdown - Stop server\n\n"
        "Example:\n"
        "  curl" + auth_hdr + " http://" + host_for_url + ":" + std::to_string(actual_port) + "/help\n"
        "  curl" + auth_hdr + " -X POST http://" + host_for_url + ":" + std::to_string(actual_port) +
        "/query -d \"SELECT name FROM funcs LIMIT 5\"";
    LogInfo("[bnsql] HTTP server started on %s:%d", bind_address.c_str(), actual_port);
    ShowMessageBox("BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
}

static void StopHTTPServer(BinaryView*) {
    std::shared_ptr<xsql::thinclient::http_query_server> server;
    int port = 0;
    {
        std::lock_guard<std::mutex> lock(g_http_server_mutex);
        if (g_http_server_stopping) {
            ShowMessageBox(
                "BNSQL HTTP Server", "HTTP server is already stopping",
                OKButtonSet, InformationIcon);
            return;
        }
        if (!g_http_server || !g_http_server->is_running()) {
            ShowMessageBox(
                "BNSQL HTTP Server", "HTTP server is not running",
                OKButtonSet, InformationIcon);
            return;
        }

        port = g_http_server->port();
        server = std::shared_ptr<xsql::thinclient::http_query_server>(
            std::move(g_http_server));
        g_http_server_bv = nullptr;
        g_http_server_stopping = true;
    }

    // stop() joins all HTTP handlers. A handler executing ui_context() can be
    // waiting for the GUI thread, so joining here on that same GUI thread forms
    // a cycle. Drain on BN's worker pool and return to the event loop so pending
    // UI-context captures can finish.
    WorkerEnqueue([server = std::move(server), port]() {
        server->stop();
        {
            std::lock_guard<std::mutex> lock(g_http_server_mutex);
            g_http_server_stopping = false;
        }
        ExecuteOnMainThread([port]() {
            LogInfo("[bnsql] HTTP server stopped");
            const std::string msg =
                "HTTP server stopped (was on port " + std::to_string(port) + ")";
            ShowMessageBox(
                "BNSQL HTTP Server", msg.c_str(), OKButtonSet,
                InformationIcon);
        });
    }, "BNSQL HTTP server stop");
}

static void HTTPServerStatus(BinaryView*) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    std::string msg;
    if (g_http_server_stopping) {
        msg = "HTTP server is STOPPING";
    } else if (g_http_server && g_http_server->is_running()) {
        int port = g_http_server->port();
        msg = "HTTP server is RUNNING on port " + std::to_string(port) +
            "\n\nExample:\n"
            "  curl http://127.0.0.1:" + std::to_string(port) + "/help\n"
            "  curl -X POST http://127.0.0.1:" + std::to_string(port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"";
    } else {
        msg = "HTTP server is STOPPED\n\nUse Start HTTP Server to enable REST API access.";
    }
    ShowMessageBox("BNSQL HTTP Server Status", msg.c_str(), OKButtonSet, InformationIcon);
}
#endif // BNSQL_HAS_HTTP

// ============================================================================
// Plugin Registration
// ============================================================================

extern "C" {

BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit() {
    // No UI (headless host, e.g. the bnsql CLI's InitPlugins()): this plugin only adds GUI
    // menu commands, so there is nothing to register. Return true = loaded OK, did nothing.
    if (!IsUIEnabled()) {
        LogInfo("bnsql: UI not enabled (headless) - plugin skipped");
        return true;
    }

    LogInfo("bnsql: Initializing SQL interface for Binary Ninja");

    // Install the live UI-context capture (Binary Ninja Python UIContext snapshot)
    // so get_ui_context_json() returns real view/cursor/selection state in the GUI.
    bnsql::install_ui_context_capture();

    PluginCommand::Register("BNSQL\\Run SQL Query...", "Execute a SQL query", RunSQLQuery);
    PluginCommand::Register("BNSQL\\Show Tables", "Show available SQL tables", ShowTables);
#ifdef BNSQL_HAS_HTTP
    PluginCommand::Register("BNSQL\\Start HTTP Server...", "Start HTTP REST API server", StartHTTPServer);
    PluginCommand::Register("BNSQL\\Stop HTTP Server", "Stop HTTP server", StopHTTPServer);
    PluginCommand::Register("BNSQL\\HTTP Server Status", "Show HTTP server status", HTTPServerStatus);
#endif

    LogInfo("bnsql: Plugin initialized successfully");
    return true;
}

} // extern "C"
