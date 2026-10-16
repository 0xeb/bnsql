// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// Modified (contribution-purpose, proposed upstream): HTTP server support was
// changed from one process-wide server to one server per BinaryView, so several
// open files/tabs can each be served on their own port.

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

#include <map>
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
// One HTTP server per BinaryView. A server is bound to the view it was started
// from (the active tab at "Start HTTP Server..."), so several open files can be
// served at the same time, each on its own port.
struct HttpServerEntry {
    std::shared_ptr<xsql::thinclient::http_query_server> server;
    Ref<BinaryView> view;
    std::string label;  // file name, for status messages
    bool stopping = false;
};
static std::map<BNBinaryView*, HttpServerEntry> g_http_servers;
static std::mutex g_http_server_mutex;
// Requests are serialized per server (serialize_requests), but with several
// servers, statements for different views could run concurrently. Runtime
// settings and the timeout stack are process-wide, so serialize statement
// execution across all servers -- the same guarantee the single server gave.
// Only taken on HTTP worker threads, never on the GUI thread: an executor can
// wait on the GUI thread (UI-context capture) while holding it.
static std::mutex g_http_exec_mutex;

static std::string ViewLabel(BinaryView* bv) {
    if (!bv) return "<no view>";
    Ref<FileMetadata> file = bv->GetFile();
    std::string name = file ? file->GetFilename() : std::string();
    return name.empty() ? "<unnamed view>" : name;
}

// Drop entries whose server is no longer running (e.g. stopped remotely via
// POST /shutdown). Caller holds g_http_server_mutex.
static void PruneStoppedHTTPServers() {
    for (auto it = g_http_servers.begin(); it != g_http_servers.end();) {
        const HttpServerEntry& e = it->second;
        if (!e.stopping && (!e.server || !e.server->is_running()))
            it = g_http_servers.erase(it);
        else
            ++it;
    }
}

// Caller holds g_http_server_mutex.
static std::string DescribeHTTPServers() {
    std::string out;
    for (const auto& [key, e] : g_http_servers) {
        out += "  port " + std::to_string(e.server ? e.server->port() : 0) +
               (e.stopping ? " (stopping)" : "") + "  " + e.label + "\n";
    }
    return out;
}

static void StartHTTPServer(BinaryView* bv) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    PruneStoppedHTTPServers();
    auto existing = g_http_servers.find(bv->GetObject());
    if (existing != g_http_servers.end()) {
        std::string msg = existing->second.stopping
            ? std::string("HTTP server for this view is still stopping")
            : "HTTP server for this view already running on port " +
                  std::to_string(existing->second.server->port());
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

    Ref<BinaryView> server_view = bv;

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
    // Capture this server's BinaryView by value into the executor. The lambda
    // runs on httplib worker threads; a captured Ref keeps the view alive for the
    // executor's lifetime, independent of the server registry.
    cfg.statement_executor =
        [view = server_view](const std::string& stmt, xsql::ScriptStatementResult& out) {
        if (!view) {
            out.success = false;
            out.error = "No binary loaded";
            return;
        }
        std::lock_guard<std::mutex> exec_lock(g_http_exec_mutex);
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
    // function count once now so status_fn never touches the engine on a worker
    // thread. Read it straight from the view (same source as the funcs table):
    // other servers may be executing queries, and the GUI thread must not wait
    // on g_http_exec_mutex.
    {
        const std::string func_count =
            std::to_string(server_view->GetAnalysisFunctionList().size());
        cfg.status_fn = [func_count]() { return bnsql::status_extra_json(func_count); };
    }
    cfg.status_requires_auth = true;
    cfg.extra_routes = [](httplib::Server& svr) {
        svr.Get("/settings", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(bnsql::settings_to_json(bnsql::runtime_settings().snapshot()),
                            "application/json");
        });
    };

    auto server = std::make_shared<xsql::thinclient::http_query_server>(cfg);
    int actual_port_check = server->start();
    if (actual_port_check < 0) {
        ShowMessageBox("Error", "Failed to start HTTP server (port in use?)", OKButtonSet, ErrorIcon);
        return;
    }

    const std::string label = ViewLabel(bv);
    g_http_servers[bv->GetObject()] = HttpServerEntry{server, server_view, label, false};

    int actual_port = server->port();
    // Echo the ACTUAL bind address in the examples. Hardcoding 127.0.0.1 handed a
    // user who bound elsewhere a copy-pasteable command that cannot work.
    const std::string host_for_url =
        (bind_address == "0.0.0.0" || bind_address == "::") ? "127.0.0.1" : bind_address;
    const std::string auth_hdr = auth_token.empty()
        ? std::string()
        : " -H \"Authorization: Bearer " + auth_token + "\"";
    std::string msg = "HTTP server started on " + bind_address + ":" + std::to_string(actual_port) +
        "\nView: " + label +
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
    LogInfo("[bnsql] HTTP server started on %s:%d for %s", bind_address.c_str(), actual_port,
            label.c_str());
    ShowMessageBox("BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
}

// Stops the server bound to the current view; servers for other views keep running.
static void StopHTTPServer(BinaryView* bv) {
    std::shared_ptr<xsql::thinclient::http_query_server> server;
    int port = 0;
    BNBinaryView* key = bv->GetObject();
    {
        std::lock_guard<std::mutex> lock(g_http_server_mutex);
        PruneStoppedHTTPServers();
        auto it = g_http_servers.find(key);
        if (it == g_http_servers.end()) {
            std::string msg = "No HTTP server is running for this view";
            if (!g_http_servers.empty())
                msg += "\n\nServers for other views (switch to that tab to stop one):\n" +
                       DescribeHTTPServers();
            ShowMessageBox(
                "BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
            return;
        }
        if (it->second.stopping) {
            ShowMessageBox(
                "BNSQL HTTP Server", "HTTP server for this view is already stopping",
                OKButtonSet, InformationIcon);
            return;
        }

        port = it->second.server->port();
        server = it->second.server;
        it->second.stopping = true;
    }

    // stop() joins all HTTP handlers. A handler executing ui_context() can be
    // waiting for the GUI thread, so joining here on that same GUI thread forms
    // a cycle. Drain on BN's worker pool and return to the event loop so pending
    // UI-context captures can finish.
    WorkerEnqueue([server = std::move(server), port, key]() {
        server->stop();
        {
            std::lock_guard<std::mutex> lock(g_http_server_mutex);
            auto it = g_http_servers.find(key);
            if (it != g_http_servers.end() && it->second.server == server)
                g_http_servers.erase(it);
        }
        ExecuteOnMainThread([port]() {
            LogInfo("[bnsql] HTTP server on port %d stopped", port);
            const std::string msg =
                "HTTP server stopped (was on port " + std::to_string(port) + ")";
            ShowMessageBox(
                "BNSQL HTTP Server", msg.c_str(), OKButtonSet,
                InformationIcon);
        });
    }, "BNSQL HTTP server stop");
}

static void HTTPServerStatus(BinaryView* bv) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    PruneStoppedHTTPServers();
    std::string msg;
    if (!g_http_servers.empty()) {
        auto it = g_http_servers.find(bv->GetObject());
        msg = "HTTP servers (" + std::to_string(g_http_servers.size()) + "):\n" +
              DescribeHTTPServers();
        if (it != g_http_servers.end() && !it->second.stopping) {
            int port = it->second.server->port();
            msg += "\nThis view is served on port " + std::to_string(port) +
                "\n\nExample:\n"
                "  curl http://127.0.0.1:" + std::to_string(port) + "/help\n"
                "  curl -X POST http://127.0.0.1:" + std::to_string(port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"";
        } else {
            msg += "\nThis view has no HTTP server. Use Start HTTP Server to add one.";
        }
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
