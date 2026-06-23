// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
#include <xsql/thinclient/server.hpp>
#include <xsql/thinclient/http_query_server.hpp>
#include "bnsql_http_routes.hpp"
#endif
#include "binaryninjaapi.h"

#include <memory>
#include <mutex>
#include <atomic>

using namespace BinaryNinja;

// ============================================================================
// Plugin Commands
// ============================================================================

static void RunSQLQuery(BinaryView* bv) {
    std::string query;
    if (!GetTextLineInput(query, "SQL Query", "Enter SQL query:")) return;
    if (query.empty()) return;

    bnsql::QueryEngine qe(bv);
    auto result = qe.query(query);

    if (!result.success) {
        LogError("SQL Error: %s", result.error.c_str());
        ShowMessageBox("SQL Error", result.error.c_str(), OKButtonSet, ErrorIcon);
        return;
    }

    std::string output = result.to_string();
    LogInfo("%s", output.c_str());

    if (result.row_count() <= 50) {
        ShowMessageBox("SQL Result", output.c_str(), OKButtonSet, InformationIcon);
    } else {
        LogInfo("SQL Result (%zu rows) - see Log window", result.row_count());
    }
}

static void ShowTables(BinaryView* bv) {
    bnsql::QueryEngine qe(bv);
    auto result = qe.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    if (!result.success) { LogError("Error: %s", result.error.c_str()); return; }
    std::string tables = "Available tables:\n\n";
    for (const auto& row : result) tables += "  " + row[0] + "\n";
    ShowMessageBox("BNSQL Tables", tables.c_str(), OKButtonSet, InformationIcon);
}

static void ListFunctions(BinaryView* bv) {
    bnsql::QueryEngine qe(bv);
    auto result = qe.query("SELECT hex(address), name, size FROM funcs ORDER BY address LIMIT 100");
    if (!result.success) { LogError("Error: %s", result.error.c_str()); return; }
    LogInfo("%s", result.to_string().c_str());
}

static void ListImports(BinaryView* bv) {
    bnsql::QueryEngine qe(bv);
    auto result = qe.query("SELECT hex(address), module, name FROM imports ORDER BY module LIMIT 100");
    if (!result.success) { LogError("Error: %s", result.error.c_str()); return; }
    LogInfo("%s", result.to_string().c_str());
}

static void ListStrings(BinaryView* bv) {
    bnsql::QueryEngine qe(bv);
    auto result = qe.query("SELECT hex(address), length, content FROM strings WHERE length > 4 ORDER BY length DESC LIMIT 100");
    if (!result.success) { LogError("Error: %s", result.error.c_str()); return; }
    LogInfo("%s", result.to_string().c_str());
}

// ============================================================================
// HTTP Server Commands
// ============================================================================

#ifdef BNSQL_HAS_HTTP
static std::unique_ptr<xsql::thinclient::http_query_server> g_http_server;
static std::mutex g_http_server_mutex;
static Ref<BinaryView> g_http_server_bv;

static void StartHTTPServer(BinaryView* bv) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    if (g_http_server && g_http_server->is_running()) {
        std::string msg = "HTTP server already running on port " + std::to_string(g_http_server->port());
        ShowMessageBox("BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
        return;
    }

    std::string port_str;
    if (!GetTextLineInput(port_str, "HTTP Server Port", "Enter port (0 for random, default: 8080):")) return;

    int port = 8080;
    if (!port_str.empty()) {
        try { port = std::stoi(port_str); if (port < 0 || port > 65535) throw 0; }
        catch (...) { ShowMessageBox("Error", "Invalid port", OKButtonSet, ErrorIcon); return; }
    }

    g_http_server_bv = bv;

    xsql::thinclient::http_query_server_config cfg;
    cfg.tool_name = "bnsql";
    cfg.help_text = bnsql::http_help_text();
    cfg.port = port;
    cfg.bind_address = "127.0.0.1";
    // Background server (no main-thread queue); serialize concurrent requests
    // since a per-request QueryEngine over the shared BinaryView isn't
    // concurrency-safe (matches the prior timed_mutex behavior).
    cfg.use_queue = false;
    cfg.serialize_requests = true;
    cfg.statement_executor = [](const std::string& stmt, xsql::ScriptStatementResult& out) {
        if (!g_http_server_bv) {
            out.success = false;
            out.error = "No binary loaded";
            return;
        }
        bnsql::QueryEngine qe(g_http_server_bv);
        auto r = qe.query(stmt);
        out.columns = r.columns;
        out.rows.reserve(r.rows.size());
        for (const auto& row : r.rows) out.rows.push_back(row.values);
        out.elapsed_ms = r.elapsed_ms;
        out.success = r.success;
        out.error = r.error;
    };
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
    std::string msg = "HTTP server started on port " + std::to_string(actual_port) +
        "\n\nEndpoints:\n"
        "  GET  /help     - API documentation\n"
        "  POST /query    - Execute SQL\n"
        "  GET  /status   - Health check\n\n"
        "Example:\n"
        "  curl http://127.0.0.1:" + std::to_string(actual_port) + "/help\n"
        "  curl -X POST http://127.0.0.1:" + std::to_string(actual_port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"";
    LogInfo("[bnsql] HTTP server started on port %d", actual_port);
    ShowMessageBox("BNSQL HTTP Server", msg.c_str(), OKButtonSet, InformationIcon);
}

static void StopHTTPServer(BinaryView*) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    if (!g_http_server || !g_http_server->is_running()) {
        ShowMessageBox("BNSQL HTTP Server", "HTTP server is not running", OKButtonSet, InformationIcon);
        return;
    }
    int port = g_http_server->port();
    g_http_server->stop();
    g_http_server.reset();
    g_http_server_bv = nullptr;
    LogInfo("[bnsql] HTTP server stopped");
    ShowMessageBox("BNSQL HTTP Server", ("HTTP server stopped (was on port " + std::to_string(port) + ")").c_str(), OKButtonSet, InformationIcon);
}

static void HTTPServerStatus(BinaryView*) {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    std::string msg;
    if (g_http_server && g_http_server->is_running()) {
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
    LogInfo("bnsql: Initializing SQL interface for Binary Ninja");

    PluginCommand::Register("BNSQL\\Run SQL Query...", "Execute a SQL query", RunSQLQuery);
    PluginCommand::Register("BNSQL\\Show Tables", "Show available SQL tables", ShowTables);
    PluginCommand::Register("BNSQL\\List Functions", "List functions via SQL", ListFunctions);
    PluginCommand::Register("BNSQL\\List Imports", "List imports via SQL", ListImports);
    PluginCommand::Register("BNSQL\\List Strings", "List strings via SQL", ListStrings);
#ifdef BNSQL_HAS_HTTP
    PluginCommand::Register("BNSQL\\HTTP Server\\Start HTTP Server...", "Start HTTP REST API server", StartHTTPServer);
    PluginCommand::Register("BNSQL\\HTTP Server\\Stop HTTP Server", "Stop HTTP server", StopHTTPServer);
    PluginCommand::Register("BNSQL\\HTTP Server\\HTTP Server Status", "Show HTTP server status", HTTPServerStatus);
#endif

    LogInfo("bnsql: Plugin initialized successfully");
    return true;
}

} // extern "C"
