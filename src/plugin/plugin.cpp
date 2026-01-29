// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * plugin.cpp - Binary Ninja plugin for bnsql
 *
 * Registers bnsql functionality with Binary Ninja:
 *   - Menu commands for SQL queries
 *   - Socket server for remote queries
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
#include <xsql/socket/server.hpp>
#include "binaryninjaapi.h"

#include <memory>
#include <mutex>
#include <atomic>

using namespace BinaryNinja;

// ============================================================================
// Server State
// ============================================================================

static std::unique_ptr<xsql::socket::Server> g_server;
static std::mutex g_server_mutex;
static Ref<BinaryView> g_server_bv;
static std::atomic<int> g_server_port{0};

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
// Server Commands
// ============================================================================

static void StartServer(BinaryView* bv) {
    std::lock_guard<std::mutex> lock(g_server_mutex);
    if (g_server && g_server->is_running()) {
        std::string msg = "Server already running on port " + std::to_string(g_server_port.load());
        ShowMessageBox("BNSQL Server", msg.c_str(), OKButtonSet, InformationIcon);
        return;
    }

    std::string port_str;
    if (!GetTextLineInput(port_str, "Server Port", "Enter port (default: 13337):")) return;

    int port = 13337;
    if (!port_str.empty()) {
        try { port = std::stoi(port_str); if (port < 1 || port > 65535) throw 0; }
        catch (...) { ShowMessageBox("Error", "Invalid port", OKButtonSet, ErrorIcon); return; }
    }

    g_server_bv = bv;

    xsql::socket::ServerConfig config;
    config.port = port;
    config.bind_address = "127.0.0.1";
    config.verbose = true;

    g_server = std::make_unique<xsql::socket::Server>(config);

    g_server->set_query_handler([](const std::string& sql) -> xsql::socket::QueryResult {
        if (!g_server_bv) return xsql::socket::QueryResult::fail("No binary loaded");
        bnsql::QueryEngine qe(g_server_bv);
        auto result = qe.query(sql);
        xsql::socket::QueryResult qr;
        qr.success = result.success;
        qr.error = result.error;
        qr.columns = result.columns;
        for (const auto& row : result) qr.rows.push_back(row.values);
        return qr;
    });

    g_server->set_log_func([](const std::string& msg) { LogInfo("[bnsql] %s", msg.c_str()); });

    if (g_server->run_async(port)) {
        g_server_port = port;
        std::string msg = "Server started on port " + std::to_string(port) + "\n\nConnect with:\n  bnsql --remote localhost:" + std::to_string(port);
        LogInfo("[bnsql] Server started on port %d", port);
        ShowMessageBox("BNSQL Server", msg.c_str(), OKButtonSet, InformationIcon);
    } else {
        g_server.reset(); g_server_bv = nullptr;
        ShowMessageBox("Error", "Failed to start server", OKButtonSet, ErrorIcon);
    }
}

static void StopServer(BinaryView*) {
    std::lock_guard<std::mutex> lock(g_server_mutex);
    if (!g_server || !g_server->is_running()) {
        ShowMessageBox("BNSQL Server", "Server is not running", OKButtonSet, InformationIcon);
        return;
    }
    g_server->stop(); g_server.reset(); g_server_bv = nullptr;
    int port = g_server_port.exchange(0);
    LogInfo("[bnsql] Server stopped");
    ShowMessageBox("BNSQL Server", ("Server stopped (was on port " + std::to_string(port) + ")").c_str(), OKButtonSet, InformationIcon);
}

static void ServerStatus(BinaryView*) {
    std::lock_guard<std::mutex> lock(g_server_mutex);
    std::string msg;
    if (g_server && g_server->is_running()) {
        int port = g_server_port.load();
        msg = "Server is RUNNING on port " + std::to_string(port) + "\n\nConnect with:\n  bnsql --remote localhost:" + std::to_string(port);
    } else {
        msg = "Server is STOPPED\n\nUse Start Server to enable remote connections.";
    }
    ShowMessageBox("BNSQL Server Status", msg.c_str(), OKButtonSet, InformationIcon);
}

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
    PluginCommand::Register("BNSQL\\Server\\Start Server...", "Start SQL server for remote connections", StartServer);
    PluginCommand::Register("BNSQL\\Server\\Stop Server", "Stop SQL server", StopServer);
    PluginCommand::Register("BNSQL\\Server\\Server Status", "Show server status", ServerStatus);

    LogInfo("bnsql: Plugin initialized successfully");
    return true;
}

} // extern "C"
