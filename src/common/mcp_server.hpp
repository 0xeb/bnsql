// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace bnsql {

// Callback for SQL query execution
using QueryCallback = std::function<std::string(const std::string& sql)>;

// Internal command structure for cross-thread execution
struct MCPPendingCommand {
    enum class Type { Query };
    Type type;
    std::string input;
    std::string result;
    bool completed = false;
    std::mutex done_mutex;
    std::condition_variable done_cv;
};

struct MCPQueueResult {
    bool success;
    std::string payload;
};

class MCPServer {
public:
    MCPServer();
    ~MCPServer();

    // Non-copyable
    MCPServer(const MCPServer&) = delete;
    MCPServer& operator=(const MCPServer&) = delete;

    // Start MCP server on given port with query callback
    // Returns actual port used (may differ if auto-assigned)
    // Callbacks will be called on the main thread (in wait())
    // bind_addr: "127.0.0.1" for localhost only, "0.0.0.0" for all interfaces
    int start(int port, QueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1");

    // Block until server stops, processing commands on the calling thread
    // This is where query_cb gets called
    void wait();

    // Stop the server
    void stop();

    // Check if running
    bool is_running() const { return running_.load(); }

    // Get the port the server is listening on
    int port() const { return port_; }

    // Set interrupt check function (called during wait loop)
    void set_interrupt_check(std::function<bool()> check);

    // Queue a command for execution on the main thread (called by MCP tool handlers)
    MCPQueueResult queue_and_wait(MCPPendingCommand::Type type, const std::string& input);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    // Command queue for cross-thread execution
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::shared_ptr<MCPPendingCommand>> pending_commands_;

    // Callback stored for main thread execution
    QueryCallback query_cb_;

    // Forward declaration - impl hides fastmcpp
    class Impl;
    std::unique_ptr<Impl> impl_;

    void complete_pending_commands(const std::string& result);
};

// Format MCP server info for display
std::string format_mcp_info(
    const std::string& database_name,
    size_t function_count,
    const std::string& url
);

} // namespace bnsql
