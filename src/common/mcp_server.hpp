#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace bnsql {

// Callbacks for handling requests
// QueryCallback: Direct SQL execution
// AskCallback: Natural language query (requires AI agent)
using QueryCallback = std::function<std::string(const std::string& sql)>;
using AskCallback = std::function<std::string(const std::string& question)>;

// Internal command structure for cross-thread execution
struct MCPPendingCommand {
    enum class Type { Query, Ask };
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

    // Start MCP server on given port with callbacks
    // Returns actual port used (may differ if auto-assigned)
    // Callbacks will be called on the main thread (in wait())
    // bind_addr: "127.0.0.1" for localhost only, "0.0.0.0" for all interfaces
    // If ask_cb is nullptr, the agent_ask tool will not be registered
    int start(int port, QueryCallback query_cb, AskCallback ask_cb = nullptr,
              const std::string& bind_addr = "127.0.0.1");

    // Block until server stops, processing commands on the calling thread
    // This is where query_cb and ask_cb get called
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

    // Callbacks stored for main thread execution
    QueryCallback query_cb_;
    AskCallback ask_cb_;

    // Forward declaration - impl hides fastmcpp
    class Impl;
    std::unique_ptr<Impl> impl_;

    void complete_pending_commands(const std::string& result);
};

// Format MCP server info for display
std::string format_mcp_info(
    const std::string& database_name,
    size_t function_count,
    const std::string& url,
    bool has_agent
);

} // namespace bnsql
