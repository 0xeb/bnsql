#include "mcp_server.hpp"

#include <fastmcpp/mcp/handler.hpp>
#include <fastmcpp/server/sse_server.hpp>
#include <fastmcpp/tools/manager.hpp>
#include <fastmcpp/tools/tool.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <sstream>

namespace bnsql {

using Json = nlohmann::json;

class MCPServer::Impl {
public:
    fastmcpp::tools::ToolManager tool_manager;
    std::unique_ptr<fastmcpp::server::SseServerWrapper> server;
};

MCPServer::MCPServer() = default;

MCPServer::~MCPServer() {
    stop();
}

MCPQueueResult MCPServer::queue_and_wait(MCPPendingCommand::Type type, const std::string& input) {
    if (!running_.load()) {
        return {false, "Error: MCP server is not running"};
    }

    auto cmd = std::make_shared<MCPPendingCommand>();
    cmd->type = type;
    cmd->input = input;
    cmd->completed = false;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_commands_.push(cmd);
    }
    queue_cv_.notify_one();

    {
        std::unique_lock<std::mutex> lock(cmd->done_mutex);
        cmd->done_cv.wait(lock, [&]() { return cmd->completed || !running_.load(); });
    }

    if (!cmd->completed) {
        return {false, "Error: MCP server stopped"};
    }

    return {true, cmd->result};
}

int MCPServer::start(int port, QueryCallback query_cb, AskCallback ask_cb,
                     const std::string& bind_addr) {
    if (running_.load()) {
        return port_;
    }

    query_cb_ = query_cb;
    ask_cb_ = ask_cb;
    bind_addr_ = bind_addr;

    impl_ = std::make_unique<Impl>();

    // Register sql_query tool - direct SQL execution
    Json query_input_schema = {
        {"type", "object"},
        {"properties", {
            {"query", {
                {"type", "string"},
                {"description", "SQL query to execute against the Binary Ninja database"}
            }}
        }},
        {"required", Json::array({"query"})}
    };

    Json query_output_schema = {
        {"type", "object"},
        {"properties", {
            {"result", {{"type", "string"}}},
            {"success", {{"type", "boolean"}}}
        }}
    };

    fastmcpp::tools::Tool sql_query_tool{
        "sql_query",
        query_input_schema,
        query_output_schema,
        [this](const Json& args) -> Json {
            std::string query = args.value("query", "");
            if (query.empty()) {
                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", "Error: missing query"}}
                    })},
                    {"isError", true}
                };
            }

            auto result = queue_and_wait(MCPPendingCommand::Type::Query, query);

            // MCP tools/call expects content array format
            return Json{
                {"content", Json::array({
                    Json{{"type", "text"}, {"text", result.payload}}
                })},
                {"isError", !result.success}
            };
        }
    };
    sql_query_tool.set_description("Execute a SQL query against the Binary Ninja database and return results");
    impl_->tool_manager.register_tool(sql_query_tool);

    // Register agent_ask tool - natural language query (if ask_cb provided)
    if (ask_cb_) {
        Json ask_input_schema = {
            {"type", "object"},
            {"properties", {
                {"question", {
                    {"type", "string"},
                    {"description", "Natural language question about the binary (e.g., 'What functions call malloc?')"}
                }}
            }},
            {"required", Json::array({"question"})}
        };

        Json ask_output_schema = {
            {"type", "object"},
            {"properties", {
                {"response", {{"type", "string"}}},
                {"success", {{"type", "boolean"}}}
            }}
        };

        fastmcpp::tools::Tool agent_ask_tool{
            "agent_ask",
            ask_input_schema,
            ask_output_schema,
            [this](const Json& args) -> Json {
                std::string question = args.value("question", "");
                if (question.empty()) {
                    return Json{
                        {"content", Json::array({
                            Json{{"type", "text"}, {"text", "Error: missing question"}}
                        })},
                        {"isError", true}
                    };
                }

                auto result = queue_and_wait(MCPPendingCommand::Type::Ask, question);

                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", result.payload}}
                    })},
                    {"isError", !result.success}
                };
            }
        };
        agent_ask_tool.set_description("Ask a natural language question about the binary - AI translates to SQL and returns results");
        impl_->tool_manager.register_tool(agent_ask_tool);
    }

    // Create MCP handler
    std::unordered_map<std::string, std::string> descriptions = {
        {"sql_query", "Execute a SQL query against the Binary Ninja database and return results"}
    };
    if (ask_cb_) {
        descriptions["agent_ask"] = "Ask a natural language question about the binary - AI translates to SQL and returns results";
    }

    auto handler = fastmcpp::mcp::make_mcp_handler(
        "bnsql",
        "1.0.0",
        impl_->tool_manager,
        descriptions
    );

    // Create and start SSE server
    impl_->server = std::make_unique<fastmcpp::server::SseServerWrapper>(
        handler,
        bind_addr_,
        port,
        "/sse",
        "/messages"
    );

    if (!impl_->server->start()) {
        impl_.reset();
        return -1;
    }

    port_ = port;
    running_.store(true);

    return port_;
}

void MCPServer::set_interrupt_check(std::function<bool()> check) {
    interrupt_check_ = check;
}

void MCPServer::wait() {
    while (running_.load()) {
        if (interrupt_check_ && interrupt_check_()) {
            stop();
            break;
        }

        std::shared_ptr<MCPPendingCommand> cmd;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
                                   [this]() { return !pending_commands_.empty() || !running_.load(); })) {
                if (!pending_commands_.empty()) {
                    cmd = pending_commands_.front();
                    pending_commands_.pop();
                }
            }
        }

        if (cmd) {
            try {
                if (cmd->type == MCPPendingCommand::Type::Query && query_cb_) {
                    cmd->result = query_cb_(cmd->input);
                } else if (cmd->type == MCPPendingCommand::Type::Ask && ask_cb_) {
                    cmd->result = ask_cb_(cmd->input);
                } else {
                    cmd->result = "Error: No handler for command type";
                }
            } catch (const std::exception& e) {
                cmd->result = std::string("Error: ") + e.what();
            }

            {
                std::lock_guard<std::mutex> lock(cmd->done_mutex);
                cmd->completed = true;
            }
            cmd->done_cv.notify_one();
        }
    }
}

void MCPServer::stop() {
    running_.store(false);
    queue_cv_.notify_all();
    complete_pending_commands("Error: MCP server stopped");

    if (impl_ && impl_->server) {
        impl_->server->stop();
    }
}

void MCPServer::complete_pending_commands(const std::string& result) {
    std::queue<std::shared_ptr<MCPPendingCommand>> pending;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        std::swap(pending, pending_commands_);
    }

    while (!pending.empty()) {
        auto cmd = pending.front();
        pending.pop();
        if (!cmd) continue;

        {
            std::lock_guard<std::mutex> lock(cmd->done_mutex);
            if (!cmd->completed) {
                cmd->result = result;
                cmd->completed = true;
            }
        }
        cmd->done_cv.notify_one();
    }
}

std::string format_mcp_info(
    const std::string& database_name,
    size_t function_count,
    const std::string& url,
    bool has_agent
) {
    std::ostringstream ss;
    ss << "MCP SERVER ACTIVE\n";
    ss << "Database: " << database_name << "\n";
    ss << "Functions: " << function_count << "\n\n";

    ss << "AVAILABLE TOOLS:\n";
    ss << "  sql_query   - Execute SQL query directly\n";
    if (has_agent) {
        ss << "  agent_ask   - Ask natural language question (AI-powered)\n";
    }
    ss << "\n";

    ss << "SSE Endpoint: " << url << "/sse\n";
    ss << "Message Endpoint: " << url << "/messages\n\n";

    ss << "MCP CLIENT CONFIGURATION:\n";
    ss << "Add to your MCP client (e.g., Claude Desktop):\n";
    ss << "{\n";
    ss << "  \"mcpServers\": {\n";
    ss << "    \"bnsql\": {\n";
    ss << "      \"url\": \"" << url << "/sse\"\n";
    ss << "    }\n";
    ss << "  }\n";
    ss << "}\n\n";

    ss << "EXAMPLE CURL COMMANDS:\n";
    ss << "  # List available tools\n";
    ss << "  curl -X POST " << url << "/messages \\\n";
    ss << "    -H \"Content-Type: application/json\" \\\n";
    ss << "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'\n\n";

    ss << "  # Execute SQL query\n";
    ss << "  curl -X POST " << url << "/messages \\\n";
    ss << "    -H \"Content-Type: application/json\" \\\n";
    ss << "    -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"sql_query\",\"arguments\":{\"query\":\"SELECT name FROM functions LIMIT 5\"}}}'\n";

    return ss.str();
}

} // namespace bnsql
