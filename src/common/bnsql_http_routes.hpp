#pragma once

/**
 * bnsql_http_routes.hpp - Shared HTTP route setup for BNSQL
 *
 * Used by both CLI (run_http_mode, .http REPL command) and plugin.
 * Requires BNSQL_HAS_HTTP / XSQL_HAS_THINCLIENT.
 */

#ifdef BNSQL_HAS_HTTP

#include <bnsql/bnsql.hpp>
#include <httplib.h>

#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace bnsql {

// JSON escape helper
inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    for (char ch : s) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(ch));
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

// Build JSON response from query result
inline std::string query_result_to_json(const bnsql::QueryResult& result) {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (result.success ? "true" : "false");

    if (result.success) {
        json << ",\"columns\":[";
        for (size_t i = 0; i < result.columns.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << json_escape(result.columns[i]) << "\"";
        }
        json << "]";

        json << ",\"rows\":[";
        size_t row_idx = 0;
        for (const auto& row : result) {
            if (row_idx++ > 0) json << ",";
            json << "[";
            for (size_t c = 0; c < row.values.size(); c++) {
                if (c > 0) json << ",";
                json << "\"" << json_escape(row.values[c]) << "\"";
            }
            json << "]";
        }
        json << "]";
        json << ",\"row_count\":" << result.rows.size();
    } else {
        json << ",\"error\":\"" << json_escape(result.error) << "\"";
    }

    json << "}";
    return json.str();
}

// Help text served at /help endpoint
inline const char* http_help_text() {
    return R"(BNSQL HTTP REST API
===================

SQL interface for Binary Ninja databases via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation (for LLM discovery)
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health and function count
  GET  /health   - Alias for /status
  POST /shutdown - Stop server

Tables:
  funcs          - Functions (address, name, size)
  strings        - String literals (address, content, length)
  imports        - Imported functions (address, name, module)
  xrefs          - Cross-references (from_ea, to_ea, is_code)
  segments       - Memory segments (start_ea, end_ea, name, perm)
  blocks         - Basic blocks (func_ea, start_ea, end_ea)
  instructions   - Instructions (address, func_addr, mnemonic, disasm)
  comments       - Address comments
  names          - Named locations
  entries        - Entry points and exports
  db_info        - Database metadata
  pseudocode     - Decompiled code lines (filter by func_addr!)
  hlil_vars      - HLIL variables (filter by func_addr!)
  hlil_calls     - HLIL function calls (filter by func_addr!)

SQL Functions:
  hex(addr)           - Format address as hex
  disasm(addr)        - Disassembly at address
  decompile(addr)     - Full pseudocode for function
  func_at(addr)       - Function name at address
  xrefs_to(addr)      - JSON array of xrefs to address
  xrefs_from(addr)    - JSON array of xrefs from address

Example Queries:
  SELECT name, hex(address), size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT content FROM strings WHERE content LIKE '%password%';
  SELECT module, COUNT(*) FROM imports GROUP BY module;
  SELECT decompile(address) FROM funcs WHERE name = 'main';

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Authentication (if enabled):
  Header: Authorization: Bearer <token>
  Or:     X-XSQL-Token: <token>

Example:
  curl http://localhost:8081/help
  curl -X POST http://localhost:8081/query -d "SELECT name FROM funcs LIMIT 5"
)";
}

// Query callback type: takes SQL string, returns QueryResult
using HttpQueryFn = std::function<bnsql::QueryResult(const std::string& sql)>;

/**
 * Set up standard BNSQL HTTP routes on an httplib::Server.
 *
 * @param svr        The httplib server to add routes to
 * @param query_fn   Query callback (thread-safe — caller must serialize if needed)
 * @param auth_token Optional auth token (empty = no auth)
 * @param port       Port number (for display in welcome message)
 */
inline void setup_http_routes(
    httplib::Server& svr,
    HttpQueryFn query_fn,
    const std::string& auth_token,
    int port)
{
    // Shared query mutex for thread safety
    auto query_mutex = std::make_shared<std::mutex>();
    auto query_fn_ptr = std::make_shared<HttpQueryFn>(std::move(query_fn));
    auto auth = std::make_shared<std::string>(auth_token);

    auto check_auth = [auth](const httplib::Request& req, httplib::Response& res) -> bool {
        if (auth->empty()) return true;
        std::string token;
        if (req.has_header("X-XSQL-Token")) {
            token = req.get_header_value("X-XSQL-Token");
        } else if (req.has_header("Authorization")) {
            const std::string a = req.get_header_value("Authorization");
            if (a.rfind("Bearer ", 0) == 0) token = a.substr(7);
        }
        if (token == *auth) return true;
        res.status = 401;
        res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
        return false;
    };

    // GET / - Welcome message
    svr.Get("/", [port](const httplib::Request&, httplib::Response& res) {
        std::string welcome = "BNSQL HTTP Server\n\n"
            "Endpoints:\n"
            "  GET  /help     - API documentation\n"
            "  POST /query    - Execute SQL query\n"
            "  GET  /status   - Health check\n"
            "  POST /shutdown - Stop server\n\n"
            "Example:\n"
            "  curl http://localhost:" + std::to_string(port) + "/help\n"
            "  curl -X POST http://localhost:" + std::to_string(port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
        res.set_content(welcome, "text/plain");
    });

    // GET /help - API documentation (public, no auth)
    svr.Get("/help", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(http_help_text(), "text/plain");
    });

    // POST /query - Execute SQL
    svr.Post("/query", [query_fn_ptr, query_mutex, check_auth](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;

        std::string sql = req.body;
        if (sql.empty()) {
            res.status = 400;
            res.set_content("{\"success\":false,\"error\":\"Empty query\"}", "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(*query_mutex);
        auto result = (*query_fn_ptr)(sql);
        res.set_content(query_result_to_json(result), "application/json");
    });

    // GET /status - Health check
    svr.Get("/status", [query_fn_ptr, check_auth](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        auto result = (*query_fn_ptr)("SELECT COUNT(*) FROM funcs");
        std::string func_count = result.success && !result.empty() ? result.rows[0][0] : "?";
        res.set_content("{\"success\":true,\"status\":\"ok\",\"tool\":\"bnsql\",\"functions\":" + func_count + "}", "application/json");
    });

    // GET /health - Alias for /status
    svr.Get("/health", [query_fn_ptr, check_auth](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        auto result = (*query_fn_ptr)("SELECT COUNT(*) FROM funcs");
        std::string func_count = result.success && !result.empty() ? result.rows[0][0] : "?";
        res.set_content("{\"success\":true,\"status\":\"ok\",\"tool\":\"bnsql\",\"functions\":" + func_count + "}", "application/json");
    });

    // POST /shutdown - Graceful shutdown
    svr.Post("/shutdown", [&svr, check_auth](const httplib::Request& req, httplib::Response& res) {
        if (!check_auth(req, res)) return;
        res.set_content("{\"success\":true,\"message\":\"Shutting down\"}", "application/json");
        std::thread([&svr] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            svr.stop();
        }).detach();
    });
}

} // namespace bnsql

#endif // BNSQL_HAS_HTTP
