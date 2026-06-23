// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

/**
 * bnsql_http_routes.hpp - Shared HTTP route setup for BNSQL
 *
 * Used by both CLI (run_http_mode, .http REPL command) and plugin.
 * Requires BNSQL_HAS_HTTP / XSQL_HAS_THINCLIENT.
 */

#ifdef BNSQL_HAS_HTTP

#include <bnsql/bnsql.hpp>
#include <bnsql/runtime_settings.hpp>
#include <httplib.h>
#include <xsql/thinclient/json_helpers.hpp>

#include <atomic>
#include <xsql/query_script.hpp>

#include <chrono>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace bnsql {

// Build JSON response from query result
inline std::string query_result_to_json(const bnsql::QueryResult& result) {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (result.success ? "true" : "false");

    if (result.success) {
        json << ",\"columns\":[";
        for (size_t i = 0; i < result.columns.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << xsql::thinclient::json_escape(result.columns[i]) << "\"";
        }
        json << "]";

        json << ",\"rows\":[";
        size_t row_idx = 0;
        for (const auto& row : result) {
            if (row_idx++ > 0) json << ",";
            json << "[";
            for (size_t c = 0; c < row.values.size(); c++) {
                if (c > 0) json << ",";
                json << "\"" << xsql::thinclient::json_escape(row.values[c]) << "\"";
            }
            json << "]";
        }
        json << "]";
        json << ",\"row_count\":" << result.rows.size();
    } else {
        json << ",\"error\":\"" << xsql::thinclient::json_escape(result.error) << "\"";
    }

    // Timing metadata
    if (result.elapsed_ms > 0.0) {
        json << ",\"elapsed_ms\":" << std::fixed << std::setprecision(1) << result.elapsed_ms;
    }
    if (result.timed_out) {
        json << ",\"timed_out\":true";
    }

    // Warnings
    if (!result.warnings.empty()) {
        json << ",\"warnings\":[";
        for (size_t i = 0; i < result.warnings.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << xsql::thinclient::json_escape(result.warnings[i]) << "\"";
        }
        json << "]";
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
  GET  /          - Welcome message
  GET  /help      - This documentation (for LLM discovery)
  POST /query     - Execute SQL (body = raw SQL, single or semicolon-separated script, response = canonical envelope)
  GET  /status    - Server health, function count, and runtime settings
  GET  /settings  - Current runtime settings (JSON)
  POST /shutdown  - Stop server

Tables:
  funcs          - Functions (address, name, prototype, size, comment)
  strings        - String literals (address, content, length)
  imports        - Imported functions (address, name, module)
  xrefs          - Cross-references (from_ea, to_ea, is_code)
  segments       - Memory segments (start_ea, end_ea, name, perm)
  blocks         - Basic blocks (func_ea, start_ea, end_ea)
  instructions   - Instructions (address, func_addr, mnemonic, disasm)
  instruction_operands - Token-level operand metadata (func_addr, insn_addr, operand_index, ...)
  comments       - Address comments
  names          - Named locations
  entries        - Entry points and exports
  db_info        - Database metadata
  entities       - Unified discovery (functions/symbols/segments/imports/strings/types)
  capabilities   - Runtime feature/capability matrix
  pseudocode     - Decompiled code lines (func_addr, line_num, line, ea, comment)
  hlil_vars      - HLIL variables (name/type writable, filter by func_addr!)
  hlil_calls     - HLIL function calls (filter by func_addr!)
  types          - Defined types (id, name, kind, size, is_struct, is_enum, ...)
  type_members   - Struct/union member fields (type_id, member_name, offset, type)
  type_enum_values - Enum constant values (type_id, value_name, value)
  func_signatures  - Function parameter/return types (func_addr, arg_index, arg_type)
  patches        - Patched bytes (address, original_byte, patched_byte, status) [read-write]

Views:
  disasm_calls     - Call sites with callee info (func_addr, ea, callee_name)
  function_chunks  - Function address ranges (func_addr, chunk_start, chunk_end)
  types_v_structs  - Struct types only
  types_v_enums    - Enum types only

SQL Functions:
  hex(addr)           - Format address as hex
  disasm(addr)        - Disassembly at address
  decompile(addr)     - Full pseudocode for function
  func_at(addr)       - Function name at address
  xrefs_to(addr)      - JSON array of xrefs to address
  xrefs_from(addr)    - JSON array of xrefs from address
  entities_search(p,l,o) - JSON entity discovery (pattern/limit/offset)

Runtime Controls (PRAGMA):
  PRAGMA bnsql.query_timeout_ms          - Get/set query timeout (0=disabled, max 3600000)
  PRAGMA bnsql.queue_admission_timeout_ms - Get/set HTTP queue wait timeout
  PRAGMA bnsql.max_queue                 - Get/set max queued HTTP requests (0=unbounded)
  PRAGMA bnsql.hints_enabled             - Get/set query hint warnings (1/0)
  PRAGMA bnsql.timeout_push = <ms>       - Push timeout onto stack
  PRAGMA bnsql.timeout_pop               - Pop timeout from stack

Writable Columns:
  funcs.name / funcs.prototype / funcs.comment
  names.name
  pseudocode.comment / pseudocode.comment_placement
  hlil_vars.name / hlil_vars.type / hlil_vars.comment
  patches.patched_byte (INSERT/DELETE supported)

Example Queries:
  SELECT name, hex(address), size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT content FROM strings WHERE content LIKE '%password%';
  SELECT module, COUNT(*) FROM imports GROUP BY module;
  SELECT name, kind FROM entities WHERE name LIKE '%main%' LIMIT 20;
  SELECT entities_search('DName', 20, 0);
  SELECT decompile(address) FROM funcs WHERE name = 'main';
  PRAGMA bnsql.query_timeout_ms = 5000;

Response Format (canonical script envelope, single = array of one):
  {
    "success": true,
    "statement_count": N,
    "results": [
      {"statement_index": 0, "success": true,
       "columns": [...], "rows": [[...]], "row_count": N,
       "elapsed_ms": 12.3, "error": null},
      ...
    ],
    "row_count_total": N,
    "elapsed_ms_total": 12.3,
    "first_error_index": null    // or index of earliest failed statement
  }
  Splitter failure (e.g. unterminated quote):
    {"success": false, "statement_count": 0, "results": [],
     "parse_error": "<message>", ...}
  Options (query string): continue_on_error=1, include_sql=1,
                          format=json|text|csv|tsv (default json; text/csv/tsv
                          are for terminal/pipe use, agents should consume json)

Authentication (if enabled):
  Header: Authorization: Bearer <token>
  Or:     X-XSQL-Token: <token>

Example:
  curl http://localhost:8080/help
  curl -X POST http://localhost:8080/query -d "SELECT name FROM funcs LIMIT 5"
  curl http://localhost:8080/settings
)";
}

// Build JSON from RuntimeSettingsSnapshot
inline std::string settings_to_json(const RuntimeSettingsSnapshot& snap) {
    std::ostringstream json;
    json << "{"
         << "\"query_timeout_ms\":" << snap.query_timeout_ms
         << ",\"queue_admission_timeout_ms\":" << snap.queue_admission_timeout_ms
         << ",\"max_queue\":" << snap.max_queue
         << ",\"hints_enabled\":" << (snap.hints_enabled ? "true" : "false")
         << ",\"timeout_stack_depth\":" << snap.timeout_stack_depth
         << "}";
    return json.str();
}


} // namespace bnsql

#endif // BNSQL_HAS_HTTP
