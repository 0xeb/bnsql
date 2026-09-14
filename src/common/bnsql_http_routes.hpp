// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * bnsql_http_routes.hpp - Shared HTTP route setup for BNSQL
 *
 * Used by both CLI (run_http_mode, .http REPL command) and plugin.
 * Requires BNSQL_HAS_HTTP / XSQL_HAS_THINCLIENT.
 */

#ifdef BNSQL_HAS_HTTP

#include <bnsql/bnsql.hpp>
#include <bnsql/num_parse.hpp>
#include <bnsql/runtime_settings.hpp>
#include "bnsql_version.hpp"
#include <httplib.h>
#include <xsql/json.hpp>
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
  funcs          - Functions (addr, name, prototype, size, comment)
  strings        - String literals (addr, content, length)
  imports        - Imported functions (addr, name, module)
  xrefs          - Cross-references (from_addr, to_addr, is_code)
  segments       - Memory segments (start_addr, end_addr, name, class, perm) [writable: INSERT/DELETE/UPDATE]
  blocks         - Basic blocks (func_addr, start_addr, end_addr)
  cfg_edges      - Control-flow edges (func_addr, from_addr, to_addr, edge_type)
  switch_tables  - Reconstructed switch metadata
  function_frames - Per-function stack-frame summaries
  data_items     - Defined data variables and best-effort values
  dominators     - Dominator-tree nodes
  post_dominators - Post-dominator-tree nodes
  loops          - Natural-loop summaries
  instructions   - Instructions (addr, func_addr, mnemonic, disasm)
  instruction_operands - One row per disassembly operand (addr, func_addr, operand_index, ...)
  bytes          - Memory bytes
  byte_search    - Pattern search (requires hidden pattern input)
  comments       - Address comments
  bookmarks      - Binary Ninja user-data tags [read-write]
  names          - Named locations
  entries        - Entry points and exports
  binary         - Database metadata
  entities       - Unified discovery (functions/symbols/segments/imports/strings/types)
  capabilities   - Runtime feature/capability matrix
  pseudocode     - Decompiled code lines (func_addr, line_num, line, addr, comment)
  hlil_vars      - HLIL variables (name/type writable, filter by func_addr!)
  hlil_calls     - HLIL function calls (filter by func_addr!)
  mlil           - Six-rung LLIL/MLIL/HLIL operation stream (filter by func_addr!)
  mlil_operands  - Value operands for mlil rows (filter by func_addr!)
  types          - Defined types (id, name, kind, size, is_struct, is_enum, ...)
  type_members   - Struct/union member fields (type_id, member_name, offset, type)
  type_enum_values - Enum constant values (type_id, value_name, value)
  func_signatures  - Function parameter/return types (func_addr, arg_index, arg_type)
  patches        - Patched bytes (addr, original_byte, patched_byte, status) [read-write]

Views:
  disasm_calls     - Call sites with callee info (func_addr, addr, callee_name)
  function_chunks  - Function address ranges (func_addr, chunk_start, chunk_end)
  types_v_structs  - Struct types only
  types_v_enums    - Enum types only
  ir_ops            - Canonical low-level IR operations
  ir_operands       - Canonical IR value operands
  ir_maturities     - Discover the six Binary Ninja IL rungs
  ir_v_calls / ir_v_mem_reads / ir_v_mem_writes / ir_v_branches / ir_v_arith

SQL Functions:
  hex(addr)           - Format address as hex
  disasm(addr)        - Disassembly at address
  decompile(addr)     - Full pseudocode for function
  func_at(addr)       - Function name at address
  xrefs_to(addr)      - JSON array of xrefs to address
  xrefs_from(addr)    - JSON array of xrefs from address
  entities_search(p,l,o) - JSON entity discovery (pattern/limit/offset)

Runtime Controls (runtime_settings table — read via SELECT, change via UPDATE):
  UPDATE runtime_settings SET value='<v>' WHERE key='query_timeout_ms'          - query timeout (0=disabled, max 3600000)
  UPDATE runtime_settings SET value='<v>' WHERE key='queue_admission_timeout_ms' - HTTP queue wait timeout
  UPDATE runtime_settings SET value='<v>' WHERE key='max_queue'                 - max queued HTTP requests (0=unbounded)
  UPDATE runtime_settings SET value='<v>' WHERE key='hints_enabled'             - query hint warnings (1/0)
  SELECT value FROM runtime_settings WHERE key='<key>'                          - read a runtime value
  PRAGMA bnsql.timeout_push = <ms>       - Push timeout onto stack
  PRAGMA bnsql.timeout_pop               - Pop timeout from stack

Writable Columns:
  funcs.name / funcs.prototype / funcs.comment
  names.name
  segments.start_addr (rebase) / segments.end_addr (resize) / segments.perm (INSERT/DELETE supported)
  pseudocode.comment / pseudocode.comment_placement
  hlil_vars.name / hlil_vars.type / hlil_vars.comment
  patches.patched_byte (INSERT/DELETE supported)

Example Queries:
  SELECT name, hex(addr), size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT content FROM strings WHERE content LIKE '%password%';
  SELECT module, COUNT(*) FROM imports GROUP BY module;
  SELECT name, kind FROM entities WHERE name LIKE '%main%' LIMIT 20;
  SELECT entities_search('DName', 20, 0);
  SELECT decompile(addr) FROM funcs WHERE name = 'main';
  UPDATE runtime_settings SET value='5000' WHERE key='query_timeout_ms';

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

// Build JSON from the shared snapshot plus bnsql's live tool-specific settings.
inline std::string settings_to_json(const RuntimeSettingsSnapshot& snap) {
    std::ostringstream json;
    json << "{"
         << "\"query_timeout_ms\":" << snap.query_timeout_ms
         << ",\"queue_admission_timeout_ms\":" << snap.queue_admission_timeout_ms
         << ",\"max_queue\":" << snap.max_queue
         << ",\"hints_enabled\":" << (snap.hints_enabled ? "true" : "false")
         << ",\"timeout_stack_depth\":" << snap.timeout_stack_depth
         << ",\"enable_python\":"
         << (runtime_settings().python_enabled() ? "true" : "false")
         // enable_python is the GATE; python_available is whether execution can
         // actually happen. They are independent: the gate can be on while the
         // provider is missing (e.g. a copied binaryninjacore.dll beside the
         // executable splitting the provider registry). Reporting only the gate
         // forced a client to run a probe snippet and parse the error to find out.
         << ",\"python_available\":"
         << (python_provider_available() ? "true" : "false")
         << ",\"python_output_max\":"
         << runtime_settings().python_output_max()
         << "}";
    return json.str();
}

// Build the /status extra-fields object: tool name, function count, and the
// full runtime-settings snapshot. Shared by the CLI --http, the REPL `.http`
// server, and the plugin server so /status is identical on all three (the
// non-CLI servers previously dropped `functions` and `settings`). `func_count`
// is pre-queried and cached by the caller — status_fn runs on a worker thread
// where touching the non-concurrency-safe engine would race /query — and is
// reported as null when the string is empty.
inline xsql::json status_extra_json(const std::string& func_count) {
    xsql::json j;
    j["tool"] = "bnsql";
    j["tool_version"] = BNSQL_VERSION_STRING;
    // func_count is normally a clean COUNT(*) string, but parse defensively:
    // a non-numeric/overflowing value must not throw out of /status. Report null
    // rather than 500 the whole endpoint (parse_strict_ll never throws).
    long long n = 0;
    j["functions"] = bnsql::parse_strict_ll(func_count, n) ? xsql::json(n)
                                                           : xsql::json(nullptr);
    j["settings"] = xsql::json::parse(settings_to_json(runtime_settings().snapshot()));
    return j;
}


} // namespace bnsql

#endif // BNSQL_HAS_HTTP
