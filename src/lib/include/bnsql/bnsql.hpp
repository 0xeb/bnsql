// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * bnsql/bnsql.hpp - Master include for bnsql
 *
 * bnsql - SQLite virtual tables for Binary Ninja
 *
 * Include this single header to get all bnsql functionality:
 *   - QueryEngine - SQL interface to BinaryView
 *   - Virtual tables for funcs, segments, names, xrefs, etc.
 *   - Decompiler tables for HLIL analysis
 *   - SQL functions for disasm, bytes, xrefs, decompile, etc.
 *
 * Example:
 *
 *   #include <bnsql/bnsql.hpp>
 *
 *   void my_plugin(Ref<BinaryView> bv) {
 *       bnsql::QueryEngine qe(bv);
 *       auto result = qe.query("SELECT name, addr FROM funcs LIMIT 10");
 *       for (const auto& row : result) {
 *           LogInfo("%s: %s", row[0].c_str(), row[1].c_str());
 *       }
 *   }
 *
 * Table compatibility with idasql:
 *   - funcs: Functions (addr, name, size, end_addr, flags)
 *   - segments: Memory segments (start_addr, end_addr, name, class, perm)
 *   - names: Symbols (addr, name, is_public, is_weak)
 *   - entries: Entry points / exports (ordinal, addr, name)
 *   - imports: Imports (addr, name, ordinal, module, module_idx)
 *   - strings: Strings (addr, length, type, type_name, content)
 *   - xrefs: Cross-references (from_addr, to_addr, type, is_code)
 *   - blocks: Basic blocks (func_addr, start_addr, end_addr, size)
 *   - cfg_edges: Control-flow edges (func_addr, from_addr, to_addr, edge_type)
 *   - instructions: Instructions (addr, mnemonic, operands, disasm, func_addr)
 *   - binary: Binary metadata (key, value, type)
 *
 * Decompiler tables (HLIL):
 *   - pseudocode: Line-by-line decompiled output (func_addr, line_num, line, indent)
 *   - hlil: HLIL AST nodes (func_addr, expr_id, op_name, addr, parent_id, depth, ...)
 *   - hlil_vars: Local variables (func_addr, var_idx, name, type, is_arg, storage, ...)
 *   - hlil_calls: Function calls with args (func_addr, callee_name, arg_idx, arg_const, ...)
 *
 * Type intelligence tables:
 *   - types: All defined types (id, name, kind, size, is_struct, is_enum, ...)
 *   - type_members: Struct/union member fields (type_id, member_name, offset, member_type)
 *   - type_enum_values: Enum constant values (type_id, value_name, value)
 *   - func_signatures: Function parameter/return types (func_addr, arg_index, arg_type)
 *   - patches: Patched bytes (addr, original_byte, patched_byte, status)
 *
 * Decompiler views:
 *   - hlil_v_calls: All function calls
 *   - disasm_calls: Call sites with callee info
 *   - hlil_v_loops: While/for/do-while loops
 *   - hlil_v_ifs: Conditional statements
 *   - hlil_v_comparisons: All comparisons
 *   - hlil_v_assignments: Variable assignments
 *   - hlil_v_returns: Return statements
 *   - hlil_v_derefs: Pointer dereferences
 *   - hlil_v_constants: All constants
 *   - hlil_v_vars_used: Variable usage
 *
 * Other views:
 *   - function_chunks: Function address ranges (aggregated from blocks)
 *   - types_v_structs: Struct types only
 *   - types_v_enums: Enum types only
 *
 * Decompiler SQL functions:
 *   - decompile(addr): Get pseudocode for function
 *   - decompile(addr, limit): Get pseudocode with line limit
 *   - hlil_at(addr): Get HLIL text at address
 *   - hlil_op_at(addr): Get HLIL operation name at address
 */

#pragma once

// Public engine surface. The table/UDF definitions are compiled into the bnsql
// library; consumers only need the QueryEngine API (database.hpp) and the vtable
// re-exports. (entities/functions/decompiler/types headers are now private to
// the library under src/lib/src/.)
#include "vtable.hpp"
#include "database.hpp"

namespace bnsql {

// True when a Binary Ninja Python ScriptingProvider is registered in THIS process,
// i.e. bnsql_python() can actually execute.
//
// Deliberately distinct from the enable_python runtime setting. The gate being on
// does not mean execution will work: the provider registers during InitPlugins()
// (headless included) but a process holding a second binaryninjacore.dll copy
// never sees it (split registry). Exposed publicly so /status and other callers
// can answer "can I use Python here?" without executing a probe snippet and
// parsing the error.
bool python_provider_available();

}  // namespace bnsql
