// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

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
 *       auto result = qe.query("SELECT name, address FROM funcs LIMIT 10");
 *       for (const auto& row : result) {
 *           LogInfo("%s: %s", row[0].c_str(), row[1].c_str());
 *       }
 *   }
 *
 * Table compatibility with idasql:
 *   - funcs: Functions (address, name, size, end_ea, flags)
 *   - segments: Memory segments (start_ea, end_ea, name, class, perm)
 *   - names: Symbols (address, name, is_public, is_weak)
 *   - entries: Entry points (ordinal, address, name)
 *   - imports: Imports (address, name, ordinal, module, module_idx)
 *   - strings: Strings (address, length, type, type_name, content)
 *   - xrefs: Cross-references (from_ea, to_ea, type, is_code)
 *   - blocks: Basic blocks (func_ea, start_ea, end_ea, size)
 *   - instructions: Instructions (address, mnemonic, operands, disasm, func_addr)
 *   - db_info: Binary metadata (key, value, type)
 *
 * Decompiler tables (HLIL):
 *   - pseudocode: Line-by-line decompiled output (func_addr, line_num, line, indent)
 *   - hlil: HLIL AST nodes (func_addr, expr_id, op_name, ea, parent_id, depth, ...)
 *   - hlil_vars: Local variables (func_addr, var_idx, name, type, is_arg, storage, ...)
 *   - hlil_calls: Function calls with args (func_addr, callee_name, arg_idx, arg_const, ...)
 *
 * Decompiler views:
 *   - hlil_v_calls: All function calls
 *   - hlil_v_loops: While/for/do-while loops
 *   - hlil_v_ifs: Conditional statements
 *   - hlil_v_comparisons: All comparisons
 *   - hlil_v_assignments: Variable assignments
 *   - hlil_v_returns: Return statements
 *   - hlil_v_derefs: Pointer dereferences
 *   - hlil_v_constants: All constants
 *   - hlil_v_vars_used: Variable usage
 *
 * Decompiler SQL functions:
 *   - decompile(addr): Get pseudocode for function
 *   - decompile(addr, limit): Get pseudocode with line limit
 *   - hlil_at(addr): Get HLIL text at address
 *   - hlil_op_at(addr): Get HLIL operation name at address
 */

#pragma once

#include "vtable.hpp"
#include "entities.hpp"
#include "functions.hpp"
#include "decompiler.hpp"
#include "database.hpp"
