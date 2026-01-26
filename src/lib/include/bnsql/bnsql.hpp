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
 *   - SQL functions for disasm, bytes, xrefs, etc.
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
 */

#pragma once

#include "vtable.hpp"
#include "entities.hpp"
#include "functions.hpp"
#include "database.hpp"
