// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * decompiler.hpp - HLIL decompiler tables for bnsql
 *
 * Provides SQLite virtual tables for Binary Ninja's High Level IL (decompiler).
 * Schema is designed to be compatible with idasql's Hex-Rays tables.
 *
 * Tables:
 *   pseudocode  - Line-by-line decompiled output (like idasql pseudocode)
 *   hlil        - HLIL AST nodes (like idasql ctree)
 *   hlil_vars   - Local variables (like idasql ctree_lvars)
 *   hlil_calls  - Function calls with arguments (like idasql ctree_call_args)
 *
 * SQL Functions:
 *   decompile(addr)         - Get pseudocode text for function
 *   decompile(addr, limit)  - Get pseudocode text with line limit
 *   hlil_at(addr)           - Get HLIL text at address
 *   hlil_op_at(addr)        - Get HLIL operation name at address
 */

#pragma once

#include <bnsql/vtable.hpp>
#include "core_common.hpp"
#include "persistence.hpp"
#include <xsql/database.hpp>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <unordered_set>
#include <functional>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <atomic>

namespace bnsql {
namespace decompiler {

using namespace BinaryNinja;

// ============================================================================
// HLIL Operation Name Mapping
// ============================================================================

inline const char* hlil_op_name(BNHighLevelILOperation op) {
    switch (op) {
        // Control flow
        case HLIL_NOP: return "HLIL_NOP";
        case HLIL_BLOCK: return "HLIL_BLOCK";
        case HLIL_IF: return "HLIL_IF";
        case HLIL_WHILE: return "HLIL_WHILE";
        case HLIL_WHILE_SSA: return "HLIL_WHILE_SSA";
        case HLIL_DO_WHILE: return "HLIL_DO_WHILE";
        case HLIL_DO_WHILE_SSA: return "HLIL_DO_WHILE_SSA";
        case HLIL_FOR: return "HLIL_FOR";
        case HLIL_FOR_SSA: return "HLIL_FOR_SSA";
        case HLIL_SWITCH: return "HLIL_SWITCH";
        case HLIL_CASE: return "HLIL_CASE";
        case HLIL_BREAK: return "HLIL_BREAK";
        case HLIL_CONTINUE: return "HLIL_CONTINUE";
        case HLIL_JUMP: return "HLIL_JUMP";
        case HLIL_RET: return "HLIL_RET";
        case HLIL_NORET: return "HLIL_NORET";
        case HLIL_UNREACHABLE: return "HLIL_UNREACHABLE";
        case HLIL_GOTO: return "HLIL_GOTO";
        case HLIL_LABEL: return "HLIL_LABEL";

        // Calls
        case HLIL_CALL: return "HLIL_CALL";
        case HLIL_CALL_SSA: return "HLIL_CALL_SSA";
        case HLIL_SYSCALL: return "HLIL_SYSCALL";
        case HLIL_SYSCALL_SSA: return "HLIL_SYSCALL_SSA";
        case HLIL_TAILCALL: return "HLIL_TAILCALL";
        case HLIL_INTRINSIC: return "HLIL_INTRINSIC";
        case HLIL_INTRINSIC_SSA: return "HLIL_INTRINSIC_SSA";

        // Variables
        case HLIL_VAR: return "HLIL_VAR";
        case HLIL_VAR_SSA: return "HLIL_VAR_SSA";
        case HLIL_VAR_PHI: return "HLIL_VAR_PHI";
        case HLIL_VAR_INIT: return "HLIL_VAR_INIT";
        case HLIL_VAR_INIT_SSA: return "HLIL_VAR_INIT_SSA";
        case HLIL_VAR_DECLARE: return "HLIL_VAR_DECLARE";
        case HLIL_ASSIGN: return "HLIL_ASSIGN";
        case HLIL_ASSIGN_UNPACK: return "HLIL_ASSIGN_UNPACK";
        case HLIL_ASSIGN_MEM_SSA: return "HLIL_ASSIGN_MEM_SSA";
        case HLIL_ASSIGN_UNPACK_MEM_SSA: return "HLIL_ASSIGN_UNPACK_MEM_SSA";
        case HLIL_MEM_PHI: return "HLIL_MEM_PHI";
        case HLIL_FORCE_VER: return "HLIL_FORCE_VER";
        case HLIL_FORCE_VER_SSA: return "HLIL_FORCE_VER_SSA";
        case HLIL_ASSERT: return "HLIL_ASSERT";
        case HLIL_ASSERT_SSA: return "HLIL_ASSERT_SSA";

        // Memory
        case HLIL_DEREF: return "HLIL_DEREF";
        case HLIL_DEREF_SSA: return "HLIL_DEREF_SSA";
        case HLIL_ADDRESS_OF: return "HLIL_ADDRESS_OF";
        case HLIL_DEREF_FIELD: return "HLIL_DEREF_FIELD";
        case HLIL_DEREF_FIELD_SSA: return "HLIL_DEREF_FIELD_SSA";
        case HLIL_STRUCT_FIELD: return "HLIL_STRUCT_FIELD";
        case HLIL_ARRAY_INDEX: return "HLIL_ARRAY_INDEX";
        case HLIL_ARRAY_INDEX_SSA: return "HLIL_ARRAY_INDEX_SSA";

        // Constants
        case HLIL_CONST: return "HLIL_CONST";
        case HLIL_CONST_PTR: return "HLIL_CONST_PTR";
        case HLIL_EXTERN_PTR: return "HLIL_EXTERN_PTR";
        case HLIL_FLOAT_CONST: return "HLIL_FLOAT_CONST";
        case HLIL_IMPORT: return "HLIL_IMPORT";
        case HLIL_CONST_DATA: return "HLIL_CONST_DATA";
        case HLIL_LOW_PART: return "HLIL_LOW_PART";
        case HLIL_SPLIT: return "HLIL_SPLIT";

        // Arithmetic
        case HLIL_ADD: return "HLIL_ADD";
        case HLIL_ADC: return "HLIL_ADC";
        case HLIL_SUB: return "HLIL_SUB";
        case HLIL_SBB: return "HLIL_SBB";
        case HLIL_AND: return "HLIL_AND";
        case HLIL_OR: return "HLIL_OR";
        case HLIL_XOR: return "HLIL_XOR";
        case HLIL_LSL: return "HLIL_LSL";
        case HLIL_LSR: return "HLIL_LSR";
        case HLIL_ASR: return "HLIL_ASR";
        case HLIL_ROL: return "HLIL_ROL";
        case HLIL_RLC: return "HLIL_RLC";
        case HLIL_ROR: return "HLIL_ROR";
        case HLIL_RRC: return "HLIL_RRC";
        case HLIL_MUL: return "HLIL_MUL";
        case HLIL_MULU_DP: return "HLIL_MULU_DP";
        case HLIL_MULS_DP: return "HLIL_MULS_DP";
        case HLIL_DIVU: return "HLIL_DIVU";
        case HLIL_DIVU_DP: return "HLIL_DIVU_DP";
        case HLIL_DIVS: return "HLIL_DIVS";
        case HLIL_DIVS_DP: return "HLIL_DIVS_DP";
        case HLIL_MODU: return "HLIL_MODU";
        case HLIL_MODU_DP: return "HLIL_MODU_DP";
        case HLIL_MODS: return "HLIL_MODS";
        case HLIL_MODS_DP: return "HLIL_MODS_DP";
        case HLIL_NEG: return "HLIL_NEG";
        case HLIL_NOT: return "HLIL_NOT";
        case HLIL_SX: return "HLIL_SX";
        case HLIL_ZX: return "HLIL_ZX";
        case HLIL_TEST_BIT: return "HLIL_TEST_BIT";
        case HLIL_BOOL_TO_INT: return "HLIL_BOOL_TO_INT";
        case HLIL_ADD_OVERFLOW: return "HLIL_ADD_OVERFLOW";

        // Comparisons
        case HLIL_CMP_E: return "HLIL_CMP_E";
        case HLIL_CMP_NE: return "HLIL_CMP_NE";
        case HLIL_CMP_SLT: return "HLIL_CMP_SLT";
        case HLIL_CMP_ULT: return "HLIL_CMP_ULT";
        case HLIL_CMP_SLE: return "HLIL_CMP_SLE";
        case HLIL_CMP_ULE: return "HLIL_CMP_ULE";
        case HLIL_CMP_SGE: return "HLIL_CMP_SGE";
        case HLIL_CMP_UGE: return "HLIL_CMP_UGE";
        case HLIL_CMP_SGT: return "HLIL_CMP_SGT";
        case HLIL_CMP_UGT: return "HLIL_CMP_UGT";

        // Floating point
        case HLIL_FADD: return "HLIL_FADD";
        case HLIL_FSUB: return "HLIL_FSUB";
        case HLIL_FMUL: return "HLIL_FMUL";
        case HLIL_FDIV: return "HLIL_FDIV";
        case HLIL_FSQRT: return "HLIL_FSQRT";
        case HLIL_FNEG: return "HLIL_FNEG";
        case HLIL_FABS: return "HLIL_FABS";
        case HLIL_FLOAT_TO_INT: return "HLIL_FLOAT_TO_INT";
        case HLIL_INT_TO_FLOAT: return "HLIL_INT_TO_FLOAT";
        case HLIL_FLOAT_CONV: return "HLIL_FLOAT_CONV";
        case HLIL_ROUND_TO_INT: return "HLIL_ROUND_TO_INT";
        case HLIL_FLOOR: return "HLIL_FLOOR";
        case HLIL_CEIL: return "HLIL_CEIL";
        case HLIL_FTRUNC: return "HLIL_FTRUNC";
        case HLIL_FCMP_E: return "HLIL_FCMP_E";
        case HLIL_FCMP_NE: return "HLIL_FCMP_NE";
        case HLIL_FCMP_LT: return "HLIL_FCMP_LT";
        case HLIL_FCMP_LE: return "HLIL_FCMP_LE";
        case HLIL_FCMP_GE: return "HLIL_FCMP_GE";
        case HLIL_FCMP_GT: return "HLIL_FCMP_GT";
        case HLIL_FCMP_O: return "HLIL_FCMP_O";
        case HLIL_FCMP_UO: return "HLIL_FCMP_UO";

        // Other
        case HLIL_BP: return "HLIL_BP";
        case HLIL_TRAP: return "HLIL_TRAP";
        case HLIL_UNDEF: return "HLIL_UNDEF";
        case HLIL_UNIMPL: return "HLIL_UNIMPL";
        case HLIL_UNIMPL_MEM: return "HLIL_UNIMPL_MEM";

        // Added in BN 6.0 (core ABI 187)
        case HLIL_ABS: return "HLIL_ABS";
        case HLIL_BSWAP: return "HLIL_BSWAP";
        case HLIL_CLS: return "HLIL_CLS";
        case HLIL_CLZ: return "HLIL_CLZ";
        case HLIL_CTZ: return "HLIL_CTZ";
        case HLIL_MAXS: return "HLIL_MAXS";
        case HLIL_MAXU: return "HLIL_MAXU";
        case HLIL_MINS: return "HLIL_MINS";
        case HLIL_MINU: return "HLIL_MINU";
        case HLIL_PASS_BY_REF: return "HLIL_PASS_BY_REF";
        case HLIL_POPCNT: return "HLIL_POPCNT";
        case HLIL_RBIT: return "HLIL_RBIT";
        case HLIL_RETURN_BY_REF: return "HLIL_RETURN_BY_REF";
        case HLIL_STRUCT_INIT: return "HLIL_STRUCT_INIT";
        case HLIL_STRUCT_INIT_FIELD: return "HLIL_STRUCT_INIT_FIELD";
        case HLIL_VAR_SSA_PARTIAL: return "HLIL_VAR_SSA_PARTIAL";

        default: return "";
    }
}

// Native MLIL-SSA operation name (provenance for ir_ops.native_op).
inline const char* mlil_op_name(BNMediumLevelILOperation op) {
    switch (op) {
        case MLIL_NOP: return "MLIL_NOP";
        case MLIL_SET_VAR: return "MLIL_SET_VAR";
        case MLIL_SET_VAR_FIELD: return "MLIL_SET_VAR_FIELD";
        case MLIL_SET_VAR_SPLIT: return "MLIL_SET_VAR_SPLIT";
        case MLIL_ASSERT: return "MLIL_ASSERT";
        case MLIL_FORCE_VER: return "MLIL_FORCE_VER";
        case MLIL_LOAD: return "MLIL_LOAD";
        case MLIL_LOAD_STRUCT: return "MLIL_LOAD_STRUCT";
        case MLIL_STORE: return "MLIL_STORE";
        case MLIL_STORE_STRUCT: return "MLIL_STORE_STRUCT";
        case MLIL_VAR: return "MLIL_VAR";
        case MLIL_VAR_FIELD: return "MLIL_VAR_FIELD";
        case MLIL_VAR_SPLIT: return "MLIL_VAR_SPLIT";
        case MLIL_ADDRESS_OF: return "MLIL_ADDRESS_OF";
        case MLIL_ADDRESS_OF_FIELD: return "MLIL_ADDRESS_OF_FIELD";
        case MLIL_CONST: return "MLIL_CONST";
        case MLIL_CONST_DATA: return "MLIL_CONST_DATA";
        case MLIL_CONST_PTR: return "MLIL_CONST_PTR";
        case MLIL_EXTERN_PTR: return "MLIL_EXTERN_PTR";
        case MLIL_FLOAT_CONST: return "MLIL_FLOAT_CONST";
        case MLIL_IMPORT: return "MLIL_IMPORT";
        case MLIL_ADD: return "MLIL_ADD";
        case MLIL_ADC: return "MLIL_ADC";
        case MLIL_SUB: return "MLIL_SUB";
        case MLIL_SBB: return "MLIL_SBB";
        case MLIL_AND: return "MLIL_AND";
        case MLIL_OR: return "MLIL_OR";
        case MLIL_XOR: return "MLIL_XOR";
        case MLIL_LSL: return "MLIL_LSL";
        case MLIL_LSR: return "MLIL_LSR";
        case MLIL_ASR: return "MLIL_ASR";
        case MLIL_ROL: return "MLIL_ROL";
        case MLIL_RLC: return "MLIL_RLC";
        case MLIL_ROR: return "MLIL_ROR";
        case MLIL_RRC: return "MLIL_RRC";
        case MLIL_MUL: return "MLIL_MUL";
        case MLIL_MULU_DP: return "MLIL_MULU_DP";
        case MLIL_MULS_DP: return "MLIL_MULS_DP";
        case MLIL_DIVU: return "MLIL_DIVU";
        case MLIL_DIVU_DP: return "MLIL_DIVU_DP";
        case MLIL_DIVS: return "MLIL_DIVS";
        case MLIL_DIVS_DP: return "MLIL_DIVS_DP";
        case MLIL_MODU: return "MLIL_MODU";
        case MLIL_MODU_DP: return "MLIL_MODU_DP";
        case MLIL_MODS: return "MLIL_MODS";
        case MLIL_MODS_DP: return "MLIL_MODS_DP";
        case MLIL_NEG: return "MLIL_NEG";
        case MLIL_NOT: return "MLIL_NOT";
        case MLIL_SX: return "MLIL_SX";
        case MLIL_ZX: return "MLIL_ZX";
        case MLIL_LOW_PART: return "MLIL_LOW_PART";
        case MLIL_JUMP: return "MLIL_JUMP";
        case MLIL_JUMP_TO: return "MLIL_JUMP_TO";
        case MLIL_RET_HINT: return "MLIL_RET_HINT";
        case MLIL_CALL: return "MLIL_CALL";
        case MLIL_CALL_UNTYPED: return "MLIL_CALL_UNTYPED";
        // The non-SSA call-output op was removed in BN 6.0; only the SSA-form
        // spelling survives (mapped further down with the other SSA ops).
        // Do NOT name the removed enumerator here: the compliance test scrapes
        // every prefixed token out of this region, comments included, and
        // compares the set against the core enum -- naming a dead enumerator
        // reintroduces it and fails coverage.
        case MLIL_CALL_PARAM: return "MLIL_CALL_PARAM";
        case MLIL_SEPARATE_PARAM_LIST: return "MLIL_SEPARATE_PARAM_LIST";
        case MLIL_SHARED_PARAM_SLOT: return "MLIL_SHARED_PARAM_SLOT";
        case MLIL_RET: return "MLIL_RET";
        case MLIL_NORET: return "MLIL_NORET";
        case MLIL_IF: return "MLIL_IF";
        case MLIL_GOTO: return "MLIL_GOTO";
        case MLIL_CMP_E: return "MLIL_CMP_E";
        case MLIL_CMP_NE: return "MLIL_CMP_NE";
        case MLIL_CMP_SLT: return "MLIL_CMP_SLT";
        case MLIL_CMP_ULT: return "MLIL_CMP_ULT";
        case MLIL_CMP_SLE: return "MLIL_CMP_SLE";
        case MLIL_CMP_ULE: return "MLIL_CMP_ULE";
        case MLIL_CMP_SGE: return "MLIL_CMP_SGE";
        case MLIL_CMP_UGE: return "MLIL_CMP_UGE";
        case MLIL_CMP_SGT: return "MLIL_CMP_SGT";
        case MLIL_CMP_UGT: return "MLIL_CMP_UGT";
        case MLIL_TEST_BIT: return "MLIL_TEST_BIT";
        case MLIL_BOOL_TO_INT: return "MLIL_BOOL_TO_INT";
        case MLIL_ADD_OVERFLOW: return "MLIL_ADD_OVERFLOW";
        case MLIL_SYSCALL: return "MLIL_SYSCALL";
        case MLIL_SYSCALL_UNTYPED: return "MLIL_SYSCALL_UNTYPED";
        case MLIL_TAILCALL: return "MLIL_TAILCALL";
        case MLIL_TAILCALL_UNTYPED: return "MLIL_TAILCALL_UNTYPED";
        case MLIL_INTRINSIC: return "MLIL_INTRINSIC";
        case MLIL_FREE_VAR_SLOT: return "MLIL_FREE_VAR_SLOT";
        case MLIL_BP: return "MLIL_BP";
        case MLIL_TRAP: return "MLIL_TRAP";
        case MLIL_UNDEF: return "MLIL_UNDEF";
        case MLIL_UNIMPL: return "MLIL_UNIMPL";
        case MLIL_UNIMPL_MEM: return "MLIL_UNIMPL_MEM";
        case MLIL_FADD: return "MLIL_FADD";
        case MLIL_FSUB: return "MLIL_FSUB";
        case MLIL_FMUL: return "MLIL_FMUL";
        case MLIL_FDIV: return "MLIL_FDIV";
        case MLIL_FSQRT: return "MLIL_FSQRT";
        case MLIL_FNEG: return "MLIL_FNEG";
        case MLIL_FABS: return "MLIL_FABS";
        case MLIL_FLOAT_TO_INT: return "MLIL_FLOAT_TO_INT";
        case MLIL_INT_TO_FLOAT: return "MLIL_INT_TO_FLOAT";
        case MLIL_FLOAT_CONV: return "MLIL_FLOAT_CONV";
        case MLIL_ROUND_TO_INT: return "MLIL_ROUND_TO_INT";
        case MLIL_FLOOR: return "MLIL_FLOOR";
        case MLIL_CEIL: return "MLIL_CEIL";
        case MLIL_FTRUNC: return "MLIL_FTRUNC";
        case MLIL_FCMP_E: return "MLIL_FCMP_E";
        case MLIL_FCMP_NE: return "MLIL_FCMP_NE";
        case MLIL_FCMP_LT: return "MLIL_FCMP_LT";
        case MLIL_FCMP_LE: return "MLIL_FCMP_LE";
        case MLIL_FCMP_GE: return "MLIL_FCMP_GE";
        case MLIL_FCMP_GT: return "MLIL_FCMP_GT";
        case MLIL_FCMP_O: return "MLIL_FCMP_O";
        case MLIL_FCMP_UO: return "MLIL_FCMP_UO";
        case MLIL_SET_VAR_SSA: return "MLIL_SET_VAR_SSA";
        case MLIL_SET_VAR_SSA_FIELD: return "MLIL_SET_VAR_SSA_FIELD";
        case MLIL_SET_VAR_SPLIT_SSA: return "MLIL_SET_VAR_SPLIT_SSA";
        case MLIL_SET_VAR_ALIASED: return "MLIL_SET_VAR_ALIASED";
        case MLIL_SET_VAR_ALIASED_FIELD: return "MLIL_SET_VAR_ALIASED_FIELD";
        case MLIL_VAR_SSA: return "MLIL_VAR_SSA";
        case MLIL_VAR_SSA_FIELD: return "MLIL_VAR_SSA_FIELD";
        case MLIL_VAR_ALIASED: return "MLIL_VAR_ALIASED";
        case MLIL_VAR_ALIASED_FIELD: return "MLIL_VAR_ALIASED_FIELD";
        case MLIL_VAR_SPLIT_SSA: return "MLIL_VAR_SPLIT_SSA";
        case MLIL_ASSERT_SSA: return "MLIL_ASSERT_SSA";
        case MLIL_FORCE_VER_SSA: return "MLIL_FORCE_VER_SSA";
        case MLIL_CALL_SSA: return "MLIL_CALL_SSA";
        case MLIL_CALL_UNTYPED_SSA: return "MLIL_CALL_UNTYPED_SSA";
        case MLIL_SYSCALL_SSA: return "MLIL_SYSCALL_SSA";
        case MLIL_SYSCALL_UNTYPED_SSA: return "MLIL_SYSCALL_UNTYPED_SSA";
        case MLIL_TAILCALL_SSA: return "MLIL_TAILCALL_SSA";
        case MLIL_TAILCALL_UNTYPED_SSA: return "MLIL_TAILCALL_UNTYPED_SSA";
        case MLIL_CALL_PARAM_SSA: return "MLIL_CALL_PARAM_SSA";
        case MLIL_CALL_OUTPUT_SSA: return "MLIL_CALL_OUTPUT_SSA";
        case MLIL_MEMORY_INTRINSIC_OUTPUT_SSA: return "MLIL_MEMORY_INTRINSIC_OUTPUT_SSA";
        case MLIL_LOAD_SSA: return "MLIL_LOAD_SSA";
        case MLIL_LOAD_STRUCT_SSA: return "MLIL_LOAD_STRUCT_SSA";
        case MLIL_STORE_SSA: return "MLIL_STORE_SSA";
        case MLIL_STORE_STRUCT_SSA: return "MLIL_STORE_STRUCT_SSA";
        case MLIL_INTRINSIC_SSA: return "MLIL_INTRINSIC_SSA";
        case MLIL_MEMORY_INTRINSIC_SSA: return "MLIL_MEMORY_INTRINSIC_SSA";
        case MLIL_FREE_VAR_SLOT_SSA: return "MLIL_FREE_VAR_SLOT_SSA";
        case MLIL_VAR_PHI: return "MLIL_VAR_PHI";
        case MLIL_MEM_PHI: return "MLIL_MEM_PHI";

        // Added in BN 6.0 (core ABI 187). The same release removed the non-SSA
        // call-output op, whose role the var-output / store-output family below
        // now covers.
        case MLIL_ABS: return "MLIL_ABS";
        case MLIL_BLOCK_TO_EXPAND: return "MLIL_BLOCK_TO_EXPAND";
        case MLIL_BSWAP: return "MLIL_BSWAP";
        case MLIL_CLS: return "MLIL_CLS";
        case MLIL_CLZ: return "MLIL_CLZ";
        case MLIL_CTZ: return "MLIL_CTZ";
        case MLIL_MAXS: return "MLIL_MAXS";
        case MLIL_MAXU: return "MLIL_MAXU";
        case MLIL_MINS: return "MLIL_MINS";
        case MLIL_MINU: return "MLIL_MINU";
        case MLIL_PASS_BY_REF: return "MLIL_PASS_BY_REF";
        case MLIL_POPCNT: return "MLIL_POPCNT";
        case MLIL_RBIT: return "MLIL_RBIT";
        case MLIL_RETURN_BY_REF: return "MLIL_RETURN_BY_REF";
        case MLIL_STORE_OUTPUT: return "MLIL_STORE_OUTPUT";
        case MLIL_VAR_OUTPUT: return "MLIL_VAR_OUTPUT";
        case MLIL_VAR_OUTPUT_ALIASED: return "MLIL_VAR_OUTPUT_ALIASED";
        case MLIL_VAR_OUTPUT_ALIASED_FIELD: return "MLIL_VAR_OUTPUT_ALIASED_FIELD";
        case MLIL_VAR_OUTPUT_FIELD: return "MLIL_VAR_OUTPUT_FIELD";
        case MLIL_VAR_OUTPUT_SSA: return "MLIL_VAR_OUTPUT_SSA";
        case MLIL_VAR_OUTPUT_SSA_FIELD: return "MLIL_VAR_OUTPUT_SSA_FIELD";

        default: return "";
    }
}

// BNMediumLevelILOperation -> canonical P-code-style op (cross-tool low-IR).
// Empty for ops with no clean canonical (var reads, consts, params, NOP, ...).
// MLIL-SSA top-level instructions are statement-level, so arithmetic mostly
// appears nested inside SET_VAR_SSA sources rather than as top-level rows.
inline const char* mlil_canonical_op(BNMediumLevelILOperation op) {
    switch (op) {
        case MLIL_SET_VAR:
        case MLIL_SET_VAR_FIELD:
        case MLIL_SET_VAR_SPLIT:
        case MLIL_SET_VAR_SSA:
        case MLIL_SET_VAR_SSA_FIELD:
        case MLIL_SET_VAR_SPLIT_SSA:
        case MLIL_SET_VAR_ALIASED:
        case MLIL_SET_VAR_ALIASED_FIELD: return "COPY";
        case MLIL_LOAD:
        case MLIL_LOAD_STRUCT:
        case MLIL_LOAD_SSA:
        case MLIL_LOAD_STRUCT_SSA:   return "LOAD";
        case MLIL_STORE:
        case MLIL_STORE_STRUCT:
        case MLIL_STORE_SSA:
        case MLIL_STORE_STRUCT_SSA:  return "STORE";
        case MLIL_VAR_PHI:
        case MLIL_MEM_PHI:           return "MULTIEQUAL";
        case MLIL_ADD:
        case MLIL_ADC:               return "INT_ADD";
        case MLIL_SUB:
        case MLIL_SBB:               return "INT_SUB";
        case MLIL_MUL:
        case MLIL_MULU_DP:
        case MLIL_MULS_DP:           return "INT_MULT";
        case MLIL_DIVU:
        case MLIL_DIVU_DP:           return "INT_DIV";
        case MLIL_DIVS:
        case MLIL_DIVS_DP:           return "INT_SDIV";
        case MLIL_MODU:
        case MLIL_MODU_DP:           return "INT_REM";
        case MLIL_MODS:
        case MLIL_MODS_DP:           return "INT_SREM";
        case MLIL_AND:               return "INT_AND";
        case MLIL_OR:                return "INT_OR";
        case MLIL_XOR:               return "INT_XOR";
        case MLIL_LSL:               return "INT_LEFT";
        case MLIL_LSR:               return "INT_RIGHT";
        case MLIL_ASR:               return "INT_SRIGHT";
        case MLIL_NEG:               return "INT_2COMP";
        case MLIL_NOT:               return "INT_NEGATE";
        case MLIL_SX:                return "INT_SEXT";
        case MLIL_ZX:                return "INT_ZEXT";
        case MLIL_LOW_PART:          return "SUBPIECE";
        case MLIL_CMP_E:             return "INT_EQUAL";
        case MLIL_CMP_NE:            return "INT_NOTEQUAL";
        case MLIL_CMP_ULT:           return "INT_LESS";
        case MLIL_CMP_ULE:           return "INT_LESSEQUAL";
        case MLIL_CMP_SLT:           return "INT_SLESS";
        case MLIL_CMP_SLE:           return "INT_SLESSEQUAL";
        case MLIL_FADD:              return "FLOAT_ADD";
        case MLIL_FSUB:              return "FLOAT_SUB";
        case MLIL_FMUL:              return "FLOAT_MULT";
        case MLIL_FDIV:              return "FLOAT_DIV";
        case MLIL_FNEG:              return "FLOAT_NEG";
        case MLIL_JUMP:
        case MLIL_JUMP_TO:           return "BRANCHIND";
        case MLIL_GOTO:              return "BRANCH";
        case MLIL_IF:                return "CBRANCH";
        case MLIL_CALL:
        case MLIL_CALL_SSA:
        case MLIL_CALL_UNTYPED:
        case MLIL_CALL_UNTYPED_SSA:
        case MLIL_TAILCALL:
        case MLIL_TAILCALL_SSA:
        case MLIL_TAILCALL_UNTYPED:
        case MLIL_TAILCALL_UNTYPED_SSA: return "CALL";
        case MLIL_SYSCALL:
        case MLIL_SYSCALL_SSA:
        case MLIL_SYSCALL_UNTYPED:
        case MLIL_SYSCALL_UNTYPED_SSA: return "CALLOTHER";
        case MLIL_RET:
        case MLIL_NORET:             return "RETURN";
        default:                     return "";
    }
}

// ---- LLIL op name (generated from BNLowLevelILOperation) ----
inline const char* llil_op_name(BNLowLevelILOperation op) {
    switch (op) {
        case LLIL_ADC: return "LLIL_ADC";
        case LLIL_ADD: return "LLIL_ADD";
        case LLIL_ADD_OVERFLOW: return "LLIL_ADD_OVERFLOW";
        case LLIL_AND: return "LLIL_AND";
        case LLIL_ASR: return "LLIL_ASR";
        case LLIL_ASSERT: return "LLIL_ASSERT";
        case LLIL_ASSERT_SSA: return "LLIL_ASSERT_SSA";
        case LLIL_BOOL_TO_INT: return "LLIL_BOOL_TO_INT";
        case LLIL_BP: return "LLIL_BP";
        case LLIL_CALL: return "LLIL_CALL";
        case LLIL_CALL_OUTPUT_SSA: return "LLIL_CALL_OUTPUT_SSA";
        case LLIL_CALL_PARAM: return "LLIL_CALL_PARAM";
        case LLIL_CALL_SSA: return "LLIL_CALL_SSA";
        case LLIL_CALL_STACK_ADJUST: return "LLIL_CALL_STACK_ADJUST";
        case LLIL_CALL_STACK_SSA: return "LLIL_CALL_STACK_SSA";
        case LLIL_CEIL: return "LLIL_CEIL";
        case LLIL_CMP_E: return "LLIL_CMP_E";
        case LLIL_CMP_NE: return "LLIL_CMP_NE";
        case LLIL_CMP_SGE: return "LLIL_CMP_SGE";
        case LLIL_CMP_SGT: return "LLIL_CMP_SGT";
        case LLIL_CMP_SLE: return "LLIL_CMP_SLE";
        case LLIL_CMP_SLT: return "LLIL_CMP_SLT";
        case LLIL_CMP_UGE: return "LLIL_CMP_UGE";
        case LLIL_CMP_UGT: return "LLIL_CMP_UGT";
        case LLIL_CMP_ULE: return "LLIL_CMP_ULE";
        case LLIL_CMP_ULT: return "LLIL_CMP_ULT";
        case LLIL_CONST: return "LLIL_CONST";
        case LLIL_CONST_PTR: return "LLIL_CONST_PTR";
        case LLIL_DIVS: return "LLIL_DIVS";
        case LLIL_DIVS_DP: return "LLIL_DIVS_DP";
        case LLIL_DIVU: return "LLIL_DIVU";
        case LLIL_DIVU_DP: return "LLIL_DIVU_DP";
        case LLIL_EXTERN_PTR: return "LLIL_EXTERN_PTR";
        case LLIL_FABS: return "LLIL_FABS";
        case LLIL_FADD: return "LLIL_FADD";
        case LLIL_FCMP_E: return "LLIL_FCMP_E";
        case LLIL_FCMP_GE: return "LLIL_FCMP_GE";
        case LLIL_FCMP_GT: return "LLIL_FCMP_GT";
        case LLIL_FCMP_LE: return "LLIL_FCMP_LE";
        case LLIL_FCMP_LT: return "LLIL_FCMP_LT";
        case LLIL_FCMP_NE: return "LLIL_FCMP_NE";
        case LLIL_FCMP_O: return "LLIL_FCMP_O";
        case LLIL_FCMP_UO: return "LLIL_FCMP_UO";
        case LLIL_FDIV: return "LLIL_FDIV";
        case LLIL_FLAG: return "LLIL_FLAG";
        case LLIL_FLAG_BIT: return "LLIL_FLAG_BIT";
        case LLIL_FLAG_BIT_SSA: return "LLIL_FLAG_BIT_SSA";
        case LLIL_FLAG_COND: return "LLIL_FLAG_COND";
        case LLIL_FLAG_GROUP: return "LLIL_FLAG_GROUP";
        case LLIL_FLAG_PHI: return "LLIL_FLAG_PHI";
        case LLIL_FLAG_SSA: return "LLIL_FLAG_SSA";
        case LLIL_FLOAT_CONST: return "LLIL_FLOAT_CONST";
        case LLIL_FLOAT_CONV: return "LLIL_FLOAT_CONV";
        case LLIL_FLOAT_TO_INT: return "LLIL_FLOAT_TO_INT";
        case LLIL_FLOOR: return "LLIL_FLOOR";
        case LLIL_FMUL: return "LLIL_FMUL";
        case LLIL_FNEG: return "LLIL_FNEG";
        case LLIL_FORCE_VER: return "LLIL_FORCE_VER";
        case LLIL_FORCE_VER_SSA: return "LLIL_FORCE_VER_SSA";
        case LLIL_FSQRT: return "LLIL_FSQRT";
        case LLIL_FSUB: return "LLIL_FSUB";
        case LLIL_FTRUNC: return "LLIL_FTRUNC";
        case LLIL_GOTO: return "LLIL_GOTO";
        case LLIL_IF: return "LLIL_IF";
        case LLIL_INTRINSIC: return "LLIL_INTRINSIC";
        case LLIL_INTRINSIC_SSA: return "LLIL_INTRINSIC_SSA";
        case LLIL_INT_TO_FLOAT: return "LLIL_INT_TO_FLOAT";
        case LLIL_JUMP: return "LLIL_JUMP";
        case LLIL_JUMP_TO: return "LLIL_JUMP_TO";
        case LLIL_LOAD: return "LLIL_LOAD";
        case LLIL_LOAD_SSA: return "LLIL_LOAD_SSA";
        case LLIL_LOW_PART: return "LLIL_LOW_PART";
        case LLIL_LSL: return "LLIL_LSL";
        case LLIL_LSR: return "LLIL_LSR";
        case LLIL_MEMORY_INTRINSIC_OUTPUT_SSA: return "LLIL_MEMORY_INTRINSIC_OUTPUT_SSA";
        case LLIL_MEMORY_INTRINSIC_SSA: return "LLIL_MEMORY_INTRINSIC_SSA";
        case LLIL_MEM_PHI: return "LLIL_MEM_PHI";
        case LLIL_MODS: return "LLIL_MODS";
        case LLIL_MODS_DP: return "LLIL_MODS_DP";
        case LLIL_MODU: return "LLIL_MODU";
        case LLIL_MODU_DP: return "LLIL_MODU_DP";
        case LLIL_MUL: return "LLIL_MUL";
        case LLIL_MULS_DP: return "LLIL_MULS_DP";
        case LLIL_MULU_DP: return "LLIL_MULU_DP";
        case LLIL_NEG: return "LLIL_NEG";
        case LLIL_NOP: return "LLIL_NOP";
        case LLIL_NORET: return "LLIL_NORET";
        case LLIL_NOT: return "LLIL_NOT";
        case LLIL_OR: return "LLIL_OR";
        case LLIL_POP: return "LLIL_POP";
        case LLIL_PUSH: return "LLIL_PUSH";
        case LLIL_REG: return "LLIL_REG";
        case LLIL_REG_PHI: return "LLIL_REG_PHI";
        case LLIL_REG_SPLIT: return "LLIL_REG_SPLIT";
        case LLIL_REG_SPLIT_DEST_SSA: return "LLIL_REG_SPLIT_DEST_SSA";
        case LLIL_REG_SPLIT_SSA: return "LLIL_REG_SPLIT_SSA";
        case LLIL_REG_SSA: return "LLIL_REG_SSA";
        case LLIL_REG_SSA_PARTIAL: return "LLIL_REG_SSA_PARTIAL";
        case LLIL_REG_STACK_ABS_SSA: return "LLIL_REG_STACK_ABS_SSA";
        case LLIL_REG_STACK_DEST_SSA: return "LLIL_REG_STACK_DEST_SSA";
        case LLIL_REG_STACK_FREE_ABS_SSA: return "LLIL_REG_STACK_FREE_ABS_SSA";
        case LLIL_REG_STACK_FREE_REG: return "LLIL_REG_STACK_FREE_REG";
        case LLIL_REG_STACK_FREE_REL: return "LLIL_REG_STACK_FREE_REL";
        case LLIL_REG_STACK_FREE_REL_SSA: return "LLIL_REG_STACK_FREE_REL_SSA";
        case LLIL_REG_STACK_PHI: return "LLIL_REG_STACK_PHI";
        case LLIL_REG_STACK_POP: return "LLIL_REG_STACK_POP";
        case LLIL_REG_STACK_PUSH: return "LLIL_REG_STACK_PUSH";
        case LLIL_REG_STACK_REL: return "LLIL_REG_STACK_REL";
        case LLIL_REG_STACK_REL_SSA: return "LLIL_REG_STACK_REL_SSA";
        case LLIL_RET: return "LLIL_RET";
        case LLIL_RLC: return "LLIL_RLC";
        case LLIL_ROL: return "LLIL_ROL";
        case LLIL_ROR: return "LLIL_ROR";
        case LLIL_ROUND_TO_INT: return "LLIL_ROUND_TO_INT";
        case LLIL_RRC: return "LLIL_RRC";
        case LLIL_SBB: return "LLIL_SBB";
        case LLIL_SEPARATE_PARAM_LIST_SSA: return "LLIL_SEPARATE_PARAM_LIST_SSA";
        case LLIL_SET_FLAG: return "LLIL_SET_FLAG";
        case LLIL_SET_FLAG_SSA: return "LLIL_SET_FLAG_SSA";
        case LLIL_SET_REG: return "LLIL_SET_REG";
        case LLIL_SET_REG_SPLIT: return "LLIL_SET_REG_SPLIT";
        case LLIL_SET_REG_SPLIT_SSA: return "LLIL_SET_REG_SPLIT_SSA";
        case LLIL_SET_REG_SSA: return "LLIL_SET_REG_SSA";
        case LLIL_SET_REG_SSA_PARTIAL: return "LLIL_SET_REG_SSA_PARTIAL";
        case LLIL_SET_REG_STACK_ABS_SSA: return "LLIL_SET_REG_STACK_ABS_SSA";
        case LLIL_SET_REG_STACK_REL: return "LLIL_SET_REG_STACK_REL";
        case LLIL_SET_REG_STACK_REL_SSA: return "LLIL_SET_REG_STACK_REL_SSA";
        case LLIL_SHARED_PARAM_SLOT_SSA: return "LLIL_SHARED_PARAM_SLOT_SSA";
        case LLIL_STORE: return "LLIL_STORE";
        case LLIL_STORE_SSA: return "LLIL_STORE_SSA";
        case LLIL_SUB: return "LLIL_SUB";
        case LLIL_SX: return "LLIL_SX";
        case LLIL_SYSCALL: return "LLIL_SYSCALL";
        case LLIL_SYSCALL_SSA: return "LLIL_SYSCALL_SSA";
        case LLIL_TAILCALL: return "LLIL_TAILCALL";
        case LLIL_TAILCALL_SSA: return "LLIL_TAILCALL_SSA";
        case LLIL_TEST_BIT: return "LLIL_TEST_BIT";
        case LLIL_TRAP: return "LLIL_TRAP";
        case LLIL_UNDEF: return "LLIL_UNDEF";
        case LLIL_UNIMPL: return "LLIL_UNIMPL";
        case LLIL_UNIMPL_MEM: return "LLIL_UNIMPL_MEM";
        case LLIL_XOR: return "LLIL_XOR";
        case LLIL_ZX: return "LLIL_ZX";

        // Added in BN 6.0 (core ABI 187)
        case LLIL_ABS: return "LLIL_ABS";
        case LLIL_BSWAP: return "LLIL_BSWAP";
        case LLIL_CLS: return "LLIL_CLS";
        case LLIL_CLZ: return "LLIL_CLZ";
        case LLIL_CTZ: return "LLIL_CTZ";
        case LLIL_MAXS: return "LLIL_MAXS";
        case LLIL_MAXU: return "LLIL_MAXU";
        case LLIL_MINS: return "LLIL_MINS";
        case LLIL_MINU: return "LLIL_MINU";
        case LLIL_POPCNT: return "LLIL_POPCNT";
        case LLIL_RBIT: return "LLIL_RBIT";

        default: return "";
    }
}

// ---- LLIL / HLIL canonical maps (same vocabulary as mlil_canonical_op) ----
inline const char* llil_canonical_op(BNLowLevelILOperation op) {
    switch (op) {
        case LLIL_SET_REG: case LLIL_SET_REG_SSA: case LLIL_SET_REG_SPLIT:
        case LLIL_SET_REG_SPLIT_SSA: case LLIL_SET_REG_SSA_PARTIAL:
        case LLIL_SET_FLAG: case LLIL_SET_FLAG_SSA:  return "COPY";
        case LLIL_LOAD: case LLIL_LOAD_SSA:          return "LOAD";
        case LLIL_STORE: case LLIL_STORE_SSA:        return "STORE";
        case LLIL_REG_PHI: case LLIL_FLAG_PHI: case LLIL_MEM_PHI:
        case LLIL_REG_STACK_PHI:                     return "MULTIEQUAL";
        case LLIL_ADD: case LLIL_ADC:                return "INT_ADD";
        case LLIL_SUB: case LLIL_SBB:                return "INT_SUB";
        case LLIL_MUL: case LLIL_MULU_DP: case LLIL_MULS_DP: return "INT_MULT";
        case LLIL_DIVU: case LLIL_DIVU_DP:           return "INT_DIV";
        case LLIL_DIVS: case LLIL_DIVS_DP:           return "INT_SDIV";
        case LLIL_MODU: case LLIL_MODU_DP:           return "INT_REM";
        case LLIL_MODS: case LLIL_MODS_DP:           return "INT_SREM";
        case LLIL_AND:                               return "INT_AND";
        case LLIL_OR:                                return "INT_OR";
        case LLIL_XOR:                               return "INT_XOR";
        case LLIL_LSL:                               return "INT_LEFT";
        case LLIL_LSR:                               return "INT_RIGHT";
        case LLIL_ASR:                               return "INT_SRIGHT";
        case LLIL_NEG:                               return "INT_2COMP";
        case LLIL_NOT:                               return "INT_NEGATE";
        case LLIL_SX:                                return "INT_SEXT";
        case LLIL_ZX:                                return "INT_ZEXT";
        case LLIL_LOW_PART:                          return "SUBPIECE";
        case LLIL_CMP_E:                             return "INT_EQUAL";
        case LLIL_CMP_NE:                            return "INT_NOTEQUAL";
        case LLIL_CMP_ULT:                           return "INT_LESS";
        case LLIL_CMP_ULE:                           return "INT_LESSEQUAL";
        case LLIL_CMP_SLT:                           return "INT_SLESS";
        case LLIL_CMP_SLE:                           return "INT_SLESSEQUAL";
        case LLIL_FADD:                              return "FLOAT_ADD";
        case LLIL_FSUB:                              return "FLOAT_SUB";
        case LLIL_FMUL:                              return "FLOAT_MULT";
        case LLIL_FDIV:                              return "FLOAT_DIV";
        case LLIL_FNEG:                              return "FLOAT_NEG";
        case LLIL_JUMP: case LLIL_JUMP_TO:           return "BRANCHIND";
        case LLIL_GOTO:                              return "BRANCH";
        case LLIL_IF:                                return "CBRANCH";
        case LLIL_CALL: case LLIL_CALL_SSA:
        case LLIL_CALL_STACK_ADJUST: case LLIL_CALL_STACK_SSA:
        case LLIL_TAILCALL: case LLIL_TAILCALL_SSA:  return "CALL";
        case LLIL_SYSCALL: case LLIL_SYSCALL_SSA:    return "CALLOTHER";
        case LLIL_RET: case LLIL_NORET:              return "RETURN";
        default:                                     return "";
    }
}

inline const char* hlil_canonical_op(BNHighLevelILOperation op) {
    switch (op) {
        case HLIL_ASSIGN: case HLIL_VAR_INIT: case HLIL_VAR_INIT_SSA:
        case HLIL_ASSIGN_UNPACK:                     return "COPY";
        case HLIL_DEREF: case HLIL_DEREF_SSA: case HLIL_DEREF_FIELD:
        case HLIL_DEREF_FIELD_SSA: case HLIL_ARRAY_INDEX: case HLIL_ARRAY_INDEX_SSA:
                                                     return "LOAD";
        case HLIL_ASSIGN_MEM_SSA: case HLIL_ASSIGN_UNPACK_MEM_SSA: return "STORE";
        case HLIL_VAR_PHI: case HLIL_MEM_PHI:        return "MULTIEQUAL";
        case HLIL_ADD: case HLIL_ADC:                return "INT_ADD";
        case HLIL_SUB: case HLIL_SBB:                return "INT_SUB";
        case HLIL_MUL: case HLIL_MULU_DP: case HLIL_MULS_DP: return "INT_MULT";
        case HLIL_DIVU: case HLIL_DIVU_DP:           return "INT_DIV";
        case HLIL_DIVS: case HLIL_DIVS_DP:           return "INT_SDIV";
        case HLIL_MODU: case HLIL_MODU_DP:           return "INT_REM";
        case HLIL_MODS: case HLIL_MODS_DP:           return "INT_SREM";
        case HLIL_AND:                               return "INT_AND";
        case HLIL_OR:                                return "INT_OR";
        case HLIL_XOR:                               return "INT_XOR";
        case HLIL_LSL:                               return "INT_LEFT";
        case HLIL_LSR:                               return "INT_RIGHT";
        case HLIL_ASR:                               return "INT_SRIGHT";
        case HLIL_NEG:                               return "INT_2COMP";
        case HLIL_NOT:                               return "INT_NEGATE";
        case HLIL_SX:                                return "INT_SEXT";
        case HLIL_ZX:                                return "INT_ZEXT";
        case HLIL_LOW_PART:                          return "SUBPIECE";
        case HLIL_CMP_E:                             return "INT_EQUAL";
        case HLIL_CMP_NE:                            return "INT_NOTEQUAL";
        case HLIL_CMP_ULT:                           return "INT_LESS";
        case HLIL_CMP_ULE:                           return "INT_LESSEQUAL";
        case HLIL_CMP_SLT:                           return "INT_SLESS";
        case HLIL_CMP_SLE:                           return "INT_SLESSEQUAL";
        case HLIL_FADD:                              return "FLOAT_ADD";
        case HLIL_FSUB:                              return "FLOAT_SUB";
        case HLIL_FMUL:                              return "FLOAT_MULT";
        case HLIL_FDIV:                              return "FLOAT_DIV";
        case HLIL_FNEG:                              return "FLOAT_NEG";
        case HLIL_JUMP:                              return "BRANCHIND";
        case HLIL_GOTO: case HLIL_BREAK: case HLIL_CONTINUE: return "BRANCH";
        case HLIL_IF:                                return "CBRANCH";
        case HLIL_CALL: case HLIL_CALL_SSA: case HLIL_TAILCALL: return "CALL";
        case HLIL_SYSCALL: case HLIL_SYSCALL_SSA:    return "CALLOTHER";
        case HLIL_RET: case HLIL_NORET:              return "RETURN";
        // Structured control flow (WHILE/FOR/DO_WHILE/SWITCH/BLOCK/CASE/LABEL) has no
        // single low-IR canonical op -> "" (ir_ops.op = NULL for those rows).
        default:                                     return "";
    }
}

// ============================================================================
// Data Structures for Decompiler Tables
// ============================================================================

/**
 * Pseudocode line (text output)
 */
struct PseudocodeLine {
    uint64_t func_addr;
    uint16_t func_variant = 0;  // same-start Function ordinal (internal row identity)
    int line_num;
    std::string line;
    int indent;
    uint64_t ea = 0;
    std::string comment;
    std::string comment_placement;  // "line" or "none"
};

/**
 * HLIL expression/statement (AST node)
 */
struct HLILItem {
    uint64_t func_addr;
    size_t expr_id;
    bool is_expr;
    int op;
    std::string op_name;
    uint64_t ea;
    int64_t parent_id;
    int depth;
    size_t size;
    std::string type;

    // Operand IDs
    int64_t left_id = -1;
    int64_t right_id = -1;
    int64_t cond_id = -1;
    int64_t true_id = -1;
    int64_t false_id = -1;
    int64_t body_id = -1;
    int64_t init_id = -1;
    int64_t update_id = -1;

    // Values
    int64_t const_val = 0;
    uint64_t const_ptr = 0;
    int64_t var_idx = -1;
    std::string var_name;
    bool var_is_arg = false;
    uint64_t obj_addr = 0;
    std::string obj_name;
    double float_val = 0.0;
    bool has_float_val = false;
    std::string str_val;
};

/**
 * Local variable
 */
struct HLILVar {
    uint64_t func_addr;
    int var_idx;
    std::string name;
    std::string type;
    std::string comment;
    size_t size;
    bool is_arg;
    int arg_idx;
    bool is_result;
    std::string storage;  // "stack", "register", "split"
    int64_t stack_off;
    std::string reg;

    // Internal identity fields used for safe UPDATE operations.
    BNVariableSourceType source_type = RegisterVariableSourceType;
    int64_t storage_id = 0;
    Ref<Function> function;  // exact same-start/platform function for this row
};

/**
 * Function call with arguments
 */
struct HLILCall {
    uint64_t func_addr = 0;
    size_t call_expr_id = 0;
    uint64_t call_ea = 0;
    uint64_t callee_addr = 0;
    std::string callee_name;
    int arg_idx = -1;
    size_t arg_expr_id = 0;
    bool has_arg_expr_id = false;
    std::string arg_op;
    int64_t arg_const = 0;
    bool has_arg_const = false;
    std::string arg_var_name;
    std::string arg_str;
};

// ============================================================================
// Helper Functions
// ============================================================================

inline Ref<BinaryView> get_bv() {
    return core::get_bv();
}

inline Ref<Function> get_function(uint64_t func_addr) {
    auto bv = get_bv();
    if (!bv) return nullptr;

    auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
    if (funcs.empty()) return nullptr;
    return funcs[0];
}

// Test instrumentation: counts HLIL decompilations (each get_hlil call forces
// GetHighLevelIL). The generator-laziness regression test resets this, runs a
// LIMIT query, and asserts only a few functions were decompiled — not the whole
// binary. One inline-function-local static == one shared counter across all TUs;
// a relaxed atomic add per decompile (a ~ms operation) is negligible overhead.
inline std::atomic<uint64_t>& hlil_decompile_counter() {
    static std::atomic<uint64_t> counter{0};
    return counter;
}

/**
 * Get HLIL for a function
 */
inline Ref<HighLevelILFunction> get_hlil(const Ref<Function>& func) {
    if (!func) return nullptr;
    hlil_decompile_counter().fetch_add(1, std::memory_order_relaxed);
    return func->GetHighLevelIL();
}

inline Ref<HighLevelILFunction> get_hlil(uint64_t func_addr) {
    return get_hlil(get_function(func_addr));
}

inline bool decode_hlil_float_constant(
        uint64_t raw, size_t size, double& value) {
    if (size == sizeof(float)) {
        const uint32_t bits = static_cast<uint32_t>(raw);
        float decoded = 0.0f;
        std::memcpy(&decoded, &bits, sizeof(decoded));
        value = static_cast<double>(decoded);
        return true;
    }
    if (size == sizeof(double)) {
        double decoded = 0.0;
        std::memcpy(&decoded, &raw, sizeof(decoded));
        value = decoded;
        return true;
    }
    return false;
}

/**
 * Convert DisassemblyTextLine to string
 */
inline std::string text_line_to_string(const std::vector<InstructionTextToken>& tokens) {
    std::string result;
    for (const auto& tok : tokens) {
        result += tok.text;
    }
    return result;
}

/**
 * Get type string from Confidence<Ref<Type>>
 */
inline std::string type_to_string(const Confidence<Ref<Type>>& type) {
    if (!type || !type.GetValue()) return "";
    return type->GetString();
}

inline std::string comment_for_address(const Ref<BinaryView>& bv, uint64_t ea) {
    if (!bv || ea == 0) return "";

    auto comment = bv->GetCommentForAddress(ea);
    if (!comment.empty()) return comment;

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (!funcs.empty()) {
        comment = funcs[0]->GetCommentForAddress(ea);
        if (!comment.empty()) return comment;
    }

    return "";
}

inline std::string hlil_var_comment_key_legacy(const HLILVar& row) {
    std::ostringstream key;
    key << "bnsql.hlil_vars.comment."
        << row.func_addr << "."
        << static_cast<int>(row.source_type) << "."
        << row.storage_id << "."
        << row.var_idx;
    return key.str();
}

inline std::string hlil_var_function_scope(const HLILVar& row) {
    if (!row.function) return "";

    std::string identity;
    if (auto platform = row.function->GetPlatform())
        identity += platform->GetName();
    identity.push_back('\0');
    if (auto arch = row.function->GetArchitecture())
        identity += arch->GetName();

    static constexpr char k_hex[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(identity.size() * 2);
    for (const unsigned char c : identity) {
        encoded.push_back(k_hex[c >> 4]);
        encoded.push_back(k_hex[c & 0xf]);
    }
    return encoded;
}

inline std::string hlil_var_comment_key(const HLILVar& row) {
    std::string key = hlil_var_comment_key_legacy(row);
    const std::string scope = hlil_var_function_scope(row);
    if (!scope.empty()) key += ".function." + scope;
    return key;
}

inline std::string get_hlil_var_comment(const Ref<BinaryView>& bv, const HLILVar& row) {
    if (!bv) return "";
    auto metadata = bv->QueryMetadata(hlil_var_comment_key(row));
    if (metadata && metadata->IsString()) return metadata->GetString();

    // Old databases used an address-only key. It is safe to read that key only
    // when the address has one function; for same-start platform functions the
    // old value is ambiguous and must not bleed into every row.
    if (bv->GetAnalysisFunctionsForAddress(row.func_addr).size() == 1) {
        metadata = bv->QueryMetadata(hlil_var_comment_key_legacy(row));
        if (metadata && metadata->IsString()) return metadata->GetString();
    }
    return "";
}

inline bool set_hlil_var_comment(const Ref<BinaryView>& bv, const HLILVar& row, const std::string& comment) {
    if (!bv) return false;
    std::string key = hlil_var_comment_key(row);
    const std::string legacy_key = hlil_var_comment_key_legacy(row);
    if (comment.empty()) {
        bv->RemoveMetadata(key);
    } else {
        bv->StoreMetadata(key, new Metadata(comment));
    }
    if (key != legacy_key &&
        bv->GetAnalysisFunctionsForAddress(row.func_addr).size() == 1)
        bv->RemoveMetadata(legacy_key);
    return true;
}

inline bool resolve_hlil_var_target(const HLILVar& row, Ref<Function>& func_out, Variable& var_out) {
    auto func = row.function ? row.function : get_function(row.func_addr);
    if (!func) return false;

    auto vars = func->GetVariables();

    // Primary match: full internal identity.
    for (const auto& [var, info] : vars) {
        (void)info;
        if (var.type == row.source_type &&
            var.storage == row.storage_id &&
            static_cast<int>(var.index) == row.var_idx) {
            func_out = func;
            var_out = var;
            return true;
        }
    }

    // Fallback match: by var_idx if identity changed after re-analysis.
    for (const auto& [var, info] : vars) {
        (void)info;
        if (static_cast<int>(var.index) == row.var_idx) {
            func_out = func;
            var_out = var;
            return true;
        }
    }

    return false;
}

inline bool parse_type_decl(
    const Ref<BinaryView>& bv,
    const std::string& decl,
    const std::string& fallback_name,
    Ref<Type>& out_type)
{
    if (!bv || decl.empty()) return false;

    auto try_parse = [&](const std::string& text) -> bool {
        QualifiedNameAndType parsed;
        std::string errors;
        if (!bv->ParseTypeString(text, parsed, errors)) return false;
        if (!parsed.type) return false;
        out_type = parsed.type;
        return true;
    };

    if (try_parse(decl)) return true;

    // Some parsers expect a complete declaration with an identifier.
    if (!fallback_name.empty()) {
        if (try_parse(decl + " " + fallback_name)) return true;
        if (try_parse(decl + " " + fallback_name + ";")) return true;
    }

    if (try_parse(decl + ";")) return true;

    return false;
}

inline bool parse_function_type_decl(
    const Ref<BinaryView>& bv,
    const std::string& decl,
    const std::string& fallback_name,
    Ref<Type>& out_type)
{
    if (!bv || decl.empty()) return false;

    auto try_parse = [&](const std::string& text) -> bool {
        QualifiedNameAndType parsed;
        std::string errors;
        if (!bv->ParseTypeString(text, parsed, errors)) return false;
        if (!parsed.type || parsed.type->GetClass() != FunctionTypeClass) return false;
        out_type = parsed.type;
        return true;
    };

    if (try_parse(decl)) return true;
    if (try_parse(decl + ";")) return true;

    // If the user provided something like "int(void)", inject function name.
    auto lparen = decl.find('(');
    if (lparen != std::string::npos && !fallback_name.empty()) {
        std::string with_name = decl.substr(0, lparen) + " " + fallback_name + decl.substr(lparen);
        if (try_parse(with_name)) return true;
        if (try_parse(with_name + ";")) return true;
    }

    return false;
}

// ============================================================================
// Collectors + table definitions (bodies in decompiler.cpp)
// ============================================================================
// with_comment=false skips the per-line comment_for_address() lookup (a BN
// comment/function query per line) for projection queries that read neither
// `comment` nor `comment_placement`. All row-identity columns are unaffected.
void collect_pseudocode(std::vector<PseudocodeLine>& out, uint64_t func_addr,
                        bool with_comment = true);
void collect_hlil_vars(std::vector<HLILVar>& out, uint64_t func_addr);
bool lookup_hlil_var_by_rowid(HLILVar& out, int64_t rowid);
void collect_hlil_calls(std::vector<HLILCall>& out, uint64_t func_addr);

CachedTableDef<PseudocodeLine> define_pseudocode();
GeneratorTableDef<HLILItem> define_hlil_ast();
CachedTableDef<HLILVar> define_hlil_vars();
GeneratorTableDef<HLILCall> define_hlil_calls();

// One BN MLIL-SSA instruction — the register-transfer IR tier below HLIL, and the
// bnsql leg of the cross-tool low-level IR. `operation` is the raw
// BNMediumLevelILOperation (canonical op naming happens in the unified ir_ops). One row
// per SSA instruction; filter by `func_addr` (one GetMediumLevelIL per function).
struct MlilRow {
    uint64_t func_addr = 0;
    uint32_t index = 0;       // instruction index within the (selected) IL form
    uint64_t addr = 0;        // source address (0 => NULL)
    int operation = 0;        // native IL operation enum value (LLIL/MLIL/HLIL per maturity)
    std::string op_name;      // native op name (LLIL_SET_REG / MLIL_SET_VAR_SSA / HLIL_ASSIGN)
    std::string canonical_op; // cross-tool canonical P-code-style op; "" if none
    uint64_t size = 0;        // operation size in bytes
    int operand_count = 0;    // number of operands
    bool is_ssa = true;       // explicit SSA (the *_ssa rungs), else false
    std::string maturity;     // returned IL form: llil|llil_ssa|mlil|mlil_ssa|hlil|hlil_ssa
    std::string stage;        // coarse cross-tool ordinal: raw|optimized|ssa|final
};

// One row per IL VALUE operand (5-kind model), across whichever IL form `maturity`
// selects. Structural operands (branch targets / SSA versions / intrinsic ids) are skipped.
struct MlilOperandRow {
    uint64_t func_addr = 0;
    uint32_t op_seq = 0;      // owning instruction index (joins mlil.seq)
    int operand_index = 0;    // operand order within the instruction
    std::string role;         // "in" | "out"
    std::string kind;         // reg | imm | mem | var | result
    std::string text;         // best-effort rendering (imm hex / native sub-op); may be empty
    int64_t value = 0;        // immediate value (valid iff has_value)
    bool has_value = false;
    uint64_t size = 0;        // operand size in bytes (0 when BN does not expose it)
    std::string maturity;
    std::string stage;
};

GeneratorTableDef<MlilRow> define_mlil();
GeneratorTableDef<MlilOperandRow> define_mlil_operands();

bool register_decompiler_functions(xsql::Database& db);

// ============================================================================
// Table Registry
// ============================================================================
struct DecompilerTableRegistry {
    CachedTableDef<PseudocodeLine> pseudocode;
    GeneratorTableDef<HLILItem> hlil_ast;
    CachedTableDef<HLILVar> hlil_vars;
    GeneratorTableDef<HLILCall> hlil_calls;
    GeneratorTableDef<MlilRow> mlil;
    GeneratorTableDef<MlilOperandRow> mlil_operands;

    DecompilerTableRegistry();
    ~DecompilerTableRegistry();
    void register_all(xsql::Database& db);

    // Drop all shared table caches so the next scan rebuilds from live
    // analysis state. Only call between statements — never while a cursor
    // on one of these tables is live.

private:
    void create_views(xsql::Database& db);
};

} // namespace decompiler
} // namespace bnsql
