// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

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
#include <bnsql/entities.hpp>
#include <xsql/database.hpp>

#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>

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

        default: return "HLIL_UNKNOWN";
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
    int line_num;
    std::string line;
    int indent;
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
    size_t size;
    bool is_arg;
    int arg_idx;
    bool is_result;
    std::string storage;  // "stack", "register", "split"
    int64_t stack_off;
    std::string reg;
};

/**
 * Function call with arguments
 */
struct HLILCall {
    uint64_t func_addr;
    size_t call_expr_id;
    uint64_t call_ea;
    uint64_t callee_addr;
    std::string callee_name;
    int arg_idx;
    size_t arg_expr_id;
    std::string arg_op;
    int64_t arg_const;
    std::string arg_var_name;
    std::string arg_str;
};

// ============================================================================
// Helper Functions
// ============================================================================

inline Ref<BinaryView> get_bv() {
    return entities::get_bv();
}

/**
 * Get HLIL for a function
 */
inline Ref<HighLevelILFunction> get_hlil(uint64_t func_addr) {
    auto bv = get_bv();
    if (!bv) return nullptr;

    auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
    if (funcs.empty()) return nullptr;

    return funcs[0]->GetHighLevelIL();
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

// ============================================================================
// Collectors: Build table data from HLIL
// ============================================================================

/**
 * Collect pseudocode lines for a function
 */
inline void collect_pseudocode(std::vector<PseudocodeLine>& out, uint64_t func_addr) {
    auto hlil = get_hlil(func_addr);
    if (!hlil) return;

    auto func = hlil->GetFunction();
    if (!func) return;

    // Get lines from HLIL root
    auto lines = func->GetHighLevelILIfAvailable();
    if (!lines) return;

    // Use GetRootExpr and walk to get text representation
    auto root = lines->GetRootExpr();
    auto textLines = lines->GetExprText(root.exprIndex, true, nullptr);

    int line_num = 0;
    for (const auto& line : textLines) {
        PseudocodeLine pl;
        pl.func_addr = func_addr;
        pl.line_num = line_num++;
        pl.line = text_line_to_string(line.tokens);
        pl.indent = 0;  // DisassemblyTextLine doesn't have indent field
        out.push_back(std::move(pl));
    }
}

/**
 * Collect HLIL items (AST nodes) for a function
 * @param max_total Optional limit on total items to collect (0 = unlimited)
 */
inline void collect_hlil_items(std::vector<HLILItem>& out, uint64_t func_addr, size_t max_total = 0) {
    auto hlil = get_hlil(func_addr);
    if (!hlil) return;

    auto func = hlil->GetFunction();

    // Map to track parent relationships
    std::unordered_map<size_t, int64_t> parent_map;
    std::unordered_map<size_t, int> depth_map;

    // Track starting size to enforce limit
    size_t start_size = out.size();

    // Visit all expressions
    hlil->VisitAllExprs([&](const HighLevelILInstruction& expr) {
        // Check limit
        if (max_total > 0 && out.size() >= max_total) {
            return false;  // Stop visiting
        }
        HLILItem item;
        item.func_addr = func_addr;
        item.expr_id = expr.exprIndex;
        item.is_expr = true;  // HLIL doesn't distinguish as cleanly
        item.op = static_cast<int>(expr.operation);
        item.op_name = hlil_op_name(expr.operation);
        item.ea = expr.address;
        item.size = expr.size;

        // Type
        auto type = expr.GetType();
        item.type = type_to_string(type);

        // Parent tracking (set by child processing below)
        auto pit = parent_map.find(expr.exprIndex);
        item.parent_id = (pit != parent_map.end()) ? pit->second : -1;

        auto dit = depth_map.find(expr.exprIndex);
        item.depth = (dit != depth_map.end()) ? dit->second : 0;

        // Process operands based on operation type
        auto operands = expr.GetOperands();
        for (size_t i = 0; i < operands.size(); ++i) {
            const auto& op = operands[i];
            if (op.GetType() == ExprHighLevelOperand) {
                size_t child_id = op.GetExpr().exprIndex;
                parent_map[child_id] = static_cast<int64_t>(expr.exprIndex);
                depth_map[child_id] = item.depth + 1;

                // Map to specific operand columns
                if (i == 0) item.left_id = static_cast<int64_t>(child_id);
                else if (i == 1) item.right_id = static_cast<int64_t>(child_id);
            }
        }

        // Extract values based on operation
        switch (expr.operation) {
            case HLIL_CONST:
            case HLIL_CONST_PTR:
                item.const_val = expr.GetConstant();
                item.const_ptr = static_cast<uint64_t>(expr.GetConstant());
                break;

            case HLIL_FLOAT_CONST:
                item.float_val = expr.GetConstant();
                break;

            case HLIL_VAR:
            case HLIL_VAR_SSA:
            case HLIL_VAR_INIT:
            case HLIL_VAR_INIT_SSA:
            case HLIL_VAR_DECLARE: {
                auto var = expr.GetVariable();
                item.var_idx = var.index;
                item.var_name = func ? func->GetVariableName(var) : "";
                // Check if argument
                auto params = func ? func->GetParameterVariables().GetValue() : std::vector<Variable>();
                for (size_t pi = 0; pi < params.size(); ++pi) {
                    if (params[pi].index == var.index) {
                        item.var_is_arg = true;
                        break;
                    }
                }
                break;
            }

            case HLIL_CALL:
            case HLIL_CALL_SSA:
            case HLIL_TAILCALL: {
                // Get callee from first operand
                if (operands.size() > 0 && operands[0].GetType() == ExprHighLevelOperand) {
                    auto dest = operands[0].GetExpr();
                    if (dest.operation == HLIL_CONST_PTR || dest.operation == HLIL_IMPORT) {
                        item.obj_addr = static_cast<uint64_t>(dest.GetConstant());
                        auto bv = get_bv();
                        if (bv) {
                            auto sym = bv->GetSymbolByAddress(item.obj_addr);
                            if (sym) item.obj_name = sym->GetFullName();
                        }
                    }
                }
                break;
            }

            case HLIL_IMPORT: {
                item.obj_addr = static_cast<uint64_t>(expr.GetConstant());
                auto bv = get_bv();
                if (bv) {
                    auto sym = bv->GetSymbolByAddress(item.obj_addr);
                    if (sym) item.obj_name = sym->GetFullName();
                }
                break;
            }

            case HLIL_IF:
                // cond_id = first operand, true_id = second, false_id = third
                if (operands.size() >= 1 && operands[0].GetType() == ExprHighLevelOperand)
                    item.cond_id = static_cast<int64_t>(operands[0].GetExpr().exprIndex);
                if (operands.size() >= 2 && operands[1].GetType() == ExprHighLevelOperand)
                    item.true_id = static_cast<int64_t>(operands[1].GetExpr().exprIndex);
                if (operands.size() >= 3 && operands[2].GetType() == ExprHighLevelOperand)
                    item.false_id = static_cast<int64_t>(operands[2].GetExpr().exprIndex);
                break;

            case HLIL_WHILE:
            case HLIL_WHILE_SSA:
            case HLIL_DO_WHILE:
            case HLIL_DO_WHILE_SSA:
                if (operands.size() >= 1 && operands[0].GetType() == ExprHighLevelOperand)
                    item.cond_id = static_cast<int64_t>(operands[0].GetExpr().exprIndex);
                if (operands.size() >= 2 && operands[1].GetType() == ExprHighLevelOperand)
                    item.body_id = static_cast<int64_t>(operands[1].GetExpr().exprIndex);
                break;

            case HLIL_FOR:
            case HLIL_FOR_SSA:
                if (operands.size() >= 1 && operands[0].GetType() == ExprHighLevelOperand)
                    item.init_id = static_cast<int64_t>(operands[0].GetExpr().exprIndex);
                if (operands.size() >= 2 && operands[1].GetType() == ExprHighLevelOperand)
                    item.cond_id = static_cast<int64_t>(operands[1].GetExpr().exprIndex);
                if (operands.size() >= 3 && operands[2].GetType() == ExprHighLevelOperand)
                    item.update_id = static_cast<int64_t>(operands[2].GetExpr().exprIndex);
                if (operands.size() >= 4 && operands[3].GetType() == ExprHighLevelOperand)
                    item.body_id = static_cast<int64_t>(operands[3].GetExpr().exprIndex);
                break;

            default:
                break;
        }

        out.push_back(std::move(item));
        return true;  // Continue
    });
}

/**
 * Collect variables for a function
 */
inline void collect_hlil_vars(std::vector<HLILVar>& out, uint64_t func_addr) {
    auto bv = get_bv();
    if (!bv) return;

    auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
    if (funcs.empty()) return;

    auto func = funcs[0];
    auto params = func->GetParameterVariables().GetValue();

    // Build parameter set for quick lookup
    std::unordered_map<uint64_t, int> param_indices;
    for (size_t i = 0; i < params.size(); ++i) {
        param_indices[params[i].index] = static_cast<int>(i);
    }

    for (const auto& [variable, varInfo] : func->GetVariables()) {
        HLILVar hv;
        hv.func_addr = func_addr;
        hv.var_idx = static_cast<int>(variable.index);
        hv.name = varInfo.name;

        hv.type = type_to_string(varInfo.type);
        hv.size = !varInfo.type ? 0 : varInfo.type->GetWidth();

        auto pit = param_indices.find(variable.index);
        hv.is_arg = (pit != param_indices.end());
        hv.arg_idx = hv.is_arg ? pit->second : -1;
        hv.is_result = false;  // BN doesn't mark return vars the same way

        // Storage type
        switch (variable.type) {
            case StackVariableSourceType:
                hv.storage = "stack";
                hv.stack_off = variable.storage;
                break;
            case RegisterVariableSourceType:
                hv.storage = "register";
                hv.reg = bv->GetDefaultArchitecture()
                    ? bv->GetDefaultArchitecture()->GetRegisterName(static_cast<uint32_t>(variable.storage))
                    : "";
                break;
            case FlagVariableSourceType:
                hv.storage = "flag";
                break;
            default:
                hv.storage = "unknown";
                break;
        }

        out.push_back(std::move(hv));
    }
}

/**
 * Collect function calls for a function
 */
inline void collect_hlil_calls(std::vector<HLILCall>& out, uint64_t func_addr) {
    auto hlil = get_hlil(func_addr);
    if (!hlil) return;

    auto func = hlil->GetFunction();
    auto bv = get_bv();

    hlil->VisitAllExprs([&](const HighLevelILInstruction& expr) {
        if (expr.operation != HLIL_CALL && expr.operation != HLIL_CALL_SSA &&
            expr.operation != HLIL_TAILCALL) {
            return true;
        }

        uint64_t callee_addr = 0;
        std::string callee_name;

        auto operands = expr.GetOperands();

        // Get callee info from first operand (destination)
        if (operands.size() > 0 && operands[0].GetType() == ExprHighLevelOperand) {
            auto dest = operands[0].GetExpr();
            if (dest.operation == HLIL_CONST_PTR || dest.operation == HLIL_IMPORT) {
                callee_addr = static_cast<uint64_t>(dest.GetConstant());
                if (bv) {
                    auto sym = bv->GetSymbolByAddress(callee_addr);
                    if (sym) callee_name = sym->GetFullName();
                }
            }
        }

        // Get arguments from parameter list operand
        if (operands.size() >= 2 && operands[1].GetType() == ExprListHighLevelOperand) {
            auto args = operands[1].GetExprList();
            for (size_t i = 0; i < args.size(); ++i) {
                HLILCall call;
                call.func_addr = func_addr;
                call.call_expr_id = expr.exprIndex;
                call.call_ea = expr.address;
                call.callee_addr = callee_addr;
                call.callee_name = callee_name;
                call.arg_idx = static_cast<int>(i);
                call.arg_expr_id = args[i].exprIndex;
                call.arg_op = hlil_op_name(args[i].operation);

                // Extract argument value
                switch (args[i].operation) {
                    case HLIL_CONST:
                    case HLIL_CONST_PTR:
                        call.arg_const = args[i].GetConstant();
                        break;
                    case HLIL_VAR:
                    case HLIL_VAR_SSA:
                        if (func) {
                            call.arg_var_name = func->GetVariableName(args[i].GetVariable());
                        }
                        break;
                    default:
                        break;
                }

                out.push_back(std::move(call));
            }
        }

        // If no arguments, still record the call
        if (operands.size() < 2 || operands[1].GetType() != ExprListHighLevelOperand ||
            operands[1].GetExprList().size() == 0) {
            HLILCall call;
            call.func_addr = func_addr;
            call.call_expr_id = expr.exprIndex;
            call.call_ea = expr.address;
            call.callee_addr = callee_addr;
            call.callee_name = callee_name;
            call.arg_idx = -1;  // No arguments
            out.push_back(std::move(call));
        }

        return true;
    });
}

// ============================================================================
// Table Definitions
// ============================================================================

/**
 * PSEUDOCODE Table - Line-by-line decompiled output
 */
inline CachedTableDef<PseudocodeLine> define_pseudocode() {
    return cached_table<PseudocodeLine>("pseudocode")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~30 lines per function
            return bv->GetAnalysisFunctionList().size() * 30;
        })
        .cache_builder([](std::vector<PseudocodeLine>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_pseudocode(cache, func->GetStart());
            }
        })
        .column_int64("func_addr", [](const PseudocodeLine& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("line_num", [](const PseudocodeLine& r) -> int {
            return r.line_num;
        })
        .column_text("line", [](const PseudocodeLine& r) -> std::string {
            return r.line;
        })
        .column_int("indent", [](const PseudocodeLine& r) -> int {
            return r.indent;
        })
        .build();
}

/**
 * HLIL_AST Table - Raw HLIL AST nodes (Advanced/Expert use)
 *
 * WARNING: This table generates many rows per function. ALWAYS filter by func_addr.
 * For typical analysis, use hlil_calls, hlil_vars, or decompile() instead.
 */
inline CachedTableDef<HLILItem> define_hlil_ast() {
    // Maximum rows to cache - prevents OOM/timeout on large binaries
    // Set conservatively low to ensure responsiveness
    static constexpr size_t MAX_HLIL_ROWS = 100000;
    static constexpr size_t MAX_FUNCTIONS = 500;

    return cached_table<HLILItem>("hlil_ast")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~100 HLIL items per function, capped
            size_t estimate = bv->GetAnalysisFunctionList().size() * 100;
            return std::min(estimate, MAX_HLIL_ROWS);
        })
        .cache_builder([](std::vector<HLILItem>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto funcs = bv->GetAnalysisFunctionList();
            size_t func_count = 0;

            for (auto& func : funcs) {
                // Stop if we've hit either limit
                if (cache.size() >= MAX_HLIL_ROWS || func_count >= MAX_FUNCTIONS) {
                    break;
                }
                try {
                    collect_hlil_items(cache, func->GetStart(), MAX_HLIL_ROWS);
                } catch (...) {
                    // Skip functions that fail to decompile
                }
                func_count++;
            }
        })
        .column_int64("func_addr", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int64("expr_id", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.expr_id);
        })
        .column_int("is_expr", [](const HLILItem& r) -> int {
            return r.is_expr ? 1 : 0;
        })
        .column_int("op", [](const HLILItem& r) -> int {
            return r.op;
        })
        .column_text("op_name", [](const HLILItem& r) -> std::string {
            return r.op_name;
        })
        .column_int64("ea", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_int64("parent_id", [](const HLILItem& r) -> int64_t {
            return r.parent_id;
        })
        .column_int("depth", [](const HLILItem& r) -> int {
            return r.depth;
        })
        .column_int64("size", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.size);
        })
        .column_text("type", [](const HLILItem& r) -> std::string {
            return r.type;
        })
        .column_int64("left_id", [](const HLILItem& r) -> int64_t {
            return r.left_id;
        })
        .column_int64("right_id", [](const HLILItem& r) -> int64_t {
            return r.right_id;
        })
        .column_int64("cond_id", [](const HLILItem& r) -> int64_t {
            return r.cond_id;
        })
        .column_int64("true_id", [](const HLILItem& r) -> int64_t {
            return r.true_id;
        })
        .column_int64("false_id", [](const HLILItem& r) -> int64_t {
            return r.false_id;
        })
        .column_int64("body_id", [](const HLILItem& r) -> int64_t {
            return r.body_id;
        })
        .column_int64("init_id", [](const HLILItem& r) -> int64_t {
            return r.init_id;
        })
        .column_int64("update_id", [](const HLILItem& r) -> int64_t {
            return r.update_id;
        })
        .column_int64("const_val", [](const HLILItem& r) -> int64_t {
            return r.const_val;
        })
        .column_int64("const_ptr", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.const_ptr);
        })
        .column_int64("var_idx", [](const HLILItem& r) -> int64_t {
            return r.var_idx;
        })
        .column_text("var_name", [](const HLILItem& r) -> std::string {
            return r.var_name;
        })
        .column_int("var_is_arg", [](const HLILItem& r) -> int {
            return r.var_is_arg ? 1 : 0;
        })
        .column_int64("obj_addr", [](const HLILItem& r) -> int64_t {
            return static_cast<int64_t>(r.obj_addr);
        })
        .column_text("obj_name", [](const HLILItem& r) -> std::string {
            return r.obj_name;
        })
        .column_double("float_val", [](const HLILItem& r) -> double {
            return r.float_val;
        })
        .column_text("str_val", [](const HLILItem& r) -> std::string {
            return r.str_val;
        })
        .build();
}

/**
 * HLIL_VARS Table - Local variables
 */
inline CachedTableDef<HLILVar> define_hlil_vars() {
    return cached_table<HLILVar>("hlil_vars")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~10 vars per function
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<HLILVar>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_hlil_vars(cache, func->GetStart());
            }
        })
        .column_int64("func_addr", [](const HLILVar& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("var_idx", [](const HLILVar& r) -> int {
            return r.var_idx;
        })
        .column_text("name", [](const HLILVar& r) -> std::string {
            return r.name;
        })
        .column_text("type", [](const HLILVar& r) -> std::string {
            return r.type;
        })
        .column_int64("size", [](const HLILVar& r) -> int64_t {
            return static_cast<int64_t>(r.size);
        })
        .column_int("is_arg", [](const HLILVar& r) -> int {
            return r.is_arg ? 1 : 0;
        })
        .column_int("arg_idx", [](const HLILVar& r) -> int {
            return r.arg_idx;
        })
        .column_int("is_result", [](const HLILVar& r) -> int {
            return r.is_result ? 1 : 0;
        })
        .column_text("storage", [](const HLILVar& r) -> std::string {
            return r.storage;
        })
        .column_int64("stack_off", [](const HLILVar& r) -> int64_t {
            return r.stack_off;
        })
        .column_text("reg", [](const HLILVar& r) -> std::string {
            return r.reg;
        })
        .build();
}

/**
 * HLIL_CALLS Table - Function calls with arguments
 */
inline CachedTableDef<HLILCall> define_hlil_calls() {
    return cached_table<HLILCall>("hlil_calls")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~15 call args per function
            return bv->GetAnalysisFunctionList().size() * 15;
        })
        .cache_builder([](std::vector<HLILCall>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_hlil_calls(cache, func->GetStart());
            }
        })
        .column_int64("func_addr", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int64("call_expr_id", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.call_expr_id);
        })
        .column_int64("call_ea", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.call_ea);
        })
        .column_int64("callee_addr", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.callee_addr);
        })
        .column_text("callee_name", [](const HLILCall& r) -> std::string {
            return r.callee_name;
        })
        .column_int("arg_idx", [](const HLILCall& r) -> int {
            return r.arg_idx;
        })
        .column_int64("arg_expr_id", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.arg_expr_id);
        })
        .column_text("arg_op", [](const HLILCall& r) -> std::string {
            return r.arg_op;
        })
        .column_int64("arg_const", [](const HLILCall& r) -> int64_t {
            return r.arg_const;
        })
        .column_text("arg_var_name", [](const HLILCall& r) -> std::string {
            return r.arg_var_name;
        })
        .column_text("arg_str", [](const HLILCall& r) -> std::string {
            return r.arg_str;
        })
        .build();
}

// ============================================================================
// SQL Functions
// ============================================================================

/**
 * decompile(addr) - Get pseudocode for function at address
 * decompile(addr, limit) - Get pseudocode with line limit
 */
static void sql_decompile(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "decompile requires at least 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    int limit = (argc >= 2) ? sqlite3_value_int(argv[1]) : 10000;
    if (limit <= 0) limit = 10000;

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        sqlite3_result_null(ctx);
        return;
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        sqlite3_result_null(ctx);
        return;
    }

    auto root = hlil->GetRootExpr();
    auto lines = hlil->GetExprText(root.exprIndex, true, nullptr);

    std::ostringstream result;
    int count = 0;
    for (const auto& line : lines) {
        if (count >= limit) break;
        if (count > 0) result << "\n";
        result << text_line_to_string(line.tokens);
        ++count;
    }

    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

/**
 * hlil_at(addr) - Get HLIL text at specific address
 */
static void sql_hlil_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "hlil_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        sqlite3_result_null(ctx);
        return;
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        sqlite3_result_null(ctx);
        return;
    }

    // Find expression at address
    std::string result;
    hlil->VisitAllExprs([&](const HighLevelILInstruction& expr) {
        if (expr.address == ea && result.empty()) {
            auto lines = hlil->GetExprText(expr.exprIndex, true, nullptr);
            if (!lines.empty()) {
                result = text_line_to_string(lines[0].tokens);
            }
            return false;  // Stop
        }
        return true;
    });

    if (!result.empty()) {
        sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

/**
 * hlil_op_at(addr) - Get HLIL operation name at address
 */
static void sql_hlil_op_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "hlil_op_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        sqlite3_result_null(ctx);
        return;
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        sqlite3_result_null(ctx);
        return;
    }

    // Find expression at address
    const char* result = nullptr;
    hlil->VisitAllExprs([&](const HighLevelILInstruction& expr) {
        if (expr.address == ea && !result) {
            result = hlil_op_name(expr.operation);
            return false;  // Stop
        }
        return true;
    });

    if (result) {
        sqlite3_result_text(ctx, result, -1, SQLITE_STATIC);
    } else {
        sqlite3_result_null(ctx);
    }
}

/**
 * Register decompiler SQL functions
 */
inline bool register_decompiler_functions(xsql::Database& db) {
    sqlite3_create_function(db.handle(), "decompile", 1, SQLITE_UTF8, nullptr,
                           sql_decompile, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "decompile", 2, SQLITE_UTF8, nullptr,
                           sql_decompile, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "hlil_at", 1, SQLITE_UTF8, nullptr,
                           sql_hlil_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "hlil_op_at", 1, SQLITE_UTF8, nullptr,
                           sql_hlil_op_at, nullptr, nullptr);
    return true;
}

// ============================================================================
// Table Registry
// ============================================================================

struct DecompilerTableRegistry {
    CachedTableDef<PseudocodeLine> pseudocode;
    CachedTableDef<HLILItem> hlil_ast;
    CachedTableDef<HLILVar> hlil_vars;
    CachedTableDef<HLILCall> hlil_calls;

    DecompilerTableRegistry()
        : pseudocode(define_pseudocode())
        , hlil_ast(define_hlil_ast())
        , hlil_vars(define_hlil_vars())
        , hlil_calls(define_hlil_calls())
    {}

    void register_all(xsql::Database& db) {
        // Register cached tables
        db.register_cached_table("bn_pseudocode", &pseudocode);
        db.create_table("pseudocode", "bn_pseudocode");

        // _hlil_ast - Advanced table for AST pattern matching (underscore = internal)
        // WARNING: Always filter by func_addr to avoid performance issues
        db.register_cached_table("bn_hlil_ast", &hlil_ast);
        db.create_table("_hlil_ast", "bn_hlil_ast");

        db.register_cached_table("bn_hlil_vars", &hlil_vars);
        db.create_table("hlil_vars", "bn_hlil_vars");

        db.register_cached_table("bn_hlil_calls", &hlil_calls);
        db.create_table("hlil_calls", "bn_hlil_calls");

        // Register SQL functions
        register_decompiler_functions(db);

        // Create views (only those not dependent on hlil table)
        create_views(db);
    }

private:
    void create_views(xsql::Database& db) {
        // hlil_v_calls - All function calls
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_calls AS
            SELECT DISTINCT
                func_addr,
                call_expr_id AS expr_id,
                call_ea AS ea,
                callee_addr,
                callee_name,
                COUNT(*) FILTER (WHERE arg_idx >= 0) AS arg_count
            FROM hlil_calls
            GROUP BY func_addr, call_expr_id, call_ea, callee_addr, callee_name
        )", nullptr, nullptr);

        // Advanced views on _hlil_ast (underscore prefix = internal/expert)
        // All require WHERE func_addr = X for performance

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_loops AS
            SELECT func_addr, expr_id, ea, op_name, cond_id, body_id, init_id, update_id
            FROM _hlil_ast
            WHERE op_name IN ('HLIL_WHILE', 'HLIL_WHILE_SSA', 'HLIL_DO_WHILE',
                             'HLIL_DO_WHILE_SSA', 'HLIL_FOR', 'HLIL_FOR_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_ifs AS
            SELECT func_addr, expr_id, ea, cond_id, true_id, false_id
            FROM _hlil_ast WHERE op_name = 'HLIL_IF'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_comparisons AS
            SELECT func_addr, expr_id, ea, op_name, left_id, right_id
            FROM _hlil_ast WHERE op_name LIKE 'HLIL_CMP_%' OR op_name LIKE 'HLIL_FCMP_%'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_assignments AS
            SELECT func_addr, expr_id, ea, op_name, left_id, right_id, var_name
            FROM _hlil_ast
            WHERE op_name IN ('HLIL_ASSIGN', 'HLIL_ASSIGN_UNPACK', 'HLIL_VAR_INIT',
                             'HLIL_VAR_INIT_SSA', 'HLIL_ASSIGN_MEM_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_returns AS
            SELECT func_addr, expr_id, ea, left_id AS return_expr_id
            FROM _hlil_ast WHERE op_name = 'HLIL_RET'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_derefs AS
            SELECT func_addr, expr_id, ea, op_name, left_id AS ptr_expr_id, type
            FROM _hlil_ast WHERE op_name IN ('HLIL_DEREF', 'HLIL_DEREF_SSA',
                                        'HLIL_DEREF_FIELD', 'HLIL_DEREF_FIELD_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_constants AS
            SELECT func_addr, expr_id, ea, op_name, const_val, const_ptr, float_val
            FROM _hlil_ast WHERE op_name IN ('HLIL_CONST', 'HLIL_CONST_PTR',
                                        'HLIL_FLOAT_CONST', 'HLIL_CONST_DATA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_vars AS
            SELECT func_addr, expr_id, ea, var_idx, var_name, var_is_arg, type
            FROM _hlil_ast WHERE var_idx >= 0
        )", nullptr, nullptr);
    }
};

} // namespace decompiler
} // namespace bnsql
