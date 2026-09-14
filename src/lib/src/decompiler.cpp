// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "decompiler.hpp"

namespace bnsql {
namespace decompiler {

using namespace BinaryNinja;

namespace {

// ----------------------------------------------------------------------------
// Pseudocode stable rowid: pack (func_addr, same-start variant, line_num).
//
// The `func_addr` filter iterator AND the DELETE row_lookup must agree on each
// row's rowid WITHOUT counting pseudocode lines in the functions that precede
// the target (line counts require a full HLIL render -- the very cost we are
// eliminating). Binary Ninja can expose multiple platform functions with the
// same entry, so the row identity also carries that function's ordinal among
// GetAnalysisFunctionsForAddress() results. line_num occupies the low bits,
// followed by the variant ordinal; func_addr occupies the high bits.
constexpr int PSEUDO_LINE_BITS = 16;
constexpr uint64_t PSEUDO_LINE_MASK = (uint64_t{1} << PSEUDO_LINE_BITS) - 1;
constexpr int PSEUDO_VARIANT_BITS = 8;
constexpr uint64_t PSEUDO_VARIANT_MASK =
    (uint64_t{1} << PSEUDO_VARIANT_BITS) - 1;
constexpr int PSEUDO_KEY_BITS = PSEUDO_LINE_BITS + PSEUDO_VARIANT_BITS;

inline int64_t encode_pseudocode_rowid(
        uint64_t func_addr, uint16_t func_variant, int line_num) {
    const uint64_t line = static_cast<uint64_t>(line_num) & PSEUDO_LINE_MASK;
    const uint64_t variant =
        static_cast<uint64_t>(func_variant) & PSEUDO_VARIANT_MASK;
    return static_cast<int64_t>(
        (func_addr << PSEUDO_KEY_BITS) | (variant << PSEUDO_LINE_BITS) | line);
}

// True if SQLite's colUsed bitmask marks column `col` as read by the query.
// Bit 63 is SQLite's "column >= 63 or unknown -> assume all columns used".
inline bool col_used_bit(uint64_t col_used, int col) {
    if (col_used & (uint64_t{1} << 63)) return true;
    return col >= 0 && col < 63 && (col_used & (uint64_t{1} << col)) != 0;
}

bool pseudocode_variant_for_function(
        const Ref<BinaryView>& bv, const Ref<Function>& func,
        uint16_t& variant_out) {
    if (!bv || !func) return false;
    const auto same_start = bv->GetAnalysisFunctionsForAddress(func->GetStart());
    for (size_t i = 0; i < same_start.size(); ++i) {
        if (!same_start[i] || same_start[i]->GetObject() != func->GetObject())
            continue;
        if (i > PSEUDO_VARIANT_MASK) {
            xsql::set_vtab_error(
                "pseudocode: too many same-start function variants at " +
                std::to_string(func->GetStart()));
            return false;
        }
        variant_out = static_cast<uint16_t>(i);
        return true;
    }
    xsql::set_vtab_error(
        "pseudocode: function identity disappeared at " +
        std::to_string(func->GetStart()));
    return false;
}

}  // namespace

// ============================================================================
// Collectors: Build table data from HLIL
// ============================================================================

/**
 * Collect pseudocode lines for a function
 */
static void collect_pseudocode_for_function(
        std::vector<PseudocodeLine>& out, const Ref<Function>& exact_func,
        uint16_t func_variant, bool with_comment) {
    auto hlil = get_hlil(exact_func);
    if (!hlil) return;

    auto func = hlil->GetFunction();
    if (!func) return;
    const uint64_t func_addr = func->GetStart();

    // get_hlil() already materialized the exact Function's HLIL. Asking the
    // Function again via GetHighLevelILIfAvailable() reintroduces a partial-
    // analysis dependency and can return null even though `hlil` is valid.
    auto lines = hlil;

    // Use GetRootExpr and walk to get text representation
    auto root = lines->GetRootExpr();
    auto textLines = lines->GetExprText(root.exprIndex, true, nullptr);
    if (textLines.size() > PSEUDO_LINE_MASK + 1) {
        xsql::set_vtab_error(
            "pseudocode: function has too many rendered lines for stable rowids at " +
            std::to_string(func_addr));
        return;
    }
    auto bv = get_bv();

    int line_num = 0;
    for (const auto& line : textLines) {
        PseudocodeLine pl;
        pl.func_addr = func_addr;
        pl.func_variant = func_variant;
        pl.line_num = line_num++;
        pl.line = text_line_to_string(line.tokens);
        pl.indent = 0;  // DisassemblyTextLine doesn't have indent field
        pl.ea = line.addr;
        if (with_comment) {
            pl.comment = comment_for_address(bv, pl.ea);
            pl.comment_placement = pl.comment.empty() ? "none" : "line";
        } else {
            // Projection query does not read comment/comment_placement; leave the
            // (unread) comment empty and skip the per-line BN comment lookup.
            pl.comment_placement = "none";
        }
        out.push_back(std::move(pl));
    }
}

void collect_pseudocode(std::vector<PseudocodeLine>& out, uint64_t func_addr,
                        bool with_comment) {
    auto bv = get_bv();
    if (!bv) return;
    const auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (i > PSEUDO_VARIANT_MASK) {
            xsql::set_vtab_error(
                "pseudocode: too many same-start function variants at " +
                std::to_string(func_addr));
            return;
        }
        collect_pseudocode_for_function(
            out, funcs[i], static_cast<uint16_t>(i), with_comment);
    }
}

/**
 * Collect HLIL items (AST nodes) for a function
 * @param max_total Optional limit on total items to collect (0 = unlimited)
 * @param col_used  SQLite colUsed bitmask; the expensive per-node string columns
 *                  (type=9, var_name=21, obj_name=24) are materialized only when
 *                  the query reads them. Defaults to all-columns (~0).
 */
static void collect_hlil_items_for_function(
        std::vector<HLILItem>& out, const Ref<Function>& exact_func,
        size_t max_total = 0, uint64_t col_used = ~uint64_t{0}) {
    auto hlil = get_hlil(exact_func);
    if (!hlil) return;

    auto func = hlil->GetFunction();
    if (!func) return;
    const uint64_t func_addr = func->GetStart();

    // Hoist the parameter-variable set ONCE per function: it is invariant across
    // every variable node, so re-fetching + copying func->GetParameterVariables()
    // (a fresh BN round-trip that materializes the whole vector) for each node was
    // O(V*P) with V vector copies. Membership is now an O(1) hash-set probe.
    std::unordered_set<uint64_t> param_var_indices;
    if (func) {
        for (const auto& p : func->GetParameterVariables().GetValue()) {
            param_var_indices.insert(p.index);
        }
    }

    const bool need_type = col_used_bit(col_used, 9);       // column `type`
    const bool need_var_name = col_used_bit(col_used, 21);  // column `var_name`
    const bool need_obj_name = col_used_bit(col_used, 24);  // column `obj_name`

    // Recursive pre-order walk from the HLIL root in FULL-AST form. We do NOT use
    // hlil->VisitAllExprs(): for functions whose body is a single HLIL_BLOCK (e.g.
    // the SEH __scrt_common_main_seh) it yields only the root block and drops every
    // if/loop/call node (verified against BN's Python API: 37 instructions, 8 ifs).
    // Instead we descend via GetOperands() — a block exposes its statements as a
    // single ExprListHighLevelOperand — re-fetching every child in full-AST form so
    // the recursion stays AST all the way down (a raw operand child is non-AST and
    // its own operands don't nest). parent_id/depth are threaded through; `visited`
    // keeps the once-per-expr semantics for any shared sub-expression.
    std::unordered_set<size_t> visited;
    std::function<void(const HighLevelILInstruction&, int64_t, int)> walk =
        [&](const HighLevelILInstruction& expr, int64_t parent_id, int depth) {
        if (max_total > 0 && out.size() >= max_total) return;
        if (!visited.insert(expr.exprIndex).second) return;

        HLILItem item;
        item.func_addr = func_addr;
        item.expr_id = expr.exprIndex;
        item.is_expr = true;  // HLIL doesn't distinguish as cleanly
        item.op = static_cast<int>(expr.operation);
        item.op_name = hlil_op_name(expr.operation);
        item.ea = expr.address;
        item.size = expr.size;

        // Type (col 9): rendering a type to string is a per-node BN round-trip;
        // skip it for projection queries that do not read `type`.
        if (need_type) {
            item.type = type_to_string(expr.GetType());
        }

        item.parent_id = parent_id;
        item.depth = depth;

        // Record the first two sub-expression operands as left_id/right_id.
        // Count expression children, not raw operand slots: several operations
        // put a variable/constant before their first expression, and RET carries
        // its sources in an ExprListHighLevelOperand.
        auto operands = expr.GetOperands();
        size_t expression_child = 0;
        auto record_child = [&](const HighLevelILInstruction& child) {
            if (expression_child == 0)
                item.left_id = static_cast<int64_t>(child.exprIndex);
            else if (expression_child == 1)
                item.right_id = static_cast<int64_t>(child.exprIndex);
            ++expression_child;
        };
        for (const auto& op : operands) {
            if (op.GetType() == ExprHighLevelOperand) {
                record_child(op.GetExpr());
            } else if (op.GetType() == ExprListHighLevelOperand) {
                for (const auto& child : op.GetExprList())
                    record_child(child);
            }
        }

        // Extract values based on operation
        switch (expr.operation) {
            case HLIL_CONST:
            case HLIL_CONST_PTR:
                item.const_val = expr.GetConstant();
                item.const_ptr = static_cast<uint64_t>(expr.GetConstant());
                break;

            case HLIL_FLOAT_CONST: {
                const uint64_t raw = static_cast<uint64_t>(expr.GetConstant());
                item.has_float_val = decode_hlil_float_constant(
                    raw, expr.size, item.float_val);
                break;
            }

            case HLIL_VAR:
            case HLIL_VAR_SSA:
            case HLIL_VAR_INIT:
            case HLIL_VAR_INIT_SSA:
            case HLIL_VAR_DECLARE: {
                // The variable is carried by a different operand *usage* per op:
                // HLIL_VAR/HLIL_VAR_DECLARE expose a plain Variable, HLIL_VAR_INIT a
                // DestVariable, and the SSA variants an SSAVariable. expr.GetVariable()
                // only reads the plain-Variable usage and THROWS
                // (HighLevelILInstructionAccessException) on HLIL_VAR_INIT — which
                // aborted the whole function's AST collection. Find the variable by
                // operand *type* instead, which is correct for every case.
                Variable var;
                bool have_var = false;
                for (const auto& op : expr.GetOperands()) {
                    const auto t = op.GetType();
                    if (t == VariableHighLevelOperand) {
                        var = op.GetVariable();
                        have_var = true;
                        break;
                    } else if (t == SSAVariableHighLevelOperand) {
                        var = op.GetSSAVariable().var;
                        have_var = true;
                        break;
                    }
                }
                if (have_var) {
                    item.var_idx = var.index;
                    // var_name (col 21): a per-node BN name lookup; skip for
                    // projections that do not read it.
                    if (func && need_var_name) {
                        item.var_name = func->GetVariableName(var);
                    }
                    // O(1) membership test against the hoisted parameter set (was an
                    // O(P) scan over a freshly-copied parameter vector per node).
                    item.var_is_arg = param_var_indices.count(var.index) != 0;
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
                        // obj_name (col 24): a per-node symbol lookup; skip when
                        // the projection does not read it.
                        if (need_obj_name) {
                            auto bv = get_bv();
                            if (bv) {
                                auto sym = bv->GetSymbolByAddress(item.obj_addr);
                                if (sym) item.obj_name = sym->GetFullName();
                            }
                        }
                    }
                }
                break;
            }

            case HLIL_IMPORT: {
                item.obj_addr = static_cast<uint64_t>(expr.GetConstant());
                // obj_name (col 24): skip the symbol lookup for projections that
                // do not read it.
                if (need_obj_name) {
                    auto bv = get_bv();
                    if (bv) {
                        auto sym = bv->GetSymbolByAddress(item.obj_addr);
                        if (sym) item.obj_name = sym->GetFullName();
                    }
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

        // Descend into every child expression — single exprs AND expr lists (block
        // bodies, call-arg lists). Materialize the child indices first, then recurse:
        // each child is re-fetched in FULL-AST form (GetExpr(idx, true)) so its own
        // operands nest correctly — a plain op.GetExpr()/GetExprList() child is
        // non-AST and would collapse one level down.
        std::vector<size_t> child_indices;
        for (const auto& op : expr.GetOperands()) {
            const auto t = op.GetType();
            if (t == ExprHighLevelOperand) {
                child_indices.push_back(op.GetExpr().exprIndex);
            } else if (t == ExprListHighLevelOperand) {
                for (const auto& child : op.GetExprList()) {
                    child_indices.push_back(child.exprIndex);
                }
            }
        }
        for (size_t child_idx : child_indices) {
            walk(hlil->GetExpr(child_idx, /*asFullAst=*/true),
                 static_cast<int64_t>(expr.exprIndex), depth + 1);
        }
    };
    walk(hlil->GetExpr(hlil->GetRootExpr().exprIndex, /*asFullAst=*/true), -1, 0);
}

/**
 * Collect variables for a function
 */
static void collect_hlil_vars_for_function(
        std::vector<HLILVar>& out, const Ref<Function>& func) {
    auto bv = get_bv();
    if (!bv || !func) return;
    const uint64_t func_addr = func->GetStart();
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
        hv.source_type = variable.type;
        hv.storage_id = variable.storage;
        hv.function = func;

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
                hv.reg = func->GetArchitecture()
                    ? func->GetArchitecture()->GetRegisterName(static_cast<uint32_t>(variable.storage))
                    : "";
                break;
            case FlagVariableSourceType:
                hv.storage = "flag";
                break;
            default:
                hv.storage = "unknown";
                break;
        }

        hv.comment = get_hlil_var_comment(bv, hv);

        out.push_back(std::move(hv));
    }
}

void collect_hlil_vars(std::vector<HLILVar>& out, uint64_t func_addr) {
    auto bv = get_bv();
    if (!bv) return;
    for (const auto& func : bv->GetAnalysisFunctionsForAddress(func_addr)) {
        collect_hlil_vars_for_function(out, func);
    }
}

bool lookup_hlil_var_by_rowid(HLILVar& out, int64_t rowid) {
    if (rowid < 0) return false;

    auto bv = get_bv();
    if (!bv) return false;

    // The global positional rowid counts variables across functions in
    // GetAnalysisFunctionList() order. collect_hlil_vars emits exactly one row
    // per func->GetVariables() entry (no filtering -- see collect_hlil_vars), so
    // we can SKIP whole prefix functions by their variable COUNT and only
    // collect (the expensive part: type render + comment lookup per var) the one
    // function that actually holds the target rowid.
    int64_t current = 0;
    for (auto& func : bv->GetAnalysisFunctionList()) {
        const int64_t n = static_cast<int64_t>(func->GetVariables().size());
        if (rowid < current + n) {
            std::vector<HLILVar> vars;
            collect_hlil_vars_for_function(vars, func);
            const int64_t local = rowid - current;
            // Defensive: collect_hlil_vars must agree with GetVariables().size().
            if (local < 0 || local >= static_cast<int64_t>(vars.size()))
                return false;
            out = std::move(vars[static_cast<size_t>(local)]);
            return true;
        }
        current += n;
    }
    return false;
}

/**
 * Collect function calls for a function
 */
static void collect_hlil_calls_for_function(
        std::vector<HLILCall>& out, const Ref<Function>& exact_func) {
    auto hlil = get_hlil(exact_func);
    if (!hlil) return;

    auto func = hlil->GetFunction();
    if (!func) return;
    const uint64_t func_addr = func->GetStart();
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
                call.has_arg_expr_id = true;
                call.arg_op = hlil_op_name(args[i].operation);

                // Extract argument value
                switch (args[i].operation) {
                    case HLIL_CONST:
                    case HLIL_CONST_PTR:
                        call.arg_const = args[i].GetConstant();
                        call.has_arg_const = true;
                        break;
                    case HLIL_VAR:
                        if (func) {
                            call.arg_var_name = func->GetVariableName(args[i].GetVariable());
                        }
                        break;
                    case HLIL_VAR_SSA:
                        if (func) {
                            call.arg_var_name =
                                func->GetVariableName(args[i].GetSSAVariable().var);
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

void collect_hlil_calls(std::vector<HLILCall>& out, uint64_t func_addr) {
    auto bv = get_bv();
    if (!bv) return;
    for (const auto& func : bv->GetAnalysisFunctionsForAddress(func_addr)) {
        collect_hlil_calls_for_function(out, func);
    }
}

namespace {

// Interrupt-poll cadence for the whole-binary cache builders below. The
// framework binds vtab_interrupted() to the query deadline; polling every N
// functions bounds cancellation latency to a single function's render (~ms)
// while keeping the check off the per-row hot path.
constexpr size_t INTERRUPT_POLL_STRIDE = 16;

// Resolve a single pseudocode line from a packed (func_addr, line_num) rowid
// (see encode_pseudocode_rowid) by rendering ONLY the owning function. Backs the
// pseudocode DELETE path so a keyed delete never rebuilds the whole binary.
bool lookup_pseudocode_by_rowid(PseudocodeLine& out, int64_t rowid) {
    if (rowid < 0) return false;
    const uint64_t key = static_cast<uint64_t>(rowid);
    const uint64_t func_addr = key >> PSEUDO_KEY_BITS;
    const uint16_t func_variant = static_cast<uint16_t>(
        (key >> PSEUDO_LINE_BITS) & PSEUDO_VARIANT_MASK);
    const int line_num = static_cast<int>(key & PSEUDO_LINE_MASK);

    auto bv = get_bv();
    if (!bv) return false;
    const auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
    if (func_variant >= funcs.size()) return false;

    std::vector<PseudocodeLine> rows;
    collect_pseudocode_for_function(
        rows, funcs[func_variant], func_variant, /*with_comment*/ true);
    // The collector assigns line_num = 0,1,2,... in order, so the target is
    // at index line_num; verify to stay robust if that ever changes.
    if (line_num >= 0 && static_cast<size_t>(line_num) < rows.size() &&
        rows[static_cast<size_t>(line_num)].line_num == line_num) {
        out = std::move(rows[static_cast<size_t>(line_num)]);
        return true;
    }
    for (auto& r : rows) {
        if (r.line_num == line_num) { out = std::move(r); return true; }
    }
    return false;
}

// Whole-binary pseudocode build shared by the full cache_builder and the
// projection-aware builder. Polls the query deadline so a long render cancels
// cooperatively instead of running to completion past the timeout.
void build_pseudocode_cache(std::vector<PseudocodeLine>& cache, bool with_comment) {
    auto bv = get_bv();
    if (!bv) return;
    size_t i = 0;
    for (auto& func : bv->GetAnalysisFunctionList()) {
        if ((i++ % INTERRUPT_POLL_STRIDE) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error("query interrupted during pseudocode materialization");
            return;
        }
        uint16_t variant = 0;
        if (!pseudocode_variant_for_function(bv, func, variant)) return;
        collect_pseudocode_for_function(cache, func, variant, with_comment);
    }
}

}  // namespace

// ============================================================================
// Table Definitions
// ============================================================================

/**
 * PSEUDOCODE Table - Line-by-line decompiled output
 */
// Iterator for pseudocode filtered to a single function. Column order MUST match
// define_pseudocode() below (guarded by the value-parity test). Renders ONLY the
// target function: rowids are the packed (func_addr, line_num) key
// (encode_pseudocode_rowid), which matches define_pseudocode().rowid() and the
// DELETE row_lookup, so no global prefix line count (a whole-binary render) is
// needed.
class PseudocodeInFuncIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeInFuncIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        const uint64_t target = static_cast<uint64_t>(addr);
        // GetAnalysisFunctionsForAddress returns every function whose entry is
        // target (filter_eq sets omit=1, so SQLite never re-checks func_addr).
        const auto funcs = bv->GetAnalysisFunctionsForAddress(target);
        for (size_t i = 0; i < funcs.size(); ++i) {
            if (i > PSEUDO_VARIANT_MASK) {
                rows_.clear();
                xsql::set_vtab_error(
                    "pseudocode: too many same-start function variants at " +
                    std::to_string(target));
                return;
            }
            const uint64_t func_addr = funcs[i] ? funcs[i]->GetStart() : target;
            try {
                collect_pseudocode_for_function(
                    rows_, funcs[i], static_cast<uint16_t>(i),
                    /*with_comment*/ true);
            } catch (const std::exception& e) {
                rows_.clear();
                xsql::set_vtab_error(
                    "pseudocode: failed to render function " +
                    std::to_string(func_addr) + ": " + e.what());
                return;
            } catch (...) {
                rows_.clear();
                xsql::set_vtab_error(
                    "pseudocode: failed to render function " +
                    std::to_string(func_addr));
                return;
            }
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1: ctx.result_int(r.line_num); break;
            case 2: ctx.result_text(r.line); break;
            case 3: ctx.result_int(r.indent); break;
            case 4: ctx.result_int64(static_cast<int64_t>(r.ea)); break;
            case 5: ctx.result_text(r.comment); break;
            case 6: ctx.result_text(r.comment_placement); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        if (pos_ >= rows_.size()) return 0;
        return encode_pseudocode_rowid(
            rows_[pos_].func_addr, rows_[pos_].func_variant,
            rows_[pos_].line_num);
    }
};

CachedTableDef<PseudocodeLine> define_pseudocode() {
    return cached_table<PseudocodeLine>("pseudocode")
        .no_shared_cache()
        // Query-scoped writes reconstruct from real argv values; NOCHANGE stays off
        // so a comment-only UPDATE carries every column (the setter needs row.ea).
        .update_from_column_values()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~30 lines per function
            return bv->GetAnalysisFunctionList().size() * 30;
        })
        // Full render (all columns), used by the index/rowid-rebuild paths.
        .cache_builder([](std::vector<PseudocodeLine>& cache) {
            build_pseudocode_cache(cache, /*with_comment*/ true);
        })
        // Full-scan path: skip the per-line comment lookup when the query reads
        // neither `comment` (col 5) nor `comment_placement` (col 6), and poll the
        // query deadline so a long render cancels cooperatively.
        .projection_cache_builder([](std::vector<PseudocodeLine>& cache, uint64_t col_used) {
            const bool need_comment = col_used_bit(col_used, 5) || col_used_bit(col_used, 6);
            build_pseudocode_cache(cache, need_comment);
        })
        // Stable non-positional rowid keyed on (func_addr, line_num): the full
        // scan and the filter iterator report the SAME rowid without either path
        // counting pseudocode lines in preceding functions (a whole-binary render).
        .rowid([](const PseudocodeLine& r) -> int64_t {
            return encode_pseudocode_rowid(
                r.func_addr, r.func_variant, r.line_num);
        })
        // DELETE reconstructs the row from that rowid by rendering ONLY the owning
        // function (UPDATE still reconstructs from argv via row_populator below).
        .row_lookup([](PseudocodeLine& row, int64_t rowid) -> bool {
            return lookup_pseudocode_by_rowid(row, rowid);
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
        .column_int64("addr", [](const PseudocodeLine& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_text_rw("comment",
            [](const PseudocodeLine& r) -> std::string {
                return r.comment;
            },
            [](PseudocodeLine& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv || r.ea == 0) return false;

                std::string comment = text ? text : "";
                bv->SetCommentForAddress(r.ea, comment);
                r.comment = comment;
                r.comment_placement = comment.empty() ? "none" : "line";
                return true;
            })
        // Read-only: comment_placement is DERIVED from `comment` (none when empty,
        // else line). To clear a comment, use `SET comment = ''` / DELETE.
        .column_text("comment_placement", [](const PseudocodeLine& r) -> std::string {
            return r.comment_placement;
        })
        .deletable([](PseudocodeLine& r) -> bool {
            auto bv = get_bv();
            if (!bv || r.ea == 0) return false;

            bv->SetCommentForAddress(r.ea, "");
            for (auto& func : bv->GetAnalysisFunctionsContainingAddress(r.ea)) {
                func->SetCommentForAddress(r.ea, "");
            }

            r.comment.clear();
            r.comment_placement = "none";
            return true;
        })
        // Single-function read pushdown (see _hlil_ast). UPDATE reconstructs from
        // argv values (row_populator); DELETE reconstructs via row_lookup from the
        // packed (func_addr, line_num) rowid that PseudocodeInFuncIterator emits --
        // both render only the target function.
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<PseudocodeInFuncIterator>(addr);
        }, 1.0, 30.0)
        .index_on("func_addr", [](const PseudocodeLine& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        // Reconstruct row identity from real argv values (query-scoped UPDATE path).
        // A bare DELETE (argc==1) has only the rowid and resolves via row_lookup.
        .row_populator([](PseudocodeLine& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 0 && !argv[0].is_null()) {
                const uint64_t key = static_cast<uint64_t>(argv[0].as_int64());
                row.func_variant = static_cast<uint16_t>(
                    (key >> PSEUDO_LINE_BITS) & PSEUDO_VARIANT_MASK);
            }
            if (argc > 2 && !argv[2].is_null())
                row.func_addr = static_cast<uint64_t>(argv[2].as_int64());
            if (argc > 3 && !argv[3].is_null())
                row.line_num = static_cast<int>(argv[3].as_int64());
            if (argc > 6 && !argv[6].is_null())
                row.ea = static_cast<uint64_t>(argv[6].as_int64());
        })
        .build();
}

/**
 * HLIL_AST Table - Raw HLIL AST nodes (Advanced/Expert use)
 *
 * WARNING: This table generates many rows per function. ALWAYS filter by func_addr.
 * For typical analysis, use hlil_calls, hlil_vars, or decompile() instead.
 */
// Iterator for hlil_ast filtered to a single function address. Decompiles ONLY
// the target function instead of rendering HLIL for the whole binary. Column
// order MUST match define_hlil_ast() below (guarded by the value-parity test).
class HlilAstInFuncIterator : public xsql::RowIterator {
    std::vector<HLILItem> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit HlilAstInFuncIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        // Collect every function whose entry is addr (filter_eq sets omit=1, so
        // SQLite never re-checks func_addr) -- matches the whole-binary scan.
        for (auto& func : bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr))) {
            const uint64_t func_addr =
                func ? func->GetStart() : static_cast<uint64_t>(addr);
            try {
                // Unlimited (max_total=0) and all columns (col_used=~0), matching
                // HlilAstGenerator so the filter and full-scan (generator) paths
                // render the identical row set for this function.
                collect_hlil_items_for_function(
                    rows_, func, /*max_total*/ 0);
            } catch (const std::exception& e) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_ast: failed to collect function " +
                    std::to_string(func_addr) + ": " + e.what());
                return;
            } catch (...) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_ast: failed to collect function " +
                    std::to_string(func_addr));
                return;
            }
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0:  ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1:  ctx.result_int64(static_cast<int64_t>(r.expr_id)); break;
            case 2:  ctx.result_int(r.is_expr ? 1 : 0); break;
            case 3:  ctx.result_int(r.op); break;
            case 4:  ctx.result_text(r.op_name); break;
            case 5:  ctx.result_int64(static_cast<int64_t>(r.ea)); break;
            case 6:  ctx.result_int64(r.parent_id); break;
            case 7:  ctx.result_int(r.depth); break;
            case 8:  ctx.result_int64(static_cast<int64_t>(r.size)); break;
            case 9:  ctx.result_text(r.type); break;
            case 10: ctx.result_int64(r.left_id); break;
            case 11: ctx.result_int64(r.right_id); break;
            case 12: ctx.result_int64(r.cond_id); break;
            case 13: ctx.result_int64(r.true_id); break;
            case 14: ctx.result_int64(r.false_id); break;
            case 15: ctx.result_int64(r.body_id); break;
            case 16: ctx.result_int64(r.init_id); break;
            case 17: ctx.result_int64(r.update_id); break;
            case 18: ctx.result_int64(r.const_val); break;
            case 19: ctx.result_int64(static_cast<int64_t>(r.const_ptr)); break;
            case 20: ctx.result_int64(r.var_idx); break;
            case 21: ctx.result_text(r.var_name); break;
            case 22: ctx.result_int(r.var_is_arg ? 1 : 0); break;
            case 23: ctx.result_int64(static_cast<int64_t>(r.obj_addr)); break;
            case 24: ctx.result_text(r.obj_name); break;
            case 25:
                if (r.has_float_val) ctx.result_double(r.float_val);
                else ctx.result_null();
                break;
            case 26: ctx.result_text(r.str_val); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

// Lazy full-scan generator for hlil_ast: decompiles ONE function at a time as
// SQLite pulls rows, so a LIMIT/bounded query renders only the functions actually
// pulled instead of the whole binary. Mirrors idasql's CtreeGenerator. Column
// reads go through define_hlil_ast()'s column getters applied to current(), so the
// generator scan is byte-identical to the (former) cache_builder and the
// HlilAstInFuncIterator pushdown path (same collect_hlil_items call).
class HlilAstGenerator : public xsql::Generator<HLILItem> {
    std::vector<Ref<Function>> funcs_;
    bool funcs_loaded_ = false;
    std::vector<HLILItem> items_;
    size_t func_idx_ = 0;
    size_t idx_ = 0;
    int64_t rowid_ = 0;
    bool started_ = false;

    bool load_next_func() {
        if (!funcs_loaded_) {
            auto bv = get_bv();
            if (bv) funcs_ = bv->GetAnalysisFunctionList();  // fetch ONCE (avoid O(N^2))
            funcs_loaded_ = true;
        }
        while (func_idx_ < funcs_.size()) {
            if ((func_idx_ % INTERRUPT_POLL_STRIDE) == 0 && xsql::vtab_interrupted()) {
                xsql::set_vtab_error("query interrupted during HLIL AST materialization");
                return false;
            }
            auto& f = funcs_[func_idx_++];
            const uint64_t func_addr = f ? f->GetStart() : 0;
            items_.clear();
            try {
                collect_hlil_items_for_function(
                    items_, f, /*max_total*/ 0);
            } catch (const std::exception& e) {
                items_.clear();
                xsql::set_vtab_error(
                    "hlil_ast: failed to collect function " +
                    std::to_string(func_addr) + ": " + e.what());
                return false;
            } catch (...) {
                items_.clear();
                xsql::set_vtab_error(
                    "hlil_ast: failed to collect function " +
                    std::to_string(func_addr));
                return false;
            }
            if (!items_.empty()) { idx_ = 0; return true; }
        }
        return false;
    }

public:
    bool next() override {
        if (!started_) {
            started_ = true;
            if (!load_next_func()) return false;
            rowid_ = 0;
            return true;
        }
        if (idx_ + 1 < items_.size()) { ++idx_; ++rowid_; return true; }
        if (!load_next_func()) return false;
        ++rowid_;
        return true;
    }
    const HLILItem& current() const override { return items_[idx_]; }
    int64_t rowid() const override { return rowid_; }
};

// ---- mlil + mlil_operands (filterable IL-form maturity ladder) --------------
// bnsql's leg of the cross-tool low-IR. The `mlil` table exposes a filterable ladder
// of SIX BN IL forms via `WHERE maturity=<form>` (default mlil_ssa); `mlil_operands`
// projects each instruction's VALUE operands onto the 5-kind model. The op stream and
// operand classification for all three IL tiers were validated measure-first (6/6 distinct
// rungs; 100% value-operand coverage) before this implementation.

// The six lifting rungs. Default (unconstrained) = MLIL_SSA (the SSA reference leg).
enum class ILForm { LLIL, LLIL_SSA, MLIL, MLIL_SSA, HLIL, HLIL_SSA };

static const char* form_name(ILForm f) {
    switch (f) {
        case ILForm::LLIL:      return "llil";
        case ILForm::LLIL_SSA:  return "llil_ssa";
        case ILForm::MLIL:      return "mlil";
        case ILForm::MLIL_SSA:  return "mlil_ssa";
        case ILForm::HLIL:      return "hlil";
        case ILForm::HLIL_SSA:  return "hlil_ssa";
    }
    return "mlil_ssa";
}
// Coarse cross-tool stage ordinal: llil=raw, mlil=optimized, every *_ssa=ssa, hlil=final.
static const char* form_stage(ILForm f) {
    switch (f) {
        case ILForm::LLIL:      return "raw";
        case ILForm::MLIL:      return "optimized";
        case ILForm::HLIL:      return "final";
        case ILForm::LLIL_SSA:
        case ILForm::MLIL_SSA:
        case ILForm::HLIL_SSA:  return "ssa";
    }
    return "ssa";
}
static bool form_is_ssa(ILForm f) {
    return f == ILForm::LLIL_SSA || f == ILForm::MLIL_SSA || f == ILForm::HLIL_SSA;
}
static bool name_to_form(const char* s, ILForm& out) {
    if (!s) return false;
    std::string n(s);
    if (n == "llil")     { out = ILForm::LLIL;     return true; }
    if (n == "llil_ssa") { out = ILForm::LLIL_SSA; return true; }
    if (n == "mlil")     { out = ILForm::MLIL;     return true; }
    if (n == "mlil_ssa") { out = ILForm::MLIL_SSA; return true; }
    if (n == "hlil")     { out = ILForm::HLIL;     return true; }
    if (n == "hlil_ssa") { out = ILForm::HLIL_SSA; return true; }
    return false;
}

// ---- op-stream row collection (uniform across the three IL instruction types) ----
template <typename ILFunc, typename OpNameFn, typename CanonFn>
static void collect_il_rows(Ref<ILFunc> il, uint64_t func_addr, ILForm form,
                            OpNameFn opname, CanonFn canon, std::vector<MlilRow>& out) {
    if (!il) return;
    const char* mat = form_name(form);
    const char* stg = form_stage(form);
    const bool ssa = form_is_ssa(form);
    // A pathological function can make a BN IL form throw from
    // GetInstructionCount()/operator[]. Surface that as a query error: returning
    // a partial stream would look authoritative while silently omitting analysis.
    try {
        const size_t count = il->GetInstructionCount();
        for (size_t i = 0; i < count; ++i) {
            auto insn = (*il)[i];
            MlilRow r;
            r.func_addr = func_addr;
            r.index = static_cast<uint32_t>(i);
            r.addr = insn.address;
            r.operation = static_cast<int>(insn.operation);
            r.op_name = opname(insn.operation);
            r.canonical_op = canon(insn.operation);
            r.size = insn.size;
            r.operand_count = static_cast<int>(insn.GetOperands().size());
            r.is_ssa = ssa;
            r.maturity = mat;
            r.stage = stg;
            out.push_back(r);
        }
    } catch (const std::exception& e) {
        xsql::set_vtab_error(
            std::string("mlil: failed to collect ") + form_name(form) +
            " for function " + std::to_string(func_addr) + ": " + e.what());
    } catch (...) {
        xsql::set_vtab_error(
            std::string("mlil: failed to collect ") + form_name(form) +
            " for function " + std::to_string(func_addr));
    }
}

// Collect the op stream from this exact Function object. This matters when BN
// has multiple analysis functions with the same start: re-resolving by address
// and taking funcs[0] duplicates the first function and drops every sibling.
static void collect_mlil_for_function(std::vector<MlilRow>& out,
                                      const Ref<Function>& func,
                                      ILForm form = ILForm::MLIL_SSA) {
    if (!func) return;
    const uint64_t func_addr = func->GetStart();
    switch (form) {
        case ILForm::LLIL:
            collect_il_rows(func->GetLowLevelIL(), func_addr, form, llil_op_name, llil_canonical_op, out);
            break;
        case ILForm::LLIL_SSA: {
            auto b = func->GetLowLevelIL();
            collect_il_rows(b ? b->GetSSAForm() : nullptr, func_addr, form, llil_op_name, llil_canonical_op, out);
            break;
        }
        case ILForm::MLIL:
            collect_il_rows(func->GetMediumLevelIL(), func_addr, form, mlil_op_name, mlil_canonical_op, out);
            break;
        case ILForm::MLIL_SSA: {
            auto b = func->GetMediumLevelIL();
            collect_il_rows(b ? b->GetSSAForm() : nullptr, func_addr, form, mlil_op_name, mlil_canonical_op, out);
            break;
        }
        case ILForm::HLIL:
            collect_il_rows(func->GetHighLevelIL(), func_addr, form, hlil_op_name, hlil_canonical_op, out);
            break;
        case ILForm::HLIL_SSA: {
            auto b = func->GetHighLevelIL();
            collect_il_rows(b ? b->GetSSAForm() : nullptr, func_addr, form, hlil_op_name, hlil_canonical_op, out);
            break;
        }
    }
}

// Address-filtered queries must include every function whose entry equals the
// requested address, matching the full generator's semantics.
void collect_mlil(std::vector<MlilRow>& out, uint64_t func_addr,
                  ILForm form = ILForm::MLIL_SSA) {
    auto bv = get_bv();
    if (!bv) return;
    for (const auto& func : bv->GetAnalysisFunctionsForAddress(func_addr))
        collect_mlil_for_function(out, func, form);
}

// ---- operand classification (5-kind), per tier (proven in the il_operand_probe lab) ----
static const char* var_kind_of(const Variable& v) {
    return v.type == RegisterVariableSourceType ? "reg" : "var";
}
static const char* llil_expr_kind(const LowLevelILInstruction& e) {
    switch (e.operation) {
        case LLIL_LOAD: case LLIL_LOAD_SSA: case LLIL_STORE: case LLIL_STORE_SSA: return "mem";
        case LLIL_CONST: case LLIL_CONST_PTR: case LLIL_EXTERN_PTR: return "imm";
        case LLIL_REG: case LLIL_REG_SSA: case LLIL_REG_SSA_PARTIAL: case LLIL_REG_PHI:
        case LLIL_REG_SPLIT: case LLIL_REG_SPLIT_SSA:
        case LLIL_FLAG: case LLIL_FLAG_SSA: case LLIL_FLAG_BIT: case LLIL_FLAG_BIT_SSA:
        case LLIL_FLAG_PHI: case LLIL_FLAG_COND: case LLIL_FLAG_GROUP: return "reg";
        default: return "result";
    }
}
static const char* mlil_expr_kind(const MediumLevelILInstruction& e) {
    switch (e.operation) {
        case MLIL_LOAD: case MLIL_LOAD_SSA: case MLIL_LOAD_STRUCT: case MLIL_LOAD_STRUCT_SSA:
        case MLIL_STORE: case MLIL_STORE_SSA: case MLIL_STORE_STRUCT: case MLIL_STORE_STRUCT_SSA:
            return "mem";
        case MLIL_CONST: case MLIL_CONST_PTR: case MLIL_EXTERN_PTR: case MLIL_IMPORT:
        case MLIL_CONST_DATA: case MLIL_FLOAT_CONST: return "imm";
        case MLIL_VAR: case MLIL_VAR_FIELD: case MLIL_VAR_SSA: case MLIL_VAR_SSA_FIELD:
        case MLIL_VAR_ALIASED: case MLIL_VAR_ALIASED_FIELD: case MLIL_VAR_PHI: return "var";
        default: return "result";
    }
}
static const char* hlil_expr_kind(const HighLevelILInstruction& e) {
    switch (e.operation) {
        case HLIL_DEREF: case HLIL_DEREF_SSA: case HLIL_DEREF_FIELD: case HLIL_DEREF_FIELD_SSA:
        case HLIL_ARRAY_INDEX: case HLIL_ARRAY_INDEX_SSA: return "mem";
        case HLIL_CONST: case HLIL_CONST_PTR: case HLIL_EXTERN_PTR: case HLIL_IMPORT:
        case HLIL_FLOAT_CONST: case HLIL_CONST_DATA: return "imm";
        case HLIL_VAR: case HLIL_VAR_SSA: case HLIL_VAR_PHI: case HLIL_STRUCT_FIELD: return "var";
        default: return "result";
    }
}

// One value-operand entry (a list operand expands to several).
struct OpVal {
    std::string kind;
    std::string text;
    bool has_value = false;
    int64_t value = 0;
    uint64_t size = 0;
};

static std::string immediate_text(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

static uint64_t variable_width(const Ref<Function>& func, const Variable& var) {
    if (!func) return 0;
    auto type = func->GetVariableType(var);
    if (!type || !type.GetValue()) return 0;
    return type->GetWidth();
}

static std::string variable_text(const Ref<Function>& func, const Variable& var) {
    return func ? func->GetVariableNameOrDefault(var) : std::string();
}

static std::string ssa_variable_text(const Ref<Function>& func, const SSAVariable& var) {
    std::string text = variable_text(func, var.var);
    if (!text.empty()) text += "#" + std::to_string(var.version);
    return text;
}

static uint64_t register_width(const Ref<Architecture>& arch, uint32_t reg) {
    return arch ? arch->GetRegisterInfo(reg).size : 0;
}

static std::string register_text(const Ref<Architecture>& arch, uint32_t reg) {
    return arch ? arch->GetRegisterName(reg) : std::string();
}

static void push_kind(std::vector<OpVal>& out, const char* kind,
                      std::string text = {}, uint64_t size = 0) {
    out.push_back({kind, std::move(text), false, 0, size});
}

static void llil_operand_values(const LowLevelILOperand& op,
                                const Ref<Function>&,
                                const Ref<Architecture>& arch,
                                uint64_t fallback_size,
                                std::vector<OpVal>& out) {
    switch (op.GetType()) {
        case IntegerLowLevelOperand:
            out.push_back({"imm", immediate_text(op.GetInteger()), true,
                           static_cast<int64_t>(op.GetInteger()), fallback_size});
            break;
        case RegisterLowLevelOperand: {
            const uint32_t reg = op.GetRegister();
            push_kind(out, "reg", register_text(arch, reg), register_width(arch, reg));
            break;
        }
        case RegisterStackLowLevelOperand:
            push_kind(out, "reg",
                      arch ? arch->GetRegisterStackName(op.GetRegisterStack()) : std::string(),
                      fallback_size);
            break;
        case FlagLowLevelOperand:
            push_kind(out, "reg",
                      arch ? arch->GetFlagName(op.GetFlag()) : std::string(), fallback_size);
            break;
        case FlagConditionLowLevelOperand:
            push_kind(out, "reg", std::to_string(static_cast<int>(op.GetFlagCondition())),
                      fallback_size);
            break;
        case SSARegisterLowLevelOperand: {
            const auto reg = op.GetSSARegister();
            std::string text = register_text(arch, reg.reg);
            if (!text.empty()) text += "#" + std::to_string(reg.version);
            push_kind(out, "reg", std::move(text), register_width(arch, reg.reg));
            break;
        }
        case SSARegisterStackLowLevelOperand: {
            const auto reg = op.GetSSARegisterStack();
            std::string text =
                arch ? arch->GetRegisterStackName(reg.regStack) : std::string();
            if (!text.empty()) text += "#" + std::to_string(reg.version);
            push_kind(out, "reg", std::move(text), fallback_size);
            break;
        }
        case SSAFlagLowLevelOperand: {
            const auto flag = op.GetSSAFlag();
            std::string text = arch ? arch->GetFlagName(flag.flag) : std::string();
            if (!text.empty()) text += "#" + std::to_string(flag.version);
            push_kind(out, "reg", std::move(text), fallback_size);
            break;
        }
        case ExprLowLevelOperand: {
            const auto expr = op.GetExpr();
            push_kind(out, llil_expr_kind(expr), llil_op_name(expr.operation), expr.size);
            break;
        }
        case ExprListLowLevelOperand:
            for (const auto& expr : op.GetExprList())
                push_kind(out, llil_expr_kind(expr), llil_op_name(expr.operation), expr.size);
            break;
        case SSARegisterListLowLevelOperand:
            for (const auto& reg : op.GetSSARegisterList()) {
                std::string text = register_text(arch, reg.reg);
                if (!text.empty()) text += "#" + std::to_string(reg.version);
                push_kind(out, "reg", std::move(text), register_width(arch, reg.reg));
            }
            break;
        case SSAFlagListLowLevelOperand:
            for (const auto& flag : op.GetSSAFlagList()) {
                std::string text = arch ? arch->GetFlagName(flag.flag) : std::string();
                if (!text.empty()) text += "#" + std::to_string(flag.version);
                push_kind(out, "reg", std::move(text), fallback_size);
            }
            break;
        case SSARegisterOrFlagListLowLevelOperand:
            for (size_t i = 0; i < op.GetSSARegisterOrFlagList().size(); ++i)
                push_kind(out, "reg", {}, fallback_size);
            break;
        default: break;  // Index/IndexList/IndexMap/Intrinsic/Semantic*/Constraint — structural
    }
}
static void mlil_operand_values(const MediumLevelILOperand& op,
                                const Ref<Function>& func,
                                const Ref<Architecture>&,
                                uint64_t fallback_size,
                                std::vector<OpVal>& out) {
    switch (op.GetType()) {
        case IntegerMediumLevelOperand:
            out.push_back({"imm", immediate_text(op.GetInteger()), true,
                           static_cast<int64_t>(op.GetInteger()), fallback_size});
            break;
        case ConstantDataMediumLevelOperand:
            push_kind(out, "imm", "const_data", fallback_size);
            break;
        case VariableMediumLevelOperand: {
            const auto var = op.GetVariable();
            push_kind(out, var_kind_of(var), variable_text(func, var),
                      variable_width(func, var));
            break;
        }
        case SSAVariableMediumLevelOperand: {
            const auto var = op.GetSSAVariable();
            push_kind(out, var_kind_of(var.var), ssa_variable_text(func, var),
                      variable_width(func, var.var));
            break;
        }
        case ExprMediumLevelOperand: {
            const auto expr = op.GetExpr();
            push_kind(out, mlil_expr_kind(expr), mlil_op_name(expr.operation), expr.size);
            break;
        }
        case ExprListMediumLevelOperand:
            for (const auto& expr : op.GetExprList())
                push_kind(out, mlil_expr_kind(expr), mlil_op_name(expr.operation), expr.size);
            break;
        case VariableListMediumLevelOperand:
            for (const auto& var : op.GetVariableList())
                push_kind(out, var_kind_of(var), variable_text(func, var),
                          variable_width(func, var));
            break;
        case SSAVariableListMediumLevelOperand:
            for (const auto& var : op.GetSSAVariableList())
                push_kind(out, var_kind_of(var.var), ssa_variable_text(func, var),
                          variable_width(func, var.var));
            break;
        default: break;  // Index/IndexList/IndexMap/Intrinsic/Constraint — structural
    }
}
static void hlil_operand_values(const HighLevelILOperand& op,
                                const Ref<Function>& func,
                                const Ref<Architecture>&,
                                uint64_t fallback_size,
                                std::vector<OpVal>& out) {
    switch (op.GetType()) {
        case IntegerHighLevelOperand:
            out.push_back({"imm", immediate_text(op.GetInteger()), true,
                           static_cast<int64_t>(op.GetInteger()), fallback_size});
            break;
        case ConstantDataHighLevelOperand:
            push_kind(out, "imm", "const_data", fallback_size);
            break;
        case VariableHighLevelOperand: {
            const auto var = op.GetVariable();
            push_kind(out, var_kind_of(var), variable_text(func, var),
                      variable_width(func, var));
            break;
        }
        case SSAVariableHighLevelOperand: {
            const auto var = op.GetSSAVariable();
            push_kind(out, var_kind_of(var.var), ssa_variable_text(func, var),
                      variable_width(func, var.var));
            break;
        }
        case ExprHighLevelOperand: {
            const auto expr = op.GetExpr();
            push_kind(out, hlil_expr_kind(expr), hlil_op_name(expr.operation), expr.size);
            break;
        }
        case ExprListHighLevelOperand:
            for (const auto& expr : op.GetExprList())
                push_kind(out, hlil_expr_kind(expr), hlil_op_name(expr.operation), expr.size);
            break;
        case SSAVariableListHighLevelOperand:
            for (const auto& var : op.GetSSAVariableList())
                push_kind(out, var_kind_of(var.var), ssa_variable_text(func, var),
                          variable_width(func, var.var));
            break;
        default: break;  // Index/IndexList/Intrinsic — structural
    }
}

static bool llil_usage_is_out(LowLevelILOperandUsage u) {
    switch (u) {
        case DestExprLowLevelOperandUsage: case DestRegisterLowLevelOperandUsage:
        case DestRegisterStackLowLevelOperandUsage: case DestFlagLowLevelOperandUsage:
        case DestSSARegisterLowLevelOperandUsage: case DestSSARegisterStackLowLevelOperandUsage:
        case DestSSAFlagLowLevelOperandUsage: return true;
        default: return false;
    }
}
static bool mlil_usage_is_out(MediumLevelILOperandUsage u) {
    switch (u) {
        case DestExprMediumLevelOperandUsage: case DestVariableMediumLevelOperandUsage:
        case DestSSAVariableMediumLevelOperandUsage: return true;
        default: return false;
    }
}
static bool hlil_usage_is_out(HighLevelILOperandUsage u) {
    switch (u) {
        case DestVariableHighLevelOperandUsage: case DestSSAVariableHighLevelOperandUsage:
        case DestExprHighLevelOperandUsage: return true;
        default: return false;
    }
}

template <typename ILFunc, typename ValFn, typename OutFn>
static void collect_il_operands(Ref<ILFunc> il, uint64_t func_addr, ILForm form,
                                ValFn valfn, OutFn outfn, std::vector<MlilOperandRow>& out) {
    if (!il) return;
    const char* mat = form_name(form);
    const char* stg = form_stage(form);
    const Ref<Function> func = il->GetFunction();
    const Ref<Architecture> arch = il->GetArchitecture();
    // See collect_il_rows: incomplete operand data must fail the query instead
    // of silently returning a credible-looking partial result.
    try {
        const size_t count = il->GetInstructionCount();
        for (size_t i = 0; i < count; ++i) {
            auto insn = (*il)[i];
            int opidx = 0;
            for (const auto& op : insn.GetOperands()) {
                const bool is_out = outfn(op.GetUsage());
                std::vector<OpVal> vals;
                valfn(op, func, arch, insn.size, vals);
                for (const auto& v : vals) {
                    MlilOperandRow r;
                    r.func_addr = func_addr;
                    r.op_seq = static_cast<uint32_t>(i);
                    r.operand_index = opidx++;
                    r.role = is_out ? "out" : "in";
                    r.kind = v.kind;
                    r.text = v.text;
                    r.has_value = v.has_value;
                    r.value = v.value;
                    r.size = v.size != 0 ? v.size : insn.size;
                    r.maturity = mat;
                    r.stage = stg;
                    out.push_back(r);
                }
            }
        }
    } catch (const std::exception& e) {
        xsql::set_vtab_error(
            std::string("mlil_operands: failed to collect ") + form_name(form) +
            " for function " + std::to_string(func_addr) + ": " + e.what());
    } catch (...) {
        xsql::set_vtab_error(
            std::string("mlil_operands: failed to collect ") + form_name(form) +
            " for function " + std::to_string(func_addr));
    }
}

static void collect_mlil_operands_for_function(
        std::vector<MlilOperandRow>& out, const Ref<Function>& func,
        ILForm form = ILForm::MLIL_SSA) {
    if (!func) return;
    const uint64_t func_addr = func->GetStart();
    switch (form) {
        case ILForm::LLIL:
            collect_il_operands(func->GetLowLevelIL(), func_addr, form, llil_operand_values, llil_usage_is_out, out);
            break;
        case ILForm::LLIL_SSA: {
            auto b = func->GetLowLevelIL();
            collect_il_operands(b ? b->GetSSAForm() : nullptr, func_addr, form, llil_operand_values, llil_usage_is_out, out);
            break;
        }
        case ILForm::MLIL:
            collect_il_operands(func->GetMediumLevelIL(), func_addr, form, mlil_operand_values, mlil_usage_is_out, out);
            break;
        case ILForm::MLIL_SSA: {
            auto b = func->GetMediumLevelIL();
            collect_il_operands(b ? b->GetSSAForm() : nullptr, func_addr, form, mlil_operand_values, mlil_usage_is_out, out);
            break;
        }
        case ILForm::HLIL:
            collect_il_operands(func->GetHighLevelIL(), func_addr, form, hlil_operand_values, hlil_usage_is_out, out);
            break;
        case ILForm::HLIL_SSA: {
            auto b = func->GetHighLevelIL();
            collect_il_operands(b ? b->GetSSAForm() : nullptr, func_addr, form, hlil_operand_values, hlil_usage_is_out, out);
            break;
        }
    }
}

void collect_mlil_operands(std::vector<MlilOperandRow>& out,
                           uint64_t func_addr,
                           ILForm form = ILForm::MLIL_SSA) {
    auto bv = get_bv();
    if (!bv) return;
    for (const auto& func : bv->GetAnalysisFunctionsForAddress(func_addr))
        collect_mlil_operands_for_function(out, func, form);
}

// Column indices (MUST match the define_* column order; the constraint filter reads by index).
enum { ML_FUNC_ADDR = 0, ML_SEQ, ML_ADDR, ML_OPERATION, ML_OP_NAME, ML_CANONICAL,
       ML_SIZE, ML_OPERAND_COUNT, ML_IS_SSA, ML_MATURITY, ML_STAGE };
enum { MLO_FUNC_ADDR = 0, MLO_OP_SEQ, MLO_OPERAND_INDEX, MLO_ROLE, MLO_KIND, MLO_TEXT,
       MLO_VALUE, MLO_SIZE, MLO_MATURITY, MLO_STAGE };

// Parse the func_addr + maturity constraints (both optional). Unknown maturity -> !valid.
static void parse_mlil_constraints(const std::vector<xsql::GeneratorConstraintArg>& args,
                                   int func_addr_col, int maturity_col,
                                   uint64_t& target, bool& has_target, ILForm& form, bool& valid) {
    target = 0; has_target = false; form = ILForm::MLIL_SSA; valid = true;
    for (const auto& arg : args) {
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        if (arg.column_index == func_addr_col) {
            target = static_cast<uint64_t>(arg.value.as_int64()); has_target = true;
        } else if (arg.column_index == maturity_col) {
            ILForm f;
            if (name_to_form(arg.value.as_c_str(), f)) form = f;
            else valid = false;  // unknown maturity -> yield nothing
        }
    }
}

// Generator over the mlil op-stream (one IL form, all or one function).
class MlilGenerator : public xsql::Generator<MlilRow> {
    uint64_t target_; bool has_target_; ILForm form_; bool valid_;
    Ref<BinaryView> bv_;
    std::vector<Ref<Function>> funcs_;
    size_t fi_ = 0; bool single_done_ = false;
    std::vector<MlilRow> current_; size_t row_idx_ = 0;
    int64_t rowid_ = -1;
    bool load_next() {
        if (has_target_) {
            if (single_done_) return false;
            single_done_ = true; current_.clear();
            collect_mlil(current_, target_, form_);
            if (!current_.empty()) { row_idx_ = 0; return true; }
            return false;
        }
        while (fi_ < funcs_.size()) {
            auto f = funcs_[fi_++];
            if (!f) continue;
            current_.clear();
            collect_mlil_for_function(current_, f, form_);
            if (!current_.empty()) { row_idx_ = 0; return true; }
        }
        return false;
    }
public:
    MlilGenerator(ILForm form = ILForm::MLIL_SSA, uint64_t target = 0, bool has_target = false, bool valid = true)
        : target_(target), has_target_(has_target), form_(form), valid_(valid) {
        bv_ = get_bv();
        if (bv_ && !has_target_) funcs_ = bv_->GetAnalysisFunctionList();
    }
    bool next() override {
        if (!valid_) return false;
        bool have_row = false;
        if (!current_.empty() && row_idx_ + 1 < current_.size()) {
            ++row_idx_;
            have_row = true;
        } else {
            have_row = load_next();
        }
        if (have_row) ++rowid_;
        return have_row;
    }
    const MlilRow& current() const override { return current_[row_idx_]; }
    int64_t rowid() const override { return rowid_; }
};

// Generator over mlil value operands (same func/form selection).
class MlilOperandGenerator : public xsql::Generator<MlilOperandRow> {
    uint64_t target_; bool has_target_; ILForm form_; bool valid_;
    Ref<BinaryView> bv_;
    std::vector<Ref<Function>> funcs_;
    size_t fi_ = 0; bool single_done_ = false;
    std::vector<MlilOperandRow> current_; size_t row_idx_ = 0;
    int64_t rowid_ = -1;
    bool load_next() {
        if (has_target_) {
            if (single_done_) return false;
            single_done_ = true; current_.clear();
            collect_mlil_operands(current_, target_, form_);
            if (!current_.empty()) { row_idx_ = 0; return true; }
            return false;
        }
        while (fi_ < funcs_.size()) {
            auto f = funcs_[fi_++];
            if (!f) continue;
            current_.clear();
            collect_mlil_operands_for_function(current_, f, form_);
            if (!current_.empty()) { row_idx_ = 0; return true; }
        }
        return false;
    }
public:
    MlilOperandGenerator(ILForm form = ILForm::MLIL_SSA, uint64_t target = 0, bool has_target = false, bool valid = true)
        : target_(target), has_target_(has_target), form_(form), valid_(valid) {
        bv_ = get_bv();
        if (bv_ && !has_target_) funcs_ = bv_->GetAnalysisFunctionList();
    }
    bool next() override {
        if (!valid_) return false;
        bool have_row = false;
        if (!current_.empty() && row_idx_ + 1 < current_.size()) {
            ++row_idx_;
            have_row = true;
        } else {
            have_row = load_next();
        }
        if (have_row) ++rowid_;
        return have_row;
    }
    const MlilOperandRow& current() const override { return current_[row_idx_]; }
    int64_t rowid() const override { return rowid_; }
};

static std::unique_ptr<xsql::Generator<MlilRow>> make_mlil_generator(
        const std::vector<xsql::GeneratorConstraintArg>& args) {
    uint64_t target; bool has_target; ILForm form; bool valid;
    parse_mlil_constraints(args, ML_FUNC_ADDR, ML_MATURITY, target, has_target, form, valid);
    return std::make_unique<MlilGenerator>(form, target, has_target, valid);
}
static std::unique_ptr<xsql::Generator<MlilOperandRow>> make_mlil_operand_generator(
        const std::vector<xsql::GeneratorConstraintArg>& args) {
    uint64_t target; bool has_target; ILForm form; bool valid;
    parse_mlil_constraints(args, MLO_FUNC_ADDR, MLO_MATURITY, target, has_target, form, valid);
    return std::make_unique<MlilOperandGenerator>(form, target, has_target, valid);
}

GeneratorTableDef<MlilRow> define_mlil() {
    // Column order MUST match the ML_* enum.
    return generator_table<MlilRow>("mlil")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() * 15 : 0;
        })
        // Unconstrained full scan: all functions at the default rung (MLIL-SSA).
        .generator([]() -> std::unique_ptr<xsql::Generator<MlilRow>> {
            return std::make_unique<MlilGenerator>(ILForm::MLIL_SSA);
        })
        .column_int64("func_addr", [](const MlilRow& r) -> int64_t { return static_cast<int64_t>(r.func_addr); })
        .column_int("seq", [](const MlilRow& r) -> int { return static_cast<int>(r.index); })
        .column("addr", xsql::ColumnType::Integer, [](xsql::FunctionContext& ctx, const MlilRow& r) {
            r.addr != 0 ? ctx.result_int64(static_cast<int64_t>(r.addr)) : ctx.result_null();
        })
        .column_int("operation", [](const MlilRow& r) -> int { return r.operation; })
        .column_text("op_name", [](const MlilRow& r) -> std::string { return r.op_name; })
        .column_text("canonical_op", [](const MlilRow& r) -> std::string { return r.canonical_op; })
        .column_int64("size", [](const MlilRow& r) -> int64_t { return static_cast<int64_t>(r.size); })
        .column_int("operand_count", [](const MlilRow& r) -> int { return r.operand_count; })
        .column_int("is_ssa", [](const MlilRow& r) -> int { return r.is_ssa ? 1 : 0; })
        .column_text("maturity", [](const MlilRow& r) -> std::string { return r.maturity; })
        .column_text("stage", [](const MlilRow& r) -> std::string { return r.stage; })
        .constraint_filter(
            { xsql::optional_eq("func_addr"), xsql::optional_eq("maturity") },
            make_mlil_generator, 5.0, 60.0)
        .build();
}

GeneratorTableDef<MlilOperandRow> define_mlil_operands() {
    // Column order MUST match the MLO_* enum.
    return generator_table<MlilOperandRow>("mlil_operands")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() * 40 : 0;
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<MlilOperandRow>> {
            return std::make_unique<MlilOperandGenerator>(ILForm::MLIL_SSA);
        })
        .column_int64("func_addr", [](const MlilOperandRow& r) -> int64_t { return static_cast<int64_t>(r.func_addr); })
        .column_int("op_seq", [](const MlilOperandRow& r) -> int { return static_cast<int>(r.op_seq); })
        .column_int("operand_index", [](const MlilOperandRow& r) -> int { return r.operand_index; })
        .column_text("role", [](const MlilOperandRow& r) -> std::string { return r.role; })
        .column_text("kind", [](const MlilOperandRow& r) -> std::string { return r.kind; })
        .column_text("text", [](const MlilOperandRow& r) -> std::string { return r.text; })
        .column("value", xsql::ColumnType::Integer, [](xsql::FunctionContext& ctx, const MlilOperandRow& r) {
            r.has_value ? ctx.result_int64(r.value) : ctx.result_null();
        })
        .column_int64("size", [](const MlilOperandRow& r) -> int64_t { return static_cast<int64_t>(r.size); })
        .column_text("maturity", [](const MlilOperandRow& r) -> std::string { return r.maturity; })
        .column_text("stage", [](const MlilOperandRow& r) -> std::string { return r.stage; })
        .constraint_filter(
            { xsql::optional_eq("func_addr"), xsql::optional_eq("maturity") },
            make_mlil_operand_generator, 5.0, 80.0)
        .build();
}

GeneratorTableDef<HLILItem> define_hlil_ast() {
    // Planner estimate only (not a truncation): ~100 HLIL items per function.
    static constexpr size_t HLIL_ROWS_ESTIMATE_CAP = 100000;

    return generator_table<HLILItem>("hlil_ast")
        .generator([]() -> std::unique_ptr<xsql::Generator<HLILItem>> {
            return std::make_unique<HlilAstGenerator>();
        })
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            size_t estimate = bv->GetAnalysisFunctionList().size() * 100;
            return std::min(estimate, HLIL_ROWS_ESTIMATE_CAP);
        })
        // Full scans stream one function at a time via HlilAstGenerator (above);
        // a LIMIT/bounded query decompiles only the functions actually pulled.
        // Note: unlike the former projection_cache_builder, the generator renders
        // all columns per node (no col_used pruning) — matching idasql's ctree
        // generator and relying on BN's native HLIL cache for repeats.
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
        .column_int64("addr", [](const HLILItem& r) -> int64_t {
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
        .column("float_val", xsql::ColumnType::Real,
                [](xsql::FunctionContext& ctx, const HLILItem& r) {
                    if (r.has_float_val) ctx.result_double(r.float_val);
                    else ctx.result_null();
                })
        .column_text("str_val", [](const HLILItem& r) -> std::string {
            return r.str_val;
        })
        // Single-function pushdown: WHERE func_addr = X decompiles only that
        // function instead of rendering HLIL for the whole binary.
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<HlilAstInFuncIterator>(addr);
        }, 1.0, 100.0)  // low cost so the planner strongly prefers the filter
        .build();
}

/**
 * HLIL_VARS Table - Local variables
 */
// Iterator for hlil_vars filtered to a single function. Column order MUST match
// define_hlil_vars() below (value-parity guarded). NOTE: hlil_vars reconstructs
// writes via a GLOBAL positional row_lookup (lookup_hlil_var_by_rowid), so this
// iterator emits the same global positional rowid (not a per-function position)
// to keep UPDATE/DELETE keyed correctly -- verified by the hlil_vars write tests.
class HlilVarsInFuncIterator : public xsql::RowIterator {
    std::vector<HLILVar> rows_;
    std::vector<int64_t> rowids_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit HlilVarsInFuncIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        const uint64_t target = static_cast<uint64_t>(addr);
        // Compute rowids in the same global positional order as
        // lookup_hlil_var_by_rowid (GetAnalysisFunctionList order). Prefix
        // functions are skipped by their cheap variable COUNT (no render), and
        // only the target function is collected -- a single-function operation.
        int64_t current = 0;
        for (auto& func : bv->GetAnalysisFunctionList()) {
            if (func->GetStart() == target) {
                std::vector<HLILVar> vars;
                collect_hlil_vars_for_function(vars, func);
                for (auto& var : vars) {
                    rowids_.push_back(current++);
                    rows_.push_back(std::move(var));
                }
                continue;
            }
            // Skip prefix functions by their variable COUNT (cheap: no type render
            // or per-var comment lookup). collect_hlil_vars emits exactly one row
            // per GetVariables() entry, so this count matches
            // lookup_hlil_var_by_rowid's global positional rowid scheme.
            current += static_cast<int64_t>(func->GetVariables().size());
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0:  ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1:  ctx.result_int(r.var_idx); break;
            case 2:  ctx.result_text(r.name); break;
            case 3:  ctx.result_text(r.type); break;
            case 4:  ctx.result_text(r.comment); break;
            case 5:  ctx.result_int64(static_cast<int64_t>(r.size)); break;
            case 6:  ctx.result_int(r.is_arg ? 1 : 0); break;
            case 7:  ctx.result_int(r.arg_idx); break;
            case 8:  ctx.result_int(r.is_result ? 1 : 0); break;
            case 9:  ctx.result_text(r.storage); break;
            case 10: ctx.result_int64(r.stack_off); break;
            case 11: ctx.result_text(r.reg); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return pos_ < rowids_.size() ? rowids_[pos_] : 0;
    }
};

// The hlil_vars commit hook flushes analysis (UpdateAnalysisAndWait) ONLY when a
// NAME or TYPE edit is pending. A rename/retype needs a re-analysis to surface in
// the next read, but a var COMMENT write is immediate metadata that reflects
// without re-analysis — forcing a flush on a comment write is both wasteful and
// disturbs the variable set (it re-derives vars, breaking a just-set comment's
// var association). The name/type setters set this flag; the commit hook consumes
// it. Thread-local: the HTTP server runs queries on worker threads, and a setter
// and its statement's xCommit run on the same thread.
static thread_local bool g_hlil_reflect_pending = false;

CachedTableDef<HLILVar> define_hlil_vars() {
    auto builder = cached_table<HLILVar>("hlil_vars");
    builder.no_shared_cache();
    // The name/type setters below only mark the function dirty
    // (CreateUser{,Stack}Variable) — deliberately NO per-write reanalysis. This
    // hook fires ONCE at the end of the write statement/transaction and flushes
    // analysis a single time, so a same-session read reflects the edit.
    persistence::install_commit_hook(builder, []() {
        if (!g_hlil_reflect_pending) return;  // comment-only writes need no flush
        g_hlil_reflect_pending = false;
        auto bv = get_bv();
        if (bv) bv->UpdateAnalysisAndWait();
    });
    return builder
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~10 vars per function
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<HLILVar>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            size_t i = 0;
            for (auto& func : bv->GetAnalysisFunctionList()) {
                if ((i++ % INTERRUPT_POLL_STRIDE) == 0 && xsql::vtab_interrupted()) {
                    xsql::set_vtab_error("query interrupted during HLIL variable materialization");
                    return;
                }
                collect_hlil_vars_for_function(cache, func);
            }
        })
        .row_lookup([](HLILVar& row, int64_t rowid) -> bool {
            return lookup_hlil_var_by_rowid(row, rowid);
        })
        .column_int64("func_addr", [](const HLILVar& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("var_idx", [](const HLILVar& r) -> int {
            return r.var_idx;
        })
        .column_text_rw("name",
            [](const HLILVar& r) -> std::string {
                return r.name;
            },
            [](HLILVar& r, const char* text) -> bool {
                std::string new_name = text ? text : "";
                if (new_name.empty()) {
                    xsql::set_vtab_error("Variable name cannot be empty");
                    return false;
                }

                Ref<Function> func;
                Variable var;
                if (!resolve_hlil_var_target(r, func, var)) {
                    xsql::set_vtab_error("Failed to resolve variable target for: " + r.name);
                    return false;
                }

                auto vars = func->GetVariables();
                auto it = vars.find(var);
                if (it == vars.end()) {
                    xsql::set_vtab_error("Variable not found in function variable map: " + r.name);
                    return false;
                }
                if (!it->second.type || !it->second.type.GetValue()) {
                    xsql::set_vtab_error("Variable has no type information: " + r.name);
                    return false;
                }
                // Use the correct BN API depending on variable source type.
                // Delete-before-create UNCONDITIONALLY: CreateUser{Stack,}Variable
                // will not override an existing variable's name, and the previous
                // `if (IsVariableUserDefinded)` guard skipped the delete for
                // analysis-named (not-yet-user-defined) vars — so renaming such a var
                // silently no-op'd (UPDATE reported success, name unchanged). Deleting
                // a var that has no user override is a safe no-op.
                if (var.type == StackVariableSourceType) {
                    func->DeleteUserStackVariable(var.storage);
                    func->CreateUserStackVariable(var.storage, it->second.type, new_name);
                } else {
                    func->DeleteUserVariable(var);
                    func->CreateUserVariable(var, it->second.type, new_name, true);
                }

                // No per-write reanalysis: mark-dirty only, and flag that a name
                // edit is pending so the hlil_vars commit hook does ONE
                // UpdateAnalysisAndWait() at the end of the write statement. A batch
                // of renames in a single UPDATE all stick and reflect in the next
                // same-session read with no manual decompile(refresh=1).
                g_hlil_reflect_pending = true;
                auto updated_type = func->GetVariableType(var);
                r.name = new_name;
                r.type = type_to_string(updated_type);
                if (updated_type.GetValue()) {
                    r.size = updated_type->GetWidth();
                }
                return true;
            })
        .column_text_rw("type",
            [](const HLILVar& r) -> std::string {
                return r.type;
            },
            [](HLILVar& r, const char* text) -> bool {
                Ref<Function> func;
                Variable var;
                if (!resolve_hlil_var_target(r, func, var)) {
                    xsql::set_vtab_error("Failed to resolve variable target for: " + r.name);
                    return false;
                }

                auto vars = func->GetVariables();
                auto it = vars.find(var);
                if (it == vars.end()) {
                    xsql::set_vtab_error("Variable not found in function variable map: " + r.name);
                    return false;
                }

                std::string new_decl = text ? text : "";
                if (new_decl.empty()) {
                    // Treat empty type as "clear user override".
                    func->DeleteUserVariable(var);

                    auto refreshed = func->GetVariables();
                    auto rit = refreshed.find(var);
                    if (rit != refreshed.end()) {
                        r.name = rit->second.name;
                        r.type = type_to_string(rit->second.type);
                        r.size = rit->second.type.GetValue()
                                     ? rit->second.type->GetWidth()
                                     : 0;
                    } else {
                        r.type.clear();
                        r.size = 0;
                    }
                    return true;
                }

                auto bv = get_bv();
                if (!bv) return false;

                std::string keep_name = r.name.empty() ? it->second.name : r.name;
                if (keep_name.empty()) {
                    keep_name = "var_" + std::to_string(r.var_idx);
                }

                Ref<Type> parsed_type;
                if (!parse_type_decl(bv, new_decl, keep_name, parsed_type) || !parsed_type) {
                    xsql::set_vtab_error("Failed to parse type: " + new_decl);
                    return false;
                }

                // Delete-before-create unconditionally (same reason as the name
                // setter above): the conditional/absent delete left analysis-named
                // vars silently un-retyped.
                if (var.type == StackVariableSourceType) {
                    func->DeleteUserStackVariable(var.storage);
                    func->CreateUserStackVariable(var.storage, Confidence<Ref<Type>>(parsed_type), keep_name);
                } else {
                    func->DeleteUserVariable(var);
                    func->CreateUserVariable(var, Confidence<Ref<Type>>(parsed_type), keep_name, true);
                }

                // A type edit needs the commit-hook analysis flush (like a rename).
                g_hlil_reflect_pending = true;
                auto updated_type = func->GetVariableType(var);
                r.name = func->GetVariableName(var);
                r.type = type_to_string(updated_type);
                r.size = updated_type.GetValue()
                             ? updated_type->GetWidth()
                             : parsed_type->GetWidth();
                return true;
            })
        .column_text_rw("comment",
            [](const HLILVar& r) -> std::string {
                return r.comment;
            },
            [](HLILVar& r, const char* text) -> bool {
                Ref<Function> func;
                Variable var;
                if (!resolve_hlil_var_target(r, func, var)) return false;

                // Refresh identity in case analysis changed variable internals.
                r.source_type = var.type;
                r.storage_id = var.storage;
                r.var_idx = static_cast<int>(var.index);

                auto bv = get_bv();
                if (!bv) return false;

                std::string new_comment = text ? text : "";
                if (!set_hlil_var_comment(bv, r, new_comment)) return false;
                r.comment = new_comment;
                return true;
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
        .deletable([](HLILVar& r) -> bool {
            Ref<Function> func;
            Variable var;
            if (!resolve_hlil_var_target(r, func, var)) {
                xsql::set_vtab_error("Failed to resolve variable target for delete: " + r.name);
                return false;
            }

            func->DeleteUserVariable(var);
            return true;
        })
        // Single-function read pushdown (see _hlil_ast). The iterator emits global
        // positional rowids matching lookup_hlil_var_by_rowid, so UPDATE/DELETE
        // keyed through the filter reconstruct the correct var (write tests guard).
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<HlilVarsInFuncIterator>(addr);
        }, 1.0, 10.0)
        .index_on("func_addr", [](const HLILVar& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

/**
 * HLIL_CALLS Table - Function calls with arguments
 */
// Iterator for hlil_calls filtered to a single function. Column order MUST match
// define_hlil_calls() below (guarded by the value-parity test).
class HlilCallsInFuncIterator : public xsql::RowIterator {
    std::vector<HLILCall> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit HlilCallsInFuncIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        for (auto& func : bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr))) {
            const uint64_t func_addr =
                func ? func->GetStart() : static_cast<uint64_t>(addr);
            try {
                collect_hlil_calls_for_function(rows_, func);
            } catch (const std::exception& e) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr) + ": " + e.what());
                return;
            } catch (...) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr));
                return;
            }
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0:  ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1:  ctx.result_int64(static_cast<int64_t>(r.call_expr_id)); break;
            case 2:  ctx.result_int64(static_cast<int64_t>(r.call_ea)); break;
            case 3:  ctx.result_int64(static_cast<int64_t>(r.callee_addr)); break;
            case 4:  ctx.result_text(r.callee_name); break;
            case 5:  ctx.result_int(r.arg_idx); break;
            case 6:
                if (r.has_arg_expr_id)
                    ctx.result_int64(static_cast<int64_t>(r.arg_expr_id));
                else
                    ctx.result_null();
                break;
            case 7:  ctx.result_text(r.arg_op); break;
            case 8:
                if (r.has_arg_const) ctx.result_int64(r.arg_const);
                else ctx.result_null();
                break;
            case 9:  ctx.result_text(r.arg_var_name); break;
            case 10: ctx.result_text(r.arg_str); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

// Iterator for hlil_calls filtered by callee_addr ("who calls X" / reverse-call).
// Resolves candidate CALLER functions via BN reverse xrefs and decompiles only
// those, instead of rendering HLIL for the whole binary. filter_eq uses omit=1
// (SQLite trusts the iterator), so it emits ONLY rows whose callee_addr exactly
// equals the target. Column order MUST match define_hlil_calls() below.
class HlilCallsByCalleeIterator : public xsql::RowIterator {
    std::vector<HLILCall> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit HlilCallsByCalleeIterator(int64_t callee) {
        auto bv = get_bv();
        if (!bv) return;
        const uint64_t target = static_cast<uint64_t>(callee);

        // Candidate caller functions. For a resolved callee, the reverse-xref set
        // (GetCallers plus GetCodeReferences) is a complete superset of the functions
        // whose HLIL records a call to `target`: collect_hlil_calls only sets a
        // non-zero callee_addr for resolved HLIL_CONST_PTR/HLIL_IMPORT dests, which
        // the analysis always cross-references. A zero target (unresolved callee)
        // has no meaningful reverse xref, so fall back to the whole-binary set to
        // keep exact parity with the full scan for that degenerate query.
        std::vector<Ref<Function>> candidates;
        if (target == 0) {
            candidates = bv->GetAnalysisFunctionList();
        } else {
            std::unordered_set<BNFunction*> seen;
            auto add = [&](const Ref<Function>& f) {
                if (f && seen.insert(f->GetObject()).second) candidates.push_back(f);
            };
            for (const auto& ref : bv->GetCallers(target)) add(ref.func);
            for (const auto& ref : bv->GetCodeReferences(target)) add(ref.func);
        }

        for (auto& func : candidates) {
            std::vector<HLILCall> calls;
            const uint64_t func_addr = func ? func->GetStart() : 0;
            try {
                collect_hlil_calls_for_function(calls, func);
            } catch (const std::exception& e) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr) + ": " + e.what());
                return;
            } catch (...) {
                rows_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr));
                return;
            }
            for (auto& c : calls) {
                if (c.callee_addr == target) rows_.push_back(std::move(c));
            }
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0:  ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1:  ctx.result_int64(static_cast<int64_t>(r.call_expr_id)); break;
            case 2:  ctx.result_int64(static_cast<int64_t>(r.call_ea)); break;
            case 3:  ctx.result_int64(static_cast<int64_t>(r.callee_addr)); break;
            case 4:  ctx.result_text(r.callee_name); break;
            case 5:  ctx.result_int(r.arg_idx); break;
            case 6:
                if (r.has_arg_expr_id)
                    ctx.result_int64(static_cast<int64_t>(r.arg_expr_id));
                else
                    ctx.result_null();
                break;
            case 7:  ctx.result_text(r.arg_op); break;
            case 8:
                if (r.has_arg_const) ctx.result_int64(r.arg_const);
                else ctx.result_null();
                break;
            case 9:  ctx.result_text(r.arg_var_name); break;
            case 10: ctx.result_text(r.arg_str); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

// Lazy full-scan generator for hlil_calls: one function decompiled at a time as
// SQLite pulls rows (see HlilAstGenerator). Reuses collect_hlil_calls so the
// generator scan is byte-identical to the (former) cache_builder and the
// HlilCallsInFuncIterator / HlilCallsByCalleeIterator pushdown paths.
class HlilCallsGenerator : public xsql::Generator<HLILCall> {
    std::vector<Ref<Function>> funcs_;
    bool funcs_loaded_ = false;
    std::vector<HLILCall> items_;
    size_t func_idx_ = 0;
    size_t idx_ = 0;
    int64_t rowid_ = 0;
    bool started_ = false;

    bool load_next_func() {
        if (!funcs_loaded_) {
            auto bv = get_bv();
            if (bv) funcs_ = bv->GetAnalysisFunctionList();  // fetch ONCE (avoid O(N^2))
            funcs_loaded_ = true;
        }
        while (func_idx_ < funcs_.size()) {
            if ((func_idx_ % INTERRUPT_POLL_STRIDE) == 0 && xsql::vtab_interrupted()) {
                xsql::set_vtab_error("query interrupted during HLIL call materialization");
                return false;
            }
            auto& f = funcs_[func_idx_++];
            const uint64_t func_addr = f ? f->GetStart() : 0;
            items_.clear();
            try {
                collect_hlil_calls_for_function(items_, f);
            } catch (const std::exception& e) {
                items_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr) + ": " + e.what());
                return false;
            } catch (...) {
                items_.clear();
                xsql::set_vtab_error(
                    "hlil_calls: failed to collect function " +
                    std::to_string(func_addr));
                return false;
            }
            if (!items_.empty()) { idx_ = 0; return true; }
        }
        return false;
    }

public:
    bool next() override {
        if (!started_) {
            started_ = true;
            if (!load_next_func()) return false;
            rowid_ = 0;
            return true;
        }
        if (idx_ + 1 < items_.size()) { ++idx_; ++rowid_; return true; }
        if (!load_next_func()) return false;
        ++rowid_;
        return true;
    }
    const HLILCall& current() const override { return items_[idx_]; }
    int64_t rowid() const override { return rowid_; }
};

GeneratorTableDef<HLILCall> define_hlil_calls() {
    return generator_table<HLILCall>("hlil_calls")
        .generator([]() -> std::unique_ptr<xsql::Generator<HLILCall>> {
            return std::make_unique<HlilCallsGenerator>();
        })
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~15 call args per function
            return bv->GetAnalysisFunctionList().size() * 15;
        })
        // Full scans stream one function at a time via HlilCallsGenerator (above);
        // WHERE func_addr = X / callee_addr = X still use the pushdown iterators.
        .column_int64("func_addr", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int64("call_expr_id", [](const HLILCall& r) -> int64_t {
            return static_cast<int64_t>(r.call_expr_id);
        })
        .column_int64("call_addr", [](const HLILCall& r) -> int64_t {
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
        .column("arg_expr_id", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const HLILCall& r) {
                if (r.has_arg_expr_id)
                    ctx.result_int64(static_cast<int64_t>(r.arg_expr_id));
                else
                    ctx.result_null();
            })
        .column_text("arg_op", [](const HLILCall& r) -> std::string {
            return r.arg_op;
        })
        .column("arg_const", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const HLILCall& r) {
                if (r.has_arg_const) ctx.result_int64(r.arg_const);
                else ctx.result_null();
            })
        .column_text("arg_var_name", [](const HLILCall& r) -> std::string {
            return r.arg_var_name;
        })
        .column_text("arg_str", [](const HLILCall& r) -> std::string {
            return r.arg_str;
        })
        // Single-function pushdown (see _hlil_ast): WHERE func_addr = X collects
        // calls for only that function.
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<HlilCallsInFuncIterator>(addr);
        }, 1.0, 15.0)
        // Reverse-call pushdown: WHERE callee_addr = X ("who calls X") resolves
        // the callers via BN reverse xrefs and decompiles only those, instead of
        // rendering HLIL for the whole binary. This is the fast path behind the
        // disasm_calls / hlil_v_calls reverse-call queries.
        .filter_eq("callee_addr", [](int64_t callee) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<HlilCallsByCalleeIterator>(callee);
        }, 2.0, 8.0)
        .build();
}

// ============================================================================
// SQL Functions
// ============================================================================

/**
 * decompile(addr) - Get pseudocode for function at address
 * decompile(addr, limit) - Get pseudocode with line limit
 * decompile(addr, limit, refresh) - Get pseudocode; refresh=1 forces re-decompilation
 */
static void sql_decompile(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("decompile requires at least 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    int limit = (argc >= 2) ? argv[1].as_int() : 10000;
    if (limit <= 0) limit = 10000;
    bool refresh = (argc >= 3) ? (argv[2].as_int() != 0) : false;

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        ctx.result_null();
        return;
    }

    if (refresh) {
        funcs[0]->Reanalyze(BNFunctionUpdateType::UserFunctionUpdate);
        bv->UpdateAnalysisAndWait();
        // Re-fetch function list after re-analysis
        funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
        if (funcs.empty()) {
            ctx.result_null();
            return;
        }
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        ctx.result_null();
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

    ctx.result_text(result.str());
}

/**
 * hlil_at(addr) - Get HLIL text at specific address
 */
static void sql_hlil_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("hlil_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        ctx.result_null();
        return;
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        ctx.result_null();
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
        ctx.result_text(result);
    } else {
        ctx.result_null();
    }
}

/**
 * hlil_op_at(addr) - Get HLIL operation name at address
 */
static void sql_hlil_op_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("hlil_op_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (funcs.empty()) {
        ctx.result_null();
        return;
    }

    auto hlil = funcs[0]->GetHighLevelIL();
    if (!hlil) {
        ctx.result_null();
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
        // hlil_op_name returns a static / long-lived C-string — use the
        // static-lifetime libxsql result variant to avoid a copy.
        ctx.result_text_static(result);
    } else {
        ctx.result_null();
    }
}

/**
 * Register decompiler SQL functions via libxsql's public API.
 */
bool register_decompiler_functions(xsql::Database& db) {
    db.register_function("decompile",  1, xsql::ScalarFn(sql_decompile));
    db.register_function("decompile",  2, xsql::ScalarFn(sql_decompile));
    db.register_function("decompile",  3, xsql::ScalarFn(sql_decompile));
    db.register_function("hlil_at",    1, xsql::ScalarFn(sql_hlil_at));
    db.register_function("hlil_op_at", 1, xsql::ScalarFn(sql_hlil_op_at));
    return true;
}


// ============================================================================
// DecompilerTableRegistry (out-of-line)
// ============================================================================
DecompilerTableRegistry::DecompilerTableRegistry()
    : pseudocode(define_pseudocode())
    , hlil_ast(define_hlil_ast())
    , hlil_vars(define_hlil_vars())
    , hlil_calls(define_hlil_calls())
    , mlil(define_mlil())
    , mlil_operands(define_mlil_operands())
{}

DecompilerTableRegistry::~DecompilerTableRegistry() {}

void DecompilerTableRegistry::register_all(xsql::Database& db) {
        // Register cached tables
        db.register_cached_table("pseudocode", &pseudocode);
        db.create_table("pseudocode", "pseudocode");

        // _hlil_ast - Advanced table for AST pattern matching (underscore = internal).
        // Lazy generator table: a full scan streams one function at a time, so a
        // LIMIT/bounded query decompiles only the functions pulled; prefer
        // WHERE func_addr = X for a single function.
        db.register_generator_table("hlil_ast", &hlil_ast);
        db.create_table("_hlil_ast", "hlil_ast");

        db.register_cached_table("hlil_vars", &hlil_vars);
        db.create_table("hlil_vars", "hlil_vars");

        // Lazy generator table (see _hlil_ast); WHERE func_addr = X / callee_addr = X
        // use the single-function pushdown iterators.
        db.register_generator_table("hlil_calls", &hlil_calls);
        db.create_table("hlil_calls", "hlil_calls");

        // mlil - BN MLIL-SSA (the register-transfer IR tier below HLIL). Lazy generator;
        // WHERE func_addr = X uses the single-function pushdown.
        db.register_generator_table("mlil", &mlil);
        db.create_table("mlil", "mlil");

        db.register_generator_table("mlil_operands", &mlil_operands);
        db.create_table("mlil_operands", "mlil_operands");

        // Register SQL functions
        register_decompiler_functions(db);

        // Create views (only those not dependent on hlil table)
        create_views(db);
}

void DecompilerTableRegistry::create_views(xsql::Database& db) {
        // hlil_v_calls - All function calls
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_calls AS
            SELECT DISTINCT
                func_addr,
                call_expr_id AS expr_id,
                call_addr AS addr,
                callee_addr,
                callee_name,
                COUNT(*) FILTER (WHERE arg_idx >= 0) AS arg_count
            FROM hlil_calls
            GROUP BY func_addr, call_expr_id, call_addr, callee_addr, callee_name
        )", nullptr, nullptr);

        // disasm_calls - Call sites with callee info (idasql parity)
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS disasm_calls AS
            SELECT DISTINCT
                func_addr,
                call_addr AS addr,
                callee_addr,
                callee_name
            FROM hlil_calls
            WHERE callee_name != ''
        )", nullptr, nullptr);

        // Advanced views on _hlil_ast (underscore prefix = internal/expert)
        // All require WHERE func_addr = X for performance

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_loops AS
            SELECT func_addr, expr_id, addr, op_name, cond_id, body_id, init_id, update_id
            FROM _hlil_ast
            WHERE op_name IN ('HLIL_WHILE', 'HLIL_WHILE_SSA', 'HLIL_DO_WHILE',
                             'HLIL_DO_WHILE_SSA', 'HLIL_FOR', 'HLIL_FOR_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_ifs AS
            SELECT func_addr, expr_id, addr, cond_id, true_id, false_id
            FROM _hlil_ast WHERE op_name = 'HLIL_IF'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_comparisons AS
            SELECT func_addr, expr_id, addr, op_name, left_id, right_id
            FROM _hlil_ast WHERE op_name LIKE 'HLIL_CMP_%' OR op_name LIKE 'HLIL_FCMP_%'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_assignments AS
            SELECT func_addr, expr_id, addr, op_name, left_id, right_id, var_name
            FROM _hlil_ast
            WHERE op_name IN ('HLIL_ASSIGN', 'HLIL_ASSIGN_UNPACK', 'HLIL_VAR_INIT',
                             'HLIL_VAR_INIT_SSA', 'HLIL_ASSIGN_MEM_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_returns AS
            SELECT func_addr, expr_id, addr,
                   NULLIF(left_id, -1) AS return_expr_id
            FROM _hlil_ast WHERE op_name = 'HLIL_RET'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_derefs AS
            SELECT func_addr, expr_id, addr, op_name, left_id AS ptr_expr_id, type
            FROM _hlil_ast WHERE op_name IN ('HLIL_DEREF', 'HLIL_DEREF_SSA',
                                        'HLIL_DEREF_FIELD', 'HLIL_DEREF_FIELD_SSA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_constants AS
            SELECT func_addr, expr_id, addr, op_name, const_val, const_ptr, float_val
            FROM _hlil_ast WHERE op_name IN ('HLIL_CONST', 'HLIL_CONST_PTR',
                                        'HLIL_FLOAT_CONST', 'HLIL_CONST_DATA')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS _hlil_ast_vars AS
            SELECT func_addr, expr_id, addr, var_idx, var_name, var_is_arg, type
            FROM _hlil_ast WHERE var_idx >= 0
        )", nullptr, nullptr);

        // Public BN-native HLIL views for common structured analysis patterns.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_loops AS
            SELECT func_addr, expr_id, addr, op_name, cond_id, body_id, init_id, update_id
            FROM _hlil_ast_loops
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_ifs AS
            SELECT func_addr, expr_id, addr, cond_id, true_id, false_id
            FROM _hlil_ast_ifs
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_comparisons AS
            SELECT func_addr, expr_id, addr, op_name, left_id, right_id
            FROM _hlil_ast_comparisons
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_assignments AS
            SELECT func_addr, expr_id, addr, op_name, left_id, right_id, var_name
            FROM _hlil_ast_assignments
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS hlil_v_returns AS
            SELECT
                r.func_addr,
                r.expr_id AS return_expr_stmt_id,
                r.addr,
                r.return_expr_id,
                e.op_name AS return_op,
                e.const_val AS return_const,
                e.var_name AS return_var_name
            FROM _hlil_ast_returns r
            LEFT JOIN _hlil_ast e
                ON e.func_addr = r.func_addr
               AND e.expr_id = r.return_expr_id
        )", nullptr, nullptr);

        // ------------------------------------------------------------------
        // Cross-tool low-IR (ir_ops family) over the mlil table. bnsql's native
        // leg is BN IL, selectable across six forms via WHERE maturity=<form>
        // (default mlil_ssa). ir_ops maps each form's operations to the canonical
        // P-code-style vocabulary (op) while preserving the native op name
        // (native_op). is_ssa is maturity-dependent (the *_ssa rungs -> 1). The
        // maturity/stage passthrough columns push WHERE down to the mlil generator.
        // The ir_v_* views are the portable surface shared with the other tools.
        // Scope by func_addr (and optionally maturity) — pushes down to the generator.
        // ------------------------------------------------------------------
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_ops AS
            SELECT
                func_addr,
                seq,
                addr,
                NULLIF(canonical_op, '') AS op,
                op_name AS native_op,
                is_ssa,
                maturity,
                stage
            FROM mlil
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_v_calls AS
            SELECT func_addr, seq, addr, canonical_op AS op
            FROM mlil WHERE canonical_op IN ('CALL', 'CALLIND', 'CALLOTHER')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_v_mem_writes AS
            SELECT func_addr, seq, addr, canonical_op AS op
            FROM mlil WHERE canonical_op = 'STORE'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_v_mem_reads AS
            SELECT func_addr, seq, addr, canonical_op AS op
            FROM mlil WHERE canonical_op = 'LOAD'
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_v_branches AS
            SELECT func_addr, seq, addr, canonical_op AS op
            FROM mlil WHERE canonical_op IN ('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN')
        )", nullptr, nullptr);

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_v_arith AS
            SELECT func_addr, seq, addr, canonical_op AS op
            FROM mlil WHERE canonical_op IN (
                'INT_ADD','INT_SUB','INT_MULT','INT_DIV','INT_SDIV','INT_REM','INT_SREM',
                'INT_2COMP','INT_NEGATE','INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_SRIGHT'
            )
        )", nullptr, nullptr);

        // ir_operands — the portable 8-column operand shape. The cross-tool view
        // has no maturity coordinate, so pin it explicitly to the default rung.
        // For another rung, join native mlil + mlil_operands on func_addr, seq,
        // and maturity.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_operands AS
            SELECT func_addr, op_seq, operand_index, role,
                   NULLIF(kind, '') AS kind, text, value, size
            FROM mlil_operands
            WHERE maturity = 'mlil_ssa'
        )", nullptr, nullptr);

        // ir_maturities — the six-rung BN IL ladder (discoverability). is_default is the
        // rung used when a query does not constrain maturity (MLIL-SSA). is_ssa=1 on the
        // three *_ssa rungs.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ir_maturities AS
            SELECT 'llil'     AS maturity, 'raw'       AS stage, 0 AS ordinal, 0 AS is_default, 0 AS is_ssa
            UNION ALL SELECT 'llil_ssa', 'ssa',       1, 0, 1
            UNION ALL SELECT 'mlil',     'optimized', 2, 0, 0
            UNION ALL SELECT 'mlil_ssa', 'ssa',       3, 1, 1
            UNION ALL SELECT 'hlil',     'final',     4, 0, 0
            UNION ALL SELECT 'hlil_ssa', 'ssa',       5, 0, 1
        )", nullptr, nullptr);
}

} // namespace decompiler
} // namespace bnsql
