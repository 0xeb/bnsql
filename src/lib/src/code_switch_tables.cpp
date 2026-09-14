// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `switch_tables` — reconstructed switch/case jump tables via BN HLIL_SWITCH.
// Canonical cross-tool surface. Yields func_addr/instr_addr/min_case/max_case and
// case_count (the jump-table SLOT span max-min+1, canonical cross-tool semantic —
// see below); table_addr and default_addr are always NULL (BN limitation —
// see the standalone BN switch lab; MLIL_JUMP_TO GetTargets keys are target
// ADDRESSES, not case values, so HLIL is the correct source for case values).

#include "code_switch_tables.hpp"

#include "highlevelilinstruction.h"

#include <algorithm>
#include <limits>

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

namespace {

bool collect_switch_tables_for_function(
        std::vector<SwitchTableInfo>& out, const Ref<Function>& func) {
    if (!func) return true;
    try {
        // GetHighLevelILIfAvailable() makes results depend on whether an
        // unrelated earlier query happened to materialize HLIL. A table scan
        // must generate the requested function's HLIL deterministically.
        Ref<HighLevelILFunction> hlil = func->GetHighLevelIL();
        if (!hlil) {
            xsql::set_vtab_error(
                "switch_tables: HLIL unavailable for function " +
                std::to_string(func->GetStart()));
            return false;
        }
        size_t count = 0;
        count = hlil->GetInstructionCount();
        for (size_t i = 0; i < count; i++) {
            HighLevelILInstruction instr = (*hlil)[i];
            if (instr.operation != HLIL_SWITCH)
                continue;

            SwitchTableInfo r;
            r.func_addr = func->GetStart();
            r.instr_addr = instr.address;

            int64_t lo = std::numeric_limits<int64_t>::max();
            int64_t hi = std::numeric_limits<int64_t>::min();
            size_t nvals = 0;
            auto cases = instr.GetCases();
            for (auto c : cases) {
                if (c.operation != HLIL_CASE)
                    continue;
                for (auto ve : c.GetValueExprs()) {
                    if (ve.operation == HLIL_CONST || ve.operation == HLIL_CONST_PTR) {
                        int64_t v = ve.GetConstant();
                        lo = std::min(lo, v);
                        hi = std::max(hi, v);
                        ++nvals;
                    }
                }
            }
            if (nvals > 0) {
                r.has_cases = true;
                r.min_case = lo;
                r.max_case = hi;
            }
            // Canonical cross-tool semantic: case_count is the jump-table SLOT span
            // (max_case - min_case + 1), matching idasql/r2sql -- NOT the distinct
            // case-label count (cases.size()). The per-target label count stays
            // derivable from a switch_cases detail table. (unify ruling 2026-07-24.)
            if (r.has_cases) {
                const uint64_t delta =
                    static_cast<uint64_t>(r.max_case) -
                    static_cast<uint64_t>(r.min_case);
                if (delta >=
                    static_cast<uint64_t>(
                        std::numeric_limits<int64_t>::max())) {
                    xsql::set_vtab_error(
                        "switch_tables: case slot span exceeds int64");
                    return false;
                }
                r.case_count = static_cast<int64_t>(delta + 1);
            }
            out.push_back(std::move(r));
        }
    } catch (const std::exception& e) {
        xsql::set_vtab_error(
            "switch_tables: failed to inspect function " +
            std::to_string(func->GetStart()) + ": " + e.what());
        return false;
    } catch (...) {
        xsql::set_vtab_error(
            "switch_tables: failed to inspect function " +
            std::to_string(func->GetStart()));
        return false;
    }
    return true;
}

void sort_switch_tables(std::vector<SwitchTableInfo>& out) {
    std::sort(out.begin(), out.end(),
              [](const SwitchTableInfo& a, const SwitchTableInfo& b) {
                  if (a.func_addr != b.func_addr) return a.func_addr < b.func_addr;
                  return a.instr_addr < b.instr_addr;
              });
}

class SwitchTablesInFuncIterator : public xsql::RowIterator {
    std::vector<SwitchTableInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit SwitchTablesInFuncIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        for (const auto& func :
             bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr))) {
            if (!collect_switch_tables_for_function(rows_, func)) {
                rows_.clear();
                return;
            }
        }
        sort_switch_tables(rows_);
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            pos_ = 0;
        } else {
            ++pos_;
        }
        return pos_ < rows_.size();
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) {
            ctx.result_null();
            return;
        }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0:
                ctx.result_int64(static_cast<int64_t>(r.func_addr));
                break;
            case 1:
                ctx.result_int64(static_cast<int64_t>(r.instr_addr));
                break;
            case 2:
                ctx.result_null();
                break;
            case 3:
                r.has_cases ? ctx.result_int64(r.min_case) : ctx.result_null();
                break;
            case 4:
                r.has_cases ? ctx.result_int64(r.max_case) : ctx.result_null();
                break;
            case 5:
                ctx.result_int64(r.case_count);
                break;
            case 6:
                ctx.result_null();
                break;
            default:
                ctx.result_null();
                break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

}  // namespace

void collect_switch_tables(std::vector<SwitchTableInfo>& out) {
    auto bv = get_bv();
    if (!bv) return;
    for (const auto& func : bv->GetAnalysisFunctionList()) {
        if (!collect_switch_tables_for_function(out, func)) return;
    }
    sort_switch_tables(out);
}

CachedTableDef<SwitchTableInfo> define_switch_tables() {
    return cached_table<SwitchTableInfo>("switch_tables")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() : 0;
        })
        .cache_builder([](std::vector<SwitchTableInfo>& cache) {
            collect_switch_tables(cache);
        })
        // Canonical column order: func_addr, instr_addr, table_addr, min_case,
        // max_case, case_count, default_addr.
        .column_int64("func_addr",
                      [](const SwitchTableInfo& r) -> int64_t {
                          return static_cast<int64_t>(r.func_addr);
                      })
        .column_int64("instr_addr",
                      [](const SwitchTableInfo& r) -> int64_t {
                          return static_cast<int64_t>(r.instr_addr);
                      })
        // BN does not expose the physical jump-table address -> always NULL.
        .column("table_addr", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const SwitchTableInfo&) {
                    ctx.result_null();
                })
        .column("min_case", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const SwitchTableInfo& r) {
                    if (r.has_cases) ctx.result_int64(r.min_case);
                    else ctx.result_null();
                })
        .column("max_case", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const SwitchTableInfo& r) {
                    if (r.has_cases) ctx.result_int64(r.max_case);
                    else ctx.result_null();
                })
        .column_int64("case_count",
                      [](const SwitchTableInfo& r) -> int64_t { return r.case_count; })
        // BN does not expose a reliable default target -> always NULL.
        .column("default_addr", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const SwitchTableInfo&) {
                    ctx.result_null();
                })
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<SwitchTablesInFuncIterator>(addr);
        }, 1.0, 4.0)
        .index_on("func_addr", [](const SwitchTableInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace code
} // namespace bnsql
