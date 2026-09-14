// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_cfg.hpp"

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Map a BN basic-block outgoing edge to the cross-tool edge_type vocabulary
// {normal, true, false} used by idasql/ghidrasql/r2sql cfg_edges. A two-way
// conditional branch yields TrueBranch/FalseBranch arms; everything else
// (unconditional, indirect, ...) is reported as "normal".
inline const char* edge_type_name(BNBranchType t) {
    switch (t) {
        case TrueBranch:  return "true";
        case FalseBranch: return "false";
        default:          return "normal";
    }
}

// Append every outgoing CFG edge of one function's blocks to `out`.
void collect_func_edges(Function* func, std::vector<CfgEdgeInfo>& out) {
    if (!func) return;
    uint64_t fa = func->GetStart();
    for (auto& block : func->GetBasicBlocks()) {
        uint64_t from = block->GetStart();
        for (const auto& edge : block->GetOutgoingEdges()) {
            if (!edge.target) continue;  // e.g. FunctionReturn has no in-function target
            CfgEdgeInfo e;
            e.func_addr = fa;
            e.from_addr = from;
            e.to_addr = edge.target->GetStart();
            e.edge_type = edge_type_name(edge.type);
            out.push_back(std::move(e));
        }
    }
}

}  // namespace

// Iterator for cfg_edges filtered to a single function address. Mirrors the
// blocks table's func_addr pushdown so `WHERE func_addr = X` walks only that
// function's blocks instead of the whole binary.
class CfgEdgeIterator : public xsql::RowIterator {
    std::vector<CfgEdgeInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit CfgEdgeIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        for (auto& func : bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr))) {
            collect_func_edges(func.GetPtr(), rows_);
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }

    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    // Column order MUST match define_cfg_edges() below:
    // 0 func_addr, 1 from_addr, 2 to_addr, 3 edge_type
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(r.from_addr)); break;
            case 2: ctx.result_int64(static_cast<int64_t>(r.to_addr)); break;
            case 3: ctx.result_text(r.edge_type); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

CachedTableDef<CfgEdgeInfo> define_cfg_edges() {
    return cached_table<CfgEdgeInfo>("cfg_edges")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            return bv->GetAnalysisFunctionList().size() * 12;
        })
        .cache_builder([](std::vector<CfgEdgeInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_func_edges(func.GetPtr(), cache);
            }
        })
        .column_int64("func_addr", [](const CfgEdgeInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int64("from_addr", [](const CfgEdgeInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_addr);
        })
        .column_int64("to_addr", [](const CfgEdgeInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_addr);
        })
        .column_text("edge_type", [](const CfgEdgeInfo& r) -> std::string {
            return r.edge_type;
        })
        // Direct source filter: single-function query bypasses the full cache.
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CfgEdgeIterator>(addr);
        }, 0.5, 12.0)
        .index_on("func_addr", [](const CfgEdgeInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace code
} // namespace bnsql
