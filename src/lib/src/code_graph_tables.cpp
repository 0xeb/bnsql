// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// dominators / post_dominators / loops — canonical CFG-graph tables,
// BN basic blocks mapped through the generic xsql::graph module.

#include "code_graph_tables.hpp"

#include <algorithm>
#include <unordered_map>
#include <vector>

#include <xsql/graph.hpp>

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Build the block-level CFG of one function: a DirectedGraph over block ids plus the
// id->start/end maps and the entry block id. Returns false for a null function or an
// empty block set.
bool build_func_graph(Function* func, xsql::graph::DirectedGraph& g_out,
                      std::vector<uint64_t>& addr, std::vector<uint64_t>& end_addr,
                      size_t& entry) {
    if (!func) return false;
    auto blocks = func->GetBasicBlocks();
    const size_t n = blocks.size();
    if (n == 0) return false;

    addr.assign(n, 0);
    end_addr.assign(n, 0);
    std::unordered_map<uint64_t, size_t> id_of;
    id_of.reserve(n * 2);
    const uint64_t fa = func->GetStart();
    entry = 0;
    for (size_t i = 0; i < n; ++i) {
        addr[i] = blocks[i]->GetStart();
        end_addr[i] = blocks[i]->GetEnd();
        id_of[addr[i]] = i;
        if (addr[i] == fa) entry = i;
    }

    xsql::graph::DirectedGraph g(n);
    for (size_t i = 0; i < n; ++i) {
        for (const auto& edge : blocks[i]->GetOutgoingEdges()) {
            if (!edge.target) continue;  // e.g. a return has no in-function target
            auto it = id_of.find(edge.target->GetStart());
            if (it != id_of.end()) g.add_edge(i, it->second);
        }
    }
    g_out = std::move(g);
    return true;
}

void collect_dominators(Function* func, std::vector<DominatorInfo>& out) {
    xsql::graph::DirectedGraph g(0);
    std::vector<uint64_t> addr, end_addr;
    size_t entry = 0;
    if (!build_func_graph(func, g, addr, end_addr, entry)) return;
    auto idom = xsql::graph::immediate_dominators(g, entry);
    const uint64_t fa = func->GetStart();
    for (size_t i = 0; i < g.node_count(); ++i) {
        if (idom[i] == xsql::graph::kNoNode) continue;  // unreachable
        DominatorInfo r;
        r.func_addr = fa;
        r.node_addr = addr[i];
        r.is_entry = (i == entry);
        if (i == entry) {
            r.has_idom = false;
        } else {
            r.has_idom = true;
            r.idom_addr = addr[idom[i]];
            int64_t d = 0;
            size_t cur = i;
            while (cur != entry) { cur = idom[cur]; ++d; }
            r.depth = d;
        }
        out.push_back(std::move(r));
    }
}

void collect_post_dominators(Function* func, std::vector<PostDominatorInfo>& out) {
    xsql::graph::DirectedGraph g(0);
    std::vector<uint64_t> addr, end_addr;
    size_t entry = 0;
    if (!build_func_graph(func, g, addr, end_addr, entry)) return;
    auto ipdom = xsql::graph::immediate_post_dominators(g);
    const uint64_t fa = func->GetStart();
    for (size_t i = 0; i < g.node_count(); ++i) {
        PostDominatorInfo r;
        r.func_addr = fa;
        r.node_addr = addr[i];
        r.is_exit = g.successors(i).empty();
        if (ipdom[i] == xsql::graph::kNoNode) {
            r.has_ipdom = false;
        } else {
            r.has_ipdom = true;
            r.ipdom_addr = addr[ipdom[i]];
            int64_t d = 0;
            size_t cur = i;
            while (ipdom[cur] != xsql::graph::kNoNode) { cur = ipdom[cur]; ++d; }
            r.depth = d;
        }
        out.push_back(std::move(r));
    }
}

void collect_loops(Function* func, std::vector<LoopInfo>& out) {
    xsql::graph::DirectedGraph g(0);
    std::vector<uint64_t> addr, end_addr;
    size_t entry = 0;
    if (!build_func_graph(func, g, addr, end_addr, entry)) return;
    auto loops = xsql::graph::natural_loops(g, entry);
    const uint64_t fa = func->GetStart();
    for (size_t li = 0; li < loops.size(); ++li) {
        const auto& lp = loops[li];
        LoopInfo r;
        r.func_addr = fa;
        r.header_addr = addr[lp.header];
        r.latch_addr = addr[lp.latch];
        r.block_count = static_cast<int64_t>(lp.body.size());
        r.loop_kind = "natural";
        uint64_t mn = 0; bool have_mn = false; uint64_t mx = 0;
        for (size_t b : lp.body) {
            if (!have_mn || addr[b] < mn) { mn = addr[b]; have_mn = true; }
            if (end_addr[b] > mx) mx = end_addr[b];
        }
        r.start_addr = mn;
        r.end_addr = mx;
        int64_t depth = 1;
        for (size_t lj = 0; lj < loops.size(); ++lj) {
            if (lj == li) continue;
            const auto& oth = loops[lj].body;
            if (oth.size() > lp.body.size() &&
                std::includes(oth.begin(), oth.end(), lp.body.begin(), lp.body.end()))
                ++depth;
        }
        r.depth = depth;
        out.push_back(std::move(r));
    }
}

// ---- per-table column emission (shared by cache accessors and the filter cursor) ----

void emit_column(xsql::FunctionContext& ctx, int col, const DominatorInfo& r) {
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
    case 1: ctx.result_int64(static_cast<int64_t>(r.node_addr)); break;
    case 2:
        if (r.has_idom) ctx.result_int64(static_cast<int64_t>(r.idom_addr));
        else ctx.result_null();
        break;
    case 3: ctx.result_int64(r.depth); break;
    case 4: ctx.result_int64(r.is_entry ? 1 : 0); break;
    default: ctx.result_null(); break;
    }
}

void emit_column(xsql::FunctionContext& ctx, int col, const PostDominatorInfo& r) {
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
    case 1: ctx.result_int64(static_cast<int64_t>(r.node_addr)); break;
    case 2:
        if (r.has_ipdom) ctx.result_int64(static_cast<int64_t>(r.ipdom_addr));
        else ctx.result_null();
        break;
    case 3: ctx.result_int64(r.depth); break;
    case 4: ctx.result_int64(r.is_exit ? 1 : 0); break;
    default: ctx.result_null(); break;
    }
}

void emit_column(xsql::FunctionContext& ctx, int col, const LoopInfo& r) {
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
    case 1: ctx.result_int64(static_cast<int64_t>(r.header_addr)); break;
    case 2: ctx.result_int64(static_cast<int64_t>(r.latch_addr)); break;
    case 3: ctx.result_int64(static_cast<int64_t>(r.start_addr)); break;
    case 4: ctx.result_int64(static_cast<int64_t>(r.end_addr)); break;
    case 5: ctx.result_int64(r.depth); break;
    case 6: ctx.result_text(r.loop_kind); break;
    case 7: ctx.result_int64(r.block_count); break;
    default: ctx.result_null(); break;
    }
}

// A func_addr-scoped cursor: collect only that function's rows.
template <typename Row, typename Collect>
class FuncScopedIterator : public xsql::RowIterator {
    std::vector<Row> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    FuncScopedIterator(int64_t addr, Collect collect) {
        auto bv = get_bv();
        if (!bv) return;
        for (auto& func : bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr)))
            collect(func.GetPtr(), rows_);
    }
    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { ++pos_; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        emit_column(ctx, col, rows_[pos_]);
    }
    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

}  // namespace

CachedTableDef<DominatorInfo> define_dominators() {
    return cached_table<DominatorInfo>("dominators")
        .no_shared_cache()
        .cache_builder([](std::vector<DominatorInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList())
                collect_dominators(func.GetPtr(), cache);
        })
        .column_int64("func_addr", [](const DominatorInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .column_int64("node_addr", [](const DominatorInfo& r) { return static_cast<int64_t>(r.node_addr); })
        .column("idom_addr", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const DominatorInfo& r) {
                    if (r.has_idom) ctx.result_int64(static_cast<int64_t>(r.idom_addr));
                    else ctx.result_null();
                })
        .column_int64("depth", [](const DominatorInfo& r) { return r.depth; })
        .column_int64("is_entry", [](const DominatorInfo& r) { return r.is_entry ? 1 : 0; })
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncScopedIterator<DominatorInfo, decltype(&collect_dominators)>>(
                addr, &collect_dominators);
        }, 0.5, 8.0)
        .index_on("func_addr", [](const DominatorInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .build();
}

CachedTableDef<PostDominatorInfo> define_post_dominators() {
    return cached_table<PostDominatorInfo>("post_dominators")
        .no_shared_cache()
        .cache_builder([](std::vector<PostDominatorInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList())
                collect_post_dominators(func.GetPtr(), cache);
        })
        .column_int64("func_addr", [](const PostDominatorInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .column_int64("node_addr", [](const PostDominatorInfo& r) { return static_cast<int64_t>(r.node_addr); })
        .column("ipdom_addr", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const PostDominatorInfo& r) {
                    if (r.has_ipdom) ctx.result_int64(static_cast<int64_t>(r.ipdom_addr));
                    else ctx.result_null();
                })
        .column_int64("depth", [](const PostDominatorInfo& r) { return r.depth; })
        .column_int64("is_exit", [](const PostDominatorInfo& r) { return r.is_exit ? 1 : 0; })
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncScopedIterator<PostDominatorInfo, decltype(&collect_post_dominators)>>(
                addr, &collect_post_dominators);
        }, 0.5, 8.0)
        .index_on("func_addr", [](const PostDominatorInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .build();
}

CachedTableDef<LoopInfo> define_loops() {
    return cached_table<LoopInfo>("loops")
        .no_shared_cache()
        .cache_builder([](std::vector<LoopInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            for (auto& func : bv->GetAnalysisFunctionList())
                collect_loops(func.GetPtr(), cache);
        })
        .column_int64("func_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .column_int64("header_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.header_addr); })
        .column_int64("latch_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.latch_addr); })
        .column_int64("start_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.start_addr); })
        .column_int64("end_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.end_addr); })
        .column_int64("depth", [](const LoopInfo& r) { return r.depth; })
        .column_text("loop_kind", [](const LoopInfo& r) { return r.loop_kind; })
        .column_int64("block_count", [](const LoopInfo& r) { return r.block_count; })
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncScopedIterator<LoopInfo, decltype(&collect_loops)>>(
                addr, &collect_loops);
        }, 0.5, 4.0)
        .index_on("func_addr", [](const LoopInfo& r) { return static_cast<int64_t>(r.func_addr); })
        .build();
}

} // namespace code
} // namespace bnsql
