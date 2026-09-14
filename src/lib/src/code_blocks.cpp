// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_blocks.hpp"

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

/**
 * Iterator for blocks filtered to a single function address.
 * Avoids the whole-binary scan when querying WHERE func_addr = X.
 */
class BlockIterator : public xsql::RowIterator {
    std::vector<BlockInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit BlockIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;

        // GetAnalysisFunctionsForAddress returns every function whose entry is addr.
        // Iterate all of them (not just funcs[0]) so this pushdown path matches the
        // whole-binary cache-scan for the rare case of >1 function sharing a start
        // address -- filter_eq sets omit=1, so SQLite never re-checks func_addr.
        auto funcs = bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr));
        for (auto& func : funcs) {
            for (auto& block : func->GetBasicBlocks()) {
                BlockInfo bi;
                bi.func_addr = func->GetStart();
                bi.start_addr = block->GetStart();
                bi.end_addr = block->GetEnd();
                rows_.push_back(bi);
            }
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    // Column order MUST match define_blocks() below:
    // 0 func_addr, 1 start_addr, 2 end_addr, 3 size
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(r.start_addr)); break;
            case 2: ctx.result_int64(static_cast<int64_t>(r.end_addr)); break;
            case 3: ctx.result_int64(static_cast<int64_t>(r.end_addr - r.start_addr)); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

CachedTableDef<BlockInfo> define_blocks() {
    return cached_table<BlockInfo>("blocks")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<BlockInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            for (auto& func : bv->GetAnalysisFunctionList()) {
                for (auto& block : func->GetBasicBlocks()) {
                    BlockInfo bi;
                    bi.func_addr = func->GetStart();
                    bi.start_addr = block->GetStart();
                    bi.end_addr = block->GetEnd();
                    cache.push_back(bi);
                }
            }
        })
        .column_int64("func_addr", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int64("start_addr", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start_addr);
        })
        .column_int64("end_addr", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_addr);
        })
        .column_int64("size", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_addr - r.start_addr);
        })
        // Direct source filter: single-function query bypasses cache
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BlockIterator>(addr);
        }, 0.5, 10.0)  // cost=0.5, estimated_rows=10
        .index_on("func_addr", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace code
} // namespace bnsql
