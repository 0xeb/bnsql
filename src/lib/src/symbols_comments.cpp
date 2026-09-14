// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_comments.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Resolve the single comment string bnsql renders for one address, using the same
// two-source precedence as collect_comments(): the global (BinaryView) comment
// wins; when it is empty, fall back to the first non-empty function-scoped comment
// among the functions whose body CONTAINS `addr`. This is the O(1) point-lookup
// form of the whole-map rule, so the filter / row_lookup paths yield exactly what
// the full-scan cache would for that address. Returns "" when no comment exists.
std::string resolve_comment_at(const Ref<BinaryView>& bv, uint64_t addr) {
    std::string comment = bv->GetCommentForAddress(addr);
    if (!comment.empty()) return comment;
    for (auto& func : bv->GetAnalysisFunctionsContainingAddress(addr)) {
        std::string fc = func->GetCommentForAddress(addr);
        if (!fc.empty()) return fc;
    }
    return std::string();
}

// Single-address pushdown iterator for `WHERE addr = X`. Instead of rebuilding the
// whole comment map (walking every function), it does two O(1) BN lookups and
// yields AT MOST one row -- and only when a comment actually exists at X, matching
// collect_comments(), which only materializes addresses with a non-empty comment.
// rowid() is the address (matching rowid_fn + the full-scan rowid in
// define_comments()), so an UPDATE/DELETE routed through this iterator reconstructs
// the exact row by address via row_lookup rather than by a fragile cache position.
class CommentAtIterator : public xsql::RowIterator {
    std::vector<CommentInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit CommentAtIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        const uint64_t target = static_cast<uint64_t>(addr);
        std::string comment = resolve_comment_at(bv, target);
        if (comment.empty()) return;  // no row for an uncommented address
        CommentInfo item;
        item.address = target;
        item.comment = comment;
        item.rpt_comment = comment;  // BN has no repeatable comment split.
        rows_.push_back(std::move(item));
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }

    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    // Column order MUST match define_comments() below:
    // 0 addr, 1 comment, 2 rpt_comment.
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.address)); break;
            case 1: ctx.result_text(r.comment); break;
            case 2: ctx.result_text(r.rpt_comment); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return pos_ < rows_.size() ? static_cast<int64_t>(rows_[pos_].address) : 0;
    }
};

}  // namespace

void collect_comments(std::vector<CommentInfo>& out) {
    auto bv = get_bv();
    if (!bv) return;

    std::unordered_map<uint64_t, std::string> by_addr;
    by_addr.reserve(256);

    // Global comments first.
    for (uint64_t addr : bv->GetCommentedAddresses()) {
        auto comment = bv->GetCommentForAddress(addr);
        if (!comment.empty()) {
            by_addr.emplace(addr, std::move(comment));
        }
    }

    // Fill gaps with function-scoped comments.
    for (auto& func : bv->GetAnalysisFunctionList()) {
        for (uint64_t addr : func->GetCommentedAddresses()) {
            if (by_addr.find(addr) != by_addr.end()) continue;
            auto comment = func->GetCommentForAddress(addr);
            if (!comment.empty()) {
                by_addr.emplace(addr, std::move(comment));
            }
        }
    }

    out.reserve(by_addr.size());
    for (const auto& [addr, comment] : by_addr) {
        CommentInfo item;
        item.address = addr;
        item.comment = comment;
        item.rpt_comment = comment;  // BN has no repeatable comment split.
        out.push_back(std::move(item));
    }

    std::sort(out.begin(), out.end(), [](const CommentInfo& a, const CommentInfo& b) {
        return a.address < b.address;
    });
}

bool set_comment_at_address(const Ref<BinaryView>& bv, uint64_t addr, const std::string& text) {
    if (!bv) return false;

    // Keep global and function-scoped comments aligned for consistent reads.
    bv->SetCommentForAddress(addr, text);
    for (auto& func : bv->GetAnalysisFunctionsContainingAddress(addr)) {
        func->SetCommentForAddress(addr, text);
    }
    return true;
}

CachedTableDef<CommentInfo> define_comments() {
    return cached_table<CommentInfo>("comments")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // collect_comments() materializes BOTH global comments AND every
            // function's function-scoped comments, so the planner estimate must
            // reflect both sources. The old global-only count
            // (GetCommentedAddresses().size()) was systematically LOW for any
            // binary with function-local comments and could mislead join ordering.
            // There is no cheap total for function-scoped comments, so approximate
            // one per function on top of the global count: rougher, but no longer
            // strictly low, and as cheap as the sibling cached tables' estimate_rows
            // (blocks/pseudocode also size off GetAnalysisFunctionList()).
            return bv->GetCommentedAddresses().size() +
                   bv->GetAnalysisFunctionList().size();
        })
        .cache_builder([](std::vector<CommentInfo>& cache) {
            collect_comments(cache);
        })
        // Stable rowid == the comment's address. The full-scan, single-address
        // filter, and range-index paths all report the SAME rowid, so an
        // UPDATE/DELETE reconstructs the row by address (via row_lookup) instead of
        // by a fragile cache position -- required now that WHERE addr = X can be
        // served by the filter iterator (whose rowid is not a cache index).
        // Addresses are unique per row (collect_comments keys a map on address), so
        // this is a collision-free rowid.
        .rowid([](const CommentInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        // Resolve a rowid (an address) back to its CommentInfo by re-reading the
        // live comment. Keeps write reconstruction O(1) and, crucially, keeps this
        // table NOCHANGE-eligible (the reconstruct_by_rowid gate accepts a resolving
        // row_lookup) so a `SET comment = ...` UPDATE does NOT also fire the
        // rpt_comment setter with a stale value and clobber the change.
        .row_lookup([](CommentInfo& out, int64_t rowid) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            uint64_t addr = static_cast<uint64_t>(rowid);
            std::string comment = resolve_comment_at(bv, addr);
            out.address = addr;
            out.comment = comment;
            out.rpt_comment = comment;
            return true;
        })
        .column_int64("addr", [](const CommentInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text_rw("comment",
            [](const CommentInfo& r) -> std::string {
                return r.comment;
            },
            [](CommentInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string value = text ? text : "";
                if (!set_comment_at_address(bv, r.address, value)) return false;
                r.comment = value;
                r.rpt_comment = value;
                return true;
            })
        .column_text_rw("rpt_comment",
            [](const CommentInfo& r) -> std::string {
                return r.rpt_comment;
            },
            [](CommentInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string value = text ? text : "";
                if (!set_comment_at_address(bv, r.address, value)) return false;
                r.comment = value;
                r.rpt_comment = value;
                return true;
            })
        // Point-lookup pushdown: WHERE addr = X resolves via two O(1) BN lookups
        // (GetCommentForAddress + a function fallback) instead of rebuilding the
        // whole comment map by walking every function. EQ is trusted (omit=1); the
        // iterator's rowid == addr lets a write through this path reconstruct the
        // exact row via row_lookup. est_rows = 1 (at most one row per address).
        .filter_eq("addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CommentAtIterator>(addr);
        }, 0.5, 1.0)  // cost=0.5, at most one row
        // Enables addr-range (BETWEEN / >=,<) pushdown off a sorted view; the EQ
        // filter above still wins for a point lookup (it is strictly cheaper).
        .index_on("addr", [](const CommentInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .deletable([](CommentInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (!set_comment_at_address(bv, r.address, "")) return false;
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (argc < 1) return false;
            if (argv[0].is_null()) return false;

            uint64_t addr = static_cast<uint64_t>(argv[0].as_int64());

            std::string value;
            if (argc >= 2 && !argv[1].is_null()) {
                const char* comment = argv[1].as_c_str();
                value = comment ? comment : "";
            } else if (argc >= 3 && !argv[2].is_null()) {
                const char* rpt_comment = argv[2].as_c_str();
                value = rpt_comment ? rpt_comment : "";
            } else {
                xsql::set_vtab_error("comments insert requires comment or rpt_comment");
                return false;
            }

            if (!set_comment_at_address(bv, addr, value)) return false;
            return true;
        })
        .build();
}

} // namespace symbols
} // namespace bnsql
