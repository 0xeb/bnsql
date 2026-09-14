// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "xrefs.hpp"

#include <set>

namespace bnsql {
namespace xrefs {

using namespace BinaryNinja;
using core::get_bv;

static uint64_t containing_func_addr(const Ref<BinaryView>& bv, uint64_t addr) {
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(addr);
    return funcs.empty() ? 0 : funcs[0]->GetStart();
}

static bool is_import_symbol_type(BNSymbolType type) {
    return type == ImportedFunctionSymbol ||
           type == ImportAddressSymbol ||
           type == ImportedDataSymbol;
}

static bool in_non_exec_segment(const Ref<BinaryView>& bv, uint64_t addr) {
    auto seg = bv->GetSegmentAt(addr);
    return seg && !(seg->GetFlags() & SegmentExecutable);
}

// How a referenced address classifies into the xrefs table's three edge
// categories, mirroring the cache builder's three passes:
//   type 0 (is_code=1) - the address is a function start
//   type 1 (is_code=0) - the address lies in a non-executable segment (data)
//   type 2 (is_code=1) - one entry per import symbol AT the address
// A target may match several categories (an IAT slot is both a data-segment
// address AND an import -> two rows); one matching none contributes no rows.
struct TargetClass {
    bool is_func_start = false;
    bool is_data = false;
    int import_count = 0;  // number of import symbols exactly at the address
};

// Classify a target using core-side INDEXED point lookups only
// (GetAnalysisFunctionsForAddress / GetSegmentAt / ranged GetSymbols) so it is
// cheap enough to call per JOIN probe. The old per-probe path walked the whole
// function list and whole symbol list, which made string_refs-style joins
// O(strings x (funcs + symbols)).
static TargetClass classify_target(const Ref<BinaryView>& bv, uint64_t target) {
    TargetClass tc;
    for (auto& func : bv->GetAnalysisFunctionsForAddress(target)) {
        if (func->GetStart() == target) {
            tc.is_func_start = true;
            break;
        }
    }
    tc.is_data = in_non_exec_segment(bv, target);
    // Ranged lookup [target, target+1): every symbol exactly at the address,
    // across namespaces -- same set the old full GetSymbols() walk saw, so the
    // per-import-symbol row multiplicity is preserved.
    for (auto& sym : bv->GetSymbols(target, 1)) {
        if (is_import_symbol_type(sym->GetType()))
            tc.import_count++;
    }
    return tc;
}

static void append_xrefs_to_target(std::vector<XrefInfo>& out,
                                   const Ref<BinaryView>& bv,
                                   uint64_t target,
                                   int type,
                                   bool is_code) {
    if (!bv) return;
    for (auto& ref : bv->GetCodeReferences(target)) {
        XrefInfo xi;
        xi.from_addr = ref.addr;
        xi.to_addr = target;
        xi.from_func = containing_func_addr(bv, ref.addr);
        xi.type = type;
        xi.is_code = is_code;
        out.push_back(xi);
    }
}

/**
 * Iterator for xrefs TO a specific address.
 *
 * Uses BN's GetCodeReferences(addr) directly for each full-scan-visible target
 * category instead of scanning the whole cache.
 */
class XrefsToIterator : public xsql::RowIterator {
    std::vector<XrefInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

    // Cached current row
    XrefInfo current_;

public:
    explicit XrefsToIterator(int64_t target) {
        auto bv = get_bv();
        if (!bv) return;
        uint64_t target_addr = static_cast<uint64_t>(target);

        // Classify the target with point lookups, then fan out over the
        // referencing sites per matching category. append_xrefs_to_target
        // enumerates GetCodeReferences(target) once per category -- the same
        // row multiplicity the cache builder produces (including one full
        // fan-out per import symbol when several share the address).
        const TargetClass tc = classify_target(bv, target_addr);
        if (tc.is_func_start)
            append_xrefs_to_target(rows_, bv, target_addr, 0, true);
        if (tc.is_data)
            append_xrefs_to_target(rows_, bv, target_addr, 1, false);
        for (int i = 0; i < tc.import_count; ++i)
            append_xrefs_to_target(rows_, bv, target_addr, 2, true);
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            pos_ = 0;
        } else {
            pos_++;
        }

        if (pos_ >= rows_.size()) {
            return false;
        }

        current_ = rows_[pos_];
        return true;
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        switch (col) {
            case 0: // from_addr
                ctx.result_int64(static_cast<int64_t>(current_.from_addr));
                break;
            case 1: // to_addr
                ctx.result_int64(static_cast<int64_t>(current_.to_addr));
                break;
            case 2: // from_func
                ctx.result_int64(current_.from_func ? static_cast<int64_t>(current_.from_func) : 0);
                break;
            case 3: // type
                ctx.result_int(current_.type);
                break;
            case 4: // is_code
                ctx.result_int(current_.is_code ? 1 : 0);
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

/**
 * Iterator for xrefs FROM a specific address (`WHERE from_addr = X`).
 *
 * IDA `xrefblk_t::first_from()` parity: without this, `from_addr = X` falls back
 * to index_on(from_addr), which builds the ENTIRE xrefs cache per cursor. Here we
 * ask BN directly what X references (GetCodeReferencesFrom), classify each target
 * the same way the cache builder does, and reproduce the cache's exact rows for
 * the edges leaving X.
 *
 * Multiplicity parity: the cache builds from_addr=X rows by iterating TARGETS and
 * calling GetCodeReferences(target) (finding X among the referrers). We reuse that
 * SAME primitive per candidate target -- counting how many times X refers to the
 * target -- so the row multiset is identical to the full scan, even when X refers
 * to a target more than once or X sits in overlapping functions.
 */
class XrefsFromIterator : public xsql::RowIterator {
    std::vector<XrefInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;
    XrefInfo current_;

public:
    explicit XrefsFromIterator(int64_t from) {
        auto bv = get_bv();
        if (!bv) return;
        const uint64_t from_addr = static_cast<uint64_t>(from);
        const uint64_t from_func = containing_func_addr(bv, from_addr);

        // Candidate targets X references. GetCodeReferencesFrom is the documented
        // inverse of GetCodeReferences; dedupe to a set (X may sit in more than
        // one function -> one ReferenceSource per containing function).
        std::set<uint64_t> targets;
        for (auto& func : bv->GetAnalysisFunctionsContainingAddress(from_addr)) {
            ReferenceSource src{func, func->GetArchitecture(), from_addr};
            for (uint64_t target : bv->GetCodeReferencesFrom(src))
                targets.insert(target);
        }

        for (uint64_t target : targets) {
            const TargetClass tc = classify_target(bv, target);
            if (!tc.is_func_start && !tc.is_data && tc.import_count == 0)
                continue;  // not an xrefs-table edge (e.g. intra-function branch)

            // Exact multiplicity: how many times does X reference this target,
            // per the same primitive the cache builder uses?
            int edge_count = 0;
            for (auto& ref : bv->GetCodeReferences(target))
                if (ref.addr == from_addr)
                    ++edge_count;

            for (int e = 0; e < edge_count; ++e) {
                if (tc.is_func_start)
                    rows_.push_back({from_addr, target, from_func, 0, true});
                if (tc.is_data)
                    rows_.push_back({from_addr, target, from_func, 1, false});
                for (int i = 0; i < tc.import_count; ++i)
                    rows_.push_back({from_addr, target, from_func, 2, true});
            }
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            pos_ = 0;
        } else {
            pos_++;
        }
        if (pos_ >= rows_.size())
            return false;
        current_ = rows_[pos_];
        return true;
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(current_.from_addr)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(current_.to_addr)); break;
            case 2: ctx.result_int64(current_.from_func ? static_cast<int64_t>(current_.from_func) : 0); break;
            case 3: ctx.result_int(current_.type); break;
            case 4: ctx.result_int(current_.is_code ? 1 : 0); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

CachedTableDef<XrefInfo> define_xrefs() {
    return cached_table<XrefInfo>("xrefs")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~10 xrefs per function
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<XrefInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            // Collect code references from all functions
            for (auto& func : bv->GetAnalysisFunctionList()) {
                uint64_t func_addr = func->GetStart();
                append_xrefs_to_target(cache, bv, func_addr, 0, true);
            }

            // Also collect data references: one ranged GetCodeReferences(start,
            // len) call per non-executable segment finds every code site that
            // references into the segment, and GetCodeReferencesFrom(site)
            // resolves each site's exact target addresses. Coverage-equivalent
            // to a per-byte GetCodeReferences walk of the segment (it catches
            // references to untyped addresses and into the interior of defined
            // variables -- enumerating DataVariable start addresses misses
            // both) at a cost proportional to the number of referencing sites,
            // not the segment size. A ground-truth parity guard pins this
            // equivalence.
            for (auto& seg : bv->GetSegments()) {
                if (seg->GetFlags() & SegmentExecutable)
                    continue;
                const uint64_t seg_start = seg->GetStart();
                const uint64_t seg_end = seg->GetEnd();
                if (seg_end <= seg_start)
                    continue;
                for (auto& ref : bv->GetCodeReferences(seg_start, seg_end - seg_start)) {
                    if (!ref.func)
                        continue;
                    for (uint64_t target : bv->GetCodeReferencesFrom(ref)) {
                        if (target < seg_start || target >= seg_end)
                            continue;
                        XrefInfo xi;
                        xi.from_addr = ref.addr;
                        xi.to_addr = target;
                        xi.from_func = containing_func_addr(bv, ref.addr);
                        xi.type = 1;
                        xi.is_code = false;
                        cache.push_back(xi);
                    }
                }
            }

            // Collect xrefs to imports (may be in executable sections as thunks)
            for (auto& sym : bv->GetSymbols()) {
                auto type = sym->GetType();
                if (is_import_symbol_type(type)) {
                    uint64_t import_addr = sym->GetAddress();
                    append_xrefs_to_target(cache, bv, import_addr, 2, true);
                }
            }
        })
        .column_int64("from_addr", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_addr);
        })
        .column_int64("to_addr", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_addr);
        })
        .column_int64("from_func", [](const XrefInfo& r) -> int64_t {
            return r.from_func ? static_cast<int64_t>(r.from_func) : 0;
        })
        .column_int("type", [](const XrefInfo& r) -> int {
            return r.type;
        })
        .column_int("is_code", [](const XrefInfo& r) -> int {
            return r.is_code ? 1 : 0;
        })
        // Direct source filter: bypass cache and query BN API directly
        // Cost 0.5 ensures this is preferred over index_on (cost 1.0)
        .filter_eq("to_addr", [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(target);
        }, 0.5, 5.0)  // cost=0.5, estimated_rows=5
        // Direct source filter for the from side ("what does address X
        // reference?"): GetCodeReferencesFrom instead of building the whole
        // cache. Cost 0.5 makes SQLite prefer it over index_on (cost 1.0).
        .filter_eq("from_addr", [](int64_t from) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsFromIterator>(from);
        }, 0.5, 5.0)
        // Indexes for full-scan JOINs (fallback when filter_eq not applicable)
        .index_on("to_addr", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_addr);
        })
        // from_addr index remains for non-eq plans and cursor reuse; the
        // filter_eq above handles the common `from_addr = X` point query.
        .index_on("from_addr", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_addr);
        })
        .index_on("from_func", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_func);
        })
        .build();
}

} // namespace xrefs
} // namespace bnsql
