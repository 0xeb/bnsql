// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_names.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Snapshot one live BN symbol into a query-scoped SymbolInfo row.
SymbolInfo snapshot_symbol(const Ref<Symbol>& sym) {
    SymbolInfo si;
    si.address = sym->GetAddress();
    si.full_name = sym->GetFullName();
    si.binding = sym->GetBinding();
    si.is_auto_defined = sym->IsAutoDefined();
    return si;
}

// Iterator for the `WHERE addr = X` pushdown: resolves the single symbol at the
// target address via GetSymbolByAddress instead of
// walking the whole symbol table. Its rowid is the symbol ADDRESS, matching
// rowid_fn() in define_names() so a scan-driven UPDATE/DELETE reconstructs the
// row through row_lookup() by address (see CachedTableDef::rowid_fn/row_lookup).
class SymbolByAddrIterator : public xsql::RowIterator {
    std::vector<SymbolInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit SymbolByAddrIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        auto sym = bv->GetSymbolByAddress(static_cast<uint64_t>(addr));
        if (sym) rows_.push_back(snapshot_symbol(sym));
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    // Column order MUST match define_names() below:
    // 0 addr, 1 name, 2 is_public, 3 is_weak
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.address)); break;
            case 1: ctx.result_text(r.full_name); break;
            case 2: ctx.result_int(r.binding == GlobalBinding ? 1 : 0); break;
            case 3: ctx.result_int(r.binding == WeakBinding ? 1 : 0); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        if (pos_ >= rows_.size()) return 0;
        return static_cast<int64_t>(rows_[pos_].address);
    }
};

}  // namespace

CachedTableDef<SymbolInfo> define_names() {
    return cached_table<SymbolInfo>("names")
        // `names` is writable (rename/delete/insert), so the cache must reflect
        // out-of-band engine edits: keep it query-scoped (rebuilt per statement),
        // never a shared engine-lifetime cache.
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetSymbols().size() : 0;
        })
        // Materialize the whole symbol table ONCE per query. Every column read
        // then hits this in-memory snapshot instead of re-calling GetSymbols()
        // (which previously made a full scan O(columns * symbols^2)).
        .cache_builder([](std::vector<SymbolInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            auto syms = bv->GetSymbols();
            cache.reserve(syms.size());
            for (const auto& sym : syms) {
                cache.push_back(snapshot_symbol(sym));
            }
        })
        .column_int64("addr", [](const SymbolInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text_rw("name",
            // Getter
            [](const SymbolInfo& r) -> std::string {
                return r.full_name;
            },
            // Setter: resolve the live symbol by ADDRESS (not by a stale list
            // index) and redefine it under the new name, preserving its type.
            [](SymbolInfo& r, const char* new_name) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                if (!new_name || !new_name[0]) {
                    xsql::set_vtab_error("Symbol name cannot be empty");
                    return false;
                }
                auto old_sym = bv->GetSymbolByAddress(r.address);
                if (!old_sym) {
                    xsql::set_vtab_error("names: no symbol at target address");
                    return false;
                }
                auto new_sym = new Symbol(old_sym->GetType(), new_name,
                                          old_sym->GetAddress());
                bv->DefineUserSymbol(new_sym);
                r.full_name = new_name;  // keep the query-scoped snapshot coherent
                return true;
            })
        .column_int("is_public", [](const SymbolInfo& r) -> int {
            // Consider globally-bound symbols as public.
            return (r.binding == GlobalBinding) ? 1 : 0;
        })
        .column_int("is_weak", [](const SymbolInfo& r) -> int {
            return (r.binding == WeakBinding) ? 1 : 0;
        })
        // Point lookup: WHERE addr = X resolves via GetSymbolByAddress and skips
        // the whole-table walk (and the per-query cache build).
        .filter_eq("addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<SymbolByAddrIterator>(addr);
        }, 0.5, 1.0)  // cost=0.5, estimated_rows=1
        .index_on("addr", [](const SymbolInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        // Row identity = symbol address. The full-scan, index, and filter_eq
        // cursors therefore all report the SAME rowid, and a scan-driven
        // UPDATE/DELETE reconstructs the target row via row_lookup() by address
        // instead of by a (shifting) cache position -- required for a deletable
        // query-scoped table that also has a filter_eq iterator.
        .rowid([](const SymbolInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .row_lookup([](SymbolInfo& out, int64_t rowid) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto sym = bv->GetSymbolByAddress(static_cast<uint64_t>(rowid));
            if (!sym) return false;
            out = snapshot_symbol(sym);
            return true;
        })
        .deletable([](SymbolInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Resolve the live symbol by address at delete time.
            auto sym = bv->GetSymbolByAddress(r.address);
            if (!sym) return false;
            if (r.is_auto_defined) {
                bv->UndefineAutoSymbol(sym);
            } else {
                bv->UndefineUserSymbol(sym);
            }
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (argc < 2) return false;
            if (argv[0].is_null() || argv[1].is_null()) {
                xsql::set_vtab_error("names insert requires addr and name");
                return false;
            }

            uint64_t address = static_cast<uint64_t>(argv[0].as_int64());
            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) {
                xsql::set_vtab_error("Symbol name cannot be empty");
                return false;
            }

            auto funcs = bv->GetAnalysisFunctionsForAddress(address);
            BNSymbolType sym_type = DataSymbol;
            if (!funcs.empty() && funcs[0]->GetStart() == address) {
                sym_type = FunctionSymbol;
            }

            auto sym = new Symbol(sym_type, name, address);
            bv->DefineUserSymbol(sym);
            return true;
        })
        .build();
}

} // namespace symbols
} // namespace bnsql
