// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_exports.hpp"

#include <unordered_set>

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

// The `entries` table (canonical cross-tool name; was `entries`) snapshots the
// binary's entry point plus its exported (GlobalBinding) function symbols ONCE
// per query into ExportInfo rows, then reads every column straight out of that
// vector.
//
// The prior implementation used a plain (index-based) table whose addr/name
// accessors each re-called GetSymbols() from scratch and linearly scanned to the
// i-th GlobalBinding FunctionSymbol -- O(total_symbols) per row per column, i.e.
// O(E*N) for E export rows over N symbols. Building a cache once makes each column
// O(1) and lets us dedup the entry point against the exported list (an exported
// entry -- e.g. a PE/DLL export or an ELF `_start` that is itself a global
// function symbol -- must yield exactly one row, not a duplicate). Read-only over
// mutable engine state (symbol renames, re-analysis), so it opts out of the shared
// cross-query cache and rebuilds from the live BinaryView on every query.
CachedTableDef<ExportInfo> define_exports() {
    return cached_table<ExportInfo>("entries")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Cheap over-estimate for planning: all function symbols + the entry.
            return bv->GetSymbolsOfType(FunctionSymbol).size() + 1;
        })
        .cache_builder([](std::vector<ExportInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            std::unordered_set<uint64_t> seen;
            int64_t ordinal = 0;

            // Ordinal 0: the main entry point (when the binary has one).
            uint64_t entry = bv->GetEntryPoint();
            if (entry != 0) {
                ExportInfo ei;
                ei.ordinal = ordinal++;
                ei.address = entry;
                auto sym = bv->GetSymbolByAddress(entry);
                ei.name = sym ? sym->GetFullName() : "_start";
                cache.push_back(std::move(ei));
                seen.insert(entry);
            }

            // Remaining ordinals: exported (GlobalBinding) function symbols.
            // GetSymbolsOfType(FunctionSymbol) replaces the manual GetSymbols()
            // type filter; skip any symbol whose address was already emitted (the
            // entry point, or a rare duplicate export) so each VA yields one row.
            for (auto& sym : bv->GetSymbolsOfType(FunctionSymbol)) {
                if (sym->GetBinding() != GlobalBinding) continue;
                uint64_t addr = sym->GetAddress();
                if (!seen.insert(addr).second) continue;  // dedup incl. entry VA
                ExportInfo ei;
                ei.ordinal = ordinal++;
                ei.address = addr;
                ei.name = sym->GetFullName();
                cache.push_back(std::move(ei));
            }
        })
        .column_int64("ordinal", [](const ExportInfo& r) -> int64_t {
            return r.ordinal;
        })
        .column_int64("addr", [](const ExportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text("name", [](const ExportInfo& r) -> std::string {
            return r.name;
        })
        .build();
}

} // namespace symbols
} // namespace bnsql
