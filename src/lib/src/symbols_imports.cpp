// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_imports.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

CachedTableDef<ImportInfo> define_imports() {
    return cached_table<ImportInfo>("imports")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Cheap, import-typed count for the planner: query only the three
            // imported symbol types instead of walking (and materializing) the
            // entire symbol list. GetSymbols() would materialize every symbol
            // Ref just to count imports, so a single import query would walk the
            // full symbol list twice -- once here for planning and once in the
            // cache_builder. Summing the per-type sizes touches only the imports
            // and yields the exact same count the cache_builder produces (each
            // symbol has exactly one type, so the three sets are disjoint).
            return bv->GetSymbolsOfType(ImportedFunctionSymbol).size() +
                   bv->GetSymbolsOfType(ImportAddressSymbol).size() +
                   bv->GetSymbolsOfType(ImportedDataSymbol).size();
        })
        .cache_builder([](std::vector<ImportInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            std::map<std::string, int> module_indices;
            int next_idx = 0;

            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetType() == ImportedFunctionSymbol ||
                    sym->GetType() == ImportAddressSymbol ||
                    sym->GetType() == ImportedDataSymbol) {
                    ImportInfo info;
                    info.address = sym->GetAddress();
                    info.name = sym->GetShortName();
                    info.ordinal = sym->GetOrdinal();

                    // Resolve the importing library/DLL from the symbol's
                    // external location (ExternalLocation -> ExternalLibrary ->
                    // name) -- the analyst-relevant module. The symbol namespace
                    // is only the internal/external bucket (its default strings
                    // are the BNINTERNALNAMESPACE/BNEXTERNALNAMESPACE constants),
                    // which collapses every import to the same string and
                    // degenerates module_idx into a single group. Fall back to
                    // the namespace, then "unknown", only when the symbol has no
                    // external location / backing library.
                    std::string resolved_module;
                    if (auto loc = bv->GetExternalLocation(sym)) {
                        if (auto lib = loc->GetExternalLibrary()) {
                            resolved_module = lib->GetName();
                        }
                    }
                    if (resolved_module.empty()) {
                        std::string ns = sym->GetNameSpace().GetString();
                        resolved_module = ns.empty() ? "unknown" : ns;
                    }
                    info.module = resolved_module;

                    // Assign module index
                    auto it = module_indices.find(info.module);
                    if (it == module_indices.end()) {
                        info.module_idx = next_idx;
                        module_indices[info.module] = next_idx++;
                    } else {
                        info.module_idx = it->second;
                    }

                    cache.push_back(info);
                }
            }
        })
        .column_int64("addr", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text("name", [](const ImportInfo& r) -> std::string {
            return r.name;
        })
        .column_int64("ordinal", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.ordinal);
        })
        .column_text("module", [](const ImportInfo& r) -> std::string {
            return r.module;
        })
        .column_int("module_idx", [](const ImportInfo& r) -> int {
            return r.module_idx;
        })
        .build();
}

} // namespace symbols
} // namespace bnsql
