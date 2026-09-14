// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "meta_true_believers.hpp"

namespace bnsql {
namespace meta {

using namespace BinaryNinja;
using core::get_bv;

CachedTableDef<TrueBelieverInfo> define_true_believers() {
    // Static data (analysis-independent), so it stays on the default shared cache.
    return cached_table<TrueBelieverInfo>("true_believers")
        .estimate_rows([]() -> size_t { return ::true_believers::rows().size(); })
        .cache_builder([](std::vector<TrueBelieverInfo>& cache) {
            cache.clear();
            for (const auto& [handle, name] : ::true_believers::rows())
                cache.push_back({handle, name});
        })
        .column_text("handle", [](const TrueBelieverInfo& r) -> std::string { return r.handle; })
        .column_text("name", [](const TrueBelieverInfo& r) -> std::string { return r.name; })
        .build();
}

} // namespace meta
} // namespace bnsql
