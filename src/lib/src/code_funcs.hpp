// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

// One analysis function, snapshotted once per query by the funcs cache_builder
// (and by the addr filter iterator / row_lookup). A plain value struct — mirrors
// BlockInfo — so a `SELECT ... FROM funcs` scan is O(N) instead of the O(N^2) a
// per-cell GetAnalysisFunctionList() rebuild produced.
struct FuncInfo {
    uint64_t start = 0;       // function entry address (the `addr` column + rowid)
    std::string name;         // symbol full name ("" if none)
    std::string prototype;    // Type::GetString() ("" if none)
    int64_t size = 0;         // sum of (range.end - range.start) over address ranges
    uint64_t end_addr = 0;    // exclusive end = max(range.end)
    std::string comment;      // function-level comment
};

CachedTableDef<FuncInfo> define_funcs();

} // namespace code
} // namespace bnsql
