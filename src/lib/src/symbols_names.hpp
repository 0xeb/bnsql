// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

// Query-scoped snapshot of one BinaryNinja symbol for the `names` cache. The
// whole symbol table is materialized ONCE per query (via GetSymbols()), or a
// single row is resolved by address on the addr-pushdown / rowid-lookup paths
// (via GetSymbolByAddress) -- so a scan never re-walks GetSymbols() per column
// read. The symbol address is the row identity (see define_names()).
struct SymbolInfo {
    uint64_t address = 0;
    std::string full_name;
    BNSymbolBinding binding = NoBinding;
    bool is_auto_defined = false;
};

CachedTableDef<SymbolInfo> define_names();

} // namespace symbols
} // namespace bnsql
