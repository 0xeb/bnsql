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

// One row of the `entries` table (canonical cross-tool name — entry points and
// exports): the binary's entry point (ordinal 0, when present) followed by each exported
// (GlobalBinding) function symbol. Snapshotted once per query into the cache so
// column reads are O(1) instead of re-walking GetSymbols() per row/column.
struct ExportInfo {
    int64_t     ordinal;   // 0-based position in the emitted export list
    uint64_t    address;   // entry / exported-function virtual address
    std::string name;      // full symbol name
};

CachedTableDef<ExportInfo> define_exports();

} // namespace symbols
} // namespace bnsql
