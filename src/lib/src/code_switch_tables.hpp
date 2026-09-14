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

// One row of the `switch_tables` table (canonical cross-tool schema
// func_addr/instr_addr/table_addr/min_case/max_case/case_count/default_addr).
// Reconstructed from HLIL_SWITCH. `table_addr` and `default_addr` are always SQL
// NULL — BN exposes neither the physical jump-table address nor a reliable default
// target (measured empirically in a standalone BN switch lab). `has_cases` is false when
// no constant case values were recovered (then min_case/max_case are NULL too).
struct SwitchTableInfo {
    uint64_t func_addr = 0;
    uint64_t instr_addr = 0;
    bool has_cases = false;
    int64_t min_case = 0;
    int64_t max_case = 0;
    int64_t case_count = 0;
};

CachedTableDef<SwitchTableInfo> define_switch_tables();

} // namespace code
} // namespace bnsql
