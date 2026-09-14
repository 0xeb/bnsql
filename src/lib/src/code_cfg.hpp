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

// One row of the `cfg_edges` table: an intra-function control-flow edge between
// two basic blocks. Canonical cross-tool schema (func_addr, from_addr, to_addr,
// edge_type); from_addr/to_addr are the source/target block START addresses.
struct CfgEdgeInfo {
    uint64_t    func_addr;   // owning function start
    uint64_t    from_addr;   // source block start address
    uint64_t    to_addr;     // target block start address
    std::string edge_type;   // "normal", "true", "false"
};

CachedTableDef<CfgEdgeInfo> define_cfg_edges();

} // namespace code
} // namespace bnsql
