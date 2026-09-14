// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// dominators / post_dominators / loops — canonical cross-tool CFG-graph tables
// matching the ghidrasql reference shapes. Each maps a function's BN
// basic blocks (GetBasicBlocks + GetOutgoingEdges) onto opaque node ids and runs the
// generic RE-agnostic xsql::graph module; the address mapping stays entirely here.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace code {

struct DominatorInfo {
    uint64_t func_addr = 0;
    uint64_t node_addr = 0;
    uint64_t idom_addr = 0;
    bool has_idom = false;
    int64_t depth = 0;
    bool is_entry = false;
};

struct PostDominatorInfo {
    uint64_t func_addr = 0;
    uint64_t node_addr = 0;
    uint64_t ipdom_addr = 0;
    bool has_ipdom = false;
    int64_t depth = 0;
    bool is_exit = false;
};

struct LoopInfo {
    uint64_t func_addr = 0;
    uint64_t header_addr = 0;
    uint64_t latch_addr = 0;
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    int64_t depth = 0;
    std::string loop_kind;
    int64_t block_count = 0;
};

CachedTableDef<DominatorInfo> define_dominators();
CachedTableDef<PostDominatorInfo> define_post_dominators();
CachedTableDef<LoopInfo> define_loops();

} // namespace code
} // namespace bnsql
