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

struct BlockInfo {
    uint64_t func_addr;
    uint64_t start_addr;
    uint64_t end_addr;
};

CachedTableDef<BlockInfo> define_blocks();

} // namespace code
} // namespace bnsql
