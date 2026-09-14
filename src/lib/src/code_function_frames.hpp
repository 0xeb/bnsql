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

// One row of the `function_frames` table (canonical cross-tool schema). Derived from
// BN's GetStackLayout (locals at negative offsets, args at positive, relative to the
// frame base) + the architecture stack-pointer register. `saved_reg_size` and
// `has_frame_pointer` are always SQL NULL — BN exposes neither (measured in
// a standalone BN frame lab).
struct FrameInfo {
    uint64_t func_addr = 0;
    int64_t frame_size = 0;
    int64_t arg_size = 0;
    int64_t local_size = 0;
    std::string stack_base_reg;  // empty -> NULL
};

CachedTableDef<FrameInfo> define_function_frames();

} // namespace code
} // namespace bnsql
