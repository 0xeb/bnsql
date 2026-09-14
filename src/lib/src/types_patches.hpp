// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

struct PatchInfo {
    uint64_t address;
    uint8_t original_byte;
    uint8_t patched_byte;
    std::string status;  // "changed" or "inserted"
};

CachedTableDef<PatchInfo> define_patches();

} // namespace types
} // namespace bnsql
