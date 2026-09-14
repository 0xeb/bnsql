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

struct ImportInfo {
    uint64_t address;
    std::string name;
    uint64_t ordinal;
    std::string module;
    int module_idx;
};

CachedTableDef<ImportInfo> define_imports();

} // namespace symbols
} // namespace bnsql
