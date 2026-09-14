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

struct InsnInfo {
    uint64_t address;
    uint64_t func_addr;
    std::string mnemonic;
    size_t size;
    std::string disasm;
    std::vector<std::string> operands;
};

CachedTableDef<InsnInfo> define_instructions();

} // namespace code
} // namespace bnsql
