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

struct OperandInfo {
    uint64_t addr;          // instruction address (canonical token; was insn_addr)
    uint64_t func_addr;
    int operand_index;
    std::string text;
    int token_type;
    std::string type_name;
    uint64_t value;
    int size;
};

CachedTableDef<OperandInfo> define_instruction_operands();

} // namespace code
} // namespace bnsql
