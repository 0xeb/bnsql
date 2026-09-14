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

struct FuncSignatureInfo {
    uint64_t func_addr;
    int arg_index;       // -1 = return type row
    std::string arg_name;
    std::string arg_type;
    std::string return_type;
    std::string calling_conv;
};

CachedTableDef<FuncSignatureInfo> define_func_signatures();

} // namespace types
} // namespace bnsql
