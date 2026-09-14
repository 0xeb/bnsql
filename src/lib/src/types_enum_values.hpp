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

struct TypeEnumValueInfo {
    int64_t type_id;
    std::string type_name;
    int value_index;
    std::string value_name;
    int64_t value;
};

CachedTableDef<TypeEnumValueInfo> define_type_enum_values();

} // namespace types
} // namespace bnsql
