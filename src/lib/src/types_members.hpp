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

struct TypeMemberInfo {
    int64_t type_id;
    std::string type_name;
    int member_index;
    std::string member_name;
    int64_t offset;
    int64_t size;
    std::string member_type;
    std::string access;
};

CachedTableDef<TypeMemberInfo> define_type_members();

} // namespace types
} // namespace bnsql
