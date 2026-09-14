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

struct TypeInfo {
    int64_t id;
    std::string name;
    std::string kind;
    int64_t size;
    int alignment;
    bool is_struct;
    bool is_union;
    bool is_enum;
    bool is_typedef;
    bool is_func;
    std::string definition;
};

CachedTableDef<TypeInfo> define_types();

} // namespace types
} // namespace bnsql
