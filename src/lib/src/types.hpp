// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types.hpp - Umbrella + registry for the bnsql type-intelligence tables.
 */

#pragma once

#include "core_common.hpp"
#include "types_types.hpp"
#include "types_members.hpp"
#include "types_enum_values.hpp"
#include "types_func_signatures.hpp"
#include "types_patches.hpp"

namespace bnsql {
namespace types {

struct TypesRegistry {
    CachedTableDef<TypeInfo> types;
    CachedTableDef<TypeMemberInfo> type_members;
    CachedTableDef<TypeEnumValueInfo> type_enum_values;
    CachedTableDef<FuncSignatureInfo> func_signatures;
    CachedTableDef<PatchInfo> patches;

    TypesRegistry();
    void register_all(xsql::Database& db);

    // Drop all shared table caches so the next scan rebuilds from live
    // analysis state (type names/declarations go stale on retypes; patches
    // on byte writes). Only call between statements — never while a cursor
    // on one of these tables is live.

private:
    void create_views(xsql::Database& db);
};

} // namespace types
} // namespace bnsql
