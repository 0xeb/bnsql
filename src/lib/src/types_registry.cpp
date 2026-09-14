// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types.hpp"

namespace bnsql {
namespace types {

TypesRegistry::TypesRegistry()
    : types(::bnsql::types::define_types())
    , type_members(::bnsql::types::define_type_members())
    , type_enum_values(::bnsql::types::define_type_enum_values())
    , func_signatures(::bnsql::types::define_func_signatures())
    , patches(::bnsql::types::define_patches())
{}

void TypesRegistry::register_all(xsql::Database& db) {
        db.register_cached_table("types", &types);
        db.create_table("types", "types");

        db.register_cached_table("type_members", &type_members);
        db.create_table("type_members", "type_members");

        db.register_cached_table("type_enum_values", &type_enum_values);
        db.create_table("type_enum_values", "type_enum_values");

        db.register_cached_table("func_signatures", &func_signatures);
        db.create_table("func_signatures", "func_signatures");

        db.register_cached_table("patches", &patches);
        db.create_table("patches", "patches");

        create_views(db);
}

void TypesRegistry::create_views(xsql::Database& db) {
        // Convenience views for common type queries
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_structs AS
            SELECT * FROM types WHERE is_struct = 1
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_enums AS
            SELECT * FROM types WHERE is_enum = 1
        )");
}

} // namespace types
} // namespace bnsql
