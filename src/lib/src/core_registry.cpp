// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "core.hpp"

#include <bnsql/runtime_settings.hpp>  // bnsql::runtime_settings() singleton

namespace bnsql {
namespace core {

CoreRegistry::CoreRegistry()
    : funcs(::bnsql::code::define_funcs())
    , segments(::bnsql::memory::define_segments())
    , names(::bnsql::symbols::define_names())
    , exports(::bnsql::symbols::define_exports())
    , strings(::bnsql::memory::define_strings())
    , comments(::bnsql::symbols::define_comments())
    , bookmarks(::bnsql::symbols::define_bookmarks())
    , binary(::bnsql::meta::define_binary())
    , capabilities(::bnsql::meta::define_capabilities())
    , runtime_settings(xsql::runtime::define_runtime_settings_table(
          ::bnsql::runtime_settings(), "bnsql"))
    , xrefs(::bnsql::xrefs::define_xrefs())
    , blocks(::bnsql::code::define_blocks())
    , cfg_edges(::bnsql::code::define_cfg_edges())
    , switch_tables(::bnsql::code::define_switch_tables())
    , function_frames(::bnsql::code::define_function_frames())
    , data_items(::bnsql::code::define_data_items())
    , dominators(::bnsql::code::define_dominators())
    , post_dominators(::bnsql::code::define_post_dominators())
    , loops(::bnsql::code::define_loops())
    , imports(::bnsql::symbols::define_imports())
    , instructions(::bnsql::code::define_instructions())
    , instruction_operands(::bnsql::code::define_instruction_operands())
    , bytes(::bnsql::memory::define_bytes_table())
    , true_believers(::bnsql::meta::define_true_believers())
{}

void CoreRegistry::register_all(xsql::Database& db) {
        // Index-based tables
        register_index_table(db, "segments", &segments);
        register_index_table(db, "binary", &binary);
        register_index_table(db, "capabilities", &capabilities);

        // Cached tables
        register_cached_table(db, "runtime_settings", &runtime_settings);
        register_cached_table(db, "funcs", &funcs);
        register_cached_table(db, "names", &names);
        register_cached_table(db, "entries", &exports);
        register_cached_table(db, "comments", &comments);
        register_cached_table(db, "bookmarks", &bookmarks);
        register_cached_table(db, "strings", &strings);
        register_cached_table(db, "xrefs", &xrefs);
        register_cached_table(db, "blocks", &blocks);
        register_cached_table(db, "cfg_edges", &cfg_edges);
        register_cached_table(db, "switch_tables", &switch_tables);
        register_cached_table(db, "function_frames", &function_frames);
        register_cached_table(db, "data_items", &data_items);
        register_cached_table(db, "dominators", &dominators);
        register_cached_table(db, "post_dominators", &post_dominators);
        register_cached_table(db, "loops", &loops);
        register_cached_table(db, "imports", &imports);
        register_cached_table(db, "instructions", &instructions);
        register_cached_table(db, "instruction_operands", &instruction_operands);
        register_cached_table(db, "true_believers", &true_believers);

        // Generator tables
        db.register_generator_table("bytes", &bytes);
        db.create_table("bytes", "bytes");

        // NOTE: helper views (entities, callers, ...) are created later, from
        // QueryEngine::init() after ALL registries + SQL functions register, so
        // every table a view references (notably `types`, owned by TypesRegistry)
        // and every scalar helper (name_at, ...) already exists. Creating them
        // here would forward-reference `types` — legal in SQLite (view bodies
        // resolve at query time) but fragile under reorders/stricter validation.
}

void CoreRegistry::create_helper_views(xsql::Database& db) {
        // entities view - unified discovery surface for common analyst lookups.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS entities AS
            SELECT
                f.name AS name,
                'function' AS kind,
                f.addr AS addr,
                '' AS parent_name,
                f.name AS qualified_name,
                'analysis.functions' AS source
            FROM funcs f
            UNION ALL
            SELECT
                n.name AS name,
                'symbol' AS kind,
                n.addr AS addr,
                '' AS parent_name,
                n.name AS qualified_name,
                'analysis.symbols' AS source
            FROM names n
            UNION ALL
            SELECT
                s.name AS name,
                'segment' AS kind,
                s.start_addr AS addr,
                '' AS parent_name,
                s.name AS qualified_name,
                'analysis.segments' AS source
            FROM segments s
            UNION ALL
            SELECT
                i.name AS name,
                'import' AS kind,
                i.addr AS addr,
                i.module AS parent_name,
                i.module || '!' || i.name AS qualified_name,
                'analysis.imports' AS source
            FROM imports i
            UNION ALL
            SELECT
                t.content AS name,
                'string' AS kind,
                t.addr AS addr,
                '' AS parent_name,
                t.content AS qualified_name,
                'analysis.strings' AS source
            FROM strings t
            UNION ALL
            SELECT
                ty.name AS name,
                'type' AS kind,
                NULL AS addr,
                '' AS parent_name,
                ty.name AS qualified_name,
                'analysis.types' AS source
            FROM types ty
        )");

        // callers view - who calls a function
        // Uses pre-computed from_func and name_at() scalar lookups to avoid
        // expensive joins against large virtual tables.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callers AS
            SELECT
                x.to_addr as func_addr,
                x.from_addr as caller_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as caller_name,
                x.from_func as caller_func_addr
            FROM xrefs x
            WHERE x.is_code = 1 AND x.from_func != 0
        )");

        // callees view - what does a function call
        // Uses scalar name_at() lookup to avoid heavy funcs/names joins.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callees AS
            SELECT
                x.from_func as func_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as func_name,
                x.to_addr as callee_addr,
                COALESCE(name_at(x.to_addr), printf('sub_%X', x.to_addr)) as callee_name
            FROM xrefs x
            WHERE x.is_code = 1 AND x.from_func != 0
        )");

        // function_chunks view - function address ranges (BN functions are typically contiguous)
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_chunks AS
            SELECT
                func_addr,
                MIN(start_addr) AS chunk_start,
                MAX(end_addr) AS chunk_end,
                COUNT(*) AS block_count,
                SUM(end_addr - start_addr) AS total_size
            FROM blocks
            GROUP BY func_addr
        )");

        // string_refs view - which functions reference which strings
        // Uses scalar name lookup to keep this view bounded on larger fixtures.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS string_refs AS
            SELECT
                s.addr as string_addr,
                s.content as string_value,
                s.length as string_length,
                x.from_addr as ref_addr,
                x.from_func as func_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as func_name
            FROM strings s
            JOIN xrefs x ON x.to_addr = s.addr
            WHERE x.from_func != 0
        )");
}

// Native canonical registration: the vtable module IS the canonical table name
// (no bn_ prefix, no alias) -- one true name per table.
void CoreRegistry::register_index_table(xsql::Database& db, const char* name,
                                         const VTableDef* def) {
        db.register_table(name, def);
        db.create_table(name, name);
}

template<typename RowData>
void CoreRegistry::register_cached_table(xsql::Database& db, const char* name,
                                          const CachedTableDef<RowData>* def) {
        db.register_cached_table(name, def);
        db.create_table(name, name);
}

} // namespace core
} // namespace bnsql
