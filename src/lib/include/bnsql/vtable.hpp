// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * vtable.hpp - SQLite Virtual Table framework for Binary Ninja
 *
 * Re-exports xsql virtual table framework types into bnsql namespace.
 * Mirrors idasql/vtable.hpp for API compatibility.
 */

#pragma once

#include <xsql/xsql.hpp>

namespace bnsql {

// ============================================================================
// Re-export xsql types into bnsql namespace
// ============================================================================

// Column types
using xsql::ColumnType;
using xsql::column_type_sql;

// Column definition (index-based)
using xsql::ColumnDef;

// Virtual table definition (index-based)
using xsql::VTableDef;

// SQLite virtual table implementation
using xsql::Vtab;
using xsql::Cursor;

// Registration helpers
using xsql::register_vtable;
using xsql::create_vtable;

// Index-based table builder
using xsql::VTableBuilder;
using xsql::table;

// ============================================================================
// Cached Table API (query-scoped — each statement rebuilds from the live BinaryView)
// ============================================================================

// Row iterator for constraint pushdown
using xsql::RowIterator;
using xsql::FilterDef;
using xsql::FILTER_NONE;

// Cached column definition (row-typed)
template<typename RowData>
using CachedColumnDef = xsql::CachedColumnDef<RowData>;

// Cached table definition
template<typename RowData>
using CachedTableDef = xsql::CachedTableDef<RowData>;

// Cached cursor (owns cache)
template<typename RowData>
using CachedCursor = xsql::CachedCursor<RowData>;

// Cached table builder
template<typename RowData>
using CachedTableBuilder = xsql::CachedTableBuilder<RowData>;

template<typename RowData>
inline CachedTableBuilder<RowData> cached_table(const char* name) {
    return xsql::cached_table<RowData>(name);
}

// ============================================================================
// Generator Table API (lazy evaluation)
// ============================================================================

template<typename RowData>
using GeneratorTableDef = xsql::GeneratorTableDef<RowData>;

template<typename RowData>
using GeneratorTableBuilder = xsql::GeneratorTableBuilder<RowData>;

template<typename RowData>
inline GeneratorTableBuilder<RowData> generator_table(const char* name) {
    return xsql::generator_table<RowData>(name);
}

} // namespace bnsql
