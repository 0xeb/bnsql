// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * core.hpp - Umbrella + registry for the core bnsql tables.
 *
 * Pulls in every per-table header (code_*, symbols_*, memory_*, xrefs, meta_*)
 * and declares the CoreRegistry that owns and registers them. The ctor and the
 * register_all/create_helper_views bodies are defined out-of-line in
 * core_registry.cpp so consumers never instantiate the per-table builders.
 */

#pragma once

#include "core_common.hpp"

// Per-table definitions (Row structs + define_*() declarations), by domain.
#include "code_funcs.hpp"
#include "code_blocks.hpp"
#include "code_cfg.hpp"
#include "code_switch_tables.hpp"
#include "code_function_frames.hpp"
#include "code_data_items.hpp"
#include "code_graph_tables.hpp"
#include "code_instructions.hpp"
#include "code_operands.hpp"
#include "symbols_names.hpp"
#include "symbols_exports.hpp"
#include "symbols_imports.hpp"
#include "symbols_comments.hpp"
#include "symbols_bookmarks.hpp"
#include "memory_segments.hpp"
#include "memory_strings.hpp"
#include "memory_bytes.hpp"
#include "xrefs.hpp"
#include "meta_binary.hpp"
#include "meta_capabilities.hpp"
#include "meta_true_believers.hpp"

#include <xsql/runtime_settings_table.hpp>

namespace bnsql {
namespace core {

// Owns every core virtual table and registers it (plus the helper SQL views).
struct CoreRegistry {
    CachedTableDef<code::FuncInfo> funcs;
    VTableDef segments;
    CachedTableDef<symbols::SymbolInfo> names;
    CachedTableDef<symbols::ExportInfo> exports;
    CachedTableDef<memory::StringInfo> strings;
    CachedTableDef<symbols::CommentInfo> comments;
    CachedTableDef<symbols::BookmarkInfo> bookmarks;
    VTableDef binary;
    VTableDef capabilities;
    CachedTableDef<xsql::runtime::RuntimeSettingEntry> runtime_settings;

    CachedTableDef<xrefs::XrefInfo> xrefs;
    CachedTableDef<code::BlockInfo> blocks;
    CachedTableDef<code::CfgEdgeInfo> cfg_edges;
    CachedTableDef<code::SwitchTableInfo> switch_tables;
    CachedTableDef<code::FrameInfo> function_frames;
    CachedTableDef<code::DataItemInfo> data_items;
    CachedTableDef<code::DominatorInfo> dominators;
    CachedTableDef<code::PostDominatorInfo> post_dominators;
    CachedTableDef<code::LoopInfo> loops;
    CachedTableDef<symbols::ImportInfo> imports;
    CachedTableDef<code::InsnInfo> instructions;
    CachedTableDef<code::OperandInfo> instruction_operands;

    GeneratorTableDef<memory::ByteRow> bytes;

    CachedTableDef<meta::TrueBelieverInfo> true_believers;

    CoreRegistry();

    void register_all(xsql::Database& db);
    void create_helper_views(xsql::Database& db);

private:
    void register_index_table(xsql::Database& db, const char* name,
                              const VTableDef* def);

    template<typename RowData>
    void register_cached_table(xsql::Database& db, const char* name,
                               const CachedTableDef<RowData>* def);
};

} // namespace core
} // namespace bnsql
