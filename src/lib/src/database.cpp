// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

// Out-of-line QueryEngine bodies. This translation unit is the single place
// that sees the complete per-table/registry/UDF definitions, so the heavy
// builders never instantiate in consumer code (they only link this lib).

#include <bnsql/database.hpp>

#include "core.hpp"
#include "core_common.hpp"
#include "decompiler.hpp"
#include "types.hpp"
// functions::register_sql_functions / search::register_search_bytes are declared
// in fwd.hpp (via database.hpp) and defined in functions.cpp / search_bytes.cpp.

namespace bnsql {

using namespace BinaryNinja;

QueryEngine::QueryEngine(Ref<BinaryView> bv) : bv_(bv) {
    init();
}

QueryEngine::~QueryEngine() {
    // Restore previous context if we changed it
    if (context_ && core::g_context == context_.get()) {
        core::set_context(nullptr);
    }
}

QueryEngine::QueryEngine(QueryEngine&&) noexcept = default;
QueryEngine& QueryEngine::operator=(QueryEngine&&) noexcept = default;

void QueryEngine::init() {
    // Create context for this BinaryView
    context_ = std::make_unique<core::BNContext>(bv_);
    core::set_context(context_.get());

    // Register all virtual tables
    core_ = std::make_unique<core::CoreRegistry>();
    core_->register_all(db_);

    // Register decompiler tables
    decompiler_ = std::make_unique<decompiler::DecompilerTableRegistry>();
    decompiler_->register_all(db_);

    // Register type intelligence tables
    types_ = std::make_unique<types::TypesRegistry>();
    types_->register_all(db_);

    // Register SQL functions
    functions::register_sql_functions(db_);

    // Register search functions
    search::register_search_bytes(db_);

    // Create convenience views LAST — after every table (including `types` from
    // TypesRegistry) and every scalar helper (name_at, ...) is registered, so
    // no view forward-references a not-yet-registered dependency.
    core_->create_helper_views(db_);
}

} // namespace bnsql
