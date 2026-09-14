// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * fwd.hpp - Forward declarations for bnsql registry types.
 *
 * Allows the public database.hpp to hold std::unique_ptr<T> registry members
 * without pulling in the per-table headers (and thus the Binary Ninja SDK).
 * Mirrors idasql/fwd.hpp.
 */

#pragma once

#include <bnsql/vtable.hpp>

#include <functional>
#include <string>

namespace bnsql {

namespace core {
    struct BNContext;
    struct CoreRegistry;

    // BN-free context accessors (the BinaryView-returning get_bv() lives in the
    // private core_common.hpp). g_context is defined once in core_common.cpp.
    extern thread_local BNContext* g_context;
    void set_context(BNContext* ctx);
    BNContext* get_context();
}

namespace decompiler {
    struct DecompilerTableRegistry;
}

namespace types {
    struct TypesRegistry;
}

namespace functions {
    bool register_sql_functions(xsql::Database& db);

    // Install a provider that supplies the live UI-context JSON envelope for
    // get_ui_context_json(). The GUI plugin sets this to a Binary Ninja Python
    // capture (binaryninjaui UIContext); when unset (CLI/headless) the function
    // returns an {available:false} envelope. Pass nullptr to clear.
    void set_ui_context_provider(std::function<std::string()> provider);
}

namespace search {
    bool register_search_bytes(xsql::Database& db);
}

} // namespace bnsql
