// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * core_common.hpp - Shared declarations for the bnsql table definition units.
 *
 * Holds the thread-local BinaryView context (BNContext + accessors) that every
 * per-table definition reads through, plus the common includes. Each per-table
 * header includes this one. The Binary Ninja SDK is pulled in via bn_headers.hpp
 * (the PCH), so it stays confined to the library's own translation units.
 */

#pragma once

#include "bn_headers.hpp"
#include "persistence.hpp"

#include <bnsql/fwd.hpp>
#include <bnsql/vtable.hpp>
#include <xsql/database.hpp>

namespace bnsql {
namespace core {

using namespace BinaryNinja;

// ============================================================================
// Context: holds the BinaryView for all table operations
// ============================================================================
// The BN-free accessors (set_context/get_context, g_context) are declared in
// the public fwd.hpp; this private header adds the full BNContext definition
// (it embeds a Ref<BinaryView>, so it needs the SDK) and the BinaryView-typed
// get_bv() that the table definitions read through.

struct BNContext {
    Ref<BinaryView> bv;

    explicit BNContext(Ref<BinaryView> view) : bv(std::move(view)) {}
};

Ref<BinaryView> get_bv();

} // namespace core
} // namespace bnsql
