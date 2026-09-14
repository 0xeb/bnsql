// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace xrefs {

using namespace BinaryNinja;
using core::get_bv;

struct XrefInfo {
    uint64_t from_addr;
    uint64_t to_addr;
    uint64_t from_func;  // Pre-computed: function containing from_addr (0 if none)
    int type;
    bool is_code;
};

CachedTableDef<XrefInfo> define_xrefs();

} // namespace xrefs
} // namespace bnsql
