// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `data_items` — defined data items via BN's GetDataVariables(). Canonical
// cross-tool surface, matching ghidrasql:
//   addr, name, data_type, size, value_repr, segment_name, is_string, is_initialized.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace code {

struct DataItemInfo {
    uint64_t addr = 0;
    std::string name;          // symbol short name, else empty
    std::string data_type;     // Type::GetString(), else empty
    int64_t size = 0;          // Type::GetWidth()
    bool has_type = false;     // data_type/size known
    std::string value_repr;    // string contents / scalar hex, best-effort
    std::string segment_name;  // containing section name (BN segments are unnamed)
    int is_string = 0;         // 1 when a string reference starts at addr
    int is_initialized = 0;    // 0 for BSS / unmapped bytes
};

CachedTableDef<DataItemInfo> define_data_items();

} // namespace code
} // namespace bnsql
