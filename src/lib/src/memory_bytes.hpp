// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace memory {

struct ByteRow {
    uint64_t address = 0;
    uint8_t value = 0;
    bool is_initialized = false;
};

GeneratorTableDef<ByteRow> define_bytes_table();

} // namespace memory
} // namespace bnsql
