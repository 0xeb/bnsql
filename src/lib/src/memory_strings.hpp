// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace memory {

using namespace BinaryNinja;
using core::get_bv;

struct StringInfo {
    uint64_t address;
    size_t length;
    int type;
    std::string type_name;
    std::string content;
};

CachedTableDef<StringInfo> define_strings();

} // namespace memory
} // namespace bnsql
