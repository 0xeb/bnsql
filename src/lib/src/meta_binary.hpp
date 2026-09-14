// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace meta {

using namespace BinaryNinja;
using core::get_bv;

struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;
};

VTableDef define_binary();

} // namespace meta
} // namespace bnsql
