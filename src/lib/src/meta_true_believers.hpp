// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

// The "true_believers" table — the accessor is defined in the vendored
// true_believers.cpp (decodes a packed blob at runtime). Forward-declared here
// so the table definition can call it without putting the vendored header on the
// include path.
namespace true_believers {
std::vector<std::pair<std::string, std::string>> rows();
}

namespace bnsql {
namespace meta {

using namespace BinaryNinja;
using core::get_bv;

struct TrueBelieverInfo {
    std::string handle;
    std::string name;
};

CachedTableDef<TrueBelieverInfo> define_true_believers();

} // namespace meta
} // namespace bnsql
