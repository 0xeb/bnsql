// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

struct CommentInfo {
    uint64_t address = 0;
    std::string comment;
    std::string rpt_comment;
};

CachedTableDef<CommentInfo> define_comments();

} // namespace symbols
} // namespace bnsql
