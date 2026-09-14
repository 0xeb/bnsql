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

// One row of the `bookmarks` table (canonical cross-tool schema
// addr/type/category/comment): a BN user *data* Tag. `type` is the tag-type name
// (default `Bookmarks`), `comment` is the tag's free-text data. `category` has no BN
// analog and is always empty. `tag_id` is the BN Tag GUID, kept so UPDATE/DELETE can
// re-resolve the exact Tag object. See the standalone BN tag lab.
struct BookmarkInfo {
    uint64_t address = 0;
    std::string type;
    std::string category;  // always "" — BN tags have no category sub-level
    std::string comment;
    std::string tag_id;
};

CachedTableDef<BookmarkInfo> define_bookmarks();

} // namespace symbols
} // namespace bnsql
