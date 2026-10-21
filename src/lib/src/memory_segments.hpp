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

// One row of `segments`: one Binary Ninja segment (BinaryView::GetSegments()).
struct SegmentRow {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t data_offset = 0;
    uint64_t data_length = 0;
    uint32_t flags = 0;
    bool auto_defined = false;

    uint64_t length() const { return end - start; }
    bool operator==(const SegmentRow& o) const {
        return start == o.start && end == o.end && data_offset == o.data_offset &&
               data_length == o.data_length && flags == o.flags && auto_defined == o.auto_defined;
    }
};

CachedTableDef<SegmentRow> define_segments();

} // namespace memory
} // namespace bnsql
