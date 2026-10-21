// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "core_common.hpp"

namespace bnsql {
namespace core {

// Single definition of the thread-local context (declared extern in the header).
thread_local BNContext* g_context = nullptr;

void set_context(BNContext* ctx) { g_context = ctx; }
BNContext* get_context() { return g_context; }
Ref<BinaryView> get_bv() { return g_context ? g_context->bv : nullptr; }

uint64_t segment_initialized_length(const Ref<BinaryView>& bv, const Ref<Segment>& seg) {
    if (!bv || !seg) return 0;
    const uint64_t length = seg->GetLength();
    const uint64_t data_length = seg->GetDataLength();
    if (data_length != 0) return data_length < length ? data_length : length;
    return length != 0 && bv->IsOffsetBackedByFile(seg->GetStart()) ? length : 0;
}

bool is_initialized_at(const Ref<BinaryView>& bv, uint64_t addr) {
    if (!bv) return false;
    Ref<Segment> seg = bv->GetSegmentAt(addr);
    if (!seg) return false;
    const uint64_t start = seg->GetStart();
    return addr >= start && addr - start < segment_initialized_length(bv, seg);
}

} // namespace core
} // namespace bnsql
