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

} // namespace core
} // namespace bnsql
