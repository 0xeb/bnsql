// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `function_frames` — per-function stack-frame layout from BN's GetStackLayout +
// architecture stack-pointer register. Canonical cross-tool surface.
// Recipe measured empirically in a standalone BN frame lab: locals sit at negative stack
// offsets, args at positive. The zero stack boundary is always part of the span,
// and each variable's type width extends its upper edge. saved_reg_size and
// has_frame_pointer are NULL (not exposed).

#include "code_function_frames.hpp"

#include <algorithm>
#include <limits>

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

void collect_function_frames(std::vector<FrameInfo>& out) {
    auto bv = get_bv();
    if (!bv)
        return;

    auto funcs = bv->GetAnalysisFunctionList();
    out.reserve(funcs.size());
    for (auto& func : funcs) {
        FrameInfo r;
        r.func_addr = func->GetStart();
        Ref<Architecture> arch = func->GetArchitecture();
        if (arch) {
            r.stack_base_reg =
                arch->GetRegisterName(arch->GetStackPointerRegister());
        }

        int64_t lo = 0, hi = 0;
        bool any = false;
        for (auto& kv : func->GetStackLayout()) {
            const int64_t off = kv.first;
            any = true;
            lo = std::min(lo, off);
            hi = std::max(hi, off);
            for (const auto& variable : kv.second) {
                Ref<Type> type = variable.type.GetValue();
                if (!type) continue;
                const uint64_t width = static_cast<uint64_t>(type->GetWidth());
                int64_t end = off;
                if (width >
                    static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                    end = std::numeric_limits<int64_t>::max();
                } else {
                    const int64_t signed_width = static_cast<int64_t>(width);
                    end = off > std::numeric_limits<int64_t>::max() - signed_width
                        ? std::numeric_limits<int64_t>::max()
                        : off + signed_width;
                }
                hi = std::max(hi, end);
            }
        }
        if (any) {
            if (lo < 0 && hi > std::numeric_limits<int64_t>::max() + lo)
                r.frame_size = std::numeric_limits<int64_t>::max();
            else
                r.frame_size = hi - lo;
            r.local_size =
                lo == std::numeric_limits<int64_t>::min()
                    ? std::numeric_limits<int64_t>::max()
                    : (lo < 0 ? -lo : 0);
            r.arg_size = hi > 0 ? hi : 0;
        }
        out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(), [](const FrameInfo& a, const FrameInfo& b) {
        return a.func_addr < b.func_addr;
    });
}

CachedTableDef<FrameInfo> define_function_frames() {
    return cached_table<FrameInfo>("function_frames")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() : 0;
        })
        .cache_builder([](std::vector<FrameInfo>& cache) {
            collect_function_frames(cache);
        })
        // Canonical order: func_addr, frame_size, arg_size, local_size,
        // saved_reg_size, stack_base_reg, has_frame_pointer.
        .column_int64("func_addr",
                      [](const FrameInfo& r) -> int64_t {
                          return static_cast<int64_t>(r.func_addr);
                      })
        .column_int64("frame_size",
                      [](const FrameInfo& r) -> int64_t { return r.frame_size; })
        .column_int64("arg_size",
                      [](const FrameInfo& r) -> int64_t { return r.arg_size; })
        .column_int64("local_size",
                      [](const FrameInfo& r) -> int64_t { return r.local_size; })
        // Not exposed by BN -> always NULL.
        .column("saved_reg_size", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const FrameInfo&) { ctx.result_null(); })
        .column("stack_base_reg", xsql::ColumnType::Text,
                [](xsql::FunctionContext& ctx, const FrameInfo& r) {
                    if (r.stack_base_reg.empty()) ctx.result_null();
                    else ctx.result_text(r.stack_base_reg);
                })
        // Not exposed by BN -> always NULL.
        .column("has_frame_pointer", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const FrameInfo&) { ctx.result_null(); })
        .build();
}

} // namespace code
} // namespace bnsql
