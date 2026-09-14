// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `data_items` — defined data items from BN's GetDataVariables(). Canonical
// cross-tool surface. One row per DataVariable; the honest NULLs are
// documented in the schema-catalog (empty name/type => NULL).

#include "code_data_items.hpp"

#include <cstdio>

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// 1 when addr lies in a segment's raw-backed data (GetDataLength), 0 for a
// mapped-but-uninitialized byte (BSS tail) or an unmapped address. Mirrors the
// bytes-table ruling (canonical byte surface).
int data_is_initialized(Ref<BinaryView>& bv, uint64_t addr) {
    if (!bv) return 0;
    auto seg = bv->GetSegmentAt(addr);
    if (!seg) return 0;
    const uint64_t start = seg->GetStart();
    return addr >= start && addr - start < seg->GetDataLength() ? 1 : 0;
}

// BN segments are unnamed; the human-facing region name is the section.
std::string section_name_at(Ref<BinaryView>& bv, uint64_t addr) {
    auto secs = bv->GetSectionsAt(addr);
    if (!secs.empty() && secs[0])
        return secs[0]->GetName();
    return "";
}

std::string symbol_name_at(Ref<BinaryView>& bv, uint64_t addr) {
    Ref<Symbol> sym = bv->GetSymbolByAddress(addr);
    return sym ? sym->GetShortName() : std::string();
}

void collect_data_items(std::vector<DataItemInfo>& out) {
    auto bv = get_bv();
    if (!bv)
        return;
    auto vars = bv->GetDataVariables();  // std::map<uint64_t, DataVariable> (sorted)
    out.reserve(vars.size());
    for (auto& kv : vars) {
        const DataVariable& dv = kv.second;
        DataItemInfo r;
        r.addr = dv.address;
        r.name = symbol_name_at(bv, dv.address);

        Ref<Type> ty = dv.type.GetValue();
        if (ty) {
            r.data_type = ty->GetString();
            r.size = static_cast<int64_t>(ty->GetWidth());
            r.has_type = true;
        }

        // String detection + contents (mirrors the strings table).
        BNStringReference sref;
        if (bv->GetStringAtAddress(dv.address, sref) && sref.start == dv.address) {
            r.is_string = 1;
            DataBuffer buf = bv->ReadBuffer(sref.start, sref.length);
            r.value_repr = std::string(reinterpret_cast<const char*>(buf.GetData()),
                                       buf.GetLength());
        } else if (r.has_type && r.size >= 1 && r.size <= 8 &&
                   data_is_initialized(bv, dv.address)) {
            DataBuffer buf = bv->ReadBuffer(dv.address, static_cast<size_t>(r.size));
            if (buf.GetLength() == static_cast<size_t>(r.size)) {
                uint64_t v = 0;
                const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.GetData());
                if (bv->GetDefaultEndianness() == BigEndian) {
                    for (int64_t i = 0; i < r.size; ++i)
                        v = (v << 8) | p[i];
                } else {
                    for (int64_t i = r.size - 1; i >= 0; --i)
                        v = (v << 8) | p[i];
                }
                char tmp[32];
                std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)v);
                r.value_repr = tmp;
            }
        }

        r.segment_name = section_name_at(bv, dv.address);
        r.is_initialized = data_is_initialized(bv, dv.address);
        out.push_back(std::move(r));
    }
}

}  // namespace

CachedTableDef<DataItemInfo> define_data_items() {
    return cached_table<DataItemInfo>("data_items")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetDataVariables().size() : 0;
        })
        .cache_builder([](std::vector<DataItemInfo>& cache) {
            collect_data_items(cache);
        })
        // Canonical order: addr, name, data_type, size, value_repr,
        // segment_name, is_string, is_initialized.
        .column_int64("addr",
                      [](const DataItemInfo& r) -> int64_t {
                          return static_cast<int64_t>(r.addr);
                      })
        .column("name", xsql::ColumnType::Text,
                [](xsql::FunctionContext& ctx, const DataItemInfo& r) {
                    if (r.name.empty()) ctx.result_null();
                    else ctx.result_text(r.name);
                })
        .column("data_type", xsql::ColumnType::Text,
                [](xsql::FunctionContext& ctx, const DataItemInfo& r) {
                    if (!r.has_type || r.data_type.empty()) ctx.result_null();
                    else ctx.result_text(r.data_type);
                })
        .column("size", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const DataItemInfo& r) {
                    if (!r.has_type) ctx.result_null();
                    else ctx.result_int64(r.size);
                })
        .column("value_repr", xsql::ColumnType::Text,
                [](xsql::FunctionContext& ctx, const DataItemInfo& r) {
                    if (r.value_repr.empty()) ctx.result_null();
                    else ctx.result_text(r.value_repr);
                })
        .column("segment_name", xsql::ColumnType::Text,
                [](xsql::FunctionContext& ctx, const DataItemInfo& r) {
                    if (r.segment_name.empty()) ctx.result_null();
                    else ctx.result_text(r.segment_name);
                })
        .column_int("is_string",
                    [](const DataItemInfo& r) -> int { return r.is_string; })
        .column_int("is_initialized",
                    [](const DataItemInfo& r) -> int { return r.is_initialized; })
        .build();
}

} // namespace code
} // namespace bnsql
