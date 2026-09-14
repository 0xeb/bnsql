// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_strings.hpp"

namespace bnsql {
namespace memory {

using namespace BinaryNinja;
using core::get_bv;

// Build a StringInfo row from a BN string reference (shared by the full-scan
// cache builder and the single-address filter iterator, so both agree).
static StringInfo make_string_info(const Ref<BinaryView>& bv, const BNStringReference& s) {
    StringInfo si;
    si.address = s.start;
    si.length = s.length;
    si.type = static_cast<int>(s.type);
    switch (s.type) {
        case AsciiString: si.type_name = "ascii"; break;
        case Utf16String: si.type_name = "utf16"; break;
        case Utf32String: si.type_name = "utf32"; break;
        default: si.type_name = "unknown"; break;
    }
    DataBuffer buf = bv->ReadBuffer(s.start, s.length);
    si.content = std::string(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());
    return si;
}

// Iterator for `strings WHERE addr = X`: the single string starting at X. Keeps
// the string_refs JOIN (xrefs.to_addr = strings.addr) fast when query-scoped
// (index_on is disabled for a per-cursor cache). Column order MUST match
// define_strings() below (value-parity guarded).
class StringAtAddrIterator : public xsql::RowIterator {
    std::vector<StringInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit StringAtAddrIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        BNStringReference sref;
        if (bv->GetStringAtAddress(static_cast<uint64_t>(addr), sref) &&
            sref.start == static_cast<uint64_t>(addr)) {
            rows_.push_back(make_string_info(bv, sref));
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }
    bool eof() const override { return !started_ || pos_ >= rows_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& s = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(s.address)); break;
            case 1: ctx.result_int(static_cast<int>(s.length)); break;
            case 2: ctx.result_int(s.type); break;
            case 3: ctx.result_text(s.type_name); break;
            case 4: ctx.result_text(s.content); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

CachedTableDef<StringInfo> define_strings() {
    return cached_table<StringInfo>("strings")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetStrings().size() : 0;
        })
        .cache_builder([](std::vector<StringInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto strs = bv->GetStrings();
            cache.reserve(strs.size());
            for (const auto& s : strs) {
                cache.push_back(make_string_info(bv, s));
            }
        })
        .column_int64("addr", [](const StringInfo& s) -> int64_t {
            return static_cast<int64_t>(s.address);
        })
        .column_int("length", [](const StringInfo& s) -> int {
            return static_cast<int>(s.length);
        })
        .column_int("type", [](const StringInfo& s) -> int {
            return s.type;
        })
        .column_text("type_name", [](const StringInfo& s) -> std::string {
            return s.type_name;
        })
        .column_text("content", [](const StringInfo& s) -> std::string {
            return s.content;
        })
        // Single-address lookup keeps string_refs JOINs (xrefs.to_addr =
        // strings.addr) fast when query-scoped.
        .filter_eq("addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<StringAtAddrIterator>(addr);
        }, 0.5, 1.0)
        .index_on("addr", [](const StringInfo& s) -> int64_t {
            return static_cast<int64_t>(s.address);
        })
        .build();
}

} // namespace memory
} // namespace bnsql
