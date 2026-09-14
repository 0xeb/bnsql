// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_func_signatures.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

std::string calling_convention_name(const Ref<Function>& func, const Ref<Type>& func_type) {
    if (!func) return "";

    // Try getting the calling convention object first
    auto cc = func->GetCallingConvention();
    if (!(!cc)) {
        return cc->GetName();
    }

    // Fall back to the type's calling convention
    if (func_type) {
        auto cc_name = func_type->GetCallingConvention();
        if (!(!cc_name)) {
            return cc_name->GetName();
        }
    }

    return "";
}
void collect_func_signature(std::vector<FuncSignatureInfo>& out, const Ref<Function>& func) {
    if (!func) return;

    auto func_type = func->GetType();
    if (!func_type) return;

    uint64_t func_addr = func->GetStart();
    std::string cc = calling_convention_name(func, func_type);

    // Return type
    auto ret_type = func_type->GetChildType();
    std::string ret_str = (!ret_type) ? "void" : ret_type->GetString();

    // Return type row (arg_index = -1)
    FuncSignatureInfo ret_row;
    ret_row.func_addr = func_addr;
    ret_row.arg_index = -1;
    ret_row.arg_name = "";
    ret_row.arg_type = "";
    ret_row.return_type = ret_str;
    ret_row.calling_conv = cc;
    out.push_back(std::move(ret_row));

    // Parameters
    auto params = func_type->GetParameters();
    for (size_t i = 0; i < params.size(); ++i) {
        FuncSignatureInfo pi;
        pi.func_addr = func_addr;
        pi.arg_index = static_cast<int>(i);
        pi.arg_name = params[i].name;
        pi.arg_type = (!params[i].type) ? "" : params[i].type->GetString();
        pi.return_type = ret_str;
        pi.calling_conv = cc;
        out.push_back(std::move(pi));
    }
}
class FuncSigIterator : public xsql::RowIterator {
    std::vector<FuncSignatureInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit FuncSigIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;

        uint64_t func_addr = static_cast<uint64_t>(addr);
        auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
        if (!funcs.empty()) {
            collect_func_signature(rows_, funcs[0]);
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            pos_ = 0;
        } else {
            pos_++;
        }
        return pos_ < rows_.size();
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 1: ctx.result_int(r.arg_index); break;
            case 2: ctx.result_text(r.arg_name); break;
            case 3: ctx.result_text(r.arg_type); break;
            case 4: ctx.result_text(r.return_type); break;
            case 5: ctx.result_text(r.calling_conv); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};
CachedTableDef<FuncSignatureInfo> define_func_signatures() {
    return cached_table<FuncSignatureInfo>("func_signatures")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~4 rows per function (return + ~3 params)
            return bv->GetAnalysisFunctionList().size() * 4;
        })
        .cache_builder([](std::vector<FuncSignatureInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_func_signature(cache, func);
            }
        })
        .column_int64("func_addr", [](const FuncSignatureInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("arg_index", [](const FuncSignatureInfo& r) -> int {
            return r.arg_index;
        })
        .column_text("arg_name", [](const FuncSignatureInfo& r) -> std::string {
            return r.arg_name;
        })
        .column_text("arg_type", [](const FuncSignatureInfo& r) -> std::string {
            return r.arg_type;
        })
        .column_text("return_type", [](const FuncSignatureInfo& r) -> std::string {
            return r.return_type;
        })
        .column_text("calling_conv", [](const FuncSignatureInfo& r) -> std::string {
            return r.calling_conv;
        })
        // Direct source filter: single-function query bypasses cache
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncSigIterator>(addr);
        }, 0.5, 5.0)  // cost=0.5, estimated_rows=5
        .index_on("func_addr", [](const FuncSignatureInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace types
} // namespace bnsql
