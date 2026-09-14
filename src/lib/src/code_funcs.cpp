// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_funcs.hpp"

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

bool parse_function_type_decl(
    const Ref<BinaryView>& bv,
    const std::string& decl,
    const std::string& fallback_name,
    Ref<Type>& out_type)
{
    if (!bv || decl.empty()) return false;

    auto try_parse = [&](const std::string& text) -> bool {
        QualifiedNameAndType parsed;
        std::string errors;
        if (!bv->ParseTypeString(text, parsed, errors)) return false;
        if (!parsed.type || parsed.type->GetClass() != FunctionTypeClass) return false;
        out_type = parsed.type;
        return true;
    };

    if (try_parse(decl)) return true;
    if (try_parse(decl + ";")) return true;

    // If declaration is missing a name (e.g. "int(void)"), inject one.
    auto lparen = decl.find('(');
    if (lparen != std::string::npos && !fallback_name.empty()) {
        std::string with_name = decl.substr(0, lparen) + " " + fallback_name + decl.substr(lparen);
        if (try_parse(with_name)) return true;
        if (try_parse(with_name + ";")) return true;
    }

    return false;
}

// Materialize one FuncInfo from a live analysis function. Shared by the
// cache_builder (full scan), the addr filter iterator, and row_lookup so every
// path emits byte-identical column values (value parity across pushdown paths).
static FuncInfo build_func_info(const Ref<Function>& func) {
    FuncInfo fi;
    if (!func) return fi;
    fi.start = func->GetStart();
    auto sym = func->GetSymbol();
    fi.name = sym ? sym->GetFullName() : "";
    auto type = func->GetType();
    fi.prototype = type ? type->GetString() : "";
    fi.comment = func->GetComment();

    // Finding #3: a true code-byte count (sum of the function's address ranges)
    // and an EXCLUSIVE end (max range end), matching the blocks table's
    // BasicBlock::GetEnd convention. GetHighestAddress() is an inclusive,
    // gap-ignoring last address and overstated size for chunked functions.
    uint64_t end = fi.start;
    int64_t total = 0;
    for (const auto& range : func->GetAddressRanges()) {
        if (range.end > range.start)
            total += static_cast<int64_t>(range.end - range.start);
        if (range.end > end)
            end = range.end;
    }
    fi.size = total;
    fi.end_addr = end;
    return fi;
}

// Resolve the live function whose ENTRY is `addr`. GetAnalysisFunctionsForAddress
// returns functions defined (starting) AT addr, so every hit already starts here;
// require GetStart()==addr defensively and take the first match. Writable setters,
// row_lookup, and DELETE resolve by address (never by list ordinal) so deleting
// one function never mis-targets another whose ordinal shifted.
static Ref<Function> resolve_func_at(const Ref<BinaryView>& bv, uint64_t addr) {
    if (!bv) return nullptr;
    for (auto& func : bv->GetAnalysisFunctionsForAddress(addr)) {
        if (func && func->GetStart() == addr) return func;
    }
    return nullptr;
}

// Iterator for `WHERE addr = X` pushdown: a targeted GetAnalysisFunctionsForAddress
// map lookup instead of a whole-binary function-list walk. Emits one row per
// function starting at addr (matching full-scan semantics under omit=1) and a
// rowid == the start address, identical to the table's rowid_fn so an UPDATE/DELETE
// routed through this filter resolves the same row via row_lookup(addr).
class FuncByAddrIterator : public xsql::RowIterator {
    std::vector<FuncInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit FuncByAddrIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;
        for (auto& func : bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr))) {
            if (func) rows_.push_back(build_func_info(func));
        }
    }

    bool next() override {
        if (!started_) { started_ = true; pos_ = 0; }
        else { pos_++; }
        return pos_ < rows_.size();
    }

    bool eof() const override {
        return !started_ || pos_ >= rows_.size();
    }

    // Column order MUST match define_funcs() below:
    // 0 addr, 1 name, 2 prototype, 3 size, 4 end_addr, 5 flags, 6 comment
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.start)); break;
            case 1: ctx.result_text(r.name); break;
            case 2: ctx.result_text(r.prototype); break;
            case 3: ctx.result_int64(r.size); break;
            case 4: ctx.result_int64(static_cast<int64_t>(r.end_addr)); break;
            case 5: ctx.result_int64(0); break;  // flags: BN has no direct func flags
            case 6: ctx.result_text(r.comment); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return pos_ < rows_.size() ? static_cast<int64_t>(rows_[pos_].start) : 0;
    }
};

// The funcs.prototype setter marks each edited function dirty (Reanalyze) but DEFERS
// the one expensive global UpdateAnalysisAndWait() to this commit hook, so a multi-row
// `UPDATE funcs SET prototype` flushes analysis ONCE instead of once per row (O(N)->O(1)).
// Thread-local: HTTP worker threads run a setter and its statement's xCommit on the
// same thread. UpdateAnalysisAndWait() is a cheap no-op when nothing is dirty.
static thread_local bool g_funcs_reflect_pending = false;

CachedTableDef<FuncInfo> define_funcs() {
    auto builder = cached_table<FuncInfo>("funcs");
    builder
        // MUST opt out of the cross-query shared cache: funcs is writable (rename/
        // prototype/comment/DELETE/INSERT mutate live BN state), so a persistent
        // cache would go stale after a mutation. Rebuilt per query, like blocks.
        .no_shared_cache();
    persistence::install_commit_hook(builder, []() {
        if (!g_funcs_reflect_pending) return;  // no prototype edit pending
        g_funcs_reflect_pending = false;
        auto bv = get_bv();
        if (bv) bv->UpdateAnalysisAndWait();
    });
    return builder
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() : 0;
        })
        .row_count([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() : 0;
        })
        // Snapshot the function list ONCE per query into a flat vector — the O(N)
        // fix for the former O(N^2) per-cell GetAnalysisFunctionList() rebuilds.
        .cache_builder([](std::vector<FuncInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;
            auto funcs = bv->GetAnalysisFunctionList();
            cache.reserve(funcs.size());
            for (auto& func : funcs) {
                if (func) cache.push_back(build_func_info(func));
            }
        })
        // Stable rowid = the function's start address, matching the `addr` column.
        // Full-scan, index, and filter cursors all report this address-keyed rowid,
        // so a multi-row UPDATE/DELETE resolves each row by its own address and
        // deleting one function never shifts another's rowid. row_lookup resolves
        // the rowid back to the live function by address (not by ordinal).
        .rowid([](const FuncInfo& row) -> int64_t {
            return static_cast<int64_t>(row.start);
        })
        .row_lookup([](FuncInfo& row, int64_t rowid) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto func = resolve_func_at(bv, static_cast<uint64_t>(rowid));
            if (!func) return false;
            row = build_func_info(func);
            return true;
        })
        .column_int64("addr", [](const FuncInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start);
        })
        .column_text_rw("name",
            // Getter
            [](const FuncInfo& r) -> std::string {
                return r.name;
            },
            // Setter - rename function (resolve the live func by address)
            [](FuncInfo& r, const char* new_name) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string requested = new_name ? new_name : "";
                if (requested.empty()) {
                    xsql::set_vtab_error("Function name cannot be empty");
                    return false;
                }
                auto func = resolve_func_at(bv, r.start);
                if (!func) return false;
                auto existing_sym = func->GetSymbol();
                std::string existing_name = existing_sym ? existing_sym->GetFullName() : "";
                if (!existing_name.empty() && requested == existing_name) {
                    return true;
                }
                // Create user symbol at function start
                auto sym = new Symbol(FunctionSymbol, requested, func->GetStart());
                bv->DefineUserSymbol(sym);
                r.name = requested;
                return true;
            })
        .column_text_rw("prototype",
            // Getter
            [](const FuncInfo& r) -> std::string {
                return r.prototype;
            },
            // Setter - apply user function prototype (resolve live func by address)
            [](FuncInfo& r, const char* new_proto) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto func = resolve_func_at(bv, r.start);
                if (!func) return false;

                std::string proto = new_proto ? new_proto : "";
                auto current_type = func->GetType();
                std::string current_proto = current_type ? current_type->GetString() : "";
                if (proto == current_proto) return true;

                if (proto.empty()) {
                    xsql::set_vtab_error("Clearing function prototype is not supported");
                    return false;
                }

                auto sym = func->GetSymbol();
                std::string fallback_name = sym ? sym->GetFullName() : "";

                Ref<Type> parsed_type;
                if (!parse_function_type_decl(bv, proto, fallback_name, parsed_type) || !parsed_type) {
                    xsql::set_vtab_error("Failed to parse prototype: " + proto);
                    return false;
                }

                func->SetUserType(parsed_type);
                // SetUserType only records a PENDING user type override: the
                // effective type (func->GetType(), read by the funcs rebuild and by
                // func_signatures) and the HLIL do not update until analysis re-runs.
                // Headless nothing re-runs it, so without this the write is a silent
                // no-op in-session (the type only surfaced after save+reopen). Force
                // the same reanalysis the decompile(addr, refresh=1) path uses
                // (decompiler.cpp) so the applied prototype reflects immediately in
                // this session (funcs.prototype, func_signatures, and re-decompile).
                func->Reanalyze(BNFunctionUpdateType::UserFunctionUpdate);
                // Defer the expensive global UpdateAnalysisAndWait() to the commit
                // hook (above) so a multi-row UPDATE flushes ONCE, not once per row.
                // Reanalyze() only marks this function dirty. Reflect the requested
                // prototype immediately; the normalized post-analysis form appears on
                // the next read after the statement commits and the hook flushes.
                g_funcs_reflect_pending = true;
                r.prototype = parsed_type->GetString();
                return true;
            })
        .column_int64("size", [](const FuncInfo& r) -> int64_t {
            return r.size;
        })
        .column_int64("end_addr", [](const FuncInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_addr);
        })
        .column_int64("flags", [](const FuncInfo&) -> int64_t {
            // BN doesn't have direct function flags like IDA
            // Return 0 for now, could map analysis flags later
            return 0;
        })
        .column_text_rw("comment",
            // Getter - function-level comment
            [](const FuncInfo& r) -> std::string {
                return r.comment;
            },
            // Setter - function-level comment (resolve live func by address)
            [](FuncInfo& r, const char* new_comment) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto func = resolve_func_at(bv, r.start);
                if (!func) return false;

                std::string updated_comment = new_comment ? new_comment : "";
                if (updated_comment == func->GetComment()) {
                    return true;
                }

                func->SetComment(updated_comment);
                r.comment = updated_comment;
                return true;
            })
        // WHERE addr = X pushdown: targeted address lookup instead of a full walk.
        .filter_eq("addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncByAddrIterator>(addr);
        }, 0.5, 1.0)  // cost=0.5, ~1 function per address
        .index_on("addr", [](const FuncInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start);
        })
        // DELETE support - remove function from analysis (resolve live func by address)
        .deletable([](FuncInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto func = resolve_func_at(bv, r.start);
            if (!func) return false;
            bv->RemoveUserFunction(func);
            return true;
        })
        // INSERT support - create new function at address
        // INSERT INTO funcs (addr, name) VALUES (0x1234, 'my_func')
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;

            // Column order: addr, name, prototype, size, end_addr, flags, comment
            // We need at least addr (column 0)
            if (argc < 1) return false;

            // Get address from first column
            if (argv[0].is_null()) return false;
            uint64_t address = static_cast<uint64_t>(argv[0].as_int64());

            // Create user function at address
            auto platform = bv->GetDefaultPlatform();
            if (!platform) return false;

            auto func = bv->CreateUserFunction(platform, address);
            if (!func) return false;

            // If name is provided (column 1), set it.
            std::string assigned_name;
            if (argc >= 2 && !argv[1].is_null()) {
                const char* name = argv[1].as_c_str();
                if (name && name[0]) {
                    assigned_name = name;
                    auto sym = new Symbol(FunctionSymbol, name, address);
                    bv->DefineUserSymbol(sym);
                }
            }

            // If prototype is provided (column 2), apply it.
            if (argc >= 3 && !argv[2].is_null()) {
                const char* proto = argv[2].as_c_str();
                if (proto && proto[0]) {
                    Ref<Type> parsed_type;
                    if (!parse_function_type_decl(bv, proto, assigned_name, parsed_type) || !parsed_type) {
                        bv->RemoveUserFunction(func);
                        if (!assigned_name.empty()) {
                            bv->UndefineUserSymbol(Ref<Symbol>(new Symbol(FunctionSymbol, assigned_name, address)));
                        }
                        return false;
                    }
                    func->SetUserType(parsed_type);
                }
            }

            // If comment is provided (column 6), apply it as function-level comment.
            if (argc >= 7 && !argv[6].is_null()) {
                const char* comment = argv[6].as_c_str();
                func->SetComment(comment ? comment : "");
            }

            return true;
        })
        .build();
}

} // namespace code
} // namespace bnsql
