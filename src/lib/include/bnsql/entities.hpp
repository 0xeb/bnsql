// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * entities.hpp - Binary Ninja entity definitions for SQLite virtual tables
 *
 * Defines all BN entities as virtual tables using the xsql framework.
 * Schema is designed to be compatible with idasql wherever possible.
 *
 * Tables:
 *   entities   - Unified discovery surface (functions/symbols/segments/imports/strings)
 *   funcs      - Functions
 *   segments   - Memory segments
 *   names      - Symbols (named locations)
 *   entries    - Entry points (exports)
 *   imports    - Imported functions
 *   strings    - String literals
 *   xrefs      - Cross-references
 *   blocks     - Basic blocks
 *   instructions - Disassembled instructions
 *   comments   - Address comments
 */

#pragma once

#include <bnsql/vtable.hpp>
#include <bnsql/bytes_table.hpp>
#include <bnsql/persistence.hpp>
#include <xsql/database.hpp>
#include <algorithm>
#include <unordered_map>
#include <vector>

// Binary Ninja API
#include "binaryninjaapi.h"

namespace bnsql {
namespace entities {

using namespace BinaryNinja;

// ============================================================================
// Context: Holds BinaryView for all table operations
// ============================================================================

struct BNContext {
    Ref<BinaryView> bv;

    explicit BNContext(Ref<BinaryView> view) : bv(std::move(view)) {}
};

// Thread-local context for current binary view
inline thread_local BNContext* g_context = nullptr;

inline void set_context(BNContext* ctx) { g_context = ctx; }
inline BNContext* get_context() { return g_context; }
inline Ref<BinaryView> get_bv() { return g_context ? g_context->bv : nullptr; }

// ============================================================================
// FUNCS Table - Functions
// Schema: address, name, prototype, size, end_ea, flags, comment
// Compatible with idasql funcs table
// Supports: SELECT, UPDATE (name/prototype/comment), DELETE, INSERT
// ============================================================================

inline bool parse_function_type_decl(
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

inline VTableDef define_funcs() {
    return table("funcs")
        .count([]() {
            auto bv = get_bv();
            return bv ? bv->GetAnalysisFunctionList().size() : 0;
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto funcs = bv->GetAnalysisFunctionList();
            if (i >= funcs.size()) return 0;
            return static_cast<int64_t>(funcs[i]->GetStart());
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                auto bv = get_bv();
                if (!bv) return "";
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return "";
                auto sym = funcs[i]->GetSymbol();
                return sym ? sym->GetFullName() : "";
            },
            // Setter - rename function
            [](size_t i, const char* new_name) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string requested = new_name ? new_name : "";
                if (requested.empty()) {
                    xsql::set_vtab_error("Function name cannot be empty");
                    return false;
                }
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return false;
                auto func = funcs[i];
                auto existing_sym = func->GetSymbol();
                std::string existing_name = existing_sym ? existing_sym->GetFullName() : "";
                if (!existing_name.empty() && requested == existing_name) {
                    return true;
                }
                // Create user symbol at function start
                auto sym = new Symbol(FunctionSymbol, requested, func->GetStart());
                bv->DefineUserSymbol(sym);
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        .column_text_rw("prototype",
            // Getter
            [](size_t i) -> std::string {
                auto bv = get_bv();
                if (!bv) return "";
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return "";
                auto type = funcs[i]->GetType();
                return type ? type->GetString() : "";
            },
            // Setter - apply user function prototype
            [](size_t i, const char* new_proto) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return false;

                auto func = funcs[i];
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
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        .column_int64("size", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto funcs = bv->GetAnalysisFunctionList();
            if (i >= funcs.size()) return 0;
            auto func = funcs[i];
            return static_cast<int64_t>(func->GetHighestAddress() - func->GetStart());
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto funcs = bv->GetAnalysisFunctionList();
            if (i >= funcs.size()) return 0;
            return static_cast<int64_t>(funcs[i]->GetHighestAddress());
        })
        .column_int64("flags", [](size_t i) -> int64_t {
            // BN doesn't have direct function flags like IDA
            // Return 0 for now, could map analysis flags later
            return 0;
        })
        .column_text_rw("comment",
            // Getter - function-level comment
            [](size_t i) -> std::string {
                auto bv = get_bv();
                if (!bv) return "";
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return "";
                return funcs[i]->GetComment();
            },
            // Setter - function-level comment
            [](size_t i, const char* new_comment) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return false;

                auto func = funcs[i];
                std::string updated_comment = new_comment ? new_comment : "";
                if (updated_comment == func->GetComment()) {
                    return true;
                }

                func->SetComment(updated_comment);
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        // DELETE support - remove function from analysis
        .deletable([](size_t i) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto funcs = bv->GetAnalysisFunctionList();
            if (i >= funcs.size()) return false;
            auto func = funcs[i];
            bv->RemoveUserFunction(func);
            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        // INSERT support - create new function at address
        // INSERT INTO funcs (address, name) VALUES (0x1234, 'my_func')
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;

            // Column order: address, name, prototype, size, end_ea, flags, comment
            // We need at least address (column 0)
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

            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        .build();
}

// ============================================================================
// SEGMENTS Table - Memory segments
// Schema: start_ea, end_ea, name, class, perm
// Compatible with idasql segments table
// ============================================================================

inline VTableDef define_segments() {
    return table("segments")
        .count([]() {
            auto bv = get_bv();
            return bv ? bv->GetSegments().size() : 0;
        })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return 0;
            return static_cast<int64_t>(segs[i]->GetStart());
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return 0;
            return static_cast<int64_t>(segs[i]->GetEnd());
        })
        .column_text("name", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return "";
            // Segments don't have names in BN, use address-based name
            char buf[32];
            snprintf(buf, sizeof(buf), "seg_%llx", (unsigned long long)segs[i]->GetStart());
            return buf;
        })
        .column_text("class", [](size_t i) -> std::string {
            // Map BN segment flags to IDA-style class names
            auto bv = get_bv();
            if (!bv) return "";
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return "";
            uint32_t flags = segs[i]->GetFlags();
            if (flags & SegmentExecutable) return "CODE";
            if (flags & SegmentWritable) return "DATA";
            return "DATA";
        })
        .column_int("perm", [](size_t i) -> int {
            // Return permissions as R/W/X bits
            auto bv = get_bv();
            if (!bv) return 0;
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return 0;
            uint32_t flags = segs[i]->GetFlags();
            int perm = 0;
            if (flags & SegmentReadable) perm |= 4;   // R
            if (flags & SegmentWritable) perm |= 2;   // W
            if (flags & SegmentExecutable) perm |= 1; // X
            return perm;
        })
        .build();
}

// ============================================================================
// NAMES Table - Symbols
// Schema: address, name, is_public, is_weak
// Compatible with idasql names table
// ============================================================================

inline VTableDef define_names() {
    return table("names")
        .count([]() {
            auto bv = get_bv();
            return bv ? bv->GetSymbols().size() : 0;
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto syms = bv->GetSymbols();
            if (i >= syms.size()) return 0;
            return static_cast<int64_t>(syms[i]->GetAddress());
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                auto bv = get_bv();
                if (!bv) return "";
                auto syms = bv->GetSymbols();
                if (i >= syms.size()) return "";
                return syms[i]->GetFullName();
            },
            // Setter
            [](size_t i, const char* new_name) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                if (!new_name || !new_name[0]) {
                    xsql::set_vtab_error("Symbol name cannot be empty");
                    return false;
                }
                auto syms = bv->GetSymbols();
                if (i >= syms.size()) return false;
                auto old_sym = syms[i];
                auto new_sym = new Symbol(old_sym->GetType(), new_name, old_sym->GetAddress());
                bv->DefineUserSymbol(new_sym);
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        .column_int("is_public", [](size_t i) -> int {
            auto bv = get_bv();
            if (!bv) return 0;
            auto syms = bv->GetSymbols();
            if (i >= syms.size()) return 0;
            // Consider exported symbols as public
            auto binding = syms[i]->GetBinding();
            return (binding == GlobalBinding) ? 1 : 0;
        })
        .column_int("is_weak", [](size_t i) -> int {
            auto bv = get_bv();
            if (!bv) return 0;
            auto syms = bv->GetSymbols();
            if (i >= syms.size()) return 0;
            auto binding = syms[i]->GetBinding();
            return (binding == WeakBinding) ? 1 : 0;
        })
        .deletable([](size_t i) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto syms = bv->GetSymbols();
            if (i >= syms.size()) return false;

            auto sym = syms[i];
            if (sym->IsAutoDefined()) {
                bv->UndefineAutoSymbol(sym);
            } else {
                bv->UndefineUserSymbol(sym);
            }
            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (argc < 2) return false;
            if (argv[0].is_null() || argv[1].is_null()) {
                xsql::set_vtab_error("names insert requires address and name");
                return false;
            }

            uint64_t address = static_cast<uint64_t>(argv[0].as_int64());
            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) {
                xsql::set_vtab_error("Symbol name cannot be empty");
                return false;
            }

            auto funcs = bv->GetAnalysisFunctionsForAddress(address);
            BNSymbolType sym_type = DataSymbol;
            if (!funcs.empty() && funcs[0]->GetStart() == address) {
                sym_type = FunctionSymbol;
            }

            auto sym = new Symbol(sym_type, name, address);
            bv->DefineUserSymbol(sym);
            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        .build();
}

// ============================================================================
// ENTRIES Table - Entry points / exports
// Schema: ordinal, address, name
// Compatible with idasql entries table
// ============================================================================

inline VTableDef define_entries() {
    return table("entries")
        .count([]() {
            auto bv = get_bv();
            if (!bv) return size_t(0);
            // Entry points include the main entry and exported functions
            size_t count = 0;
            if (bv->GetEntryPoint() != 0) count++;
            // Add exported symbols
            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetBinding() == GlobalBinding &&
                    sym->GetType() == FunctionSymbol) {
                    count++;
                }
            }
            return count;
        })
        .column_int64("ordinal", [](size_t i) -> int64_t {
            return static_cast<int64_t>(i);
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // First entry is the main entry point
            if (i == 0 && bv->GetEntryPoint() != 0) {
                return static_cast<int64_t>(bv->GetEntryPoint());
            }
            // Rest are exported functions
            size_t idx = (bv->GetEntryPoint() != 0) ? i - 1 : i;
            size_t count = 0;
            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetBinding() == GlobalBinding &&
                    sym->GetType() == FunctionSymbol) {
                    if (count == idx) {
                        return static_cast<int64_t>(sym->GetAddress());
                    }
                    count++;
                }
            }
            return 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";
            if (i == 0 && bv->GetEntryPoint() != 0) {
                auto sym = bv->GetSymbolByAddress(bv->GetEntryPoint());
                return sym ? sym->GetFullName() : "_start";
            }
            size_t idx = (bv->GetEntryPoint() != 0) ? i - 1 : i;
            size_t count = 0;
            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetBinding() == GlobalBinding &&
                    sym->GetType() == FunctionSymbol) {
                    if (count == idx) {
                        return sym->GetFullName();
                    }
                    count++;
                }
            }
            return "";
        })
        .build();
}

// ============================================================================
// STRINGS Table
// Schema: address, length, type, type_name, content
// Compatible with idasql strings table (simplified)
// ============================================================================

// ============================================================================
// STRINGS Table - String literals in binary
// Schema: address, length, type, type_name, content
//
// Cached for efficient JOINs with xrefs (e.g., string_refs view)
// index_on("address") enables hash lookups when joining xrefs.to_ea
// ============================================================================

struct StringInfo {
    uint64_t address;
    size_t length;
    int type;
    std::string type_name;
    std::string content;
};

inline CachedTableDef<StringInfo> define_strings() {
    return cached_table<StringInfo>("strings")
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

                // Read string content from binary
                DataBuffer buf = bv->ReadBuffer(s.start, s.length);
                si.content = std::string(
                    reinterpret_cast<const char*>(buf.GetData()),
                    buf.GetLength()
                );

                cache.push_back(std::move(si));
            }
        })
        .column_int64("address", [](const StringInfo& s) -> int64_t {
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
        // Index on address for efficient JOINs with xrefs.to_ea
        .index_on("address", [](const StringInfo& s) -> int64_t {
            return static_cast<int64_t>(s.address);
        })
        .build();
}

// ============================================================================
// XREFS Table - Cross-references
// Schema: from_ea, to_ea, from_func, type, is_code
// from_func is pre-computed at load time for fast caller/callee queries
//
// Optimization: filter_eq("to_ea", ...) uses BN's GetCodeReferences(addr)
// directly, bypassing cache for O(1) lookup. This is critical for JOINs.
// ============================================================================

struct XrefInfo {
    uint64_t from_ea;
    uint64_t to_ea;
    uint64_t from_func;  // Pre-computed: function containing from_ea (0 if none)
    int type;
    bool is_code;
};

/**
 * Iterator for xrefs TO a specific address.
 *
 * Uses BN's GetCodeReferences(addr) directly instead of scanning a cache.
 * This is O(1) in BN's internal xref database.
 */
class XrefsToIterator : public xsql::RowIterator {
    Ref<BinaryView> bv_;
    uint64_t target_;
    std::vector<ReferenceSource> refs_;
    size_t pos_ = 0;
    bool started_ = false;

    // Cached current row
    XrefInfo current_;

public:
    explicit XrefsToIterator(int64_t target) : target_(static_cast<uint64_t>(target)) {
        bv_ = get_bv();
        if (bv_) {
            refs_ = bv_->GetCodeReferences(target_);
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            pos_ = 0;
        } else {
            pos_++;
        }

        if (pos_ >= refs_.size()) {
            return false;
        }

        // Build current row
        const auto& ref = refs_[pos_];
        current_.from_ea = ref.addr;
        current_.to_ea = target_;
        current_.type = 0;  // Code reference
        current_.is_code = true;

        // Compute from_func (containing function)
        current_.from_func = 0;
        if (bv_) {
            auto funcs = bv_->GetAnalysisFunctionsContainingAddress(ref.addr);
            if (!funcs.empty()) {
                current_.from_func = funcs[0]->GetStart();
            }
        }

        return true;
    }

    bool eof() const override {
        return !started_ || pos_ >= refs_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        switch (col) {
            case 0: // from_ea
                ctx.result_int64(static_cast<int64_t>(current_.from_ea));
                break;
            case 1: // to_ea
                ctx.result_int64(static_cast<int64_t>(current_.to_ea));
                break;
            case 2: // from_func
                ctx.result_int64(current_.from_func ? static_cast<int64_t>(current_.from_func) : 0);
                break;
            case 3: // type
                ctx.result_int(current_.type);
                break;
            case 4: // is_code
                ctx.result_int(current_.is_code ? 1 : 0);
                break;
            default:
                ctx.result_null();
                break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

inline CachedTableDef<XrefInfo> define_xrefs() {
    return cached_table<XrefInfo>("xrefs")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~10 xrefs per function
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<XrefInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            // Helper to get containing function address (0 if none)
            auto get_func_addr = [&bv](uint64_t addr) -> uint64_t {
                auto funcs = bv->GetAnalysisFunctionsContainingAddress(addr);
                return funcs.empty() ? 0 : funcs[0]->GetStart();
            };

            // Collect code references from all functions
            for (auto& func : bv->GetAnalysisFunctionList()) {
                uint64_t func_addr = func->GetStart();

                // Xrefs TO this function (callers)
                for (auto& ref : bv->GetCodeReferences(func_addr)) {
                    XrefInfo xi;
                    xi.from_ea = ref.addr;
                    xi.to_ea = func_addr;
                    xi.from_func = get_func_addr(ref.addr);
                    xi.type = 0; // Code call
                    xi.is_code = true;
                    cache.push_back(xi);
                }
            }

            // Also collect data references
            for (auto& seg : bv->GetSegments()) {
                if (seg->GetFlags() & SegmentExecutable) continue;

                uint64_t addr = seg->GetStart();
                uint64_t end = seg->GetEnd();
                while (addr < end) {
                    for (auto& ref : bv->GetCodeReferences(addr)) {
                        XrefInfo xi;
                        xi.from_ea = ref.addr;
                        xi.to_ea = addr;
                        xi.from_func = get_func_addr(ref.addr);
                        xi.type = 1; // Data reference
                        xi.is_code = false;
                        cache.push_back(xi);
                    }
                    addr += bv->GetAddressSize();
                }
            }

            // Collect xrefs to imports (may be in executable sections as thunks)
            for (auto& sym : bv->GetSymbols()) {
                auto type = sym->GetType();
                if (type == ImportedFunctionSymbol ||
                    type == ImportAddressSymbol ||
                    type == ImportedDataSymbol) {
                    uint64_t import_addr = sym->GetAddress();
                    for (auto& ref : bv->GetCodeReferences(import_addr)) {
                        XrefInfo xi;
                        xi.from_ea = ref.addr;
                        xi.to_ea = import_addr;
                        xi.from_func = get_func_addr(ref.addr);
                        xi.type = 2; // Import call
                        xi.is_code = true;
                        cache.push_back(xi);
                    }
                }
            }
        })
        .column_int64("from_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_ea);
        })
        .column_int64("to_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_ea);
        })
        .column_int64("from_func", [](const XrefInfo& r) -> int64_t {
            return r.from_func ? static_cast<int64_t>(r.from_func) : 0;
        })
        .column_int("type", [](const XrefInfo& r) -> int {
            return r.type;
        })
        .column_int("is_code", [](const XrefInfo& r) -> int {
            return r.is_code ? 1 : 0;
        })
        // Direct source filter: bypass cache and query BN API directly
        // Cost 0.5 ensures this is preferred over index_on (cost 1.0)
        .filter_eq("to_ea", [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(target);
        }, 0.5, 5.0)  // cost=0.5, estimated_rows=5
        // Indexes for full-scan JOINs (fallback when filter_eq not applicable)
        .index_on("to_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_ea);
        })
        .index_on("from_func", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_func);
        })
        .build();
}

// ============================================================================
// BLOCKS Table - Basic blocks
// Schema: func_ea, start_ea, end_ea, size
// Compatible with idasql blocks table
// ============================================================================

struct BlockInfo {
    uint64_t func_ea;
    uint64_t start_ea;
    uint64_t end_ea;
};

inline CachedTableDef<BlockInfo> define_blocks() {
    return cached_table<BlockInfo>("blocks")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            return bv->GetAnalysisFunctionList().size() * 10;
        })
        .cache_builder([](std::vector<BlockInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            for (auto& func : bv->GetAnalysisFunctionList()) {
                for (auto& block : func->GetBasicBlocks()) {
                    BlockInfo bi;
                    bi.func_ea = func->GetStart();
                    bi.start_ea = block->GetStart();
                    bi.end_ea = block->GetEnd();
                    cache.push_back(bi);
                }
            }
        })
        .column_int64("func_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_ea);
        })
        .column_int64("start_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start_ea);
        })
        .column_int64("end_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea);
        })
        .column_int64("size", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea - r.start_ea);
        })
        .build();
}

// ============================================================================
// IMPORTS Table
// Schema: address, name, ordinal, module, module_idx
// Compatible with idasql imports table
// ============================================================================

struct ImportInfo {
    uint64_t address;
    std::string name;
    std::string module;
    int module_idx;
};

inline CachedTableDef<ImportInfo> define_imports() {
    return cached_table<ImportInfo>("imports")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            size_t count = 0;
            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetType() == ImportedFunctionSymbol ||
                    sym->GetType() == ImportAddressSymbol ||
                    sym->GetType() == ImportedDataSymbol) {
                    count++;
                }
            }
            return count;
        })
        .cache_builder([](std::vector<ImportInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            std::map<std::string, int> module_indices;
            int next_idx = 0;

            for (auto& sym : bv->GetSymbols()) {
                if (sym->GetType() == ImportedFunctionSymbol ||
                    sym->GetType() == ImportAddressSymbol ||
                    sym->GetType() == ImportedDataSymbol) {
                    ImportInfo info;
                    info.address = sym->GetAddress();
                    info.name = sym->GetShortName();

                    // Extract module from namespace
                    std::string ns = sym->GetNameSpace().GetString();
                    if (!ns.empty()) {
                        info.module = ns;
                    } else {
                        info.module = "unknown";
                    }

                    // Assign module index
                    auto it = module_indices.find(info.module);
                    if (it == module_indices.end()) {
                        info.module_idx = next_idx;
                        module_indices[info.module] = next_idx++;
                    } else {
                        info.module_idx = it->second;
                    }

                    cache.push_back(info);
                }
            }
        })
        .column_int64("address", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text("name", [](const ImportInfo& r) -> std::string {
            return r.name;
        })
        .column_int64("ordinal", [](const ImportInfo& r) -> int64_t {
            return 0; // BN doesn't expose ordinals directly
        })
        .column_text("module", [](const ImportInfo& r) -> std::string {
            return r.module;
        })
        .column_int("module_idx", [](const ImportInfo& r) -> int {
            return r.module_idx;
        })
        .build();
}

// ============================================================================
// INSTRUCTIONS Table
// Schema: address, itype, mnemonic, size, operand0-2, disasm, func_addr
// Compatible with idasql instructions table
// ============================================================================

struct InsnInfo {
    uint64_t address;
    uint64_t func_addr;
    std::string mnemonic;
    size_t size;
    std::string disasm;
    std::vector<std::string> operands;
};

inline CachedTableDef<InsnInfo> define_instructions() {
    return cached_table<InsnInfo>("instructions")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~20 instructions per function
            return bv->GetAnalysisFunctionList().size() * 20;
        })
        .cache_builder([](std::vector<InsnInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto arch = bv->GetDefaultArchitecture();
            auto settings = DisassemblySettings::GetDefaultSettings();

            for (auto& func : bv->GetAnalysisFunctionList()) {
                for (auto& block : func->GetBasicBlocks()) {
                    // Use BasicBlock::GetDisassemblyText for proper tokens
                    auto lines = block->GetDisassemblyText(settings);

                    for (auto& line : lines) {
                        InsnInfo info;
                        info.address = line.addr;
                        info.func_addr = func->GetStart();

                        // Build mnemonic and full disassembly from tokens
                        std::string disasm;
                        bool past_mnemonic = false;
                        std::string current_op;

                        for (auto& tok : line.tokens) {
                            // Extract mnemonic
                            if (info.mnemonic.empty() &&
                                tok.type == InstructionToken) {
                                info.mnemonic = tok.text;
                            }
                            disasm += tok.text;

                            // Extract operands
                            if (tok.type == InstructionToken) {
                                past_mnemonic = true;
                                continue;
                            }
                            if (!past_mnemonic) continue;

                            if (tok.type == OperandSeparatorToken) {
                                if (!current_op.empty()) {
                                    info.operands.push_back(current_op);
                                    current_op.clear();
                                }
                            } else {
                                current_op += tok.text;
                            }
                        }
                        if (!current_op.empty()) {
                            info.operands.push_back(current_op);
                        }
                        info.disasm = disasm;

                        // Get instruction size
                        if (arch) {
                            info.size = bv->GetInstructionLength(arch, line.addr);
                        }
                        if (info.size == 0) {
                            info.size = 1;  // Default to 1 byte if unknown
                        }

                        cache.push_back(info);
                    }
                }
            }
        })
        .column_int64("address", [](const InsnInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_int("itype", [](const InsnInfo& r) -> int {
            return 0; // BN doesn't have itype equivalent
        })
        .column_text("mnemonic", [](const InsnInfo& r) -> std::string {
            return r.mnemonic;
        })
        .column_int("size", [](const InsnInfo& r) -> int {
            return static_cast<int>(r.size);
        })
        .column_text("operand0", [](const InsnInfo& r) -> std::string {
            return r.operands.size() > 0 ? r.operands[0] : "";
        })
        .column_text("operand1", [](const InsnInfo& r) -> std::string {
            return r.operands.size() > 1 ? r.operands[1] : "";
        })
        .column_text("operand2", [](const InsnInfo& r) -> std::string {
            return r.operands.size() > 2 ? r.operands[2] : "";
        })
        .column_text("disasm", [](const InsnInfo& r) -> std::string {
            return r.disasm;
        })
        .column_int64("func_addr", [](const InsnInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

// ============================================================================
// INSTRUCTION_OPERANDS Table
// Schema: insn_addr, func_addr, operand_index, text, token_type, type_name,
//         value, size
//
// Per-token operand metadata from disassembly tokens.
// filter_eq("func_addr") enables fast single-function queries.
// ============================================================================

struct OperandInfo {
    uint64_t insn_addr;
    uint64_t func_addr;
    int operand_index;
    std::string text;
    int token_type;
    std::string type_name;
    uint64_t value;
    int size;
};

inline std::string token_type_name(int type) {
    switch (type) {
        case TextToken:              return "text";
        case InstructionToken:       return "instruction";
        case OperandSeparatorToken:  return "separator";
        case RegisterToken:          return "register";
        case IntegerToken:           return "integer";
        case PossibleAddressToken:   return "address";
        case BeginMemoryOperandToken: return "memory_start";
        case EndMemoryOperandToken:  return "memory_end";
        case FloatingPointToken:     return "float";
        case AnnotationToken:        return "annotation";
        case CodeRelativeAddressToken: return "code_address";
        case ArgumentNameToken:      return "argument";
        case OpcodeToken:            return "opcode";
        case StringToken:            return "string";
        case CharacterConstantToken: return "char";
        case KeywordToken:           return "keyword";
        case TypeNameToken:          return "type_name";
        case FieldNameToken:         return "field_name";
        case NameSpaceToken:         return "namespace";
        case StructOffsetToken:      return "struct_offset";
        case GotoLabelToken:         return "goto_label";
        case CommentToken:           return "comment";
        case EnumerationMemberToken: return "enum_member";
        case OperationToken:         return "operation";
        case CodeSymbolToken:        return "code_symbol";
        case DataSymbolToken:        return "data_symbol";
        case LocalVariableToken:     return "local_variable";
        case ImportToken:            return "import";
        case ExternalSymbolToken:    return "external_symbol";
        case StackVariableToken:     return "stack_variable";
        default:                     return "other";
    }
}

/**
 * Iterator for instruction_operands filtered to a single function address.
 * Avoids full cache scan when querying WHERE func_addr = X.
 */
class OperandIterator : public xsql::RowIterator {
    std::vector<OperandInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit OperandIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;

        uint64_t func_addr = static_cast<uint64_t>(addr);
        auto funcs = bv->GetAnalysisFunctionsForAddress(func_addr);
        if (funcs.empty()) return;

        auto func = funcs[0];
        auto settings = DisassemblySettings::GetDefaultSettings();

        for (auto& block : func->GetBasicBlocks()) {
            auto lines = block->GetDisassemblyText(settings);
            for (auto& line : lines) {
                for (auto& tok : line.tokens) {
                    if (tok.operand == BN_INVALID_OPERAND) continue;

                    OperandInfo oi;
                    oi.insn_addr = line.addr;
                    oi.func_addr = func_addr;
                    oi.operand_index = static_cast<int>(tok.operand);
                    oi.text = tok.text;
                    oi.token_type = static_cast<int>(tok.type);
                    oi.type_name = token_type_name(static_cast<int>(tok.type));
                    oi.value = tok.value;
                    oi.size = static_cast<int>(tok.size);
                    rows_.push_back(std::move(oi));
                }
            }
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

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.insn_addr)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 2: ctx.result_int(r.operand_index); break;
            case 3: ctx.result_text(r.text); break;
            case 4: ctx.result_int(r.token_type); break;
            case 5: ctx.result_text(r.type_name); break;
            case 6: ctx.result_int64(static_cast<int64_t>(r.value)); break;
            case 7: ctx.result_int(r.size); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

inline CachedTableDef<OperandInfo> define_instruction_operands() {
    return cached_table<OperandInfo>("instruction_operands")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~3 operand tokens per instruction, ~20 instructions per function
            return bv->GetAnalysisFunctionList().size() * 60;
        })
        .cache_builder([](std::vector<OperandInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto settings = DisassemblySettings::GetDefaultSettings();

            for (auto& func : bv->GetAnalysisFunctionList()) {
                uint64_t func_addr = func->GetStart();
                for (auto& block : func->GetBasicBlocks()) {
                    auto lines = block->GetDisassemblyText(settings);
                    for (auto& line : lines) {
                        for (auto& tok : line.tokens) {
                            if (tok.operand == BN_INVALID_OPERAND) continue;

                            OperandInfo oi;
                            oi.insn_addr = line.addr;
                            oi.func_addr = func_addr;
                            oi.operand_index = static_cast<int>(tok.operand);
                            oi.text = tok.text;
                            oi.token_type = static_cast<int>(tok.type);
                            oi.type_name = token_type_name(static_cast<int>(tok.type));
                            oi.value = tok.value;
                            oi.size = static_cast<int>(tok.size);
                            cache.push_back(std::move(oi));
                        }
                    }
                }
            }
        })
        .column_int64("insn_addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.insn_addr);
        })
        .column_int64("func_addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("operand_index", [](const OperandInfo& r) -> int {
            return r.operand_index;
        })
        .column_text("text", [](const OperandInfo& r) -> std::string {
            return r.text;
        })
        .column_int("token_type", [](const OperandInfo& r) -> int {
            return r.token_type;
        })
        .column_text("type_name", [](const OperandInfo& r) -> std::string {
            return r.type_name;
        })
        .column_int64("value", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.value);
        })
        .column_int("size", [](const OperandInfo& r) -> int {
            return r.size;
        })
        // Direct source filter: single-function query bypasses cache
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<OperandIterator>(addr);
        }, 0.5, 20.0)  // cost=0.5, estimated_rows=20
        .index_on("func_addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

// ============================================================================
// COMMENTS Table
// Schema: address, comment, rpt_comment
// Compatible with idasql comments table
// ============================================================================

struct CommentInfo {
    uint64_t address = 0;
    std::string comment;
    std::string rpt_comment;
};

inline void collect_comments(std::vector<CommentInfo>& out) {
    auto bv = get_bv();
    if (!bv) return;

    std::unordered_map<uint64_t, std::string> by_addr;
    by_addr.reserve(256);

    // Global comments first.
    for (uint64_t addr : bv->GetCommentedAddresses()) {
        auto comment = bv->GetCommentForAddress(addr);
        if (!comment.empty()) {
            by_addr.emplace(addr, std::move(comment));
        }
    }

    // Fill gaps with function-scoped comments.
    for (auto& func : bv->GetAnalysisFunctionList()) {
        for (uint64_t addr : func->GetCommentedAddresses()) {
            if (by_addr.find(addr) != by_addr.end()) continue;
            auto comment = func->GetCommentForAddress(addr);
            if (!comment.empty()) {
                by_addr.emplace(addr, std::move(comment));
            }
        }
    }

    out.reserve(by_addr.size());
    for (const auto& [addr, comment] : by_addr) {
        CommentInfo item;
        item.address = addr;
        item.comment = comment;
        item.rpt_comment = comment;  // BN has no repeatable comment split.
        out.push_back(std::move(item));
    }

    std::sort(out.begin(), out.end(), [](const CommentInfo& a, const CommentInfo& b) {
        return a.address < b.address;
    });
}

inline bool set_comment_at_address(const Ref<BinaryView>& bv, uint64_t addr, const std::string& text) {
    if (!bv) return false;

    // Keep global and function-scoped comments aligned for consistent reads.
    bv->SetCommentForAddress(addr, text);
    for (auto& func : bv->GetAnalysisFunctionsContainingAddress(addr)) {
        func->SetCommentForAddress(addr, text);
    }
    return true;
}

inline CachedTableDef<CommentInfo> define_comments() {
    return cached_table<CommentInfo>("comments")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetCommentedAddresses().size() : 0;
        })
        .cache_builder([](std::vector<CommentInfo>& cache) {
            collect_comments(cache);
        })
        .column_int64("address", [](const CommentInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_text_rw("comment",
            [](const CommentInfo& r) -> std::string {
                return r.comment;
            },
            [](CommentInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string value = text ? text : "";
                if (!set_comment_at_address(bv, r.address, value)) return false;
                r.comment = value;
                r.rpt_comment = value;
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        .column_text_rw("rpt_comment",
            [](const CommentInfo& r) -> std::string {
                return r.rpt_comment;
            },
            [](CommentInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string value = text ? text : "";
                if (!set_comment_at_address(bv, r.address, value)) return false;
                r.comment = value;
                r.rpt_comment = value;
                if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
                return true;
            })
        .deletable([](CommentInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (!set_comment_at_address(bv, r.address, "")) return false;
            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            if (argc < 1) return false;
            if (argv[0].is_null()) return false;

            uint64_t addr = static_cast<uint64_t>(argv[0].as_int64());

            std::string value;
            if (argc >= 2 && !argv[1].is_null()) {
                const char* comment = argv[1].as_c_str();
                value = comment ? comment : "";
            } else if (argc >= 3 && !argv[2].is_null()) {
                const char* rpt_comment = argv[2].as_c_str();
                value = rpt_comment ? rpt_comment : "";
            } else {
                xsql::set_vtab_error("comments insert requires comment or rpt_comment");
                return false;
            }

            if (!set_comment_at_address(bv, addr, value)) return false;
            if (persistence::on_decompiler_invalidate) persistence::on_decompiler_invalidate();
            return true;
        })
        .build();
}

// ============================================================================
// DB_INFO Table - Database metadata
// Schema: key, value, type
// Compatible with idasql db_info table
// ============================================================================

struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;
};

struct CapabilityItem {
    std::string key;
    std::string value;
    std::string type;
    std::string note;
};

inline VTableDef define_db_info() {
    return table("db_info")
        .count([]() {
            return size_t(10); // Fixed number of metadata items
        })
        .column_text("key", [](size_t i) -> std::string {
            static const char* keys[] = {
                "processor", "filetype", "min_ea", "max_ea",
                "start_ea", "is_64bit", "endianness", "filename",
                "platform", "entry_point"
            };
            return i < 10 ? keys[i] : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";

            switch (i) {
                case 0: return bv->GetDefaultArchitecture()
                              ? bv->GetDefaultArchitecture()->GetName() : "";
                case 1: return bv->GetTypeName();
                case 2: return std::to_string(bv->GetStart());
                case 3: return std::to_string(bv->GetEnd());
                case 4: return std::to_string(bv->GetEntryPoint());
                case 5: return bv->GetAddressSize() == 8 ? "true" : "false";
                case 6: return bv->GetDefaultEndianness() == BigEndian
                              ? "big" : "little";
                case 7: return bv->GetFile()->GetFilename();
                case 8: return bv->GetDefaultPlatform()
                              ? bv->GetDefaultPlatform()->GetName() : "";
                case 9: {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llx",
                             (unsigned long long)bv->GetEntryPoint());
                    return buf;
                }
                default: return "";
            }
        })
        .column_text("type", [](size_t i) -> std::string {
            static const char* types[] = {
                "string", "string", "hex", "hex",
                "hex", "bool", "string", "string",
                "string", "hex"
            };
            return i < 10 ? types[i] : "";
        })
        .build();
}

// ============================================================================
// CAPABILITIES Table - Runtime feature flags
// Schema: key, value, type, note
// ============================================================================ 

inline VTableDef define_capabilities() {
    static const std::vector<CapabilityItem> kCaps = {
        // Mutation capabilities
        {"mutation.table_first_default", "true", "bool", "Mutations should prefer table UPDATE/DELETE/INSERT surfaces."},
        {"mutation.funcs.prototype_clear", "false", "bool", "Clearing user prototype override is not exposed safely by BN API here."},
        {"mutation.funcs.name", "true", "bool", "Function names writable via funcs.name."},
        {"mutation.funcs.prototype", "true", "bool", "Function prototypes writable via funcs.prototype."},
        {"mutation.funcs.comment", "true", "bool", "Function comments writable via funcs.comment."},
        {"mutation.names.insert", "true", "bool", "User symbols can be defined via INSERT INTO names."},
        {"mutation.names.delete", "true", "bool", "Matching symbols can be undefined via DELETE FROM names."},
        {"mutation.comments.insert", "true", "bool", "Address comments writable via INSERT INTO comments."},
        {"mutation.comments.delete", "true", "bool", "Address comments clearable via DELETE FROM comments."},
        {"mutation.pseudocode.comment", "true", "bool", "Pseudocode line comments writable via pseudocode.comment."},
        {"mutation.pseudocode.delete_clear", "true", "bool", "DELETE FROM pseudocode clears line comment for matching line."},
        {"mutation.hlil_vars.name", "true", "bool", "Variable names writable via hlil_vars.name."},
        {"mutation.hlil_vars.type", "true", "bool", "Variable types writable via hlil_vars.type."},
        {"mutation.hlil_vars.delete_clear", "true", "bool", "DELETE FROM hlil_vars clears user variable override."},
        {"mutation.hlil_vars.comment", "true", "bool", "Variable comments writable via hlil_vars.comment using persistent BN metadata keyed by variable identity."},
        // Discovery capabilities
        {"discovery.entities", "true", "bool", "Unified discovery surface via entities view."},
        // UDF capabilities
        {"udf.decompiler_helper_mutators", "false", "bool", "rename_var/set_var_type/set_func_prototype/set_pseudocode_comment removed in favor of table mutations."},
        {"udf.legacy.set_name", "true", "bool", "Legacy helper preserved; table names/funcs updates remain preferred."},
        {"udf.legacy.set_comment", "true", "bool", "Legacy helper preserved; table comments/pseudocode/funcs updates remain preferred."},
        // Feature-level capabilities
        {"feature.decompiler", "true", "bool", "HLIL decompiler tables available."},
        {"feature.types", "true", "bool", "Type intelligence tables (types, type_members, type_enum_values, func_signatures) available."},
        {"feature.search_bytes", "true", "bool", "search_bytes() UDF available."},
        {"feature.write_ops", "true", "bool", "Table-first write operations available."},
        {"feature.entities_search", "true", "bool", "entities_search() UDF available."},
        {"feature.disasm_calls", "true", "bool", "disasm_calls view available."},
        {"feature.patches", "true", "bool", "patches table available (read-write)."},
        {"mutation.patches.insert", "true", "bool", "New patches can be applied via INSERT INTO patches (address, patched_byte)."},
        {"mutation.patches.delete", "true", "bool", "Patches can be reverted via DELETE FROM patches WHERE address = <addr>."},
        {"mutation.patches.patched_byte", "true", "bool", "Patch bytes writable via UPDATE patches SET patched_byte = <byte>."},
        {"feature.runtime_settings", "true", "bool", "PRAGMA bnsql.* runtime controls available."},
        {"feature.query_timeout", "true", "bool", "Query timeout enforcement via xsql::QueryOptions::timeout_ms."},
        {"feature.instruction_operands", "true", "bool", "instruction_operands table available."},
#ifdef BNSQL_HAS_HTTP
        {"feature.http_server", "true", "bool", "HTTP query server available."},
#else
        {"feature.http_server", "false", "bool", "HTTP query server not compiled in."},
#endif
#ifdef BNSQL_HAS_MCP
        {"feature.mcp_server", "true", "bool", "MCP server available."},
#else
        {"feature.mcp_server", "false", "bool", "MCP server not compiled in."},
#endif
    };

    return table("capabilities")
        .count([]() {
            return kCaps.size();
        })
        .column_text("key", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].key : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].value : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].type : "";
        })
        .column_text("note", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].note : "";
        })
        .build();
}

// ============================================================================
// Table Registry - All tables in one place
// ============================================================================

struct TableRegistry {
    VTableDef funcs;
    VTableDef segments;
    VTableDef names;
    VTableDef entries;
    CachedTableDef<StringInfo> strings;
    CachedTableDef<CommentInfo> comments;
    VTableDef db_info;
    VTableDef capabilities;

    CachedTableDef<XrefInfo> xrefs;
    CachedTableDef<BlockInfo> blocks;
    CachedTableDef<ImportInfo> imports;
    CachedTableDef<InsnInfo> instructions;
    CachedTableDef<OperandInfo> instruction_operands;

    GeneratorTableDef<ByteRow> bytes;

    TableRegistry()
        : funcs(define_funcs())
        , segments(define_segments())
        , names(define_names())
        , entries(define_entries())
        , strings(define_strings())
        , comments(define_comments())
        , db_info(define_db_info())
        , capabilities(define_capabilities())
        , xrefs(define_xrefs())
        , blocks(define_blocks())
        , imports(define_imports())
        , instructions(define_instructions())
        , instruction_operands(define_instruction_operands())
        , bytes(define_bytes_table())
    {}

    void register_all(xsql::Database& db) {
        // Index-based tables
        register_index_table(db, "funcs", &funcs);
        register_index_table(db, "segments", &segments);
        register_index_table(db, "names", &names);
        register_index_table(db, "entries", &entries);
        register_index_table(db, "db_info", &db_info);
        register_index_table(db, "capabilities", &capabilities);

        // Cached tables
        register_cached_table(db, "comments", &comments);
        register_cached_table(db, "strings", &strings);
        register_cached_table(db, "xrefs", &xrefs);
        register_cached_table(db, "blocks", &blocks);
        register_cached_table(db, "imports", &imports);
        register_cached_table(db, "instructions", &instructions);
        register_cached_table(db, "instruction_operands", &instruction_operands);

        // Generator tables
        db.register_generator_table("bn_bytes", &bytes);
        db.create_table("bytes", "bn_bytes");

        // Create convenience views for common queries
        create_helper_views(db);
    }

    void create_helper_views(xsql::Database& db) {
        // entities view - unified discovery surface for common analyst lookups.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS entities AS
            SELECT
                f.name AS name,
                'function' AS kind,
                f.address AS address,
                '' AS parent_name,
                f.name AS qualified_name,
                'analysis.functions' AS source
            FROM funcs f
            UNION ALL
            SELECT
                n.name AS name,
                'symbol' AS kind,
                n.address AS address,
                '' AS parent_name,
                n.name AS qualified_name,
                'analysis.symbols' AS source
            FROM names n
            UNION ALL
            SELECT
                s.name AS name,
                'segment' AS kind,
                s.start_ea AS address,
                '' AS parent_name,
                s.name AS qualified_name,
                'analysis.segments' AS source
            FROM segments s
            UNION ALL
            SELECT
                i.name AS name,
                'import' AS kind,
                i.address AS address,
                i.module AS parent_name,
                i.module || '!' || i.name AS qualified_name,
                'analysis.imports' AS source
            FROM imports i
            UNION ALL
            SELECT
                t.content AS name,
                'string' AS kind,
                t.address AS address,
                '' AS parent_name,
                t.content AS qualified_name,
                'analysis.strings' AS source
            FROM strings t
            UNION ALL
            SELECT
                ty.name AS name,
                'type' AS kind,
                NULL AS address,
                '' AS parent_name,
                ty.name AS qualified_name,
                'analysis.types' AS source
            FROM types ty
        )");

        // callers view - who calls a function
        // Uses pre-computed from_func and name_at() scalar lookups to avoid
        // expensive joins against large virtual tables.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callers AS
            SELECT
                x.to_ea as func_addr,
                x.from_ea as caller_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as caller_name,
                x.from_func as caller_func_addr
            FROM xrefs x
            WHERE x.is_code = 1 AND x.from_func != 0
        )");

        // callees view - what does a function call
        // Uses scalar name_at() lookup to avoid heavy funcs/names joins.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callees AS
            SELECT
                x.from_func as func_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as func_name,
                x.to_ea as callee_addr,
                COALESCE(name_at(x.to_ea), printf('sub_%X', x.to_ea)) as callee_name
            FROM xrefs x
            WHERE x.is_code = 1 AND x.from_func != 0
        )");

        // function_chunks view - function address ranges (BN functions are typically contiguous)
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_chunks AS
            SELECT
                func_ea AS func_addr,
                MIN(start_ea) AS chunk_start,
                MAX(end_ea) AS chunk_end,
                COUNT(*) AS block_count,
                SUM(end_ea - start_ea) AS total_size
            FROM blocks
            GROUP BY func_ea
        )");

        // string_refs view - which functions reference which strings
        // Uses scalar name lookup to keep this view bounded on larger fixtures.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS string_refs AS
            SELECT
                s.address as string_addr,
                s.content as string_value,
                s.length as string_length,
                x.from_ea as ref_addr,
                x.from_func as func_addr,
                COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) as func_name
            FROM strings s
            JOIN xrefs x ON x.to_ea = s.address
            WHERE x.from_func != 0
        )");
    }

private:
    void register_index_table(xsql::Database& db, const char* name,
                              const VTableDef* def) {
        std::string module_name = std::string("bn_") + name;
        db.register_table(module_name.c_str(), def);
        db.create_table(name, module_name.c_str());
    }

    template<typename RowData>
    void register_cached_table(xsql::Database& db, const char* name,
                               const CachedTableDef<RowData>* def) {
        std::string module_name = std::string("bn_") + name;
        db.register_cached_table(module_name.c_str(), def);
        db.create_table(name, module_name.c_str());
    }
};

} // namespace entities
} // namespace bnsql
