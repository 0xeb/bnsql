// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * types.hpp - Type intelligence tables for bnsql
 *
 * Provides SQLite virtual tables for Binary Ninja's type system.
 *
 * Tables:
 *   types            - All defined types (structs, enums, typedefs, etc.)
 *   type_members     - Struct/union member fields
 *   type_enum_values - Enumeration constant values
 *   func_signatures  - Function parameter/return type information
 *
 * Views:
 *   types_v_structs  - Convenience: WHERE is_struct = 1
 *   types_v_enums    - Convenience: WHERE is_enum = 1
 */

#pragma once

#include <bnsql/vtable.hpp>
#include <bnsql/entities.hpp>
#include <xsql/database.hpp>

#include "binaryninjaapi.h"

#include <string>
#include <vector>
#include <map>

namespace bnsql {
namespace types {

using namespace BinaryNinja;

// ============================================================================
// Helper: Get BinaryView from thread-local context
// ============================================================================

inline Ref<BinaryView> get_bv() {
    return entities::get_bv();
}

// ============================================================================
// Helper: Map BNTypeClass to human-readable kind string
// ============================================================================

inline std::string type_kind_string(const Ref<Type>& type) {
    if (!type) return "other";

    switch (type->GetClass()) {
        case StructureTypeClass: {
            auto s = type->GetStructure();
            if (s) {
                switch (s->GetStructureType()) {
                    case ClassStructureType:  return "struct";
                    case StructStructureType: return "struct";
                    case UnionStructureType:  return "union";
                    default: return "struct";
                }
            }
            return "struct";
        }
        case EnumerationTypeClass: return "enum";
        case NamedTypeReferenceClass: return "typedef";
        case FunctionTypeClass: return "func";
        case PointerTypeClass: return "ptr";
        case ArrayTypeClass: return "array";
        case IntegerTypeClass: return "int";
        case FloatTypeClass: return "float";
        case VoidTypeClass: return "void";
        case BoolTypeClass: return "bool";
        case WideCharTypeClass: return "wchar";
        default: return "other";
    }
}

// ============================================================================
// TYPES Table
// Schema: id, name, kind, size, alignment, is_struct, is_union, is_enum,
//         is_typedef, is_func, definition
// ============================================================================

struct TypeInfo {
    int64_t id;
    std::string name;
    std::string kind;
    int64_t size;
    int alignment;
    bool is_struct;
    bool is_union;
    bool is_enum;
    bool is_typedef;
    bool is_func;
    std::string definition;
};

inline CachedTableDef<TypeInfo> define_types() {
    return cached_table<TypeInfo>("types")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            return bv->GetTypes().size();
        })
        .cache_builder([](std::vector<TypeInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto all_types = bv->GetTypes();
            cache.reserve(all_types.size());

            int64_t id = 0;
            for (const auto& [qname, type] : all_types) {
                TypeInfo ti;
                ti.id = id++;
                ti.name = qname.GetString();
                ti.kind = type_kind_string(type);
                ti.size = static_cast<int64_t>(type->GetWidth());
                ti.alignment = static_cast<int>(type->GetAlignment());

                ti.is_struct = (type->GetClass() == StructureTypeClass &&
                    type->GetStructure() &&
                    type->GetStructure()->GetStructureType() != UnionStructureType);
                ti.is_union = (type->GetClass() == StructureTypeClass &&
                    type->GetStructure() &&
                    type->GetStructure()->GetStructureType() == UnionStructureType);
                ti.is_enum = (type->GetClass() == EnumerationTypeClass);
                ti.is_typedef = (type->GetClass() == NamedTypeReferenceClass);
                ti.is_func = (type->GetClass() == FunctionTypeClass);
                ti.definition = type->GetString();

                cache.push_back(std::move(ti));
            }
        })
        .column_int64("id", [](const TypeInfo& r) -> int64_t {
            return r.id;
        })
        .column_text("name", [](const TypeInfo& r) -> std::string {
            return r.name;
        })
        .column_text("kind", [](const TypeInfo& r) -> std::string {
            return r.kind;
        })
        .column_int64("size", [](const TypeInfo& r) -> int64_t {
            return r.size;
        })
        .column_int("alignment", [](const TypeInfo& r) -> int {
            return r.alignment;
        })
        .column_int("is_struct", [](const TypeInfo& r) -> int {
            return r.is_struct ? 1 : 0;
        })
        .column_int("is_union", [](const TypeInfo& r) -> int {
            return r.is_union ? 1 : 0;
        })
        .column_int("is_enum", [](const TypeInfo& r) -> int {
            return r.is_enum ? 1 : 0;
        })
        .column_int("is_typedef", [](const TypeInfo& r) -> int {
            return r.is_typedef ? 1 : 0;
        })
        .column_int("is_func", [](const TypeInfo& r) -> int {
            return r.is_func ? 1 : 0;
        })
        .column_text("definition", [](const TypeInfo& r) -> std::string {
            return r.definition;
        })
        .index_on("id", [](const TypeInfo& r) -> int64_t {
            return r.id;
        })
        .build();
}

// ============================================================================
// TYPE_MEMBERS Table
// Schema: type_id, type_name, member_index, member_name, offset, size,
//         member_type, access
// ============================================================================

struct TypeMemberInfo {
    int64_t type_id;
    std::string type_name;
    int member_index;
    std::string member_name;
    int64_t offset;
    int64_t size;
    std::string member_type;
    std::string access;
};

inline std::string member_access_string(BNMemberAccess access) {
    switch (access) {
        case NoAccess: return "public";  // Default for C structs
        case PrivateAccess: return "private";
        case ProtectedAccess: return "protected";
        case PublicAccess: return "public";
        default: return "public";
    }
}

inline CachedTableDef<TypeMemberInfo> define_type_members() {
    return cached_table<TypeMemberInfo>("type_members")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Rough estimate: ~5 members per struct/union type
            size_t count = 0;
            for (const auto& [qname, type] : bv->GetTypes()) {
                if (type->GetClass() == StructureTypeClass) {
                    auto s = type->GetStructure();
                    if (s) count += s->GetMembers().size();
                }
            }
            return count;
        })
        .cache_builder([](std::vector<TypeMemberInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto all_types = bv->GetTypes();
            int64_t type_id = 0;

            for (const auto& [qname, type] : all_types) {
                if (type->GetClass() == StructureTypeClass) {
                    auto s = type->GetStructure();
                    if (!s) { type_id++; continue; }

                    auto members = s->GetMembers();
                    int member_index = 0;
                    for (const auto& m : members) {
                        TypeMemberInfo mi;
                        mi.type_id = type_id;
                        mi.type_name = qname.GetString();
                        mi.member_index = member_index++;
                        mi.member_name = m.name;
                        mi.offset = static_cast<int64_t>(m.offset);
                        mi.size = (!m.type) ? 0 : static_cast<int64_t>(m.type->GetWidth());
                        mi.member_type = (!m.type) ? "" : m.type->GetString();
                        mi.access = member_access_string(m.access);
                        cache.push_back(std::move(mi));
                    }
                }
                type_id++;
            }
        })
        .column_int64("type_id", [](const TypeMemberInfo& r) -> int64_t {
            return r.type_id;
        })
        .column_text("type_name", [](const TypeMemberInfo& r) -> std::string {
            return r.type_name;
        })
        .column_int("member_index", [](const TypeMemberInfo& r) -> int {
            return r.member_index;
        })
        .column_text("member_name", [](const TypeMemberInfo& r) -> std::string {
            return r.member_name;
        })
        .column_int64("offset", [](const TypeMemberInfo& r) -> int64_t {
            return r.offset;
        })
        .column_int64("size", [](const TypeMemberInfo& r) -> int64_t {
            return r.size;
        })
        .column_text("member_type", [](const TypeMemberInfo& r) -> std::string {
            return r.member_type;
        })
        .column_text("access", [](const TypeMemberInfo& r) -> std::string {
            return r.access;
        })
        .index_on("type_id", [](const TypeMemberInfo& r) -> int64_t {
            return r.type_id;
        })
        .build();
}

// ============================================================================
// TYPE_ENUM_VALUES Table
// Schema: type_id, type_name, value_index, value_name, value
// ============================================================================

struct TypeEnumValueInfo {
    int64_t type_id;
    std::string type_name;
    int value_index;
    std::string value_name;
    int64_t value;
};

inline CachedTableDef<TypeEnumValueInfo> define_type_enum_values() {
    return cached_table<TypeEnumValueInfo>("type_enum_values")
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            size_t count = 0;
            for (const auto& [qname, type] : bv->GetTypes()) {
                if (type->GetClass() == EnumerationTypeClass) {
                    auto e = type->GetEnumeration();
                    if (e) count += e->GetMembers().size();
                }
            }
            return count;
        })
        .cache_builder([](std::vector<TypeEnumValueInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto all_types = bv->GetTypes();
            int64_t type_id = 0;

            for (const auto& [qname, type] : all_types) {
                if (type->GetClass() == EnumerationTypeClass) {
                    auto e = type->GetEnumeration();
                    if (!e) { type_id++; continue; }

                    auto members = e->GetMembers();
                    int value_index = 0;
                    for (const auto& m : members) {
                        TypeEnumValueInfo vi;
                        vi.type_id = type_id;
                        vi.type_name = qname.GetString();
                        vi.value_index = value_index++;
                        vi.value_name = m.name;
                        vi.value = static_cast<int64_t>(m.value);
                        cache.push_back(std::move(vi));
                    }
                }
                type_id++;
            }
        })
        .column_int64("type_id", [](const TypeEnumValueInfo& r) -> int64_t {
            return r.type_id;
        })
        .column_text("type_name", [](const TypeEnumValueInfo& r) -> std::string {
            return r.type_name;
        })
        .column_int("value_index", [](const TypeEnumValueInfo& r) -> int {
            return r.value_index;
        })
        .column_text("value_name", [](const TypeEnumValueInfo& r) -> std::string {
            return r.value_name;
        })
        .column_int64("value", [](const TypeEnumValueInfo& r) -> int64_t {
            return r.value;
        })
        .index_on("type_id", [](const TypeEnumValueInfo& r) -> int64_t {
            return r.type_id;
        })
        .build();
}

// ============================================================================
// FUNC_SIGNATURES Table
// Schema: func_addr, arg_index, arg_name, arg_type, return_type, calling_conv
//
// arg_index = -1 is the return type row, 0..N are parameters.
// filter_eq("func_addr") enables fast single-function queries.
// ============================================================================

struct FuncSignatureInfo {
    uint64_t func_addr;
    int arg_index;       // -1 = return type row
    std::string arg_name;
    std::string arg_type;
    std::string return_type;
    std::string calling_conv;
};

inline std::string calling_convention_name(const Ref<Function>& func, const Ref<Type>& func_type) {
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

inline void collect_func_signature(std::vector<FuncSignatureInfo>& out, const Ref<Function>& func) {
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

/**
 * Iterator for func_signatures filtered to a single function address.
 * Avoids full cache scan when querying WHERE func_addr = X.
 */
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

inline CachedTableDef<FuncSignatureInfo> define_func_signatures() {
    return cached_table<FuncSignatureInfo>("func_signatures")
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

// ============================================================================
// PATCHES Table (Read-Only)
// Schema: address, original_byte, patched_byte, status
// ============================================================================

struct PatchInfo {
    uint64_t address;
    uint8_t original_byte;
    uint8_t patched_byte;
    std::string status;  // "changed" or "inserted"
};

inline CachedTableDef<PatchInfo> define_patches() {
    return cached_table<PatchInfo>("patches")
        .estimate_rows([]() -> size_t {
            // Patches are typically rare; estimate low
            return 100;
        })
        .cache_builder([](std::vector<PatchInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            for (auto& seg : bv->GetSegments()) {
                uint64_t addr = seg->GetStart();
                uint64_t end = seg->GetEnd();

                while (addr < end) {
                    auto mod = bv->GetModification(addr);
                    if (mod != Original) {
                        PatchInfo pi;
                        pi.address = addr;

                        // Read current (patched) byte
                        uint8_t patched = 0;
                        bv->Read(&patched, addr, 1);
                        pi.patched_byte = patched;

                        // Original byte: read from original file data
                        // Parent/raw view uses file offsets, not VAs — translate first
                        uint8_t orig = 0;
                        auto parent = bv->GetParentView();
                        if (parent) {
                            uint64_t file_offset;
                            if (bv->GetDataOffsetForAddress(addr, file_offset)) {
                                parent->Read(&orig, file_offset, 1);
                            }
                        }
                        pi.original_byte = orig;

                        pi.status = (mod == Changed) ? "changed" : "inserted";
                        cache.push_back(std::move(pi));
                    }
                    addr++;
                }
            }
        })
        .column_int64("address", [](const PatchInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_int("original_byte", [](const PatchInfo& r) -> int {
            return static_cast<int>(r.original_byte);
        })
        .column_int_rw("patched_byte",
            [](const PatchInfo& r) -> int {
                return static_cast<int>(r.patched_byte);
            },
            [](PatchInfo& r, int new_byte) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                if (new_byte < 0 || new_byte > 255) {
                    xsql::set_vtab_error("patched_byte must be 0-255");
                    return false;
                }
                uint8_t byte_val = static_cast<uint8_t>(new_byte);
                if (!bv->Write(r.address, &byte_val, 1)) {
                    xsql::set_vtab_error("Failed to write patch byte");
                    return false;
                }
                r.patched_byte = byte_val;
                return true;
            })
        .column_text("status", [](const PatchInfo& r) -> std::string {
            return r.status;
        })
        // DELETE: revert patch by writing original byte back
        .deletable([](PatchInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            uint8_t orig = r.original_byte;
            if (!bv->Write(r.address, &orig, 1)) {
                xsql::set_vtab_error("Failed to revert patch byte");
                return false;
            }
            return true;
        })
        // INSERT: apply new patch at address
        // INSERT INTO patches (address, patched_byte) VALUES (0x1234, 0x90)
        .insertable([](int argc, sqlite3_value** argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Column order: address, original_byte, patched_byte, status
            if (argc < 1 || sqlite3_value_type(argv[0]) == SQLITE_NULL) {
                xsql::set_vtab_error("patches insert requires address");
                return false;
            }
            uint64_t address = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
            // patched_byte is column 2 (index 2)
            if (argc < 3 || sqlite3_value_type(argv[2]) == SQLITE_NULL) {
                xsql::set_vtab_error("patches insert requires patched_byte");
                return false;
            }
            int byte_val = sqlite3_value_int(argv[2]);
            if (byte_val < 0 || byte_val > 255) {
                xsql::set_vtab_error("patched_byte must be 0-255");
                return false;
            }
            uint8_t patch = static_cast<uint8_t>(byte_val);
            if (!bv->Write(address, &patch, 1)) {
                xsql::set_vtab_error("Failed to write patch byte");
                return false;
            }
            return true;
        })
        .build();
}

// ============================================================================
// Types Registry - All type tables in one place
// ============================================================================

struct TypesRegistry {
    CachedTableDef<TypeInfo> types;
    CachedTableDef<TypeMemberInfo> type_members;
    CachedTableDef<TypeEnumValueInfo> type_enum_values;
    CachedTableDef<FuncSignatureInfo> func_signatures;
    CachedTableDef<PatchInfo> patches;

    TypesRegistry()
        : types(define_types())
        , type_members(define_type_members())
        , type_enum_values(define_type_enum_values())
        , func_signatures(define_func_signatures())
        , patches(define_patches())
    {}

    void register_all(xsql::Database& db) {
        db.register_cached_table("bn_types", &types);
        db.create_table("types", "bn_types");

        db.register_cached_table("bn_type_members", &type_members);
        db.create_table("type_members", "bn_type_members");

        db.register_cached_table("bn_type_enum_values", &type_enum_values);
        db.create_table("type_enum_values", "bn_type_enum_values");

        db.register_cached_table("bn_func_signatures", &func_signatures);
        db.create_table("func_signatures", "bn_func_signatures");

        db.register_cached_table("bn_patches", &patches);
        db.create_table("patches", "bn_patches");

        create_views(db);
    }

private:
    void create_views(xsql::Database& db) {
        // Convenience views for common type queries
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_structs AS
            SELECT * FROM types WHERE is_struct = 1
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_enums AS
            SELECT * FROM types WHERE is_enum = 1
        )");
    }
};

} // namespace types
} // namespace bnsql
