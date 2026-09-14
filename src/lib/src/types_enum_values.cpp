// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_enum_values.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Resolve an enum type by name for editing. Sets a vtab error and returns null if
// the name is missing or not an enum.
Ref<Type> enum_type_for_edit(const Ref<BinaryView>& bv, const std::string& name) {
    auto type = bv->GetTypeByName(QualifiedName(name));
    if (!type || type->GetClass() != EnumerationTypeClass || !type->GetEnumeration()) {
        xsql::set_vtab_error("type_enum_values: '" + name + "' is not an enum type");
        return nullptr;
    }
    return type;
}

// Re-define a named enum from a mutated builder, preserving its byte width.
// Fails cleanly (sets a vtab error, returns false) when the BinaryView has no
// default architecture — mirrors define_empty_type (types_types.cpp) so the
// enum-edit path never passes a null Architecture* into Type::EnumerationType.
bool redefine_enum(const Ref<BinaryView>& bv, const std::string& name,
                   const Ref<Type>& original, EnumerationBuilder& eb) {
    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        xsql::set_vtab_error("type_enum_values: no default architecture for enum");
        return false;
    }
    size_t width = static_cast<size_t>(original->GetWidth());
    if (width == 0) width = 4;
    bv->DefineUserType(QualifiedName(name),
                       Type::EnumerationType(arch, eb.Finalize(), width));
    return true;
}

}  // namespace

CachedTableDef<TypeEnumValueInfo> define_type_enum_values() {
    return cached_table<TypeEnumValueInfo>("type_enum_values")
        .no_shared_cache()
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
        .column_text_rw("value_name",
            [](const TypeEnumValueInfo& r) -> std::string {
                return r.value_name;
            },
            [](TypeEnumValueInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string new_name = text ? text : "";
                if (new_name.empty()) {
                    xsql::set_vtab_error("type_enum_values: value name must not be empty");
                    return false;
                }
                auto type = enum_type_for_edit(bv, r.type_name);
                if (!type) return false;
                auto members = type->GetEnumeration()->GetMembers();
                if (r.value_index < 0 ||
                    static_cast<size_t>(r.value_index) >= members.size()) {
                    xsql::set_vtab_error("type_enum_values: value index out of range");
                    return false;
                }
                EnumerationBuilder eb(type->GetEnumeration());
                eb.ReplaceMember(static_cast<size_t>(r.value_index), new_name,
                                 members[r.value_index].value);
                if (!redefine_enum(bv, r.type_name, type, eb)) return false;
                r.value_name = new_name;
                return true;
            })
        .column_int64_rw("value",
            [](const TypeEnumValueInfo& r) -> int64_t {
                return r.value;
            },
            [](TypeEnumValueInfo& r, int64_t new_value) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto type = enum_type_for_edit(bv, r.type_name);
                if (!type) return false;
                auto members = type->GetEnumeration()->GetMembers();
                if (r.value_index < 0 ||
                    static_cast<size_t>(r.value_index) >= members.size()) {
                    xsql::set_vtab_error("type_enum_values: value index out of range");
                    return false;
                }
                EnumerationBuilder eb(type->GetEnumeration());
                eb.ReplaceMember(static_cast<size_t>(r.value_index),
                                 members[r.value_index].name,
                                 static_cast<uint64_t>(new_value));
                if (!redefine_enum(bv, r.type_name, type, eb)) return false;
                r.value = new_value;
                return true;
            })
        .index_on("type_id", [](const TypeEnumValueInfo& r) -> int64_t {
            return r.type_id;
        })
        .deletable([](TypeEnumValueInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto type = enum_type_for_edit(bv, r.type_name);
            if (!type) return false;
            auto members = type->GetEnumeration()->GetMembers();
            // Resolve the live index by the stable value NAME, not the cached
            // positional `value_index`: a multi-row DELETE removes members
            // mid-statement (the shared cache is not invalidated until the
            // statement boundary), which shifts every later member's live index.
            // Name-keying makes each delete self-locating regardless of prior
            // removals in the same statement.
            size_t live_index = members.size();
            for (size_t i = 0; i < members.size(); ++i) {
                if (members[i].name == r.value_name) {
                    live_index = i;
                    break;
                }
            }
            if (live_index >= members.size()) {
                xsql::set_vtab_error("type_enum_values: no value '" +
                                     r.value_name + "' in enum '" + r.type_name +
                                     "'");
                return false;
            }
            EnumerationBuilder eb(type->GetEnumeration());
            eb.RemoveMember(live_index);
            return redefine_enum(bv, r.type_name, type, eb);
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Column order: type_id,type_name,value_index,value_name,value
            if (argc < 4 || argv[1].is_null() || argv[3].is_null()) {
                xsql::set_vtab_error(
                    "type_enum_values insert requires type_name and value_name");
                return false;
            }
            const char* tn = argv[1].as_c_str();
            std::string type_name = tn ? tn : "";
            const char* vn = argv[3].as_c_str();
            std::string value_name = vn ? vn : "";
            if (type_name.empty() || value_name.empty()) {
                xsql::set_vtab_error("type_enum_values insert requires non-empty "
                                     "type_name and value_name");
                return false;
            }
            auto type = enum_type_for_edit(bv, type_name);
            if (!type) return false;
            EnumerationBuilder eb(type->GetEnumeration());
            if (argc > 4 && !argv[4].is_null()) {
                eb.AddMemberWithValue(value_name,
                                      static_cast<uint64_t>(argv[4].as_int64()));
            } else {
                eb.AddMember(value_name);  // auto value = previous + 1
            }
            return redefine_enum(bv, type_name, type, eb);
        })
        .build();
}

} // namespace types
} // namespace bnsql
