// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_types.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

std::string type_kind_string(const Ref<Type>& type) {
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

// Materialize one TypeInfo from a (name, type) pair at a given enumeration index.
// Shared by the full-scan cache_builder AND the WHERE name=X filter iterator so
// both paths emit byte-identical column values (value parity across pushdown
// paths) -- including the enumeration-ordered `id`, which doubles as the row's
// stable rowid for scan-driven UPDATE/DELETE resolution.
static TypeInfo build_type_info(int64_t id, const QualifiedName& qname,
                                const Ref<Type>& type) {
    TypeInfo ti;
    ti.id = id;
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
    return ti;
}

namespace {

// Resolve the type kind to create for an INSERT: prefer the `kind` text column,
// else fall back to the is_struct/is_union/is_enum flag columns. Returns "" for
// an unsupported/unspecified kind.
std::string resolve_insert_kind(xsql::FunctionArg* argv, int argc) {
    // Column order: id,name,kind,size,alignment,is_struct,is_union,is_enum,...
    if (argc > 2 && !argv[2].is_null()) {
        const char* k = argv[2].as_c_str();
        std::string kind = k ? k : "";
        for (char& c : kind) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (kind == "struct" || kind == "union" || kind == "enum") return kind;
        if (!kind.empty()) return "";  // explicit but unsupported kind
    }
    if (argc > 5 && !argv[5].is_null() && argv[5].as_int() != 0) return "struct";
    if (argc > 6 && !argv[6].is_null() && argv[6].as_int() != 0) return "union";
    if (argc > 7 && !argv[7].is_null() && argv[7].as_int() != 0) return "enum";
    return "struct";  // default
}

// Create an empty named user type of the given kind. Returns false + sets a vtab
// error on failure.
bool define_empty_type(const Ref<BinaryView>& bv, const std::string& name,
                       const std::string& kind) {
    if (kind == "struct" || kind == "union") {
        StructureBuilder sb;
        sb.SetStructureType(kind == "union" ? UnionStructureType : StructStructureType);
        Ref<Type> type = Type::StructureType(sb.Finalize());
        bv->DefineUserType(QualifiedName(name), type);
        return true;
    }
    if (kind == "enum") {
        auto arch = bv->GetDefaultArchitecture();
        if (!arch) {
            xsql::set_vtab_error("types insert: no default architecture for enum");
            return false;
        }
        EnumerationBuilder eb;
        // Default enum width 4 bytes (matches typical C `enum`).
        Ref<Type> type = Type::EnumerationType(arch, eb.Finalize(), 4);
        bv->DefineUserType(QualifiedName(name), type);
        return true;
    }
    xsql::set_vtab_error("types insert: unsupported kind '" + kind +
                         "' (use struct, union, or enum)");
    return false;
}

}  // namespace

// Iterator for `WHERE name = X` pushdown. The whole-table cache_builder copies
// GetTypes() and renders type->GetString() (the full textual definition) for
// EVERY type; a single-name query wants exactly one row. This iterator walks
// GetTypes() in the SAME std::map(QualifiedName) order the cache_builder uses,
// so the matched row's enumeration index -- reported as both the `id` column and
// the rowid -- is identical to the full scan. That consistency is load-bearing:
// an UPDATE/DELETE routed through this filter resolves the exact target against
// the pre-mutation snapshot by rowid_fn(id) (see define_types: .rowid() +
// .snapshot_mutations()). GetString() is rendered for ONLY the matched type, so
// WHERE name=X costs one map walk + one render instead of N renders.
class TypeByNameIterator : public xsql::RowIterator {
    std::vector<TypeInfo> rows_;  // 0 or 1 rows (type names are unique)
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit TypeByNameIterator(std::string name) {
        auto bv = get_bv();
        if (!bv) return;

        auto all_types = bv->GetTypes();
        int64_t id = 0;
        for (const auto& [qname, type] : all_types) {
            if (qname.GetString() == name) {
                rows_.push_back(build_type_info(id, qname, type));
                break;
            }
            ++id;
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

    // Column order MUST match define_types() below:
    // 0 id, 1 name, 2 kind, 3 size, 4 alignment, 5 is_struct, 6 is_union,
    // 7 is_enum, 8 is_typedef, 9 is_func, 10 definition
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(r.id); break;
            case 1: ctx.result_text(r.name); break;
            case 2: ctx.result_text(r.kind); break;
            case 3: ctx.result_int64(r.size); break;
            case 4: ctx.result_int(r.alignment); break;
            case 5: ctx.result_int(r.is_struct ? 1 : 0); break;
            case 6: ctx.result_int(r.is_union ? 1 : 0); break;
            case 7: ctx.result_int(r.is_enum ? 1 : 0); break;
            case 8: ctx.result_int(r.is_typedef ? 1 : 0); break;
            case 9: ctx.result_int(r.is_func ? 1 : 0); break;
            case 10: ctx.result_text(r.definition); break;
            default: ctx.result_null(); break;
        }
    }

    // Stable rowid == the enumeration `id`, matching define_types().rowid() so a
    // filter-routed UPDATE/DELETE resolves the same row via the mutation snapshot.
    int64_t rowid() const override {
        return pos_ < rows_.size() ? rows_[pos_].id : 0;
    }
};

CachedTableDef<TypeInfo> define_types() {
    return cached_table<TypeInfo>("types")
        .no_shared_cache()
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
                cache.push_back(build_type_info(id++, qname, type));
            }
        })
        .column_int64("id", [](const TypeInfo& r) -> int64_t {
            return r.id;
        })
        .column_text_rw("name",
            [](const TypeInfo& r) -> std::string {
                return r.name;
            },
            [](TypeInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string new_name = text ? text : "";
                if (new_name.empty()) {
                    xsql::set_vtab_error("types: new name must not be empty");
                    return false;
                }
                if (new_name == r.name) return true;
                QualifiedName old_qn(r.name);
                if (!bv->GetTypeByName(old_qn)) {
                    xsql::set_vtab_error("types: no such type '" + r.name + "'");
                    return false;
                }
                if (bv->GetTypeByName(QualifiedName(new_name))) {
                    xsql::set_vtab_error("types: a type named '" + new_name +
                                         "' already exists");
                    return false;
                }
                // RenameType is the only rename primitive and it returns void, so
                // (mirroring the DELETE auto/user fix below) verify the rename
                // actually took effect rather than reporting success blindly.
                // GetTypes() includes auto-defined types (platform/type-library/
                // analysis-recovered) which can resist a rename; if the new name
                // does not resolve afterward, fail honestly instead of claiming a
                // phantom rename.
                const bool was_auto = bv->IsTypeAutoDefined(old_qn);
                bv->RenameType(old_qn, QualifiedName(new_name));
                if (!bv->GetTypeByName(QualifiedName(new_name))) {
                    xsql::set_vtab_error("types: rename of '" + r.name + "' to '" +
                                         new_name + "' did not take effect" +
                                         (was_auto ? " (type is auto-defined)" : ""));
                    return false;
                }
                r.name = new_name;
                return true;
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
        // WHERE name = X pushdown: one GetTypes() walk + one GetString() render
        // instead of rendering every type's full definition (Finding #1). Names
        // are unique in the type namespace, so at most one row. cost=0.5 keeps it
        // preferred over the full scan; est_rows=1.
        .filter_eq_text("name", [](const char* name) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<TypeByNameIterator>(name ? name : "");
        }, 0.5, 1.0)
        // Stable rowid = the enumeration `id`. Required for write correctness once
        // a filter exists: adding a filter disables the framework's POSITIONAL
        // mutation snapshot (it assumes filter rowids are non-positional), so a
        // multi-row `WHERE name=...` DELETE/UPDATE must resolve each row by KEY
        // against the pre-mutation snapshot instead. .snapshot_mutations() opts
        // into that key-matched path; the filter iterator and the full scan both
        // report this same id, so the target row is resolved exactly (never a
        // shifted cache position). id == the full-scan position, so non-filter
        // rowids are unchanged.
        .rowid([](const TypeInfo& r) -> int64_t {
            return r.id;
        })
        .snapshot_mutations()
        .index_on("id", [](const TypeInfo& r) -> int64_t {
            return r.id;
        })
        .deletable([](TypeInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            QualifiedName qn(r.name);
            if (!bv->GetTypeByName(qn)) {
                xsql::set_vtab_error("types: no such type '" + r.name + "'");
                return false;
            }
            // GetTypes() (which populates this table) includes auto-defined types
            // (platform/type-library/analysis-recovered). UndefineUserType removes
            // ONLY user types, so on an auto type it is a silent no-op that would
            // falsely report the row deleted (Finding #2). Route each kind to the
            // primitive that actually removes it, then verify the type is gone
            // before reporting success.
            if (bv->IsTypeAutoDefined(qn)) {
                std::string id = bv->GetTypeId(qn);
                if (id.empty()) {
                    xsql::set_vtab_error("types: cannot resolve type id for "
                                         "auto-defined '" + r.name + "'");
                    return false;
                }
                bv->UndefineType(id);
            } else {
                bv->UndefineUserType(qn);
            }
            if (bv->GetTypeByName(qn)) {
                xsql::set_vtab_error("types: type '" + r.name +
                                     "' could not be removed");
                return false;
            }
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Column order: id,name,kind,size,alignment,is_struct,...
            if (argc < 2 || argv[1].is_null()) {
                xsql::set_vtab_error("types insert requires a name");
                return false;
            }
            const char* name_c = argv[1].as_c_str();
            std::string name = name_c ? name_c : "";
            if (name.empty()) {
                xsql::set_vtab_error("types insert requires a non-empty name");
                return false;
            }
            if (bv->GetTypeByName(QualifiedName(name))) {
                xsql::set_vtab_error("types insert: a type named '" + name +
                                     "' already exists");
                return false;
            }
            std::string kind = resolve_insert_kind(argv, argc);
            if (kind.empty()) {
                xsql::set_vtab_error("types insert: unsupported kind (use struct, "
                                     "union, or enum via the `kind` column or the "
                                     "is_struct/is_union/is_enum flags)");
                return false;
            }
            return define_empty_type(bv, name, kind);
        })
        .build();
}

} // namespace types
} // namespace bnsql
