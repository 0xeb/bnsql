// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_members.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

std::string member_access_string(BNMemberAccess access) {
    switch (access) {
        case NoAccess: return "public";  // Default for C structs
        case PrivateAccess: return "private";
        case ProtectedAccess: return "protected";
        case PublicAccess: return "public";
        default: return "public";
    }
}

namespace {

// Parse a member type declaration ("uint32_t", "char[16]", "MY_HEADER *") into a
// BN type. Returns false (no error set) if the text does not parse.
bool parse_member_type(const Ref<BinaryView>& bv, const std::string& decl,
                       Ref<Type>& out) {
    if (!bv || decl.empty()) return false;
    QualifiedNameAndType parsed;
    std::string errors;
    if (bv->ParseTypeString(decl, parsed, errors) && parsed.type) {
        out = parsed.type;
        return true;
    }
    if (bv->ParseTypeString(decl + ";", parsed, errors) && parsed.type) {
        out = parsed.type;
        return true;
    }
    return false;
}

// Resolve a struct/union type by name for editing. Sets a vtab error and returns
// null if the name is missing or not a struct/union.
Ref<Structure> struct_for_edit(const Ref<BinaryView>& bv, const std::string& name) {
    auto type = bv->GetTypeByName(QualifiedName(name));
    if (!type || type->GetClass() != StructureTypeClass) {
        xsql::set_vtab_error("type_members: '" + name +
                             "' is not a struct/union type");
        return nullptr;
    }
    auto s = type->GetStructure();
    if (!s) {
        xsql::set_vtab_error("type_members: '" + name + "' has no structure");
        return nullptr;
    }
    return s;
}

// Re-define a named struct/union from a mutated builder, preserving its variant.
void redefine_struct(const Ref<BinaryView>& bv, const std::string& name,
                     const Ref<Structure>& original, StructureBuilder& sb) {
    sb.SetStructureType(original->GetStructureType());
    bv->DefineUserType(QualifiedName(name), Type::StructureType(sb.Finalize()));
}

// Resolve the LIVE index of a cached row's member by its stable NAME (offset as
// a fallback for anonymous members), never by the cached positional
// `member_index`: a multi-row UPDATE/DELETE rewrites the struct mid-statement
// (and a widening retype can consume following members), shifting every later
// member's live index. Name-keying makes each row self-locating. Sets a vtab
// error and returns members.size() when the member no longer exists.
size_t live_member_index(const std::vector<StructureMember>& members,
                         const TypeMemberInfo& r) {
    for (size_t i = 0; i < members.size(); ++i) {
        bool match = r.member_name.empty()
                         ? (members[i].offset == static_cast<uint64_t>(r.offset))
                         : (members[i].name == r.member_name);
        if (match) return i;
    }
    xsql::set_vtab_error("type_members: no member '" + r.member_name +
                         "' in type '" + r.type_name + "'");
    return members.size();
}

// --- Stable rowid + type_name pushdown support ------------------------------
//
// A member row's identity is (type ordinal in bv->GetTypes(), member_index).
// Pack it into one int64 so the full-scan cursor, the type_name filter iterator,
// and row_lookup all report the SAME rowid for a given member -- which is what
// lets a snapshot-backed multi-row UPDATE/DELETE resolve each scan rowid to its
// pre-mutation row by identity (see .snapshot_mutations()). 24 low bits hold the
// member index (far beyond any real struct); the ordinal takes the rest.
constexpr int kMemberIndexBits = 24;
constexpr int64_t kMemberIndexMask = (int64_t{1} << kMemberIndexBits) - 1;

int64_t pack_member_rowid(int64_t type_id, int member_index) {
    return (type_id << kMemberIndexBits) |
           (static_cast<int64_t>(member_index) & kMemberIndexMask);
}

void unpack_member_rowid(int64_t rowid, int64_t& type_id, int& member_index) {
    type_id = rowid >> kMemberIndexBits;
    member_index = static_cast<int>(rowid & kMemberIndexMask);
}

// Append one TypeMemberInfo per member of the struct/union `type` (named
// `type_name`, at map ordinal `type_id`). Byte-for-byte identical to the
// full-scan cache_builder so a pushed-down (type_name filter) row matches its
// cache twin -- same columns, same packed rowid. `type` MUST be a
// StructureTypeClass type; a null structure yields no rows.
void append_struct_member_rows(int64_t type_id, const std::string& type_name,
                               const Ref<Type>& type,
                               std::vector<TypeMemberInfo>& out) {
    auto s = type->GetStructure();
    if (!s) return;
    auto members = s->GetMembers();
    int member_index = 0;
    for (const auto& m : members) {
        TypeMemberInfo mi;
        mi.type_id = type_id;
        mi.type_name = type_name;
        mi.member_index = member_index++;
        mi.member_name = m.name;
        mi.offset = static_cast<int64_t>(m.offset);
        mi.size = (!m.type) ? 0 : static_cast<int64_t>(m.type->GetWidth());
        mi.member_type = (!m.type) ? "" : m.type->GetString();
        mi.access = member_access_string(m.access);
        out.push_back(std::move(mi));
    }
}

// Rebuild the single member row identified by (type ordinal, member_index) from
// LIVE BinaryView state -- the row_lookup path (rowid-equality reads and the
// reconstruct-by-rowid safety net). Mutations resolve via the pre-mutation
// snapshot first, so this only ever reads unmutated live state.
bool build_member_at(const Ref<BinaryView>& bv, int64_t type_id,
                     int member_index, TypeMemberInfo& out) {
    if (!bv || type_id < 0 || member_index < 0) return false;
    int64_t ord = 0;
    for (const auto& [qname, type] : bv->GetTypes()) {
        if (ord == type_id) {
            if (type->GetClass() != StructureTypeClass) return false;
            std::vector<TypeMemberInfo> rows;
            append_struct_member_rows(type_id, qname.GetString(), type, rows);
            if (static_cast<size_t>(member_index) >= rows.size()) return false;
            out = std::move(rows[static_cast<size_t>(member_index)]);
            return true;
        }
        ord++;
    }
    return false;
}

// Pushdown iterator for `WHERE type_name = '<name>'`: resolves ONLY the named
// struct/union and walks ONLY its members, instead of the whole-binary member
// walk (GetMembers()+GetString() per member of every struct) that cache_builder
// does. Rows carry the same type ordinal (bv->GetTypes() position) and packed
// rowid as the cache, so type_id JOINs and snapshot-backed mutations stay
// correct. The EQ filter is applied with omit=1, so every row this yields has
// type_name == name by construction.
class TypeMembersByNameIterator : public xsql::RowIterator {
    std::vector<TypeMemberInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit TypeMembersByNameIterator(const std::string& name) {
        auto bv = get_bv();
        if (!bv) return;
        int64_t type_id = 0;
        // GetTypes() is keyed by QualifiedName, so at most one type carries this
        // name; stop as soon as it is found (whether or not it is a struct). The
        // running ordinal matches cache_builder's type_id for that map position.
        for (const auto& [qname, type] : bv->GetTypes()) {
            if (qname.GetString() == name) {
                if (type->GetClass() == StructureTypeClass) {
                    append_struct_member_rows(type_id, qname.GetString(), type,
                                              rows_);
                }
                break;
            }
            type_id++;
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

    // Column order MUST match define_type_members() below:
    // 0 type_id, 1 type_name, 2 member_index, 3 member_name, 4 offset,
    // 5 size, 6 member_type, 7 access.
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(r.type_id); break;
            case 1: ctx.result_text(r.type_name); break;
            case 2: ctx.result_int(r.member_index); break;
            case 3: ctx.result_text(r.member_name); break;
            case 4: ctx.result_int64(r.offset); break;
            case 5: ctx.result_int64(r.size); break;
            case 6: ctx.result_text(r.member_type); break;
            case 7: ctx.result_text(r.access); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        if (pos_ >= rows_.size()) return 0;
        return pack_member_rowid(rows_[pos_].type_id, rows_[pos_].member_index);
    }
};

}  // namespace
CachedTableDef<TypeMemberInfo> define_type_members() {
    return cached_table<TypeMemberInfo>("type_members")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Cheap planner heuristic: type count * an average member fanout.
            // Deliberately does NOT call GetMembers()/GetString() per struct --
            // cache_builder (and the type_name filter iterator) are the single
            // place that pays the member walk, so the planner no longer duplicates
            // the O(structs * members) cost before xFilter runs it again.
            return bv->GetTypes().size() * 8;
        })
        .cache_builder([](std::vector<TypeMemberInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            int64_t type_id = 0;
            for (const auto& [qname, type] : bv->GetTypes()) {
                if (type->GetClass() == StructureTypeClass) {
                    append_struct_member_rows(type_id, qname.GetString(), type,
                                              cache);
                }
                type_id++;
            }
        })
        // Stable rowid = pack(type ordinal, member_index). The full-scan cursor,
        // the type_name filter iterator, and row_lookup all report this SAME value
        // for a given member, so both an unfiltered UPDATE/DELETE and a
        // `WHERE type_name=...` UPDATE/DELETE reconstruct the correct member.
        .rowid([](const TypeMemberInfo& r) -> int64_t {
            return pack_member_rowid(r.type_id, r.member_index);
        })
        .row_lookup([](TypeMemberInfo& r, int64_t rowid) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            int64_t type_id = 0;
            int member_index = 0;
            unpack_member_rowid(rowid, type_id, member_index);
            return build_member_at(bv, type_id, member_index, r);
        })
        // The packed (ordinal, member_index) rowid encodes a SHIFTING identity: a
        // RemoveMember / widening retype rewrites the struct mid-statement and
        // moves later members. Snapshot the pre-mutation row set once so each scan
        // rowid resolves to its scan-time row; the setters/DELETE then re-resolve
        // the live member by name (live_member_index), failing loudly if it was
        // renamed within the same statement. REQUIRED once a filter is added
        // below -- a non-empty filter set disables the default positional
        // query-scoped mutation snapshot, so a multi-row DELETE/UPDATE would
        // otherwise rebuild on already-mutated state (wrong rows / BN abort).
        .snapshot_mutations()
        .column_int64("type_id", [](const TypeMemberInfo& r) -> int64_t {
            return r.type_id;
        })
        .column_text("type_name", [](const TypeMemberInfo& r) -> std::string {
            return r.type_name;
        })
        .column_int("member_index", [](const TypeMemberInfo& r) -> int {
            return r.member_index;
        })
        .column_text_rw("member_name",
            [](const TypeMemberInfo& r) -> std::string {
                return r.member_name;
            },
            [](TypeMemberInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string new_name = text ? text : "";
                if (new_name.empty()) {
                    xsql::set_vtab_error("type_members: member name must not be empty");
                    return false;
                }
                auto s = struct_for_edit(bv, r.type_name);
                if (!s) return false;
                auto members = s->GetMembers();
                const size_t live = live_member_index(members, r);
                if (live >= members.size()) return false;
                StructureBuilder sb(s);
                sb.ReplaceMember(live, members[live].type, new_name);
                redefine_struct(bv, r.type_name, s, sb);
                r.member_name = new_name;
                return true;
            })
        .column_int64("offset", [](const TypeMemberInfo& r) -> int64_t {
            return r.offset;
        })
        .column_int64("size", [](const TypeMemberInfo& r) -> int64_t {
            return r.size;
        })
        .column_text_rw("member_type",
            [](const TypeMemberInfo& r) -> std::string {
                return r.member_type;
            },
            [](TypeMemberInfo& r, const char* text) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                std::string decl = text ? text : "";
                Ref<Type> mtype;
                if (!parse_member_type(bv, decl, mtype)) {
                    xsql::set_vtab_error("type_members: could not parse member type '" +
                                         decl + "'");
                    return false;
                }
                auto s = struct_for_edit(bv, r.type_name);
                if (!s) return false;
                auto members = s->GetMembers();
                const size_t live = live_member_index(members, r);
                if (live >= members.size()) return false;
                StructureBuilder sb(s);
                sb.ReplaceMember(live, mtype, members[live].name);
                redefine_struct(bv, r.type_name, s, sb);
                r.member_type = decl;
                return true;
            })
        .column_text("access", [](const TypeMemberInfo& r) -> std::string {
            return r.access;
        })
        // Direct source filter: `WHERE type_name='X'` resolves the single struct
        // via GetTypes() and walks only ITS members, bypassing the whole-binary
        // cache_builder (GetTypes() copy + GetMembers()+GetString() per member of
        // every struct). cost=1.0 keeps it well below the full-scan estimate.
        .filter_eq_text("type_name",
            [](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                return std::make_unique<TypeMembersByNameIterator>(
                    name ? name : "");
            }, 1.0, 8.0)
        .index_on("type_id", [](const TypeMemberInfo& r) -> int64_t {
            return r.type_id;
        })
        .deletable([](TypeMemberInfo& r) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto s = struct_for_edit(bv, r.type_name);
            if (!s) return false;
            auto members = s->GetMembers();
            const size_t live = live_member_index(members, r);
            if (live >= members.size()) return false;
            StructureBuilder sb(s);
            sb.RemoveMember(live);
            redefine_struct(bv, r.type_name, s, sb);
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Column order: type_id,type_name,member_index,member_name,offset,size,
            //               member_type,access
            if (argc < 4 || argv[1].is_null() || argv[3].is_null()) {
                xsql::set_vtab_error(
                    "type_members insert requires type_name and member_name");
                return false;
            }
            const char* tn = argv[1].as_c_str();
            std::string type_name = tn ? tn : "";
            const char* mn = argv[3].as_c_str();
            std::string member_name = mn ? mn : "";
            if (type_name.empty() || member_name.empty()) {
                xsql::set_vtab_error("type_members insert requires non-empty "
                                     "type_name and member_name");
                return false;
            }
            std::string member_type = "int";
            if (argc > 6 && !argv[6].is_null()) {
                const char* mt = argv[6].as_c_str();
                if (mt && *mt) member_type = mt;
            }
            Ref<Type> mtype;
            if (!parse_member_type(bv, member_type, mtype)) {
                xsql::set_vtab_error("type_members insert: could not parse member "
                                     "type '" + member_type + "'");
                return false;
            }
            auto s = struct_for_edit(bv, type_name);
            if (!s) return false;
            StructureBuilder sb(s);
            if (argc > 4 && !argv[4].is_null()) {
                int64_t signed_offset = argv[4].as_int64();
                if (signed_offset < 0) {
                    xsql::set_vtab_error(
                        "type_members insert: offset must be non-negative");
                    return false;
                }
                uint64_t offset = static_cast<uint64_t>(signed_offset);
                sb.AddMemberAtOffset(mtype, member_name, offset);
            } else {
                sb.AddMember(mtype, member_name);
            }
            redefine_struct(bv, type_name, s, sb);
            return true;
        })
        .build();
}

} // namespace types
} // namespace bnsql
