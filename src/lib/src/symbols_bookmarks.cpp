// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `bookmarks` — writable, backed by BN user data Tags. Closes the cross-tool gap
// (bnsql previously had no bookmarks surface). Recipe measured empirically in
// a standalone BN tag lab (CreateUserDataTag does NOT auto-create the tag type; the
// built-in `Bookmarks` type is the default; Tag::SetData updates in place).

#include "symbols_bookmarks.hpp"

namespace bnsql {
namespace symbols {

using namespace BinaryNinja;
using core::get_bv;

namespace {

constexpr const char* kDefaultTagType = "Bookmarks";

// Re-resolve the exact BN Tag object behind a bookmarks row by its GUID. The row
// carries the id (stable across the per-statement cache rebuild), so UPDATE/DELETE
// act on the right tag even when several bookmarks share one address.
Ref<Tag> find_user_tag_by_id(const Ref<BinaryView>& bv, const std::string& id) {
    if (!bv || id.empty()) return nullptr;
    for (const auto& r : bv->GetUserDataTagReferences()) {
        if (r.tag && r.tag->GetId() == id) return r.tag;
    }
    return nullptr;
}

}  // namespace

void collect_bookmarks(std::vector<BookmarkInfo>& out) {
    auto bv = get_bv();
    if (!bv) return;
    auto refs = bv->GetUserDataTagReferences();
    out.reserve(refs.size());
    for (const auto& r : refs) {
        if (!r.tag) continue;
        BookmarkInfo item;
        item.address = r.addr;
        item.type = r.tag->GetType() ? r.tag->GetType()->GetName() : std::string();
        item.category = std::string();  // BN has no category sub-level
        item.comment = r.tag->GetData();
        item.tag_id = r.tag->GetId();
        out.push_back(std::move(item));
    }
    std::sort(out.begin(), out.end(), [](const BookmarkInfo& a, const BookmarkInfo& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.type < b.type;
    });
}

CachedTableDef<BookmarkInfo> define_bookmarks() {
    return cached_table<BookmarkInfo>("bookmarks")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetUserDataTagReferences().size() : 0;
        })
        .cache_builder([](std::vector<BookmarkInfo>& cache) {
            collect_bookmarks(cache);
        })
        .column_int64("addr", [](const BookmarkInfo& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        // `type` is the tag-type name; set at INSERT time. Changing a tag's type in BN
        // means remove+recreate, so it is read-only here (DELETE + INSERT to re-type).
        .column_text("type", [](const BookmarkInfo& r) -> std::string {
            return r.type;
        })
        // BN has no category sub-level under a tag type — always empty, read-only.
        .column_text("category", [](const BookmarkInfo& r) -> std::string {
            return r.category;
        })
        // The bookmark's free-text: writable in place via Tag::SetData.
        .column_text_rw("comment",
            [](const BookmarkInfo& r) -> std::string {
                return r.comment;
            },
            [](BookmarkInfo& r, const char* text) -> bool {
                std::string value = text ? text : "";
                if (value == r.comment) return true;  // no-op replay guard
                auto bv = get_bv();
                Ref<Tag> tag = find_user_tag_by_id(bv, r.tag_id);
                if (!tag) {
                    xsql::set_vtab_error("bookmarks: cannot resolve tag to update");
                    return false;
                }
                tag->SetData(value);
                r.comment = value;
                return true;
            })
        .deletable([](BookmarkInfo& r) -> bool {
            auto bv = get_bv();
            Ref<Tag> tag = find_user_tag_by_id(bv, r.tag_id);
            if (!tag) {
                xsql::set_vtab_error("bookmarks: cannot resolve tag to delete");
                return false;
            }
            bv->RemoveUserDataTag(r.address, tag);
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // columns: addr(0), type(1), category(2), comment(3).
            auto bv = get_bv();
            if (!bv) return false;
            if (argc < 1 || argv[0].is_null()) {
                xsql::set_vtab_error("bookmarks: INSERT requires addr");
                return false;
            }
            uint64_t addr = static_cast<uint64_t>(argv[0].as_int64());

            std::string type = kDefaultTagType;
            if (argc >= 2 && !argv[1].is_null()) {
                const char* t = argv[1].as_c_str();
                if (t && *t) type = t;
            }
            if (argc >= 3 && !argv[2].is_null()) {
                const char* category = argv[2].as_c_str();
                if (category && *category) {
                    xsql::set_vtab_error(
                        "bookmarks: category is unsupported by Binary Ninja "
                        "and must be NULL or empty");
                    return false;
                }
            }
            std::string comment;
            if (argc >= 4 && !argv[3].is_null()) {
                const char* c = argv[3].as_c_str();
                comment = c ? c : "";
            }

            // The tag type MUST already exist (CreateUserDataTag does not auto-create
            // it — measured in the tag lab). BN ships `Bookmarks`, `Important`, … .
            Ref<TagType> tt = bv->GetTagType(type);
            if (!tt) {
                xsql::set_vtab_error(
                    "bookmarks: unknown tag type '" + type +
                    "' (BN does not auto-create tag types; use a built-in such as "
                    "'Bookmarks'/'Important' or create the type in Binary Ninja first)");
                return false;
            }
            Ref<Tag> tag = bv->CreateUserDataTag(addr, tt, comment, /*unique*/false);
            if (!tag) {
                xsql::set_vtab_error("bookmarks: CreateUserDataTag failed");
                return false;
            }
            return true;
        })
        .build();
}

} // namespace symbols
} // namespace bnsql
