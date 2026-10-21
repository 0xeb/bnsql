// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_segments.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace bnsql {
namespace memory {

using namespace BinaryNinja;
using core::get_bv;

namespace {

// Segment bounds are unsigned 64-bit addresses. SQL holds one at or above 2^63
// as a negative INTEGER, so every value is bit-cast and compared unsigned.
// Binary Ninja cannot hold a segment that reaches 2^64: AddUserSegment silently
// shortens it to end at 0xFFFFFFFFFFFFFFFF (measured on Binary Ninja 6.0), so
// that is the highest end_addr -- -1 in SQL -- and an end_addr of 0 is refused,
// not wrapped.
constexpr const char* kSegmentBoundsError =
    "segments: end_addr must be > start_addr (unsigned; an address >= 2^63 is a "
    "negative INTEGER, the highest end_addr is 0xFFFFFFFFFFFFFFFF = -1)";

// perm is R/W/X; a perm change keeps the other flags (ContainsCode/ContainsData).
constexpr uint32_t kPermFlags = SegmentReadable | SegmentWritable | SegmentExecutable;

std::string hex_addr(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

bool valid_segment_bounds(uint64_t start, uint64_t end) {
    if (end <= start) {
        xsql::set_vtab_error(kSegmentBoundsError);
        return false;
    }
    return true;
}

// An INSERT value must be an INTEGER: a decimal literal >= 2^63 is a REAL in
// SQLite and would otherwise clamp to 0x7FFFFFFFFFFFFFFF.
std::optional<uint64_t> address_arg(xsql::FunctionArg& arg, const char* column) {
    const std::optional<int64_t> value = xsql::exact_int64(arg);
    if (!value) {
        xsql::set_vtab_error(std::string("segments: ") + column +
                             " must be an INTEGER address (write one >= 2^63 as a hex "
                             "literal or a negative decimal)");
        return std::nullopt;
    }
    return static_cast<uint64_t>(*value);
}

uint32_t perm_to_segment_flags(int perm) {
    uint32_t flags = 0;
    if (perm & 4) flags |= SegmentReadable;
    if (perm & 2) flags |= SegmentWritable;
    if (perm & 1) flags |= SegmentExecutable;
    return flags;
}

int segment_flags_to_perm(uint32_t flags) {
    int perm = 0;
    if (flags & SegmentReadable) perm |= 4;
    if (flags & SegmentWritable) perm |= 2;
    if (flags & SegmentExecutable) perm |= 1;
    return perm;
}

SegmentRow row_of(const Ref<Segment>& seg) {
    SegmentRow r;
    r.start = seg->GetStart();
    r.end = seg->GetEnd();
    r.data_offset = seg->GetDataOffset();
    r.data_length = seg->GetDataLength();
    r.flags = seg->GetFlags();
    r.auto_defined = seg->IsAutoDefined();
    return r;
}

std::vector<SegmentRow> snapshot(const Ref<BinaryView>& bv) {
    std::vector<SegmentRow> rows;
    for (const auto& seg : bv->GetSegments())
        if (seg) rows.push_back(row_of(seg));
    return rows;
}

bool contains(const std::vector<SegmentRow>& rows, const SegmentRow& r) {
    return std::find(rows.begin(), rows.end(), r) != rows.end();
}

// Rows of `a` that are not in `b`, in `a`'s (unsigned ascending) order.
std::vector<SegmentRow> minus(const std::vector<SegmentRow>& a, const std::vector<SegmentRow>& b) {
    std::vector<SegmentRow> out;
    for (const auto& r : a)
        if (!contains(b, r)) out.push_back(r);
    return out;
}

// The live segment starting exactly at `start` (the table's row identity).
std::optional<SegmentRow> live_row(const Ref<BinaryView>& bv, uint64_t start) {
    auto seg = bv->GetSegmentAt(start);
    if (!seg || seg->GetStart() != start) return std::nullopt;
    return row_of(seg);
}

void add_user_segment(const Ref<BinaryView>& bv, const SegmentRow& r) {
    bv->AddUserSegment(r.start, r.length(), r.data_offset, r.data_length, r.flags);
}

// ---------------------------------------------------------------------------
// Who owns a row. Measured on Binary Ninja 6.0:
//
//   memory region   added to this view through the memory map
//                   (MemoryMap::AddDataMemoryRegion and friends). The active
//                   region at the row's start is *local* to the view.
//                   RemoveUserSegment and AddUserSegment do not touch it; the
//                   region API does (RemoveMemoryRegion, SetMemoryRegionFlags).
//   user segment    AddUserSegment. RemoveUserSegment removes it -- and when
//                   Binary Ninja split it in two rows (data length < length),
//                   both rows.
//   loader segment  the view's own (a PE/ELF section, a raw view's mapping),
//                   including the unbacked tail Binary Ninja splits off a
//                   section, which reports IsAutoDefined() false. Its region is
//                   not local, and RemoveUserSegment removes nothing; but
//                   SetMemoryRegionFlags on its region changes its flags and
//                   persists. Every loader region backs exactly one row (a
//                   section and its unbacked tail are two regions:
//                   origin<PE>@off and unbound_origin<PE>@off).
//
// A region's flags and existence are shared by every row it backs, so a perm
// change or DELETE through the region API is done only when the region backs
// exactly the target row (its own bounds equal the row's): a region split by
// an overlapping segment would otherwise change rows the statement did not
// name. Every write acts on what the row is, or is refused by name with
// nothing changed: none reports success without its effect.
// ---------------------------------------------------------------------------

// The memory region added to this view that the row at `start` comes from.
std::optional<BinaryNinja::MemoryRegionInfo> local_region_at(const Ref<BinaryView>& bv, uint64_t start) {
    MemoryMap* mm = bv->GetMemoryMap();
    if (!mm) return std::nullopt;
    auto info = mm->GetActiveMemoryRegionInfoAt(start);
    if (!info || !info->local || info->name.empty()) return std::nullopt;
    return info;
}

std::string active_region_name(const Ref<BinaryView>& bv, uint64_t start) {
    MemoryMap* mm = bv->GetMemoryMap();
    if (!mm) return "";
    auto info = mm->GetActiveMemoryRegionInfoAt(start);
    return info ? info->name : "";
}

bool refuse_loader(const Ref<BinaryView>& bv, const SegmentRow& row) {
    std::string region = active_region_name(bv, row.start);
    xsql::set_vtab_error(
        "segments: the segment at " + hex_addr(row.start) + " is defined by the loader" +
        (region.empty() ? std::string() : " (memory region '" + region + "')") +
        "; its perm can be changed, but it cannot be deleted, moved or resized "
        "through segments");
    return false;
}

// The region's own definition, when it backs exactly `row`; otherwise the
// vtab error names the region and its bounds (it backs other rows too).
std::optional<BinaryNinja::MemoryRegionInfo> region_of_row_only(
    const Ref<BinaryView>& bv, const SegmentRow& row, const std::string& name, const char* what) {
    MemoryMap* mm = bv->GetMemoryMap();
    auto info = mm ? mm->GetMemoryRegionInfo(name) : std::nullopt;
    if (!info) {
        xsql::set_vtab_error("segments: memory region '" + name + "' of the segment at " +
                             hex_addr(row.start) + " is not in the memory map");
        return std::nullopt;
    }
    if (info->start != row.start || info->length != row.length()) {
        xsql::set_vtab_error(
            "segments: memory region '" + name + "' [" + hex_addr(info->start) + ", " +
            hex_addr(info->start + info->length) + ") backs more than the segment at " +
            hex_addr(row.start) + "; " + what + " would change its other rows too");
        return std::nullopt;
    }
    return info;
}

// perm of a row backed by a region (added to the view, or the loader's): set
// the region's R/W/X and check that exactly this row changed, and only its
// perm; otherwise put the flags back.
bool set_region_perm(const Ref<BinaryView>& bv, const SegmentRow& row, const std::string& name,
                     uint32_t perm_flags) {
    auto info = region_of_row_only(bv, row, name, "a perm change");
    if (!info) return false;
    MemoryMap* mm = bv->GetMemoryMap();
    const auto before = snapshot(bv);
    mm->SetMemoryRegionFlags(name, (info->flags & ~kPermFlags) | perm_flags);
    const auto after = snapshot(bv);
    const auto gone = minus(before, after);
    const auto made = minus(after, before);
    const bool ok = gone.size() == 1 && gone[0] == row && made.size() == 1 &&
                    made[0].start == row.start && made[0].end == row.end &&
                    (made[0].flags & kPermFlags) == perm_flags;
    if (ok) return true;
    mm->SetMemoryRegionFlags(name, info->flags);
    xsql::set_vtab_error("segments: Binary Ninja did not change the perm of the segment at " +
                         hex_addr(row.start) + " alone (memory region '" + name +
                         "'); nothing was changed");
    return false;
}

bool refuse_region_bounds(const SegmentRow& row, const std::string& region) {
    xsql::set_vtab_error(
        "segments: the segment at " + hex_addr(row.start) + " comes from memory region '" +
        region + "'; start_addr/end_addr of a memory region cannot be changed through "
        "segments (a region is a mapped view, not a segment edit)");
    return false;
}

// Remove the user segment behind `row` and put back every other row the removal
// took (the other half of a segment Binary Ninja split in two), so exactly `row`
// is gone. Returns false, with nothing changed, when the removal took nothing:
// the row is the loader's.
bool detach_user_row(const Ref<BinaryView>& bv, const SegmentRow& row) {
    const auto before = snapshot(bv);
    bv->RemoveUserSegment(row.start, row.length());
    const auto gone = minus(before, snapshot(bv));
    if (!contains(gone, row)) {
        for (const auto& r : gone) add_user_segment(bv, r);
        return false;
    }
    for (const auto& r : gone)
        if (!(r == row)) add_user_segment(bv, r);
    return true;
}

// The first row overlapping [start, end), if any.
std::optional<SegmentRow> overlapping(const std::vector<SegmentRow>& rows,
                                      uint64_t start, uint64_t end) {
    for (const auto& r : rows)
        if (r.start < end && start < r.end) return r;
    return std::nullopt;
}

bool refuse_overlap(uint64_t start, uint64_t end, const SegmentRow& other) {
    xsql::set_vtab_error(
        "segments: [" + hex_addr(start) + ", " + hex_addr(end) + ") overlaps the segment at " +
        hex_addr(other.start) + " (to " + hex_addr(other.end) +
        "); delete or shrink that segment first");
    return false;
}

// Add `want` as a user segment where nothing is mapped, and check Binary
// Ninja did it: the rows the add created must tile exactly [want.start,
// want.end) with want's perm, and no other row may change. On failure the add
// is undone and the vtab error says why.
bool place_user_row(const Ref<BinaryView>& bv, const SegmentRow& want) {
    const auto mid = snapshot(bv);
    if (auto other = overlapping(mid, want.start, want.end))
        return refuse_overlap(want.start, want.end, *other);
    add_user_segment(bv, want);
    const auto after = snapshot(bv);
    const auto made = minus(after, mid);
    bool ok = !made.empty() && minus(mid, after).empty() && made.front().start == want.start &&
              made.back().end == want.end;
    for (size_t i = 0; ok && i < made.size(); ++i) {
        ok = (made[i].flags & kPermFlags) == (want.flags & kPermFlags) &&
             (i + 1 == made.size() || made[i].end == made[i + 1].start);
    }
    if (ok) return true;
    bv->RemoveUserSegment(want.start, want.length());
    xsql::set_vtab_error("segments: Binary Ninja did not map [" + hex_addr(want.start) + ", " +
                         hex_addr(want.end) + ") as asked; nothing was changed");
    return false;
}

// Replace the user row `row` with `want`: detach it, place `want`, and put
// `row` back if `want` cannot be placed.
bool replace_user_row(const Ref<BinaryView>& bv, const SegmentRow& row, const SegmentRow& want) {
    if (!detach_user_row(bv, row)) return refuse_loader(bv, row);
    if (place_user_row(bv, want)) return true;
    const std::string err = xsql::get_vtab_error();
    add_user_segment(bv, row);
    xsql::set_vtab_error(err);
    return false;
}

void reload(SegmentRow& r, const Ref<BinaryView>& bv, uint64_t start) {
    if (auto live = live_row(bv, start)) r = *live;
}

// The live row the setter was handed (row_lookup resolved it at the start of
// the statement; an earlier setter of the same UPDATE may have moved it, and
// then updated `r`).
std::optional<SegmentRow> current(const Ref<BinaryView>& bv, const SegmentRow& r) {
    auto live = live_row(bv, r.start);
    if (!live) {
        xsql::set_vtab_error("segments: no segment starts at " + hex_addr(r.start) + " any more");
        return std::nullopt;
    }
    return live;
}

bool set_start(SegmentRow& r, int64_t new_start_s) {
    auto bv = get_bv();
    if (!bv) return false;
    auto row = current(bv, r);
    if (!row) return false;
    const uint64_t new_start = static_cast<uint64_t>(new_start_s);
    if (new_start == row->start) return true;
    if (auto region = local_region_at(bv, row->start))
        return refuse_region_bounds(*row, region->name);
    if (row->length() > std::numeric_limits<uint64_t>::max() - new_start) {
        xsql::set_vtab_error(
            "segments: moved there the segment would end past "
            "0xFFFFFFFFFFFFFFFF, the highest end_addr");
        return false;
    }
    SegmentRow want = *row;
    want.start = new_start;
    want.end = new_start + row->length();
    if (!replace_user_row(bv, *row, want)) return false;
    reload(r, bv, new_start);
    return true;
}

bool set_end(SegmentRow& r, int64_t new_end_s) {
    auto bv = get_bv();
    if (!bv) return false;
    auto row = current(bv, r);
    if (!row) return false;
    const uint64_t new_end = static_cast<uint64_t>(new_end_s);
    if (!valid_segment_bounds(row->start, new_end)) return false;
    if (new_end == row->end) return true;
    if (auto region = local_region_at(bv, row->start))
        return refuse_region_bounds(*row, region->name);
    SegmentRow want = *row;
    want.end = new_end;
    want.data_length = std::min(row->data_length, want.length());
    if (!replace_user_row(bv, *row, want)) return false;
    reload(r, bv, row->start);
    return true;
}

bool set_perm(SegmentRow& r, int new_perm) {
    auto bv = get_bv();
    if (!bv) return false;
    if (new_perm < 0 || new_perm > 7) {
        xsql::set_vtab_error("segments: perm must be 0..7");
        return false;
    }
    auto row = current(bv, r);
    if (!row) return false;
    if (segment_flags_to_perm(row->flags) == new_perm) return true;
    const uint32_t perm_flags = perm_to_segment_flags(new_perm);
    if (auto region = local_region_at(bv, row->start)) {
        if (!set_region_perm(bv, *row, region->name, perm_flags)) return false;
    } else if (detach_user_row(bv, *row)) {
        // A user segment: re-add it with the new perm.
        SegmentRow want = *row;
        want.flags = (row->flags & ~kPermFlags) | perm_flags;
        if (!place_user_row(bv, want)) {
            const std::string err = xsql::get_vtab_error();
            add_user_segment(bv, *row);
            xsql::set_vtab_error(err);
            return false;
        }
    } else {
        // The loader's: RemoveUserSegment took nothing, so set its region's flags.
        const std::string name = active_region_name(bv, row->start);
        if (name.empty()) return refuse_loader(bv, *row);
        if (!set_region_perm(bv, *row, name, perm_flags)) return false;
    }
    reload(r, bv, row->start);
    return true;
}

bool delete_row(SegmentRow& r) {
    auto bv = get_bv();
    if (!bv) return false;
    auto row = current(bv, r);
    if (!row) return false;
    if (auto region = local_region_at(bv, row->start)) {
        if (!region_of_row_only(bv, *row, region->name, "removing it")) return false;
        MemoryMap* mm = bv->GetMemoryMap();
        if (!mm->RemoveMemoryRegion(region->name) || live_row(bv, row->start) == row) {
            xsql::set_vtab_error("segments: Binary Ninja did not remove memory region '" +
                                 region->name + "'");
            return false;
        }
        return true;
    }
    if (!detach_user_row(bv, *row)) return refuse_loader(bv, *row);
    return true;
}

bool insert_row(int argc, xsql::FunctionArg* argv) {
    auto bv = get_bv();
    if (!bv) return false;
    // cols: 0 start_addr, 1 end_addr, 2 name, 3 class, 4 perm.
    // NOTE: name (col 2) and class (col 3) are intentionally ignored on
    // INSERT. Binary Ninja segments carry no stored name or class: the
    // read-side `name` is derived from the start address (seg_<addr>) and
    // `class` is derived from the segment's R/W/X flags (CODE vs DATA).
    // AddUserSegment() takes no name, and class always follows perm, so a
    // supplied name/class cannot round-trip and is not persisted. The
    // segment's identity is (start_addr, end_addr, perm) only.
    if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
        xsql::set_vtab_error("segments: start_addr and end_addr are required");
        return false;
    }
    const std::optional<uint64_t> start = address_arg(argv[0], "start_addr");
    if (!start) return false;
    const std::optional<uint64_t> end = address_arg(argv[1], "end_addr");
    if (!end) return false;
    if (!valid_segment_bounds(*start, *end)) return false;
    int perm = 6; // default RW-
    if (argc > 4 && !argv[4].is_null()) {
        perm = argv[4].as_int();
        if (perm < 0 || perm > 7) {
            xsql::set_vtab_error("segments: perm must be 0..7");
            return false;
        }
    }
    // dataOffset/dataLength = 0 -> an unbacked (zero-init) region, e.g. SRAM.
    SegmentRow want;
    want.start = *start;
    want.end = *end;
    want.flags = perm_to_segment_flags(perm);
    return place_user_row(bv, want);
}

}  // namespace

CachedTableDef<SegmentRow> define_segments() {
    return cached_table<SegmentRow>("segments")
        // Writable: a persistent cache would go stale after a write.
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetSegments().size() : 0;
        })
        .row_count([]() -> size_t {
            auto bv = get_bv();
            return bv ? bv->GetSegments().size() : 0;
        })
        .cache_builder([](std::vector<SegmentRow>& cache) {
            auto bv = get_bv();
            if (bv) cache = snapshot(bv);
        })
        // Row identity is the start address (segments are disjoint), so each row
        // of a multi-row UPDATE/DELETE is the segment it was when the statement
        // began, however earlier rows moved or went away.
        .rowid([](const SegmentRow& r) -> int64_t { return static_cast<int64_t>(r.start); })
        .row_lookup([](SegmentRow& r, int64_t rowid) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto live = live_row(bv, static_cast<uint64_t>(rowid));
            if (!live) {
                xsql::set_vtab_error("segments: no segment starts at " +
                                     hex_addr(static_cast<uint64_t>(rowid)));
                return false;
            }
            r = *live;
            return true;
        })
        // UPDATE start_addr moves (rebases) a user segment; end_addr resizes it.
        .column_int64_rw("start_addr",
            [](const SegmentRow& r) -> int64_t { return static_cast<int64_t>(r.start); },
            [](SegmentRow& r, int64_t v) -> bool { return set_start(r, v); })
        .column_int64_rw("end_addr",
            [](const SegmentRow& r) -> int64_t { return static_cast<int64_t>(r.end); },
            [](SegmentRow& r, int64_t v) -> bool { return set_end(r, v); })
        // Segments don't have names in BN, use an address-based name.
        .column_text("name", [](const SegmentRow& r) -> std::string {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "seg_%llx", static_cast<unsigned long long>(r.start));
            return buf;
        })
        // IDA-style class from the flags.
        .column_text("class", [](const SegmentRow& r) -> std::string {
            return (r.flags & SegmentExecutable) ? "CODE" : "DATA";
        })
        .column_int_rw("perm",
            [](const SegmentRow& r) -> int { return segment_flags_to_perm(r.flags); },
            [](SegmentRow& r, int v) -> bool { return set_perm(r, v); })
        .deletable([](SegmentRow& r) -> bool { return delete_row(r); })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool { return insert_row(argc, argv); })
        .build();
}

} // namespace memory
} // namespace bnsql
