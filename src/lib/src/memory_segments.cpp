// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_segments.hpp"

namespace bnsql {
namespace memory {

using namespace BinaryNinja;
using core::get_bv;

uint32_t perm_to_segment_flags(int perm) {
    uint32_t flags = 0;
    if (perm & 4) flags |= SegmentReadable;
    if (perm & 2) flags |= SegmentWritable;
    if (perm & 1) flags |= SegmentExecutable;
    return flags;
}
VTableDef define_segments() {
    return table("segments")
        .row_count([]() {
            auto bv = get_bv();
            return bv ? bv->GetSegments().size() : 0;
        })
        // Canonical address columns (writable).
        .column_int64_rw("start_addr",
            [](size_t i) -> int64_t {
                auto bv = get_bv();
                if (!bv) return 0;
                auto segs = bv->GetSegments();
                if (i >= segs.size()) return 0;
                return static_cast<int64_t>(segs[i]->GetStart());
            },
            // Setter - rebase: move the user segment to a new start address.
            [](size_t i, int64_t new_start) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto segs = bv->GetSegments();
                if (i >= segs.size()) { xsql::set_vtab_error("segments: index out of range"); return false; }
                if (new_start < 0) { xsql::set_vtab_error("segments: invalid start_addr"); return false; }
                auto seg = segs[i];
                uint64_t len = seg->GetLength();
                uint64_t data_off = seg->GetDataOffset();
                uint64_t data_len = seg->GetDataLength();
                uint32_t flags = seg->GetFlags();
                bv->RemoveUserSegment(seg->GetStart(), len);
                bv->AddUserSegment(static_cast<uint64_t>(new_start), len, data_off, data_len, flags);
                return true;
            })
        .column_int64_rw("end_addr",
            [](size_t i) -> int64_t {
                auto bv = get_bv();
                if (!bv) return 0;
                auto segs = bv->GetSegments();
                if (i >= segs.size()) return 0;
                return static_cast<int64_t>(segs[i]->GetEnd());
            },
            // Setter - resize: change the user segment end (re-add with new length).
            [](size_t i, int64_t new_end) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto segs = bv->GetSegments();
                if (i >= segs.size()) { xsql::set_vtab_error("segments: index out of range"); return false; }
                auto seg = segs[i];
                uint64_t start = seg->GetStart();
                if (new_end <= static_cast<int64_t>(start)) {
                    xsql::set_vtab_error("segments: end_addr must be > start_addr");
                    return false;
                }
                uint64_t new_len = static_cast<uint64_t>(new_end) - start;
                uint64_t data_off = seg->GetDataOffset();
                uint64_t data_len = seg->GetDataLength();
                if (data_len > new_len) data_len = new_len;
                uint32_t flags = seg->GetFlags();
                bv->RemoveUserSegment(start, seg->GetLength());
                bv->AddUserSegment(start, new_len, data_off, data_len, flags);
                return true;
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
        .column_int_rw("perm",
            [](size_t i) -> int {
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
            },
            // Setter - change permissions (re-add the user segment with new flags).
            [](size_t i, int new_perm) -> bool {
                auto bv = get_bv();
                if (!bv) return false;
                auto segs = bv->GetSegments();
                if (i >= segs.size()) { xsql::set_vtab_error("segments: index out of range"); return false; }
                if (new_perm < 0 || new_perm > 7) { xsql::set_vtab_error("segments: perm must be 0..7"); return false; }
                auto seg = segs[i];
                bv->RemoveUserSegment(seg->GetStart(), seg->GetLength());
                bv->AddUserSegment(seg->GetStart(), seg->GetLength(), seg->GetDataOffset(),
                                   seg->GetDataLength(), perm_to_segment_flags(new_perm));
                return true;
            })
        .deletable([](size_t i) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto segs = bv->GetSegments();
            if (i >= segs.size()) return false;
            bv->RemoveUserSegment(segs[i]->GetStart(), segs[i]->GetLength());
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
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
            int64_t start = argv[0].as_int64();
            int64_t end = argv[1].as_int64();
            if (start < 0 || end <= start) {
                xsql::set_vtab_error("segments: end_addr must be > start_addr");
                return false;
            }
            int perm = 6; // default RW-
            if (argc > 4 && !argv[4].is_null()) {
                perm = argv[4].as_int();
                if (perm < 0 || perm > 7) { xsql::set_vtab_error("segments: perm must be 0..7"); return false; }
            }
            // dataOffset/dataLength = 0 -> an unbacked (zero-init) region, e.g. SRAM.
            bv->AddUserSegment(static_cast<uint64_t>(start), static_cast<uint64_t>(end - start),
                               0, 0, perm_to_segment_flags(perm));
            return true;
        })
        .build();
}

} // namespace memory
} // namespace bnsql
