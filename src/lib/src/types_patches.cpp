// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_patches.hpp"

namespace bnsql {
namespace types {

using namespace BinaryNinja;
using core::get_bv;

CachedTableDef<PatchInfo> define_patches() {
    return cached_table<PatchInfo>("patches")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            // Patches are typically rare; estimate low
            return 100;
        })
        .cache_builder([](std::vector<PatchInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            // Parent/raw view is stable for the whole scan — resolve it once.
            auto parent = bv->GetParentView();

            // Batch-scan each segment for modification status. The array
            // overload GetModification(start, len) answers the whole window in a
            // single FFI round-trip (result[i] is the status of start+i), versus
            // the per-byte GetModification(addr) which cost one core call for
            // every byte of every segment on every (re)build. Window the request
            // so a multi-MB segment doesn't allocate a status array as large as
            // itself in one shot.
            constexpr uint64_t kWindow = 64 * 1024;

            for (auto& seg : bv->GetSegments()) {
                uint64_t addr = seg->GetStart();
                uint64_t end = seg->GetEnd();

                while (addr < end) {
                    uint64_t chunk = std::min<uint64_t>(kWindow, end - addr);
                    // One core round-trip for the whole window. May return fewer
                    // than requested — advance by the actual count so we always
                    // make forward progress and never re-scan a byte.
                    auto mods = bv->GetModification(addr, static_cast<size_t>(chunk));
                    if (mods.empty()) break;  // no progress -> avoid an infinite loop

                    for (size_t i = 0; i < mods.size(); i++) {
                        // The vast majority of bytes are Original — do zero
                        // per-byte work for them.
                        if (mods[i] == Original) continue;
                        uint64_t byte_addr = addr + i;

                        // Read the current (patched) byte. Read() returns the
                        // number of bytes read; a short/failed read (0) means the
                        // address isn't really readable, so skip it rather than
                        // emit a spurious 0x00 patch row.
                        uint8_t patched = 0;
                        if (bv->Read(&patched, byte_addr, 1) != 1) continue;

                        PatchInfo pi;
                        pi.address = byte_addr;
                        pi.patched_byte = patched;

                        // Original byte: the parent/raw view is addressed by file
                        // offset, not VA — translate first, then read. Only trust
                        // a byte we actually read (a short read leaves the buffer
                        // untouched); inserted bytes have no original mapping, so
                        // 0 remains the sentinel there.
                        uint8_t orig = 0;
                        if (parent) {
                            uint64_t file_offset;
                            if (bv->GetDataOffsetForAddress(byte_addr, file_offset)) {
                                uint8_t raw = 0;
                                if (parent->Read(&raw, file_offset, 1) == 1) {
                                    orig = raw;
                                }
                            }
                        }
                        pi.original_byte = orig;

                        pi.status = (mods[i] == Changed) ? "changed" : "inserted";
                        cache.push_back(std::move(pi));
                    }

                    addr += mods.size();
                }
            }
        })
        .column_int64("addr", [](const PatchInfo& r) -> int64_t {
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
        // INSERT INTO patches (addr, patched_byte) VALUES (0x1234, 0x90)
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            // Column order: addr, original_byte, patched_byte, status
            if (argc < 1 || argv[0].is_null()) {
                xsql::set_vtab_error("patches insert requires addr");
                return false;
            }
            uint64_t address = static_cast<uint64_t>(argv[0].as_int64());
            // patched_byte is column 2 (index 2)
            if (argc < 3 || argv[2].is_null()) {
                xsql::set_vtab_error("patches insert requires patched_byte");
                return false;
            }
            int byte_val = argv[2].as_int();
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

} // namespace types
} // namespace bnsql
