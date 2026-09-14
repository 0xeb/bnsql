// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// binary — orientation/metadata table, canonical key/value/type shape
// (one row per fact). This is the family-wide reference implementation of
// the canonical `binary` contract: columns (key TEXT, value TEXT, type TEXT)
// with type in {string, hex, bool, int}. Canonical core keys shared with
// idasql/ghidrasql/r2sql: tool_name, tool_version, processor, filetype,
// image_base, entry_point, min_addr, max_addr, is_64bit, bits, endianness,
// filename, summary. bnsql extra: platform. md5/sha256 are best-effort core
// keys and are not emitted here (Binary Ninja does not surface input-file
// hashes natively).

#include "meta_binary.hpp"

#include <cstdio>
#include <string>

#include "bnsql_version.hpp"

namespace bnsql {
namespace meta {

using namespace BinaryNinja;
using core::get_bv;

namespace {

constexpr size_t kRowCount = 14;

// Row order: summary first (agents doing `SELECT * FROM binary` see the
// digest up top), then tool identity, then canonical keys, then extras.
constexpr const char* kKeys[kRowCount] = {
    "summary",      // 0
    "tool_name",    // 1
    "tool_version", // 2
    "processor",    // 3
    "filetype",     // 4
    "image_base",   // 5
    "entry_point",  // 6
    "min_addr",     // 7
    "max_addr",     // 8
    "is_64bit",     // 9
    "bits",         // 10
    "endianness",   // 11
    "filename",     // 12
    "platform",     // 13
};

constexpr const char* kTypes[kRowCount] = {
    "string", // summary
    "string", // tool_name
    "string", // tool_version
    "string", // processor
    "string", // filetype
    "hex",    // image_base
    "hex",    // entry_point
    "hex",    // min_addr
    "hex",    // max_addr
    "bool",   // is_64bit
    "int",    // bits
    "string", // endianness
    "string", // filename
    "string", // platform
};

// Hex-typed address keys are rendered as 0x-prefixed hex so the "value"
// string matches its declared "type".
std::string hex_u64(uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

}  // namespace

VTableDef define_binary() {
    return table("binary")
        .row_count([]() {
            return kRowCount; // Fixed number of metadata items
        })
        .column_text("key", [](size_t i) -> std::string {
            return i < kRowCount ? kKeys[i] : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";

            auto processor = [&]() -> std::string {
                return bv->GetDefaultArchitecture()
                           ? bv->GetDefaultArchitecture()->GetName() : "";
            };
            auto platform = [&]() -> std::string {
                return bv->GetDefaultPlatform()
                           ? bv->GetDefaultPlatform()->GetName() : "";
            };
            const int bits = static_cast<int>(bv->GetAddressSize()) * 8;

            switch (i) {
                case 0: { // summary — one-line digest (no counts: computing
                          // them would force analysis on a metadata read)
                    std::string s = processor();
                    s += " " + std::to_string(bits) + "-bit";
                    const std::string plat = platform();
                    if (!plat.empty()) s += " | " + plat;
                    s += " | entry: " + hex_u64(bv->GetEntryPoint());
                    return s;
                }
                case 1: return "bnsql";
                case 2: return BNSQL_VERSION_STRING;
                case 3: return processor();
                case 4: return bv->GetTypeName();
                case 5: return hex_u64(bv->GetImageBase());   // image_base: image base of the main input file
                                                              // (GetImageBase — its own thing; NOT min_addr, NOT entry_point)
                case 6: return hex_u64(bv->GetEntryPoint());  // entry_point
                case 7: return hex_u64(bv->GetStart());       // min_addr: first valid/lowest mapped view address
                case 8: return hex_u64(bv->GetEnd());         // max_addr: end virtual address of the view
                case 9: return bv->GetAddressSize() == 8 ? "true" : "false";
                case 10: return std::to_string(bits);
                case 11: return bv->GetDefaultEndianness() == BigEndian
                              ? "big" : "little";
                case 12: return bv->GetFile()->GetFilename();
                case 13: return platform();
                default: return "";
            }
        })
        .column_text("type", [](size_t i) -> std::string {
            return i < kRowCount ? kTypes[i] : "";
        })
        .build();
}

} // namespace meta
} // namespace bnsql
