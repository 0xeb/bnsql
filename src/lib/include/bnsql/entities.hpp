// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * entities.hpp - Binary Ninja entity definitions for SQLite virtual tables
 *
 * Defines all BN entities as virtual tables using the xsql framework.
 * Schema is designed to be compatible with idasql wherever possible.
 *
 * Tables:
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
#include <xsql/database.hpp>

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
// Schema: address, name, size, end_ea, flags
// Compatible with idasql funcs table
// Supports: SELECT, UPDATE (name), DELETE, INSERT
// ============================================================================

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
                auto funcs = bv->GetAnalysisFunctionList();
                if (i >= funcs.size()) return false;
                auto func = funcs[i];
                // Create user symbol at function start
                auto sym = new Symbol(FunctionSymbol, new_name, func->GetStart());
                bv->DefineUserSymbol(sym);
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
        // DELETE support - remove function from analysis
        .deletable([](size_t i) -> bool {
            auto bv = get_bv();
            if (!bv) return false;
            auto funcs = bv->GetAnalysisFunctionList();
            if (i >= funcs.size()) return false;
            auto func = funcs[i];
            bv->RemoveUserFunction(func);
            return true;
        })
        // INSERT support - create new function at address
        // INSERT INTO funcs (address, name) VALUES (0x1234, 'my_func')
        .insertable([](int argc, sqlite3_value** argv) -> bool {
            auto bv = get_bv();
            if (!bv) return false;

            // Column order: address, name, size, end_ea, flags
            // We need at least address (column 0)
            if (argc < 1) return false;

            // Get address from first column
            if (sqlite3_value_type(argv[0]) == SQLITE_NULL) return false;
            uint64_t address = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

            // Create user function at address
            auto platform = bv->GetDefaultPlatform();
            if (!platform) return false;

            auto func = bv->CreateUserFunction(platform, address);
            if (!func) return false;

            // If name is provided (column 1), set it
            if (argc >= 2 && sqlite3_value_type(argv[1]) != SQLITE_NULL) {
                const char* name = reinterpret_cast<const char*>(sqlite3_value_text(argv[1]));
                if (name && name[0]) {
                    auto sym = new Symbol(FunctionSymbol, name, address);
                    bv->DefineUserSymbol(sym);
                }
            }

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
                auto syms = bv->GetSymbols();
                if (i >= syms.size()) return false;
                auto old_sym = syms[i];
                auto new_sym = new Symbol(old_sym->GetType(), new_name, old_sym->GetAddress());
                bv->DefineUserSymbol(new_sym);
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

inline VTableDef define_strings() {
    return table("strings")
        .count([]() {
            auto bv = get_bv();
            return bv ? bv->GetStrings().size() : 0;
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto bv = get_bv();
            if (!bv) return 0;
            auto strs = bv->GetStrings();
            if (i >= strs.size()) return 0;
            return static_cast<int64_t>(strs[i].start);
        })
        .column_int("length", [](size_t i) -> int {
            auto bv = get_bv();
            if (!bv) return 0;
            auto strs = bv->GetStrings();
            if (i >= strs.size()) return 0;
            return static_cast<int>(strs[i].length);
        })
        .column_int("type", [](size_t i) -> int {
            auto bv = get_bv();
            if (!bv) return 0;
            auto strs = bv->GetStrings();
            if (i >= strs.size()) return 0;
            return static_cast<int>(strs[i].type);
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";
            auto strs = bv->GetStrings();
            if (i >= strs.size()) return "";
            switch (strs[i].type) {
                case AsciiString: return "ascii";
                case Utf16String: return "utf16";
                case Utf32String: return "utf32";
                default: return "unknown";
            }
        })
        .column_text("content", [](size_t i) -> std::string {
            auto bv = get_bv();
            if (!bv) return "";
            auto strs = bv->GetStrings();
            if (i >= strs.size()) return "";
            auto& s = strs[i];
            // Read string content from binary
            DataBuffer buf = bv->ReadBuffer(s.start, s.length);
            return std::string(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());
        })
        .build();
}

// ============================================================================
// XREFS Table - Cross-references
// Schema: from_ea, to_ea, type, is_code
// Compatible with idasql xrefs table
// ============================================================================

struct XrefInfo {
    uint64_t from_ea;
    uint64_t to_ea;
    int type;
    bool is_code;
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

            // Collect code references from all functions
            for (auto& func : bv->GetAnalysisFunctionList()) {
                uint64_t func_addr = func->GetStart();

                // Xrefs TO this function (callers)
                for (auto& ref : bv->GetCodeReferences(func_addr)) {
                    XrefInfo xi;
                    xi.from_ea = ref.addr;
                    xi.to_ea = func_addr;
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
        .column_int("type", [](const XrefInfo& r) -> int {
            return r.type;
        })
        .column_int("is_code", [](const XrefInfo& r) -> int {
            return r.is_code ? 1 : 0;
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
// COMMENTS Table
// Schema: address, comment, rpt_comment
// Compatible with idasql comments table
// ============================================================================

// Note: BN comments are simpler - no repeatable comments like IDA
// We'll store in a vector and rebuild on access

inline VTableDef define_comments() {
    // For now, a minimal implementation
    // Full implementation would iterate all addresses with comments
    return table("comments")
        .count([]() {
            // Count would require iterating all addresses
            // Return 0 for now - this table needs optimization
            return size_t(0);
        })
        .column_int64("address", [](size_t) -> int64_t { return 0; })
        .column_text("comment", [](size_t) -> std::string { return ""; })
        .column_text("rpt_comment", [](size_t) -> std::string { return ""; })
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
// Table Registry - All tables in one place
// ============================================================================

struct TableRegistry {
    VTableDef funcs;
    VTableDef segments;
    VTableDef names;
    VTableDef entries;
    VTableDef strings;
    VTableDef comments;
    VTableDef db_info;

    CachedTableDef<XrefInfo> xrefs;
    CachedTableDef<BlockInfo> blocks;
    CachedTableDef<ImportInfo> imports;
    CachedTableDef<InsnInfo> instructions;

    TableRegistry()
        : funcs(define_funcs())
        , segments(define_segments())
        , names(define_names())
        , entries(define_entries())
        , strings(define_strings())
        , comments(define_comments())
        , db_info(define_db_info())
        , xrefs(define_xrefs())
        , blocks(define_blocks())
        , imports(define_imports())
        , instructions(define_instructions())
    {}

    void register_all(xsql::Database& db) {
        // Index-based tables
        register_index_table(db, "funcs", &funcs);
        register_index_table(db, "segments", &segments);
        register_index_table(db, "names", &names);
        register_index_table(db, "entries", &entries);
        register_index_table(db, "strings", &strings);
        register_index_table(db, "comments", &comments);
        register_index_table(db, "db_info", &db_info);

        // Cached tables
        register_cached_table(db, "xrefs", &xrefs);
        register_cached_table(db, "blocks", &blocks);
        register_cached_table(db, "imports", &imports);
        register_cached_table(db, "instructions", &instructions);

        // Create convenience views for common queries
        create_helper_views(db);
    }

    void create_helper_views(xsql::Database& db) {
        // callers view - who calls a function
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callers AS
            SELECT
                x.to_ea as func_addr,
                x.from_ea as caller_addr,
                f.name as caller_name,
                f.address as caller_func_addr
            FROM xrefs x
            LEFT JOIN funcs f ON x.from_ea >= f.address
                AND x.from_ea < f.address + f.size
            WHERE x.is_code = 1
        )");

        // callees view - what does a function call
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callees AS
            SELECT
                f.address as func_addr,
                f.name as func_name,
                x.to_ea as callee_addr,
                COALESCE(f2.name, n.name, printf('sub_%X', x.to_ea)) as callee_name
            FROM funcs f
            JOIN xrefs x ON x.from_ea >= f.address
                AND x.from_ea < f.address + f.size
            LEFT JOIN funcs f2 ON x.to_ea = f2.address
            LEFT JOIN names n ON x.to_ea = n.address
            WHERE x.is_code = 1
        )");

        // string_refs view - which functions reference which strings
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS string_refs AS
            SELECT
                s.address as string_addr,
                s.content as string_value,
                s.length as string_length,
                x.from_ea as ref_addr,
                f.address as func_addr,
                f.name as func_name
            FROM strings s
            JOIN xrefs x ON x.to_ea = s.address
            LEFT JOIN funcs f ON x.from_ea >= f.address
                AND x.from_ea < f.address + f.size
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
