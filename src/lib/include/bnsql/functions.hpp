// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * functions.hpp - Custom SQL functions for Binary Ninja operations
 *
 * Compatible with idasql functions where applicable.
 *
 * Query Functions:
 *   - disasm(address)           - Get disassembly line at address
 *   - disasm(address, count)    - Get multiple disassembly lines
 *   - bytes(address, count)     - Get bytes as hex string
 *   - bytes_raw(address, count) - Get bytes as blob
 *   - name_at(address)          - Get name at address
 *   - func_at(address)          - Get function name containing address
 *   - func_start(address)       - Get start address of function containing address
 *   - func_end(address)         - Get end address of function containing address
 *   - xrefs_to(address)         - Get xrefs to address (JSON array)
 *   - xrefs_from(address)       - Get xrefs from address (JSON array)
 *   - segment_at(address)       - Get segment name containing address
 *   - comment_at(address)       - Get comment at address
 *   - set_comment(address, text) - Set comment at address
 *   - set_name(address, name)   - Set name at address
 *
 * Navigation:
 *   - next_head(address)        - Get next defined head
 *   - prev_head(address)        - Get previous defined head
 *   - hex(value)                - Format integer as hex string
 *
 * Function Index (O(1)):
 *   - func_qty()                - Get total function count
 *   - func_at_index(n)          - Get function address at index n
 */

#pragma once

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include "binaryninjaapi.h"
#include <bnsql/entities.hpp>

namespace bnsql {
namespace functions {

using namespace BinaryNinja;

// ============================================================================
// Helper: Get current BinaryView from context
// ============================================================================

inline Ref<BinaryView> get_bv() {
    return entities::get_bv();
}

// ============================================================================
// Disassembly Functions
// ============================================================================

static void sql_disasm(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "disasm requires at least 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        sqlite3_result_error(ctx, "No architecture", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    int count = (argc >= 2) ? sqlite3_value_int(argv[1]) : 1;
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;

    std::ostringstream result;
    for (int i = 0; i < count && ea < bv->GetEnd(); i++) {
        size_t len = bv->GetInstructionLength(arch, ea);
        if (len == 0) break;

        std::vector<InstructionTextToken> tokens;
        size_t instrLen = 0;
        DataBuffer buf = bv->ReadBuffer(ea, 16);
        arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens);

        if (i > 0) result << "\n";
        result << std::hex << ea << ": ";
        for (auto& tok : tokens) {
            result << tok.text;
        }

        ea += len;
    }

    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Bytes Functions
// ============================================================================

static void sql_bytes_hex(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "bytes requires 2 arguments (address, count)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    size_t count = static_cast<size_t>(sqlite3_value_int(argv[1]));
    if (count > 4096) count = 4096;

    DataBuffer buf = bv->ReadBuffer(ea, count);

    std::ostringstream result;
    result << std::hex << std::setfill('0');
    const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
    for (size_t i = 0; i < buf.GetLength(); i++) {
        if (i > 0) result << " ";
        result << std::setw(2) << static_cast<int>(data[i]);
    }

    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

static void sql_bytes_raw(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "bytes_raw requires 2 arguments (address, count)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    size_t count = static_cast<size_t>(sqlite3_value_int(argv[1]));
    if (count > 4096) count = 4096;

    DataBuffer buf = bv->ReadBuffer(ea, count);
    sqlite3_result_blob(ctx, buf.GetData(), static_cast<int>(buf.GetLength()), SQLITE_TRANSIENT);
}

// ============================================================================
// Name Functions
// ============================================================================

static void sql_name_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "name_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    auto sym = bv->GetSymbolByAddress(ea);

    if (sym) {
        std::string name = sym->GetFullName();
        sqlite3_result_text(ctx, name.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

static void sql_func_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        auto sym = funcs[0]->GetSymbol();
        std::string name = sym ? sym->GetFullName() : "";
        if (name.empty()) {
            char buf[32];
            snprintf(buf, sizeof(buf), "sub_%llx", (unsigned long long)funcs[0]->GetStart());
            name = buf;
        }
        sqlite3_result_text(ctx, name.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

static void sql_func_start(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_start requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        sqlite3_result_int64(ctx, static_cast<int64_t>(funcs[0]->GetStart()));
    } else {
        sqlite3_result_null(ctx);
    }
}

static void sql_func_end(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_end requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        sqlite3_result_int64(ctx, static_cast<int64_t>(funcs[0]->GetHighestAddress()));
    } else {
        sqlite3_result_null(ctx);
    }
}

// ============================================================================
// Function Index Functions (O(1) access)
// ============================================================================

static void sql_func_qty(sqlite3_context* ctx, int, sqlite3_value**) {
    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_int64(ctx, 0);
        return;
    }
    sqlite3_result_int64(ctx, static_cast<int64_t>(bv->GetAnalysisFunctionList().size()));
}

static void sql_func_at_index(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_at_index requires 1 argument (index)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_null(ctx);
        return;
    }

    size_t idx = static_cast<size_t>(sqlite3_value_int64(argv[0]));
    auto funcs = bv->GetAnalysisFunctionList();

    if (idx < funcs.size()) {
        sqlite3_result_int64(ctx, static_cast<int64_t>(funcs[idx]->GetStart()));
    } else {
        sqlite3_result_null(ctx);
    }
}

// ============================================================================
// Name Modification Functions
// ============================================================================

static void sql_set_name(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "set_name requires 2 arguments (address, name)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    const char* name = (const char*)sqlite3_value_text(argv[1]);

    if (!name) {
        sqlite3_result_int(ctx, 0);
        return;
    }

    auto sym = new Symbol(DataSymbol, name, ea);
    bv->DefineUserSymbol(sym);
    sqlite3_result_int(ctx, 1);
}

// ============================================================================
// Segment Functions
// ============================================================================

static void sql_segment_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "segment_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    for (auto& seg : bv->GetSegments()) {
        if (ea >= seg->GetStart() && ea < seg->GetEnd()) {
            // Segments don't have names in BN, use address-based name
            char buf[32];
            snprintf(buf, sizeof(buf), "seg_%llx", (unsigned long long)seg->GetStart());
            sqlite3_result_text(ctx, buf, -1, SQLITE_TRANSIENT);
            return;
        }
    }
    sqlite3_result_null(ctx);
}

// ============================================================================
// Comment Functions
// ============================================================================

static void sql_comment_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "comment_at requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    std::string comment = bv->GetCommentForAddress(ea);

    if (!comment.empty()) {
        sqlite3_result_text(ctx, comment.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        // Try function comment
        auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
        if (!funcs.empty()) {
            comment = funcs[0]->GetCommentForAddress(ea);
            if (!comment.empty()) {
                sqlite3_result_text(ctx, comment.c_str(), -1, SQLITE_TRANSIENT);
                return;
            }
        }
        sqlite3_result_null(ctx);
    }
}

static void sql_set_comment(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "set_comment requires 2 arguments (address, text)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    const char* cmt = (const char*)sqlite3_value_text(argv[1]);

    bv->SetCommentForAddress(ea, cmt ? cmt : "");
    sqlite3_result_int(ctx, 1);
}

// ============================================================================
// Cross-Reference Functions
// ============================================================================

static void sql_xrefs_to(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xrefs_to requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    std::ostringstream json;
    json << "[";
    bool first = true;

    // Code references to this address
    for (auto& ref : bv->GetCodeReferences(ea)) {
        if (!first) json << ",";
        first = false;
        json << "{\"from\":" << ref.addr << ",\"type\":0}";
    }

    // Data references to this address
    for (auto& ref : bv->GetDataReferences(ea)) {
        if (!first) json << ",";
        first = false;
        json << "{\"from\":" << ref << ",\"type\":1}";
    }

    json << "]";
    std::string str = json.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

static void sql_xrefs_from(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xrefs_from requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    std::ostringstream json;
    json << "[";
    bool first = true;

    // Code references from this address - need to create ReferenceSource
    auto arch = bv->GetDefaultArchitecture();
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (!funcs.empty() && arch) {
        ReferenceSource src;
        src.func = funcs[0];
        src.arch = arch;
        src.addr = ea;

        for (auto& ref : bv->GetCodeReferencesFrom(src)) {
            if (!first) json << ",";
            first = false;
            json << "{\"to\":" << ref << ",\"type\":0}";
        }
    }

    // Data references from this address
    for (auto& ref : bv->GetDataReferencesFrom(ea)) {
        if (!first) json << ",";
        first = false;
        json << "{\"to\":" << ref << ",\"type\":1}";
    }

    json << "]";
    std::string str = json.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Navigation Functions
// ============================================================================

static void sql_next_head(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "next_head requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        sqlite3_result_null(ctx);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    // Get instruction length at current address
    size_t len = bv->GetInstructionLength(arch, ea);
    if (len > 0) {
        sqlite3_result_int64(ctx, static_cast<int64_t>(ea + len));
    } else {
        // Try next valid offset
        uint64_t next = bv->GetNextValidOffset(ea);
        if (next > ea && next < bv->GetEnd()) {
            sqlite3_result_int64(ctx, static_cast<int64_t>(next));
        } else {
            sqlite3_result_null(ctx);
        }
    }
}

static void sql_prev_head(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "prev_head requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));

    // BN doesn't have GetPreviousValidOffset, use simple approach
    // Try to find previous instruction by scanning backwards
    if (ea <= bv->GetStart()) {
        sqlite3_result_null(ctx);
        return;
    }

    // Simple heuristic: go back by max instruction size and scan forward
    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        sqlite3_result_null(ctx);
        return;
    }

    uint64_t scan_start = (ea > 16) ? ea - 16 : bv->GetStart();
    uint64_t prev_addr = scan_start;
    uint64_t curr = scan_start;

    while (curr < ea) {
        size_t len = bv->GetInstructionLength(arch, curr);
        if (len == 0) {
            curr++;
            continue;
        }
        prev_addr = curr;
        curr += len;
    }

    if (prev_addr < ea && prev_addr >= bv->GetStart()) {
        sqlite3_result_int64(ctx, static_cast<int64_t>(prev_addr));
    } else {
        sqlite3_result_null(ctx);
    }
}

static void sql_hex(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "hex requires 1 argument (value)", -1);
        return;
    }

    int64_t val = sqlite3_value_int64(argv[0]);
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
    sqlite3_result_text(ctx, buf, -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Item Query Functions
// ============================================================================

static void sql_mnemonic(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "mnemonic requires 1 argument (address)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        sqlite3_result_null(ctx);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    std::vector<InstructionTextToken> tokens;
    size_t instrLen = 0;
    DataBuffer buf = bv->ReadBuffer(ea, 16);
    arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens);

    for (auto& tok : tokens) {
        if (tok.type == InstructionToken) {
            sqlite3_result_text(ctx, tok.text.c_str(), -1, SQLITE_TRANSIENT);
            return;
        }
    }
    sqlite3_result_null(ctx);
}

static void sql_operand(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "operand requires 2 arguments (address, operand_num)", -1);
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        sqlite3_result_error(ctx, "No BinaryView context", -1);
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        sqlite3_result_null(ctx);
        return;
    }

    uint64_t ea = static_cast<uint64_t>(sqlite3_value_int64(argv[0]));
    int n = sqlite3_value_int(argv[1]);

    std::vector<InstructionTextToken> tokens;
    size_t instrLen = 0;
    DataBuffer buf = bv->ReadBuffer(ea, 16);
    arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens);

    // Extract operands
    std::vector<std::string> operands;
    std::string current_op;
    bool past_mnemonic = false;

    for (auto& tok : tokens) {
        if (tok.type == InstructionToken) {
            past_mnemonic = true;
            continue;
        }
        if (!past_mnemonic) continue;

        if (tok.type == OperandSeparatorToken) {
            if (!current_op.empty()) {
                operands.push_back(current_op);
                current_op.clear();
            }
        } else {
            current_op += tok.text;
        }
    }
    if (!current_op.empty()) {
        operands.push_back(current_op);
    }

    if (n >= 0 && static_cast<size_t>(n) < operands.size()) {
        sqlite3_result_text(ctx, operands[n].c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

// ============================================================================
// Registration
// ============================================================================

inline bool register_sql_functions(xsql::Database& db) {
    // Disassembly
    sqlite3_create_function(db.handle(), "disasm", 1, SQLITE_UTF8, nullptr, sql_disasm, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "disasm", 2, SQLITE_UTF8, nullptr, sql_disasm, nullptr, nullptr);

    // Bytes
    sqlite3_create_function(db.handle(), "bytes", 2, SQLITE_UTF8, nullptr, sql_bytes_hex, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "bytes_raw", 2, SQLITE_UTF8, nullptr, sql_bytes_raw, nullptr, nullptr);

    // Names
    sqlite3_create_function(db.handle(), "name_at", 1, SQLITE_UTF8, nullptr, sql_name_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_at", 1, SQLITE_UTF8, nullptr, sql_func_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_start", 1, SQLITE_UTF8, nullptr, sql_func_start, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_end", 1, SQLITE_UTF8, nullptr, sql_func_end, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "set_name", 2, SQLITE_UTF8, nullptr, sql_set_name, nullptr, nullptr);

    // Function index (O(1) access)
    sqlite3_create_function(db.handle(), "func_qty", 0, SQLITE_UTF8, nullptr, sql_func_qty, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_at_index", 1, SQLITE_UTF8, nullptr, sql_func_at_index, nullptr, nullptr);

    // Segments
    sqlite3_create_function(db.handle(), "segment_at", 1, SQLITE_UTF8, nullptr, sql_segment_at, nullptr, nullptr);

    // Comments
    sqlite3_create_function(db.handle(), "comment_at", 1, SQLITE_UTF8, nullptr, sql_comment_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "set_comment", 2, SQLITE_UTF8, nullptr, sql_set_comment, nullptr, nullptr);

    // Cross-references
    sqlite3_create_function(db.handle(), "xrefs_to", 1, SQLITE_UTF8, nullptr, sql_xrefs_to, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "xrefs_from", 1, SQLITE_UTF8, nullptr, sql_xrefs_from, nullptr, nullptr);

    // Navigation
    sqlite3_create_function(db.handle(), "next_head", 1, SQLITE_UTF8, nullptr, sql_next_head, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "prev_head", 1, SQLITE_UTF8, nullptr, sql_prev_head, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "hex", 1, SQLITE_UTF8, nullptr, sql_hex, nullptr, nullptr);

    // Instruction functions
    sqlite3_create_function(db.handle(), "mnemonic", 1, SQLITE_UTF8, nullptr, sql_mnemonic, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "operand", 2, SQLITE_UTF8, nullptr, sql_operand, nullptr, nullptr);

    return true;
}

} // namespace functions
} // namespace bnsql
