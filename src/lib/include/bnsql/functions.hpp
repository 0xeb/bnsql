// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
 *   - set_comment(address, text) - Set address comment
 *   - set_name(address, name)   - Set name at address
 *   - entities_search(pattern, limit, offset) - Search unified entities (JSON array)
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

#include <xsql/database.hpp>
#include <xsql/functions.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cctype>

#include "binaryninjaapi.h"
#include <bnsql/entities.hpp>
#include <bnsql/persistence.hpp>

namespace bnsql {
namespace functions {

using namespace BinaryNinja;

// ============================================================================
// Helper: Get current BinaryView from context
// ============================================================================

inline Ref<BinaryView> get_bv() {
    return entities::get_bv();
}

inline Ref<Function> get_function_for_address(const Ref<BinaryView>& bv, uint64_t ea) {
    if (!bv) return nullptr;

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (!funcs.empty()) return funcs[0];

    funcs = bv->GetAnalysisFunctionsForAddress(ea);
    if (!funcs.empty()) return funcs[0];

    return nullptr;
}

inline std::string to_ascii_lower(std::string in) {
    std::transform(in.begin(), in.end(), in.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return in;
}

inline std::string json_escape_ascii(const std::string& in) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    // Escape control characters as \u00XX
                    out += "\\u00";
                    out += kHex[(c >> 4) & 0x0f];
                    out += kHex[c & 0x0f];
                } else {
                    // Pass through printable ASCII and UTF-8 bytes (JSON allows raw UTF-8)
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

// ============================================================================
// Disassembly Functions
// ============================================================================

static void sql_disasm(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("disasm requires at least 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        ctx.result_error("No architecture");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    int count = (argc >= 2) ? argv[1].as_int() : 1;
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;

    std::ostringstream result;

    // Try to get function at this address for proper disassembly
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        // Use BasicBlock::GetDisassemblyText for proper disassembly within function
        auto func = funcs[0];

        // Find the basic block containing this address
        Ref<BasicBlock> target_block;
        for (auto& block : func->GetBasicBlocks()) {
            if (ea >= block->GetStart() && ea < block->GetEnd()) {
                target_block = block;
                break;
            }
        }

        if (target_block) {
            auto settings = DisassemblySettings::GetDefaultSettings();
            auto lines = target_block->GetDisassemblyText(settings);
            int output_count = 0;
            for (auto& line : lines) {
                if (output_count >= count) break;
                if (line.addr < ea) continue;  // Skip lines before our target

                if (output_count > 0) result << "\n";
                result << std::hex << line.addr << ": ";
                for (auto& tok : line.tokens) {
                    result << tok.text;
                }
                output_count++;
            }
        }
    }

    // If no result yet, fall back to architecture-based disassembly
    if (result.str().empty()) {
        for (int i = 0; i < count && ea < bv->GetEnd(); i++) {
            size_t len = bv->GetInstructionLength(arch, ea);
            if (len == 0) break;

            std::vector<InstructionTextToken> tokens;
            size_t instrLen = len;
            DataBuffer buf = bv->ReadBuffer(ea, 16);
            if (!arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens)) {
                break;
            }

            if (i > 0) result << "\n";
            result << std::hex << ea << ": ";
            for (auto& tok : tokens) {
                result << tok.text;
            }

            ea += len;
        }
    }

    std::string str = result.str();
    ctx.result_text(str);
}

// ============================================================================
// Name Functions
// ============================================================================

static void sql_name_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("name_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    auto sym = bv->GetSymbolByAddress(ea);

    if (sym) {
        std::string name = sym->GetFullName();
        ctx.result_text(name);
    } else {
        ctx.result_null();
    }
}

static void sql_func_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        auto sym = funcs[0]->GetSymbol();
        std::string name = sym ? sym->GetFullName() : "";
        if (name.empty()) {
            char buf[32];
            snprintf(buf, sizeof(buf), "sub_%llx", (unsigned long long)funcs[0]->GetStart());
            name = buf;
        }
        ctx.result_text(name);
    } else {
        ctx.result_null();
    }
}

static void sql_func_start(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_start requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        ctx.result_int64(static_cast<int64_t>(funcs[0]->GetStart()));
    } else {
        ctx.result_null();
    }
}

static void sql_func_end(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_end requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);

    if (!funcs.empty()) {
        ctx.result_int64(static_cast<int64_t>(funcs[0]->GetHighestAddress()));
    } else {
        ctx.result_null();
    }
}

// ============================================================================
// Function Index Functions (O(1) access)
// ============================================================================

static void sql_func_qty(xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
    auto bv = get_bv();
    if (!bv) {
        ctx.result_int64(0);
        return;
    }
    ctx.result_int64(static_cast<int64_t>(bv->GetAnalysisFunctionList().size()));
}

static void sql_func_at_index(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_at_index requires 1 argument (index)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_null();
        return;
    }

    size_t idx = static_cast<size_t>(argv[0].as_int64());
    auto funcs = bv->GetAnalysisFunctionList();

    if (idx < funcs.size()) {
        ctx.result_int64(static_cast<int64_t>(funcs[idx]->GetStart()));
    } else {
        ctx.result_null();
    }
}

// ============================================================================
// Name Modification Functions
// ============================================================================

static void sql_set_name(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("set_name requires 2 arguments (address, name)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    const char* name = argv[1].as_c_str();

    if (!name) {
        ctx.result_int(0);
        return;
    }

    auto sym = new Symbol(DataSymbol, name, ea);
    bv->DefineUserSymbol(sym);
    ctx.result_int(1);
}

// ============================================================================
// Segment Functions
// ============================================================================

static void sql_segment_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("segment_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    for (auto& seg : bv->GetSegments()) {
        if (ea >= seg->GetStart() && ea < seg->GetEnd()) {
            // Segments don't have names in BN, use address-based name
            char buf[32];
            snprintf(buf, sizeof(buf), "seg_%llx", (unsigned long long)seg->GetStart());
            ctx.result_text(buf);
            return;
        }
    }
    ctx.result_null();
}

// ============================================================================
// Comment Functions
// ============================================================================

static void sql_comment_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("comment_at requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    std::string comment = bv->GetCommentForAddress(ea);
    if (!comment.empty()) {
        ctx.result_text(comment);
        return;
    }

    auto func = get_function_for_address(bv, ea);
    if (!func) {
        ctx.result_null();
        return;
    }

    comment = func->GetCommentForAddress(ea);
    if (!comment.empty()) {
        ctx.result_text(comment);
        return;
    }

    // BN function comments are function-level metadata, not tied to an address.
    // We expose them at the function start address for address-centric workflows.
    if (ea == func->GetStart()) {
        comment = func->GetComment();
        if (!comment.empty()) {
            ctx.result_text(comment);
            return;
        }
    }

    ctx.result_null();
}

static void sql_set_comment(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("set_comment requires 2 arguments (address, text)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    const char* cmt = argv[1].as_c_str();

    bv->SetCommentForAddress(ea, cmt ? cmt : "");
    ctx.result_int(1);
}

// ============================================================================
// Cross-Reference Functions
// ============================================================================

static void sql_xrefs_to(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("xrefs_to requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

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
    ctx.result_text(str);
}

static void sql_xrefs_from(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("xrefs_from requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

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
    ctx.result_text(str);
}

// ============================================================================
// Navigation Functions
// ============================================================================

static void sql_next_head(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("next_head requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        ctx.result_null();
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    // Get instruction length at current address
    size_t len = bv->GetInstructionLength(arch, ea);
    if (len > 0) {
        ctx.result_int64(static_cast<int64_t>(ea + len));
    } else {
        // Try next valid offset
        uint64_t next = bv->GetNextValidOffset(ea);
        if (next > ea && next < bv->GetEnd()) {
            ctx.result_int64(static_cast<int64_t>(next));
        } else {
            ctx.result_null();
        }
    }
}

static void sql_prev_head(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("prev_head requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    // BN doesn't have GetPreviousValidOffset, use simple approach
    // Try to find previous instruction by scanning backwards
    if (ea <= bv->GetStart()) {
        ctx.result_null();
        return;
    }

    // Simple heuristic: go back by max instruction size and scan forward
    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        ctx.result_null();
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
        ctx.result_int64(static_cast<int64_t>(prev_addr));
    } else {
        ctx.result_null();
    }
}

static void sql_hex(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("hex requires 1 argument (value)");
        return;
    }

    int64_t val = argv[0].as_int64();
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
    ctx.result_text(buf);
}

// ============================================================================
// Item Query Functions
// ============================================================================

static void sql_mnemonic(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("mnemonic requires 1 argument (address)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());

    // Try function-based approach first
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (!funcs.empty()) {
        auto func = funcs[0];
        auto settings = DisassemblySettings::GetDefaultSettings();
        for (auto& block : func->GetBasicBlocks()) {
            if (ea >= block->GetStart() && ea < block->GetEnd()) {
                auto lines = block->GetDisassemblyText(settings);
                for (auto& line : lines) {
                    if (line.addr == ea) {
                        for (auto& tok : line.tokens) {
                            if (tok.type == InstructionToken) {
                                ctx.result_text(tok.text);
                                return;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // Fallback to architecture-based
    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        ctx.result_null();
        return;
    }

    std::vector<InstructionTextToken> tokens;
    size_t instrLen = 0;
    DataBuffer buf = bv->ReadBuffer(ea, 16);
    if (arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens)) {
        for (auto& tok : tokens) {
            if (tok.type == InstructionToken) {
                ctx.result_text(tok.text);
                return;
            }
        }
    }
    ctx.result_null();
}

// Helper to extract operands from tokens
static std::vector<std::string> extract_operands(const std::vector<InstructionTextToken>& tokens) {
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
    return operands;
}

static void sql_operand(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("operand requires 2 arguments (address, operand_num)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    uint64_t ea = static_cast<uint64_t>(argv[0].as_int64());
    int n = argv[1].as_int();

    std::vector<std::string> operands;

    // Try function-based approach first
    auto funcs = bv->GetAnalysisFunctionsContainingAddress(ea);
    if (!funcs.empty()) {
        auto func = funcs[0];
        auto settings = DisassemblySettings::GetDefaultSettings();
        for (auto& block : func->GetBasicBlocks()) {
            if (ea >= block->GetStart() && ea < block->GetEnd()) {
                auto lines = block->GetDisassemblyText(settings);
                for (auto& line : lines) {
                    if (line.addr == ea) {
                        operands = extract_operands(line.tokens);
                        break;
                    }
                }
                break;
            }
        }
    }

    // Fallback to architecture-based if no operands found
    if (operands.empty()) {
        auto arch = bv->GetDefaultArchitecture();
        if (!arch) {
            ctx.result_null();
            return;
        }

        std::vector<InstructionTextToken> tokens;
        size_t instrLen = 0;
        DataBuffer buf = bv->ReadBuffer(ea, 16);
        if (arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), ea, instrLen, tokens)) {
            operands = extract_operands(tokens);
        }
    }

    if (n >= 0 && static_cast<size_t>(n) < operands.size()) {
        ctx.result_text(operands[n]);
    } else {
        ctx.result_null();
    }
}

// ============================================================================
// Database operations
// ============================================================================

static void sql_save(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* /*argv*/) {
    (void)argc;
    std::string saved_path;
    std::string save_error;
    if (!persistence::save_binary_view(get_bv(), &save_error, &saved_path)) {
        ctx.result_error(save_error);
        return;
    }
    if (saved_path.empty()) {
        ctx.result_text_static("Database saved");
        return;
    }
    ctx.result_text("Database saved: " + saved_path);
}

static void sql_entities_search(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("entities_search requires at least 1 argument (pattern)");
        return;
    }

    auto bv = get_bv();
    if (!bv) {
        ctx.result_error("No BinaryView context");
        return;
    }

    const char* pattern_cstr = argv[0].as_c_str();
    if (!pattern_cstr || pattern_cstr[0] == '\0') {
        ctx.result_text_static("[]");
        return;
    }

    int limit_in = (argc >= 2) ? argv[1].as_int() : 50;
    int offset_in = (argc >= 3) ? argv[2].as_int() : 0;
    if (limit_in < 0) limit_in = 0;
    if (offset_in < 0) offset_in = 0;

    size_t limit = static_cast<size_t>(limit_in);
    size_t offset = static_cast<size_t>(offset_in);
    if (limit > 500) limit = 500;
    if (limit == 0) {
        ctx.result_text_static("[]");
        return;
    }

    struct EntityMatch {
        std::string name;
        std::string kind;
        uint64_t address = 0;
        std::string parent_name;
        std::string qualified_name;
        std::string source;
    };

    std::vector<EntityMatch> matches;
    const std::string pattern = to_ascii_lower(std::string(pattern_cstr));

    auto matches_text = [&](const std::string& value) -> bool {
        return to_ascii_lower(value).find(pattern) != std::string::npos;
    };

    const size_t max_matches = offset + limit;
    auto maybe_add = [&](EntityMatch&& e) {
        if (matches.size() >= max_matches) return;
        if (matches_text(e.name) || matches_text(e.parent_name) || matches_text(e.qualified_name)) {
            matches.push_back(std::move(e));
        }
    };

    for (auto& f : bv->GetAnalysisFunctionList()) {
        auto sym = f->GetSymbol();
        std::string name = sym ? sym->GetFullName() : ("sub_" + std::to_string(f->GetStart()));
        EntityMatch e;
        e.name = name;
        e.kind = "function";
        e.address = f->GetStart();
        e.parent_name = "";
        e.qualified_name = name;
        e.source = "analysis.functions";
        maybe_add(std::move(e));
    }

    auto symbols = bv->GetSymbols();
    std::sort(symbols.begin(), symbols.end(), [](const Ref<Symbol>& a, const Ref<Symbol>& b) {
        if (a->GetAddress() != b->GetAddress()) return a->GetAddress() < b->GetAddress();
        return a->GetFullName() < b->GetFullName();
    });
    for (const auto& sym : symbols) {
        EntityMatch e;
        e.name = sym->GetFullName();
        e.kind = "symbol";
        e.address = sym->GetAddress();
        e.parent_name = "";
        e.qualified_name = e.name;
        e.source = "analysis.symbols";
        maybe_add(std::move(e));
    }

    for (const auto& seg : bv->GetSegments()) {
        EntityMatch e;
        char seg_name[32];
        snprintf(seg_name, sizeof(seg_name), "seg_%llx", (unsigned long long)seg->GetStart());
        e.name = seg_name;
        e.kind = "segment";
        e.address = seg->GetStart();
        e.parent_name = "";
        e.qualified_name = e.name;
        e.source = "analysis.segments";
        maybe_add(std::move(e));
    }

    for (const auto& sym : symbols) {
        if (sym->GetType() != ImportedFunctionSymbol &&
            sym->GetType() != ImportAddressSymbol &&
            sym->GetType() != ImportedDataSymbol) {
            continue;
        }
        std::string module = sym->GetNameSpace().GetString();
        if (module.empty()) module = "unknown";

        EntityMatch e;
        e.name = sym->GetShortName();
        e.kind = "import";
        e.address = sym->GetAddress();
        e.parent_name = module;
        e.qualified_name = module + "!" + e.name;
        e.source = "analysis.imports";
        maybe_add(std::move(e));
    }

    auto strings = bv->GetStrings();
    for (const auto& s : strings) {
        if (matches.size() >= max_matches) break;
        size_t length = s.length;
        if (length > 256) length = 256;
        DataBuffer buf = bv->ReadBuffer(s.start, length);
        if (!buf.GetData() || buf.GetLength() == 0) continue;
        std::string content(
            reinterpret_cast<const char*>(buf.GetData()),
            static_cast<size_t>(buf.GetLength())
        );

        EntityMatch e;
        e.name = content;
        e.kind = "string";
        e.address = s.start;
        e.parent_name = "";
        e.qualified_name = content;
        e.source = "analysis.strings";
        maybe_add(std::move(e));
    }

    if (offset >= matches.size()) {
        ctx.result_text_static("[]");
        return;
    }

    size_t end = std::min(matches.size(), offset + limit);
    std::ostringstream json;
    json << "[";
    bool first = true;
    for (size_t i = offset; i < end; ++i) {
        const auto& e = matches[i];
        if (!first) json << ",";
        first = false;
        json << "{"
             << "\"name\":\"" << json_escape_ascii(e.name) << "\","
             << "\"kind\":\"" << e.kind << "\","
             << "\"address\":" << e.address << ","
             << "\"parent_name\":\"" << json_escape_ascii(e.parent_name) << "\","
             << "\"qualified_name\":\"" << json_escape_ascii(e.qualified_name) << "\","
             << "\"source\":\"" << e.source << "\""
             << "}";
    }
    json << "]";
    ctx.result_text(json.str());
}

// ============================================================================
// UI Context (plugin-only)
// ============================================================================

static void sql_get_ui_context_json(xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
#ifdef BNSQL_PLUGIN_BUILD
    // In plugin builds, attempt to get UI context from Binary Ninja
    // UIContext may not always be available (headless, background threads)
    ctx.result_null();
#else
    // CLI/headless builds: no UI context available
    ctx.result_null();
#endif
}

// ============================================================================
// Registration
// ============================================================================

inline bool register_sql_functions(xsql::Database& db) {
    // Disassembly
    db.register_function("disasm", 1, xsql::ScalarFn(sql_disasm));
    db.register_function("disasm", 2, xsql::ScalarFn(sql_disasm));

    // Bytes — bulk reads go through the `bytes` virtual table with hidden
    // `start_address` + `n` input columns: SELECT hex(blob_concat(value))
    // FROM bytes WHERE start_address = X AND n = N ORDER BY address; (or
    // blob_concat(value) for BLOB). Byte patching uses the existing
    // `patches` table.

    // Names
    db.register_function("name_at", 1, xsql::ScalarFn(sql_name_at));
    db.register_function("func_at", 1, xsql::ScalarFn(sql_func_at));
    db.register_function("func_start", 1, xsql::ScalarFn(sql_func_start));
    db.register_function("func_end", 1, xsql::ScalarFn(sql_func_end));
    db.register_function("set_name", 2, xsql::ScalarFn(sql_set_name));

    // Function index (O(1) access)
    db.register_function("func_qty", 0, xsql::ScalarFn(sql_func_qty));
    db.register_function("func_at_index", 1, xsql::ScalarFn(sql_func_at_index));

    // Segments
    db.register_function("segment_at", 1, xsql::ScalarFn(sql_segment_at));

    // Comments
    db.register_function("comment_at", 1, xsql::ScalarFn(sql_comment_at));
    db.register_function("set_comment", 2, xsql::ScalarFn(sql_set_comment));

    // Cross-references
    db.register_function("xrefs_to", 1, xsql::ScalarFn(sql_xrefs_to));
    db.register_function("xrefs_from", 1, xsql::ScalarFn(sql_xrefs_from));

    // Navigation
    db.register_function("next_head", 1, xsql::ScalarFn(sql_next_head));
    db.register_function("prev_head", 1, xsql::ScalarFn(sql_prev_head));
    db.register_function("hex", 1, xsql::ScalarFn(sql_hex));

    // Instruction functions
    db.register_function("mnemonic", 1, xsql::ScalarFn(sql_mnemonic));
    db.register_function("operand", 2, xsql::ScalarFn(sql_operand));

    // Database operations
    db.register_function("save", 0, xsql::ScalarFn(sql_save));

    // Discovery helpers
    db.register_function("entities_search", 1, xsql::ScalarFn(sql_entities_search));
    db.register_function("entities_search", 2, xsql::ScalarFn(sql_entities_search));
    db.register_function("entities_search", 3, xsql::ScalarFn(sql_entities_search));

    // UI context (plugin-only, returns NULL in CLI/headless)
    db.register_function("get_ui_context_json", 0, xsql::ScalarFn(sql_get_ui_context_json));

    return true;
}

} // namespace functions
} // namespace bnsql
