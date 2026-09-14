// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_operands.hpp"

#include <algorithm>
#include <map>

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

std::string token_type_name(int type) {
    switch (type) {
        case TextToken:              return "text";
        case InstructionToken:       return "instruction";
        case OperandSeparatorToken:  return "separator";
        case RegisterToken:          return "register";
        case IntegerToken:           return "integer";
        case PossibleAddressToken:   return "address";
        case BeginMemoryOperandToken: return "memory_start";
        case EndMemoryOperandToken:  return "memory_end";
        case FloatingPointToken:     return "float";
        case AnnotationToken:        return "annotation";
        case CodeRelativeAddressToken: return "code_address";
        case ArgumentNameToken:      return "argument";
        case OpcodeToken:            return "opcode";
        case StringToken:            return "string";
        case CharacterConstantToken: return "char";
        case KeywordToken:           return "keyword";
        case TypeNameToken:          return "type_name";
        case FieldNameToken:         return "field_name";
        case NameSpaceToken:         return "namespace";
        case StructOffsetToken:      return "struct_offset";
        case GotoLabelToken:         return "goto_label";
        case CommentToken:           return "comment";
        case EnumerationMemberToken: return "enum_member";
        case OperationToken:         return "operation";
        case CodeSymbolToken:        return "code_symbol";
        case DataSymbolToken:        return "data_symbol";
        case LocalVariableToken:     return "local_variable";
        case ImportToken:            return "import";
        case ExternalSymbolToken:    return "external_symbol";
        case StackVariableToken:     return "stack_variable";
        default:                     return "other";
    }
}

namespace {

inline std::string trim_ws(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

// Emit ONE row per DISASSEMBLY operand for a single instruction line (mirrors idasql's
// insn.ops[] model). Binary Ninja annotates every rendered token with the operand it
// belongs to (tok.operand); BN_INVALID_OPERAND (0xffffffff) marks non-operand tokens
// (e.g. `{Case ...}` annotations). Two token TYPES must be excluded even though they
// carry a valid operand index: the mnemonic (InstructionToken, which carries operand 0)
// and the ", " separator (OperandSeparatorToken, which carries the preceding operand's
// index). All the tokens of one operand share its index -- including memory delimiters
// `[ ] +` -- so concatenating them in order and trimming rebuilds the full operand text
// (e.g. "dword [rsp+0x20]"). Measured empirically in a standalone BN operand lab;
// this is BN's authoritative per-operand metadata, NOT text parsing.
void collect_line_operands(uint64_t insn_addr, uint64_t func_addr,
                           const std::vector<BinaryNinja::InstructionTextToken>& tokens,
                           std::vector<OperandInfo>& out) {
    const bool is_instruction_line = std::any_of(
        tokens.begin(), tokens.end(), [](const auto& token) {
            return token.type == InstructionToken;
        });
    if (!is_instruction_line) return;

    struct Acc {
        std::string text;
        bool is_memory = false;
        bool have_rep = false;
        int rep_priority = -1;
        int token_type = 0;
        std::string type_name;
        uint64_t value = 0;
        int size = 0;
        int memory_width = 0;
    };
    // std::map keeps operands in ascending operand-index order (== operand order).
    std::map<size_t, Acc> ops;
    for (const auto& tok : tokens) {
        if (tok.operand == BN_INVALID_OPERAND) continue;
        if (tok.type == InstructionToken) continue;       // the mnemonic (carries operand 0)
        if (tok.type == OperandSeparatorToken) continue;  // the ", " between operands
        Acc& a = ops[tok.operand];
        a.text += tok.text;
        if (tok.type == BeginMemoryOperandToken || tok.type == EndMemoryOperandToken)
            a.is_memory = true;

        // x86 memory widths are rendering metadata carried by a KeywordToken
        // ("byte ", "word ", ...), whose numeric value/size are both zero.
        // Preserve that width separately while allowing a later semantic token
        // (symbol/address/integer/register) to represent value and token type.
        if (tok.type == KeywordToken) {
            const std::string width = trim_ws(tok.text);
            if (width == "byte") a.memory_width = 1;
            else if (width == "word") a.memory_width = 2;
            else if (width == "dword") a.memory_width = 4;
            else if (width == "qword") a.memory_width = 8;
            else if (width == "xword") a.memory_width = 16;
            else if (width == "oword") a.memory_width = 16;
            else if (width == "ymmword") a.memory_width = 32;
            else if (width == "zmmword") a.memory_width = 64;
        }

        auto representative_priority = [](BNInstructionTextTokenType type) {
            switch (type) {
                case CodeSymbolToken:
                case DataSymbolToken:
                case ImportToken:
                case ExternalSymbolToken:
                case PossibleAddressToken:
                case CodeRelativeAddressToken:
                    return 40;
                case IntegerToken:
                case FloatingPointToken:
                case CharacterConstantToken:
                    return 30;
                case RegisterToken:
                case LocalVariableToken:
                case StackVariableToken:
                    return 20;
                case KeywordToken:
                    return 5;
                default:
                    return 10;
            }
        };

        // Representative semantic token drives token_type/value. Pure text,
        // delimiters, and separators never replace real operand information.
        if (tok.type != TextToken && tok.type != AddressSeparatorToken &&
            tok.type != BeginMemoryOperandToken &&
            tok.type != EndMemoryOperandToken && !trim_ws(tok.text).empty()) {
            const int priority = representative_priority(tok.type);
            if (priority <= a.rep_priority) continue;
            a.have_rep = true;
            a.rep_priority = priority;
            a.token_type = static_cast<int>(tok.type);
            a.type_name = token_type_name(static_cast<int>(tok.type));
            a.value = tok.value;
            a.size = static_cast<int>(tok.size);
        }
    }
    for (auto& kv : ops) {
        Acc& a = kv.second;
        OperandInfo oi;
        oi.addr = insn_addr;
        oi.func_addr = func_addr;
        oi.operand_index = static_cast<int>(kv.first);
        oi.text = trim_ws(a.text);
        oi.token_type = a.token_type;
        oi.type_name = a.is_memory ? std::string("memory")
                                   : (a.have_rep ? a.type_name : token_type_name(a.token_type));
        oi.value = a.value;
        oi.size = a.size > 0 ? a.size : a.memory_width;
        out.push_back(std::move(oi));
    }
}

}  // namespace

/**
 * Iterator for instruction_operands filtered to a single function address.
 * Avoids full cache scan when querying WHERE func_addr = X.
 */
class OperandIterator : public xsql::RowIterator {
    std::vector<OperandInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit OperandIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;

        // GetAnalysisFunctionsForAddress returns every function whose entry is addr.
        // Iterate all of them (not just funcs[0]) so this pushdown path matches the
        // whole-binary cache-scan for the rare case of >1 function sharing a start
        // address -- filter_eq sets omit=1, so SQLite never re-checks func_addr and
        // would otherwise silently drop the extra functions' operand rows.
        auto funcs = bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr));
        auto settings = DisassemblySettings::GetDefaultSettings();
        for (auto& func : funcs) {
            uint64_t func_addr = func->GetStart();
            for (auto& block : func->GetBasicBlocks()) {
                auto lines = block->GetDisassemblyText(settings);
                for (auto& line : lines) {
                    collect_line_operands(line.addr, func_addr, line.tokens, rows_);
                }
            }
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

    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.addr)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            case 2: ctx.result_int(r.operand_index); break;
            case 3: ctx.result_text(r.text); break;
            case 4: ctx.result_int(r.token_type); break;
            case 5: ctx.result_text(r.type_name); break;
            case 6: ctx.result_int64(static_cast<int64_t>(r.value)); break;
            case 7: ctx.result_int(r.size); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

CachedTableDef<OperandInfo> define_instruction_operands() {
    return cached_table<OperandInfo>("instruction_operands")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~2 operands per instruction, ~20 instructions per function
            return bv->GetAnalysisFunctionList().size() * 40;
        })
        .cache_builder([](std::vector<OperandInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto settings = DisassemblySettings::GetDefaultSettings();

            for (auto& func : bv->GetAnalysisFunctionList()) {
                uint64_t func_addr = func->GetStart();
                for (auto& block : func->GetBasicBlocks()) {
                    auto lines = block->GetDisassemblyText(settings);
                    for (auto& line : lines) {
                        collect_line_operands(line.addr, func_addr, line.tokens, cache);
                    }
                }
            }
        })
        .column_int64("addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.addr);
        })
        .column_int64("func_addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .column_int("operand_index", [](const OperandInfo& r) -> int {
            return r.operand_index;
        })
        .column_text("text", [](const OperandInfo& r) -> std::string {
            return r.text;
        })
        .column_int("token_type", [](const OperandInfo& r) -> int {
            return r.token_type;
        })
        .column_text("type_name", [](const OperandInfo& r) -> std::string {
            return r.type_name;
        })
        .column_int64("value", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.value);
        })
        .column_int("size", [](const OperandInfo& r) -> int {
            return r.size;
        })
        // Direct source filter: single-function query bypasses cache
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<OperandIterator>(addr);
        }, 0.5, 20.0)  // cost=0.5, estimated_rows=20
        .index_on("func_addr", [](const OperandInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace code
} // namespace bnsql
