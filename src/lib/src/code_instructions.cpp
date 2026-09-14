// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_instructions.hpp"

namespace bnsql {
namespace code {

using namespace BinaryNinja;
using core::get_bv;

// Render one function's instructions (mnemonic/operands/disasm from tokens)
// into `out`. Shared by the whole-binary cache builder and the single-function
// pushdown iterator so the two can never drift.
static void collect_function_instructions(const Ref<Function>& func,
                                          const Ref<DisassemblySettings>& settings,
                                          std::vector<InsnInfo>& out) {
    for (auto& block : func->GetBasicBlocks()) {
        // Use BasicBlock::GetDisassemblyText for proper tokens
        auto lines = block->GetDisassemblyText(settings);
        const uint64_t block_end = block->GetEnd();

        // Binary Ninja interleaves annotation rows (comments, headers, and
        // other display-only text) with real instructions. They can share an
        // instruction address, but they do not carry an InstructionToken and
        // must never become rows in the canonical `instructions` table.
        std::vector<size_t> instruction_line_indices;
        instruction_line_indices.reserve(lines.size());
        for (size_t i = 0; i < lines.size(); ++i) {
            for (const auto& tok : lines[i].tokens) {
                if (tok.type == InstructionToken) {
                    instruction_line_indices.push_back(i);
                    break;
                }
            }
        }

        for (size_t row_index = 0;
             row_index < instruction_line_indices.size();
             ++row_index) {
            const size_t line_index = instruction_line_indices[row_index];
            const auto& line = lines[line_index];
            InsnInfo info;
            info.address = line.addr;
            info.func_addr = func->GetStart();
            info.size = 0;

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

            // Derive the instruction size from the next REAL instruction line,
            // not the next display line: an annotation may share this address.
            // For the block's last instruction, use the basic-block boundary.
            uint64_t end_addr = block_end;
            for (size_t next = row_index + 1;
                 next < instruction_line_indices.size();
                 ++next) {
                const uint64_t candidate =
                    lines[instruction_line_indices[next]].addr;
                if (candidate > info.address) {
                    end_addr = candidate;
                    break;
                }
            }
            if (end_addr > info.address) {
                info.size = static_cast<size_t>(end_addr - info.address);
            }
            if (info.size == 0) {
                info.size = 1;  // Defensive fallback for a malformed block.
            }

            out.push_back(std::move(info));
        }
    }
}

/**
 * Iterator for instructions filtered to a single function address.
 * Avoids the whole-binary disassembly render when querying WHERE func_addr = X.
 */
class InsnIterator : public xsql::RowIterator {
    std::vector<InsnInfo> rows_;
    size_t pos_ = 0;
    bool started_ = false;

public:
    explicit InsnIterator(int64_t addr) {
        auto bv = get_bv();
        if (!bv) return;

        // GetAnalysisFunctionsForAddress returns every function whose entry is addr.
        // Collect all of them (not just funcs[0]) so this pushdown path matches the
        // whole-binary cache-scan for the rare case of >1 function sharing a start
        // address -- filter_eq sets omit=1, so SQLite never re-checks func_addr and
        // would otherwise silently drop the extra functions' rows.
        auto funcs = bv->GetAnalysisFunctionsForAddress(static_cast<uint64_t>(addr));
        auto settings = DisassemblySettings::GetDefaultSettings();
        for (auto& func : funcs) {
            collect_function_instructions(func, settings, rows_);
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

    // Column order MUST match define_instructions() below:
    // 0 addr, 1 itype, 2 mnemonic, 3 size, 4-6 operand0-2, 7 disasm, 8 func_addr
    void column(xsql::FunctionContext& ctx, int col) override {
        if (pos_ >= rows_.size()) { ctx.result_null(); return; }
        const auto& r = rows_[pos_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(r.address)); break;
            case 1: ctx.result_int(0); break;  // itype: no BN equivalent
            case 2: ctx.result_text(r.mnemonic); break;
            case 3: ctx.result_int(static_cast<int>(r.size)); break;
            case 4: ctx.result_text(r.operands.size() > 0 ? r.operands[0] : ""); break;
            case 5: ctx.result_text(r.operands.size() > 1 ? r.operands[1] : ""); break;
            case 6: ctx.result_text(r.operands.size() > 2 ? r.operands[2] : ""); break;
            case 7: ctx.result_text(r.disasm); break;
            case 8: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(pos_);
    }
};

CachedTableDef<InsnInfo> define_instructions() {
    return cached_table<InsnInfo>("instructions")
        // no_shared_cache is deliberate: the rendered disassembly depends on
        // MUTABLE view state (renames, applied types, comments), so a cache held
        // across queries would go stale after a write. The cost is that a full
        // scan (SELECT * FROM instructions) re-tokenizes the WHOLE binary on
        // EVERY query -- BasicBlock::GetDisassemblyText runs for every block of
        // every function, with no cross-query reuse -- so two back-to-back
        // read-only full scans render the entire binary twice. To answer "do
        // full scans re-tokenize?": yes, every time. Bulk/repeated read
        // consumers should filter by func_addr (WHERE func_addr = X), which the
        // filter_eq pushdown below serves via InsnIterator -- rendering a single
        // function instead of the whole binary. Making repeated full scans cheap
        // would require a shared cache invalidated on BN analysis-changed
        // notifications (a framework-level change), NOT dropping this opt-out --
        // an unsynchronized shared cache here would reintroduce write staleness.
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            auto bv = get_bv();
            if (!bv) return 0;
            // Estimate ~20 instructions per function
            return bv->GetAnalysisFunctionList().size() * 20;
        })
        .cache_builder([](std::vector<InsnInfo>& cache) {
            auto bv = get_bv();
            if (!bv) return;

            auto settings = DisassemblySettings::GetDefaultSettings();
            for (auto& func : bv->GetAnalysisFunctionList()) {
                collect_function_instructions(func, settings, cache);
            }
        })
        .column_int64("addr", [](const InsnInfo& r) -> int64_t {
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
        // Direct source filter: single-function query bypasses cache
        .filter_eq("func_addr", [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InsnIterator>(addr);
        }, 0.5, 20.0)  // cost=0.5, estimated_rows=20
        .index_on("func_addr", [](const InsnInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_addr);
        })
        .build();
}

} // namespace code
} // namespace bnsql
