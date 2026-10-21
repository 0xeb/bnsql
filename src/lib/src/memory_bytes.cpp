// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_bytes.hpp"

#include <algorithm>
#include <limits>
#include <optional>

namespace bnsql {
namespace memory {

using namespace BinaryNinja;

namespace bytes_detail {

uint8_t read_one_byte(const BinaryNinja::Ref<BinaryNinja::BinaryView>& bv, uint64_t addr) {
    if (!bv) return 0;
    BinaryNinja::DataBuffer buf = bv->ReadBuffer(addr, 1);
    if (buf.GetLength() < 1) return 0;
    return static_cast<const uint8_t*>(buf.GetData())[0];
}

// Column indices for the bytes table; keep in sync with define_bytes_table().
enum BytesColumn {
    kBytesAddress = 0,
    kBytesValue = 1,
    kBytesIsInitialized = 2,
    kBytesStartAddress = 3,
    kBytesN = 4,
};

// Whether a byte is initialized (core::is_initialized_at: in a segment and
// loaded -- file data or a data memory region, not BSS), remembering the
// segment of the previous answer. A walk visits consecutive addresses, so the
// segment lookup and the initialized check run once per segment instead of once
// per byte (measured on Binary Ninja 6.0: about 140 ns for GetSegmentAt and
// 45 ns for IsOffsetBackedByFile per call; an uninitialized row now costs
// about 40 ns). Binary Ninja's segments are disjoint (each is one resolved
// memory range), so the remembered bounds answer every address inside them.
class InitializedCursor {
    bool have_ = false;
    uint64_t start_ = 0;
    uint64_t last_ = 0;  // inclusive
    uint64_t initialized_ = 0;

public:
    bool initialized(const BinaryNinja::Ref<BinaryNinja::BinaryView>& bv, uint64_t addr) {
        if (!have_ || addr < start_ || addr > last_) {
            have_ = false;
            if (!bv) return false;
            BinaryNinja::Ref<BinaryNinja::Segment> seg = bv->GetSegmentAt(addr);
            if (!seg) return false;
            const uint64_t start = seg->GetStart();
            const uint64_t length = seg->GetLength();
            if (length == 0 || addr < start) return false;
            start_ = start;
            last_ = length - 1 > std::numeric_limits<uint64_t>::max() - start
                        ? std::numeric_limits<uint64_t>::max()
                        : start + (length - 1);
            initialized_ = core::segment_initialized_length(bv, seg);
            have_ = true;
        }
        return addr - start_ < initialized_;
    }
};

void populate_byte_row(const BinaryNinja::Ref<BinaryNinja::BinaryView>& bv,
                       ByteRow& row, uint64_t addr, InitializedCursor& cursor) {
    row.address = addr;
    row.value = 0;
    row.is_initialized = false;
    // Computed once per row; the column getters reuse the snapshot.
    if (!cursor.initialized(bv, addr)) return;
    row.is_initialized = true;
    row.value = read_one_byte(bv, addr);
}

// Walks the mapped bytes of an addr window in SQL order. SQL holds an address
// at or above 2^63 as a negative INTEGER, so the window is walked as its
// unsigned spans (xsql::Int64KeyRange::unsigned_spans): the part at or above
// 2^63 first, then the part below. Within a span the walk follows the merged
// segment list upward and skips unmapped gaps. The unconstrained scan walks
// every address the same way.
class BytesRangeGenerator : public xsql::Generator<ByteRow> {
    BinaryNinja::Ref<BinaryNinja::BinaryView> bv_;
    // Inclusive runs of mapped addresses, in the order they are yielded.
    std::vector<xsql::U64Span> runs_;
    size_t run_ = 0;
    bool in_run_ = false;
    uint64_t current_ = 0;
    InitializedCursor cursor_;
    mutable ByteRow row_{};

public:
    BytesRangeGenerator(BinaryNinja::Ref<BinaryNinja::BinaryView> bv,
                        const xsql::Int64KeyRange& range)
        : bv_(std::move(bv)) {
        if (!bv_) return;
        // Segments as inclusive, merged, unsigned-ascending spans. A segment
        // cannot reach 2^64: Binary Ninja ends the highest one at
        // 0xFFFFFFFFFFFFFFFF, so its last byte is 0xFFFFFFFFFFFFFFFE.
        std::vector<xsql::U64Span> mapped;
        for (auto& seg : bv_->GetSegments()) {
            const uint64_t s = seg->GetStart();
            const uint64_t length = seg->GetLength();
            if (length == 0) continue;
            const uint64_t last = length - 1 > std::numeric_limits<uint64_t>::max() - s
                                      ? std::numeric_limits<uint64_t>::max()
                                      : s + (length - 1);
            mapped.push_back({s, last});
        }
        std::sort(mapped.begin(), mapped.end(),
                  [](const xsql::U64Span& a, const xsql::U64Span& b) { return a.lo < b.lo; });
        std::vector<xsql::U64Span> merged;
        for (const auto& m : mapped) {
            if (!merged.empty() &&
                (merged.back().hi == std::numeric_limits<uint64_t>::max() ||
                 m.lo <= merged.back().hi + 1)) {
                merged.back().hi = std::max(merged.back().hi, m.hi);
            } else {
                merged.push_back(m);
            }
        }
        for (const xsql::U64Span& span : range.unsigned_spans()) {
            for (const auto& m : merged) {
                const uint64_t lo = std::max(span.lo, m.lo);
                const uint64_t hi = std::min(span.hi, m.hi);
                if (lo <= hi) runs_.push_back({lo, hi});
            }
        }
    }

    bool next() override {
        while (run_ < runs_.size()) {
            const xsql::U64Span& run = runs_[run_];
            if (!in_run_) {
                in_run_ = true;
                current_ = run.lo;
            } else if (current_ < run.hi) {
                ++current_;
            } else {
                ++run_;
                in_run_ = false;
                continue;
            }
            populate_byte_row(bv_, row_, current_, cursor_);
            return true;
        }
        return false;
    }

    const ByteRow& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_); }
};

// Yields the N consecutive addresses X, X+1, ... (unsigned), ignoring segment
// boundaries, and stops after 0xFFFFFFFFFFFFFFFF -- an ordinary Binary Ninja
// address (readable, though no segment holds it), not a sentinel as in IDA.
// `value` is NULL wherever the byte is not initialized (see
// core::is_initialized_at). The
// plan claims ORDER BY addr, so the rows come out in SQL order: when the run
// crosses 2^63 (0x7FFF...FFFF -> 0x8000...0000), the part at or above 2^63 --
// negative INTEGERs -- comes first.
class BytesNGenerator : public xsql::Generator<ByteRow> {
    std::vector<xsql::U64Span> runs_;  // at most two, walked upward in order
    size_t run_ = 0;
    bool in_run_ = false;
    uint64_t current_ = 0;
    BinaryNinja::Ref<BinaryNinja::BinaryView> bv_ = core::get_bv();
    InitializedCursor cursor_;
    mutable ByteRow row_{};

public:
    BytesNGenerator(uint64_t start, int64_t n) {
        if (n <= 0) return;
        const uint64_t room = std::numeric_limits<uint64_t>::max() - start;
        const uint64_t last = static_cast<uint64_t>(n - 1) > room
                                  ? std::numeric_limits<uint64_t>::max()
                                  : start + static_cast<uint64_t>(n - 1);
        constexpr uint64_t kSeam = uint64_t{1} << 63;
        if (start < kSeam && last >= kSeam) {
            runs_.push_back({kSeam, last});
            runs_.push_back({start, kSeam - 1});
        } else {
            runs_.push_back({start, last});
        }
    }

    bool next() override {
        while (run_ < runs_.size()) {
            const xsql::U64Span& run = runs_[run_];
            if (!in_run_) {
                in_run_ = true;
                current_ = run.lo;
            } else if (current_ < run.hi) {
                ++current_;
            } else {
                ++run_;
                in_run_ = false;
                continue;
            }
            populate_byte_row(bv_, row_, current_, cursor_);
            return true;
        }
        return false;
    }

    const ByteRow& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_); }
};

// Both plans are omit=1, so every value is compared the way SQLite compares
// the INTEGER column it constrains: `addr = 4096.5` and `addr = NULL` match
// nothing, `addr >= 4095.5` starts at 4096 (as_int64() truncated all three).
std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_range_generator(const std::vector<xsql::GeneratorConstraintArg>& args) {
    xsql::Int64KeyRange range;
    for (const auto& arg : args) {
        if (arg.column_index != kBytesAddress) continue;
        range.constrain(arg.op, arg.value);
    }
    if (range.empty()) return nullptr;
    return std::make_unique<BytesRangeGenerator>(core::get_bv(), range);
}

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_n_generator(const std::vector<xsql::GeneratorConstraintArg>& args) {
    uint64_t start = 0;
    int64_t n = 0;
    for (const auto& arg : args) {
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        const std::optional<int64_t> value = xsql::exact_int64(arg.value);
        if (!value) return nullptr;  // start_addr = 4096.5 / NULL reads nothing
        if (arg.column_index == kBytesStartAddress) {
            start = static_cast<uint64_t>(*value);
        } else if (arg.column_index == kBytesN) {
            n = *value;
        }
    }
    return std::make_unique<BytesNGenerator>(start, n);
}

} // namespace bytes_detail

GeneratorTableDef<ByteRow> define_bytes_table() {
    using namespace bytes_detail;
    return generator_table<ByteRow>("bytes")
        .estimate_rows([]() -> size_t {
            auto bv = core::get_bv();
            if (!bv) return 0;
            uint64_t total = 0;
            for (auto& seg : bv->GetSegments()) total += seg->GetLength();
            return static_cast<size_t>(total);
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
            return std::make_unique<BytesRangeGenerator>(core::get_bv(),
                                                         xsql::Int64KeyRange{});
        })
        .column_int64("addr", [](const ByteRow& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        // Canonical byte surface: value is NULL for a mapped-but-uninitialized byte
        // (e.g. BSS), preserving the "unknown" vs "real 0" distinction. This is the
        // ratified cross-tool decision (uninitialized => NULL, not 0), matching
        // ghidrasql; is_initialized carries the 0/1 flag.
        .column("value", xsql::ColumnType::Integer,
                [](xsql::FunctionContext& ctx, const ByteRow& r) {
                    if (r.is_initialized)
                        ctx.result_int64(static_cast<int64_t>(r.value));
                    else
                        ctx.result_null();
                })
        .column_int("is_initialized", [](const ByteRow& r) -> int {
            return r.is_initialized ? 1 : 0;
        })
        // Hidden input columns for bounded reads: WHERE start_addr = X
        // AND n = N. Both are HIDDEN (input-only); keeping start_addr
        // distinct from the visible `addr` keeps any user predicate on
        // `addr` enforceable by SQLite (joins stay correct).
        .hidden_column_int64("start_addr")
        .hidden_column_int64("n")
        .row_lookup([](ByteRow& row, int64_t addr_val) -> bool {
            InitializedCursor cursor;
            populate_byte_row(core::get_bv(), row, static_cast<uint64_t>(addr_val), cursor);
            return true;
        })
        // Bounded read: start_addr = X AND n = N, yielded in SQL order (the
        // part at or above 2^63 first when the run crosses it).
        .constraint_filter(
            {xsql::required_eq("start_addr", ""), xsql::required_eq("n", "")},
            make_bytes_n_generator,
            1.0, 1.0)
        .order_by_consumed("addr")
        // Point read.
        .constraint_filter(
            {xsql::required_eq("addr", "")},
            make_bytes_range_generator,
            1.0, 1.0)
        // Range scan, walked in SQL order (see BytesRangeGenerator).
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            make_bytes_range_generator,
            10.0, 100.0)
        .order_by_consumed("addr")
        .build();
}

} // namespace memory
} // namespace bnsql
