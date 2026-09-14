// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_bytes.hpp"

#include <algorithm>
#include <limits>

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

void populate_byte_row(const BinaryNinja::Ref<BinaryNinja::BinaryView>& bv,
                       ByteRow& row, uint64_t addr) {
    row.address = addr;
    row.value = 0;
    row.is_initialized = false;
    if (!bv) return;

    // Use BN's canonical segment lookup for overlaps and compute initialization
    // once per row. The column getters then reuse the snapshot instead of each
    // rebuilding the complete segment list.
    auto seg = bv->GetSegmentAt(addr);
    if (!seg) return;
    const uint64_t start = seg->GetStart();
    if (addr < start || addr - start >= seg->GetDataLength()) return;
    row.is_initialized = true;
    row.value = read_one_byte(bv, addr);
}

struct ByteBounds {
    bool has_lower = false;
    uint64_t lower = 0;
    bool lower_inclusive = true;
    bool has_upper = false;
    uint64_t upper = 0;
    bool upper_inclusive = true;
};

void tighten_lower(ByteBounds& b, uint64_t ea, bool inclusive) {
    if (!b.has_lower || ea > b.lower ||
        (ea == b.lower && !inclusive && b.lower_inclusive)) {
        b.has_lower = true;
        b.lower = ea;
        b.lower_inclusive = inclusive;
    }
}

void tighten_upper(ByteBounds& b, uint64_t ea, bool inclusive) {
    if (!b.has_upper || ea < b.upper ||
        (ea == b.upper && !inclusive && b.upper_inclusive)) {
        b.has_upper = true;
        b.upper = ea;
        b.upper_inclusive = inclusive;
    }
}

bool within_bounds(uint64_t ea, const ByteBounds& b) {
    if (b.has_lower &&
        (ea < b.lower || (ea == b.lower && !b.lower_inclusive))) {
        return false;
    }
    if (b.has_upper &&
        (ea > b.upper || (ea == b.upper && !b.upper_inclusive))) {
        return false;
    }
    return true;
}

// Walk mapped bytes through a BinaryView's segments, ascending. Skips
// unmapped regions.
class BytesRangeGenerator : public xsql::Generator<ByteRow> {
    BinaryNinja::Ref<BinaryNinja::BinaryView> bv_;
    std::vector<std::pair<uint64_t, uint64_t>> spans_;
    size_t span_idx_ = 0;
    uint64_t current_ = 0;
    bool started_ = false;
    bool ended_ = false;
    ByteBounds bounds_;
    mutable ByteRow row_{};

public:
    BytesRangeGenerator(BinaryNinja::Ref<BinaryNinja::BinaryView> bv, ByteBounds bounds)
        : bv_(bv), bounds_(bounds) {
        if (!bv_) {
            ended_ = true;
            return;
        }
        for (auto& seg : bv_->GetSegments()) {
            uint64_t s = seg->GetStart();
            const uint64_t length = seg->GetLength();
            uint64_t e = length > std::numeric_limits<uint64_t>::max() - s
                             ? std::numeric_limits<uint64_t>::max()
                             : s + length;
            if (e <= s) continue;
            // Apply bounds to the segment span.
            if (bounds_.has_lower) {
                if (!bounds_.lower_inclusive &&
                    bounds_.lower == std::numeric_limits<uint64_t>::max()) {
                    continue;
                }
                uint64_t lo = bounds_.lower_inclusive
                                  ? bounds_.lower
                                  : bounds_.lower + 1;
                if (lo > s) s = lo;
            }
            if (bounds_.has_upper) {
                uint64_t hi = bounds_.upper;
                if (bounds_.upper_inclusive &&
                    bounds_.upper != std::numeric_limits<uint64_t>::max()) {
                    ++hi;
                } else if (bounds_.upper_inclusive) {
                    hi = std::numeric_limits<uint64_t>::max();
                }
                if (hi < e) e = hi;
            }
            if (e > s) spans_.emplace_back(s, e);
        }
        std::sort(spans_.begin(), spans_.end());
        std::vector<std::pair<uint64_t, uint64_t>> merged;
        merged.reserve(spans_.size());
        for (const auto& span : spans_) {
            if (merged.empty() || span.first > merged.back().second) {
                merged.push_back(span);
            } else if (span.second > merged.back().second) {
                merged.back().second = span.second;
            }
        }
        spans_ = std::move(merged);
    }

    bool next() override {
        if (ended_) return false;
        if (!started_) {
            started_ = true;
            if (spans_.empty()) { ended_ = true; return false; }
            current_ = spans_[0].first;
        } else {
            if (current_ + 1 >= spans_[span_idx_].second) {
                ++span_idx_;
                if (span_idx_ >= spans_.size()) { ended_ = true; return false; }
                current_ = spans_[span_idx_].first;
            } else {
                ++current_;
            }
        }
        if (!within_bounds(current_, bounds_)) { ended_ = true; return false; }
        populate_byte_row(bv_, row_, current_);
        return true;
    }

    const ByteRow& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_); }
};

// Yields exactly N consecutive addresses starting at X, ignoring segment
// boundaries (mirrors the idasql BytesNGenerator semantic). The `value`
// column reads through ReadBuffer; unmapped positions yield 0.
class BytesNGenerator : public xsql::Generator<ByteRow> {
    uint64_t start_;
    int64_t remaining_;
    bool started_ = false;
    uint64_t current_ = 0;
    mutable ByteRow row_{};

public:
    BytesNGenerator(uint64_t start, int64_t n)
        : start_(start), remaining_(n < 0 ? 0 : n) {}

    bool next() override {
        if (remaining_ <= 0) return false;
        if (!started_) {
            started_ = true;
            current_ = start_;
        } else {
            if (current_ + 1 < current_) return false;  // overflow guard
            ++current_;
        }
        --remaining_;
        populate_byte_row(core::get_bv(), row_, current_);
        return true;
    }

    const ByteRow& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_); }
};

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_range_generator(const std::vector<xsql::GeneratorConstraintArg>& args) {
    ByteBounds bounds;
    for (const auto& arg : args) {
        if (arg.column_index != kBytesAddress) continue;
        const uint64_t ea = static_cast<uint64_t>(arg.value.as_int64());
        switch (arg.op) {
            case xsql::ConstraintOp::Eq:
                tighten_lower(bounds, ea, true);
                tighten_upper(bounds, ea, true);
                break;
            case xsql::ConstraintOp::Gt:
                tighten_lower(bounds, ea, false);
                break;
            case xsql::ConstraintOp::Ge:
                tighten_lower(bounds, ea, true);
                break;
            case xsql::ConstraintOp::Lt:
                tighten_upper(bounds, ea, false);
                break;
            case xsql::ConstraintOp::Le:
                tighten_upper(bounds, ea, true);
                break;
        }
    }
    return std::make_unique<BytesRangeGenerator>(core::get_bv(), bounds);
}

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_n_generator(const std::vector<xsql::GeneratorConstraintArg>& args) {
    uint64_t start = 0;
    int64_t n = 0;
    for (const auto& arg : args) {
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        if (arg.column_index == kBytesStartAddress) {
            start = static_cast<uint64_t>(arg.value.as_int64());
        } else if (arg.column_index == kBytesN) {
            n = arg.value.as_int64();
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
            return std::make_unique<BytesRangeGenerator>(core::get_bv(), ByteBounds{});
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
            auto bv = core::get_bv();
            populate_byte_row(bv, row, static_cast<uint64_t>(addr_val));
            return true;
        })
        // Bounded read: start_addr = X AND n = N.
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
        // Range scan.
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
