// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * bytes_table.hpp - Pure mapped-byte virtual table for Binary Ninja.
 *
 * One row per mapped byte address. Backed by `bv->ReadBuffer(...)` /
 * `bv->IsValidOffset(...)`. Read-only; byte patching lives in the
 * existing `patches` table (see types.hpp).
 *
 * Pushdown:
 *   - `WHERE address = X`                    point lookup
 *   - `WHERE start_address = X AND n = N`    bounded read (N consecutive bytes from X)
 *   - `WHERE address BETWEEN A AND B`        two-sided range
 *
 * Bulk reads compose with libxsql's `blob_concat` aggregate:
 *   SELECT hex(blob_concat(value))
 *     FROM bytes WHERE start_address = X AND n = N ORDER BY address;   -- hex string
 *   SELECT blob_concat(value)
 *     FROM bytes WHERE start_address = X AND n = N ORDER BY address;   -- BLOB
 *
 * The hidden `start_address` and `n` columns are input-only — they do
 * NOT appear in `SELECT *`. Keeping `start_address` distinct from the
 * visible `address` ensures any user predicate on `address` (e.g.
 * inside a JOIN) stays enforceable by SQLite. Unbounded
 * `WHERE address > X` without an upper bound or LIMIT walks every
 * mapped byte from X to end-of-image.
 */

#pragma once

#include <bnsql/vtable.hpp>

#include "binaryninjaapi.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace bnsql {

// Forward declaration: implemented in entities.hpp as
// bnsql::entities::get_bv(). Returns the current thread/session
// BinaryView reference; may be null when no session is active. Declared
// here (not included) to keep bytes_table.hpp free of the entities.hpp
// dependency cycle (entities.hpp pulls bytes_table.hpp in).
namespace entities {
BinaryNinja::Ref<BinaryNinja::BinaryView> get_bv();
}

struct ByteRow {
    uint64_t address = 0;
};

namespace bytes_detail {

inline uint8_t read_one_byte(BinaryNinja::Ref<BinaryNinja::BinaryView>& bv, uint64_t addr) {
    if (!bv) return 0;
    BinaryNinja::DataBuffer buf = bv->ReadBuffer(addr, 1);
    if (buf.GetLength() < 1) return 0;
    return static_cast<const uint8_t*>(buf.GetData())[0];
}

// Column indices for the bytes table; keep in sync with define_bytes_table().
enum BytesColumn {
    kBytesAddress = 0,
    kBytesValue = 1,
    kBytesStartAddress = 2,
    kBytesN = 3,
};

struct ByteBounds {
    bool has_lower = false;
    uint64_t lower = 0;
    bool lower_inclusive = true;
    bool has_upper = false;
    uint64_t upper = 0;
    bool upper_inclusive = true;
};

inline void tighten_lower(ByteBounds& b, uint64_t ea, bool inclusive) {
    if (!b.has_lower || ea > b.lower ||
        (ea == b.lower && !inclusive && b.lower_inclusive)) {
        b.has_lower = true;
        b.lower = ea;
        b.lower_inclusive = inclusive;
    }
}

inline void tighten_upper(ByteBounds& b, uint64_t ea, bool inclusive) {
    if (!b.has_upper || ea < b.upper ||
        (ea == b.upper && !inclusive && b.upper_inclusive)) {
        b.has_upper = true;
        b.upper = ea;
        b.upper_inclusive = inclusive;
    }
}

inline bool within_bounds(uint64_t ea, const ByteBounds& b) {
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
            uint64_t e = s + seg->GetLength();
            if (e <= s) continue;
            // Apply bounds to the segment span.
            if (bounds_.has_lower) {
                uint64_t lo = bounds_.lower_inclusive ? bounds_.lower : bounds_.lower + 1;
                if (lo > s) s = lo;
            }
            if (bounds_.has_upper) {
                uint64_t hi = bounds_.upper_inclusive ? bounds_.upper + 1 : bounds_.upper;
                if (hi < e) e = hi;
            }
            if (e > s) spans_.emplace_back(s, e);
        }
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
        row_.address = current_;
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
        row_.address = current_;
        return true;
    }

    const ByteRow& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_); }
};

inline std::unique_ptr<xsql::Generator<ByteRow>>
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
    return std::make_unique<BytesRangeGenerator>(entities::get_bv(), bounds);
}

inline std::unique_ptr<xsql::Generator<ByteRow>>
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

inline GeneratorTableDef<ByteRow> define_bytes_table() {
    using namespace bytes_detail;
    return generator_table<ByteRow>("bytes")
        .estimate_rows([]() -> size_t {
            auto bv = entities::get_bv();
            if (!bv) return 0;
            uint64_t total = 0;
            for (auto& seg : bv->GetSegments()) total += seg->GetLength();
            return static_cast<size_t>(total);
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
            return std::make_unique<BytesRangeGenerator>(entities::get_bv(), ByteBounds{});
        })
        .column_int64("address", [](const ByteRow& r) -> int64_t {
            return static_cast<int64_t>(r.address);
        })
        .column_int("value", [](const ByteRow& r) -> int {
            auto bv = entities::get_bv();
            return static_cast<int>(read_one_byte(bv, r.address));
        })
        // Hidden input columns for bounded reads: WHERE start_address = X
        // AND n = N. Both are HIDDEN (input-only); keeping start_address
        // distinct from the visible `address` keeps any user predicate on
        // `address` enforceable by SQLite (joins stay correct).
        .hidden_column_int64("start_address")
        .hidden_column_int64("n")
        .row_lookup([](ByteRow& row, int64_t addr_val) -> bool {
            row.address = static_cast<uint64_t>(addr_val);
            return true;
        })
        // Bounded read: start_address = X AND n = N.
        .constraint_filter(
            {xsql::required_eq("start_address", ""), xsql::required_eq("n", "")},
            make_bytes_n_generator,
            1.0, 1.0)
        .order_by_consumed("address")
        // Point read.
        .constraint_filter(
            {xsql::required_eq("address", "")},
            make_bytes_range_generator,
            1.0, 1.0)
        // Range scan.
        .constraint_filter(
            {xsql::optional_ge("address"), xsql::optional_gt("address"),
             xsql::optional_lt("address"), xsql::optional_le("address")},
            make_bytes_range_generator,
            10.0, 100.0)
        .order_by_consumed("address")
        .build();
}

} // namespace bnsql
