// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * @file num_parse.hpp
 * @brief Small, dependency-free numeric parsing helpers.
 *
 * Header-only and Binary-Ninja-free so it can be unit-tested in isolation.
 */

#include <exception>
#include <string>

namespace bnsql {

/// Strict, non-throwing base-10 parse of a whole `long long`.
///
/// Returns true and writes `out` only when the ENTIRE string is a valid
/// integer. Returns false (leaving `out` untouched) on empty, non-numeric,
/// partially-numeric ("12x"), or out-of-range input. Never throws — std::stoll
/// would otherwise throw std::invalid_argument / std::out_of_range, which must
/// not escape a /status handler.
inline bool parse_strict_ll(const std::string& s, long long& out) {
    if (s.empty()) {
        return false;
    }
    try {
        std::size_t consumed = 0;
        const long long value = std::stoll(s, &consumed);
        if (consumed != s.size()) {
            return false;  // trailing non-numeric characters
        }
        out = value;
        return true;
    } catch (const std::exception&) {
        return false;  // invalid_argument or out_of_range
    }
}

}  // namespace bnsql
