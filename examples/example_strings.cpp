// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * example_strings.cpp - String analysis with BNSQL
 *
 * Demonstrates:
 *   - Querying the strings table
 *   - Pattern matching with LIKE
 *   - Finding xrefs to strings
 *   - String statistics
 */

#include <iostream>
#include <iomanip>
#include <bnsql/bnsql.hpp>

using namespace BinaryNinja;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.bndb|binary>\n";
        return 1;
    }

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

    auto loaded = bnsql::loader::load_binary(argv[1]);
    if (!loaded) {
        std::cerr << "Error: " << loaded.error << "\n";
        return 1;
    }

    bnsql::QueryEngine qe(loaded.bv);

    // =========================================================================
    // String statistics
    // =========================================================================

    std::cout << "=== String Statistics ===\n";

    std::cout << "Total strings: " << qe.scalar("SELECT COUNT(*) FROM strings") << "\n";

    auto avg_len = qe.scalar("SELECT AVG(length) FROM strings");
    std::cout << "Average length: " << avg_len << " chars\n";

    // =========================================================================
    // Longest strings
    // =========================================================================

    std::cout << "\n=== Top 10 Longest Strings ===\n";

    auto longest = qe.query(
        "SELECT printf('0x%X', address) as addr, length, "
        "       SUBSTR(content, 1, 60) as preview "
        "FROM strings "
        "ORDER BY length DESC "
        "LIMIT 10"
    );

    for (const auto& row : longest) {
        std::cout << row[0] << " [" << row[1] << "] \"" << row[2];
        if (std::stoi(row[1]) > 60) std::cout << "...";
        std::cout << "\"\n";
    }

    // =========================================================================
    // Search for interesting strings
    // =========================================================================

    std::cout << "\n=== Error/Warning Strings ===\n";

    auto errors = qe.query(
        "SELECT printf('0x%X', address) as addr, content "
        "FROM strings "
        "WHERE content LIKE '%error%' "
        "   OR content LIKE '%fail%' "
        "   OR content LIKE '%warning%' "
        "   OR content LIKE '%exception%' "
        "LIMIT 15"
    );

    for (const auto& row : errors) {
        std::cout << row[0] << ": \"" << row[1] << "\"\n";
    }

    // =========================================================================
    // URL/Path strings
    // =========================================================================

    std::cout << "\n=== URL/Path Strings ===\n";

    auto urls = qe.query(
        "SELECT printf('0x%X', address) as addr, content "
        "FROM strings "
        "WHERE content LIKE 'http%' "
        "   OR content LIKE 'https%' "
        "   OR content LIKE '%.exe%' "
        "   OR content LIKE '%.dll%' "
        "   OR content LIKE 'C:\\\\%' "
        "LIMIT 15"
    );

    for (const auto& row : urls) {
        std::cout << row[0] << ": \"" << row[1] << "\"\n";
    }

    // =========================================================================
    // Strings with most xrefs (most used)
    // =========================================================================

    std::cout << "\n=== Most Referenced Strings (Top 10) ===\n";

    auto most_used = qe.query(
        "SELECT s.content, COUNT(x.from_ea) as refs "
        "FROM strings s "
        "LEFT JOIN xrefs x ON s.address = x.to_ea "
        "GROUP BY s.address "
        "HAVING refs > 0 "
        "ORDER BY refs DESC "
        "LIMIT 10"
    );

    for (const auto& row : most_used) {
        auto content = row[0].length() > 50 ? row[0].substr(0, 50) + "..." : row[0];
        std::cout << std::setw(5) << row[1] << " refs: \"" << content << "\"\n";
    }

    // =========================================================================
    // Functions using most strings
    // =========================================================================

    std::cout << "\n=== Functions Using Most Strings (Top 10) ===\n";

    auto by_func = qe.query(
        "SELECT func_at(x.from_ea) as func_name, COUNT(DISTINCT s.address) as str_count "
        "FROM strings s "
        "JOIN xrefs x ON s.address = x.to_ea "
        "WHERE func_at(x.from_ea) IS NOT NULL "
        "GROUP BY func_at(x.from_ea) "
        "ORDER BY str_count DESC "
        "LIMIT 10"
    );

    for (const auto& row : by_func) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " strings\n";
    }

    // =========================================================================
    // Format strings (potential printf-like usage)
    // =========================================================================

    std::cout << "\n=== Format Strings (contain %s, %d, etc.) ===\n";

    auto formats = qe.query(
        "SELECT printf('0x%X', address) as addr, content "
        "FROM strings "
        "WHERE content LIKE '%\\%s%' ESCAPE '\\' "
        "   OR content LIKE '%\\%d%' ESCAPE '\\' "
        "   OR content LIKE '%\\%x%' ESCAPE '\\' "
        "   OR content LIKE '%\\%p%' ESCAPE '\\' "
        "LIMIT 10"
    );

    for (const auto& row : formats) {
        std::cout << row[0] << ": \"" << row[1] << "\"\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
