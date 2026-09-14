// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * example_functions.cpp - Function analysis with BNSQL
 *
 * Demonstrates:
 *   - Querying the funcs table
 *   - Using xrefs for call graph analysis
 *   - Using blocks for CFG analysis
 *   - Combining tables with JOINs
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
    // Function size distribution
    // =========================================================================

    std::cout << "=== Function Size Distribution ===\n";

    auto dist = qe.query(
        "SELECT "
        "  CASE "
        "    WHEN size < 16 THEN '1. tiny (<16)' "
        "    WHEN size < 64 THEN '2. small (16-64)' "
        "    WHEN size < 256 THEN '3. medium (64-256)' "
        "    WHEN size < 1024 THEN '4. large (256-1K)' "
        "    ELSE '5. huge (>1K)' "
        "  END as category, "
        "  COUNT(*) as count, "
        "  SUM(size) as total_bytes "
        "FROM funcs "
        "GROUP BY category "
        "ORDER BY category"
    );

    std::cout << std::left << std::setw(20) << "Category"
              << std::setw(10) << "Count"
              << std::setw(15) << "Total Bytes" << "\n";
    std::cout << std::string(45, '-') << "\n";

    for (const auto& row : dist) {
        std::cout << std::setw(20) << row[0]
                  << std::setw(10) << row[1]
                  << std::setw(15) << row[2] << "\n";
    }

    // =========================================================================
    // Most called functions (incoming xrefs)
    // =========================================================================

    std::cout << "\n=== Top 10 Most Called Functions ===\n";

    auto most_called = qe.query(
        "SELECT f.name, COUNT(*) as callers "
        "FROM funcs f "
        "JOIN xrefs x ON f.addr = x.to_addr "
        "WHERE x.is_code = 1 "
        "GROUP BY f.addr "
        "ORDER BY callers DESC "
        "LIMIT 10"
    );

    for (const auto& row : most_called) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " callers\n";
    }

    // =========================================================================
    // Functions with most basic blocks (complex CFG)
    // =========================================================================

    std::cout << "\n=== Top 10 Functions by Basic Block Count ===\n";

    auto complex = qe.query(
        "SELECT "
        "  (SELECT name FROM funcs WHERE addr = b.func_addr) as name, "
        "  COUNT(*) as blocks, "
        "  SUM(b.size) as total_size "
        "FROM blocks b "
        "GROUP BY b.func_addr "
        "ORDER BY blocks DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(40) << "Function"
              << std::setw(10) << "Blocks"
              << std::setw(12) << "Size" << "\n";
    std::cout << std::string(62, '-') << "\n";

    for (const auto& row : complex) {
        std::cout << std::setw(40) << row[0]
                  << std::setw(10) << row[1]
                  << std::setw(12) << row[2] << "\n";
    }

    // =========================================================================
    // Orphan functions (no incoming xrefs)
    // =========================================================================

    std::cout << "\n=== Orphan Functions (no callers, first 10) ===\n";

    auto orphans = qe.query(
        "SELECT f.name, printf('0x%X', f.addr) as addr "
        "FROM funcs f "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM xrefs x WHERE x.to_addr = f.addr AND x.is_code = 1"
        ") "
        "LIMIT 10"
    );

    for (const auto& row : orphans) {
        std::cout << row[0] << " at " << row[1] << "\n";
    }

    // =========================================================================
    // Functions by import usage
    // =========================================================================

    std::cout << "\n=== Top 10 Functions Using Most Imports ===\n";

    auto import_users = qe.query(
        "SELECT func_at(x.from_addr) as func_name, COUNT(DISTINCT i.name) as imports_used "
        "FROM imports i "
        "JOIN xrefs x ON i.addr = x.to_addr "
        "WHERE func_at(x.from_addr) IS NOT NULL "
        "GROUP BY func_at(x.from_addr) "
        "ORDER BY imports_used DESC "
        "LIMIT 10"
    );

    for (const auto& row : import_users) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " imports\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
