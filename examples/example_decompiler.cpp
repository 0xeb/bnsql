// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * example_decompiler.cpp - Decompiler analysis with BNSQL
 *
 * Demonstrates:
 *   - Querying pseudocode table (line-by-line access)
 *   - Querying hlil_vars table (local variables)
 *   - Querying hlil_calls table (function call arguments)
 *   - Using decompile() SQL function (full text)
 *   - Finding patterns in decompiled code
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

    std::cout << "=== Decompiler Analysis ===\n\n";

    // =========================================================================
    // Functions by pseudocode line count
    // =========================================================================

    std::cout << "=== Functions by Pseudocode Complexity ===\n";

    auto complex = qe.query(
        "SELECT "
        "  func_at(func_addr) as name, "
        "  COUNT(*) as lines "
        "FROM pseudocode "
        "GROUP BY func_addr "
        "ORDER BY lines DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(40) << "Function" << "Lines\n";
    std::cout << std::string(50, '-') << "\n";
    for (const auto& row : complex) {
        std::cout << std::setw(40) << row[0] << row[1] << "\n";
    }

    // =========================================================================
    // Functions with most local variables
    // =========================================================================

    std::cout << "\n=== Functions with Most Local Variables ===\n";

    auto most_vars = qe.query(
        "SELECT "
        "  func_at(func_addr) as name, "
        "  COUNT(*) as total_vars, "
        "  SUM(CASE WHEN is_arg = 1 THEN 1 ELSE 0 END) as args, "
        "  SUM(CASE WHEN is_arg = 0 THEN 1 ELSE 0 END) as locals "
        "FROM hlil_vars "
        "GROUP BY func_addr "
        "ORDER BY total_vars DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(35) << "Function"
              << std::setw(8) << "Total"
              << std::setw(8) << "Args"
              << "Locals\n";
    std::cout << std::string(60, '-') << "\n";
    for (const auto& row : most_vars) {
        std::cout << std::setw(35) << row[0]
                  << std::setw(8) << row[1]
                  << std::setw(8) << row[2]
                  << row[3] << "\n";
    }

    // =========================================================================
    // Variable storage analysis
    // =========================================================================

    std::cout << "\n=== Variable Storage Types ===\n";

    auto storage = qe.query(
        "SELECT storage, COUNT(*) as count "
        "FROM hlil_vars "
        "GROUP BY storage "
        "ORDER BY count DESC"
    );

    for (const auto& row : storage) {
        std::cout << std::setw(15) << row[0] << ": " << row[1] << " variables\n";
    }

    // =========================================================================
    // Most called functions (by hlil_calls table)
    // =========================================================================

    std::cout << "\n=== Top 10 Called Functions (from hlil_calls) ===\n";

    auto top_calls = qe.query(
        "SELECT callee_name, COUNT(DISTINCT func_addr) as callers "
        "FROM hlil_calls "
        "WHERE callee_name IS NOT NULL "
        "GROUP BY callee_name "
        "ORDER BY callers DESC "
        "LIMIT 10"
    );

    for (const auto& row : top_calls) {
        std::cout << std::setw(40) << row[0] << " - called from " << row[1] << " functions\n";
    }

    // =========================================================================
    // Calls with constant arguments (potential interesting patterns)
    // =========================================================================

    std::cout << "\n=== Calls with Constant Arguments ===\n";

    auto const_args = qe.query(
        "SELECT callee_name, arg_idx, arg_const, COUNT(*) as occurrences "
        "FROM hlil_calls "
        "WHERE arg_const IS NOT NULL AND arg_const != '' "
        "GROUP BY callee_name, arg_idx, arg_const "
        "ORDER BY occurrences DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(30) << "Callee" << std::setw(6) << "Arg#"
              << std::setw(15) << "Const" << "Count\n";
    std::cout << std::string(60, '-') << "\n";
    for (const auto& row : const_args) {
        std::cout << std::setw(30) << row[0]
                  << std::setw(6) << row[1]
                  << std::setw(15) << row[2]
                  << row[3] << "\n";
    }

    // =========================================================================
    // Show pseudocode for largest function
    // =========================================================================

    std::cout << "\n=== Pseudocode for Largest Function (first 25 lines) ===\n";

    auto largest = qe.scalar("SELECT address FROM funcs ORDER BY size DESC LIMIT 1");
    if (!largest.empty()) {
        std::string pseudocode_sql =
            "SELECT line "
            "FROM pseudocode "
            "WHERE func_addr = " + largest + " "
            "ORDER BY line_num "
            "LIMIT 25";
        auto pseudocode = qe.query(pseudocode_sql.c_str());

        for (const auto& row : pseudocode) {
            std::cout << row[0] << "\n";
        }
        if (pseudocode.row_count() == 25) {
            std::cout << "...\n";
        }
    }

    // =========================================================================
    // Local variables for a function
    // =========================================================================

    std::cout << "\n=== Variables in Largest Function ===\n";

    if (!largest.empty()) {
        std::string vars_sql =
            "SELECT name, type, storage, "
            "       CASE WHEN is_arg = 1 THEN 'arg' ELSE 'local' END as kind "
            "FROM hlil_vars "
            "WHERE func_addr = " + largest + " "
            "ORDER BY is_arg DESC, var_idx "
            "LIMIT 15";
        auto vars = qe.query(vars_sql.c_str());

        std::cout << std::setw(20) << "Name"
                  << std::setw(30) << "Type"
                  << std::setw(10) << "Storage"
                  << "Kind\n";
        std::cout << std::string(70, '-') << "\n";
        for (const auto& row : vars) {
            std::cout << std::setw(20) << row[0]
                      << std::setw(30) << row[1]
                      << std::setw(10) << row[2]
                      << row[3] << "\n";
        }
    }

    // =========================================================================
    // Search pseudocode for patterns
    // =========================================================================

    std::cout << "\n=== Lines Containing 'if' Statements ===\n";

    auto if_lines = qe.query(
        "SELECT func_at(func_addr) as func, line "
        "FROM pseudocode "
        "WHERE line LIKE '%if (%' "
        "LIMIT 10"
    );

    for (const auto& row : if_lines) {
        std::cout << "[" << row[0] << "] " << row[1] << "\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
