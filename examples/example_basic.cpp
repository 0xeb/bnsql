/**
 * example_basic.cpp - Basic BNSQL usage with QueryEngine
 *
 * Demonstrates:
 *   - Loading a Binary Ninja database with loader::load_binary()
 *   - Creating a QueryEngine for SQL access
 *   - Running queries with query() and getting results
 *   - Using scalar() for single values
 *   - Iterating over result rows
 *
 * Build & Run:
 *   cmake -B build -DBN_INSTALL_DIR=/path/to/binaryninja
 *   cmake --build build --config Release
 *   set PATH=%BN_INSTALL_DIR%;%PATH%
 *   build\Release\example_basic.exe database.bndb
 */

#include <iostream>
#include <bnsql/bnsql.hpp>

using namespace BinaryNinja;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.bndb|binary>\n";
        return 1;
    }

    // ==========================================================================
    // Initialize Binary Ninja
    // ==========================================================================

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

    // ==========================================================================
    // Load the binary using BNSQL's loader
    // ==========================================================================

    std::cout << "Loading: " << argv[1] << "...\n";

    bnsql::loader::LoadOptions opts;
    opts.auto_save = true;  // Save .bndb if analyzing raw binary
    opts.log = [](const std::string& msg) { std::cout << "  " << msg << "\n"; };

    auto loaded = bnsql::loader::load_binary(argv[1], opts);
    if (!loaded) {
        std::cerr << "Error: " << loaded.error << "\n";
        return 1;
    }

    // ==========================================================================
    // Create QueryEngine
    // ==========================================================================

    bnsql::QueryEngine qe(loaded.bv);

    // ==========================================================================
    // Example 1: Get single values with scalar()
    // ==========================================================================

    std::cout << "\n=== Scalar Queries ===\n";

    std::string func_count = qe.scalar("SELECT COUNT(*) FROM funcs");
    std::cout << "Total functions: " << func_count << "\n";

    std::string segment_count = qe.scalar("SELECT COUNT(*) FROM segments");
    std::cout << "Total segments: " << segment_count << "\n";

    std::string string_count = qe.scalar("SELECT COUNT(*) FROM strings");
    std::cout << "Total strings: " << string_count << "\n";

    // ==========================================================================
    // Example 2: Query with result set
    // ==========================================================================

    std::cout << "\n=== Top 5 Largest Functions ===\n";

    auto result = qe.query(
        "SELECT printf('0x%X', address) as addr, name, size "
        "FROM funcs ORDER BY size DESC LIMIT 5"
    );

    if (result.success) {
        // Print column headers
        for (const auto& col : result.columns) {
            std::cout << col << "\t";
        }
        std::cout << "\n" << std::string(50, '-') << "\n";

        // Print rows
        for (const auto& row : result) {
            std::cout << row[0] << "\t" << row[1] << "\t" << row[2] << "\n";
        }
        std::cout << "\n(" << result.row_count() << " rows)\n";
    } else {
        std::cerr << "Query failed: " << result.error << "\n";
    }

    // ==========================================================================
    // Example 3: Segments listing
    // ==========================================================================

    std::cout << "\n=== Segments ===\n";

    auto segments = qe.query(
        "SELECT name, printf('0x%X', start_ea) as start, "
        "       printf('0x%X', end_ea) as end, perm "
        "FROM segments"
    );

    for (const auto& row : segments) {
        std::cout << row[0] << ": " << row[1] << " - " << row[2]
                  << " (perm: " << row[3] << ")\n";
    }

    // ==========================================================================
    // Example 4: Using SQL functions
    // ==========================================================================

    std::cout << "\n=== SQL Functions ===\n";

    // Get first function using SQL
    auto first_func = qe.query(
        "SELECT printf('0x%X', address) as addr, name "
        "FROM funcs LIMIT 1"
    );
    if (!first_func.empty()) {
        std::cout << "First function: " << first_func.rows[0][1]
                  << " at " << first_func.rows[0][0] << "\n";
    }

    // Database info
    auto db_info = qe.query(
        "SELECT key, value FROM db_info WHERE key IN ('filename', 'arch', 'platform')"
    );
    std::cout << "\nDatabase info:\n";
    for (const auto& row : db_info) {
        std::cout << "  " << row[0] << ": " << row[1] << "\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
