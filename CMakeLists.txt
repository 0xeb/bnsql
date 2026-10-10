#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

cmake_minimum_required(VERSION 3.20)
project(bnsql LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Version single source of truth: src/common/bnsql_version.hpp. Parse it here so
# the Windows VERSIONINFO resource can never drift from the header (the CLI reads
# BNSQL_VERSION_STRING from the same header).
set(_bnsql_version_hpp "${CMAKE_CURRENT_SOURCE_DIR}/src/common/bnsql_version.hpp")
file(READ "${_bnsql_version_hpp}" _bnsql_version_contents)
string(REGEX MATCH
    "BNSQL_VERSION_STRING[ \t]+\"([0-9]+)\\.([0-9]+)\\.([0-9]+)\""
    _bnsql_version_match "${_bnsql_version_contents}")
set(TOOL_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(TOOL_VERSION_MINOR "${CMAKE_MATCH_2}")
set(TOOL_VERSION_PATCH "${CMAKE_MATCH_3}")
if(TOOL_VERSION_MAJOR STREQUAL "" OR TOOL_VERSION_MINOR STREQUAL "" OR TOOL_VERSION_PATCH STREQUAL "")
    message(FATAL_ERROR "bnsql: failed to parse version from ${_bnsql_version_hpp}")
endif()
message(STATUS "bnsql: version ${TOOL_VERSION_MAJOR}.${TOOL_VERSION_MINOR}.${TOOL_VERSION_PATCH}")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# Output directories
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# ============================================================================
# Binary Ninja API
# ============================================================================

# Resolve BN_INSTALL_DIR: -D flag > env var > warn. Used to install the CLI next
# to Binary Ninja so it can locate libbinaryninjacore at runtime.
if(NOT BN_INSTALL_DIR)
    if(DEFINED ENV{BN_INSTALL_DIR})
        set(BN_INSTALL_DIR "$ENV{BN_INSTALL_DIR}" CACHE PATH "Path to Binary Ninja installation")
        message(STATUS "bnsql: Using BN_INSTALL_DIR from environment: ${BN_INSTALL_DIR}")
    else()
        message(WARNING "bnsql: BN_INSTALL_DIR not specified. The CLI will build but won't be\n"
            "  installed next to Binary Ninja (needed to locate libbinaryninjacore at runtime).\n"
            "  Set via cmake flag:  -DBN_INSTALL_DIR=/path/to/binaryninja\n"
            "  Or environment var:  export BN_INSTALL_DIR=/path/to/binaryninja")
    endif()
else()
    message(STATUS "bnsql: Using BN_INSTALL_DIR from cmake flag: ${BN_INSTALL_DIR}")
endif()

# Helper: install a Binary Ninja plugin target into the BN user plugins directory
function(bn_install_plugin target)
    if(WIN32)
        set(BN_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    elseif(APPLE)
        set(BN_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    else()
        set(BN_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    endif()
    install(TARGETS ${target}
        LIBRARY DESTINATION "${BN_PLUGINS_DIR}"
        RUNTIME DESTINATION "${BN_PLUGINS_DIR}"
    )
endfunction()

# Option to specify BN API path (defaults to external submodule)
set(BN_API_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external/binaryninja-api" CACHE PATH "Path to Binary Ninja API")

if(NOT EXISTS "${BN_API_PATH}/CMakeLists.txt")
    message(FATAL_ERROR "Binary Ninja API not found at ${BN_API_PATH}\n"
        "Initialize submodule: git submodule update --init --recursive")
endif()

# Add Binary Ninja API
if(NOT DEFINED HEADLESS)
    set(HEADLESS ON CACHE BOOL "Build Binary Ninja API in headless mode" FORCE)
endif()
if(HEADLESS)
    message(STATUS "bnsql: Configuring Binary Ninja API in HEADLESS mode")
endif()
add_subdirectory(${BN_API_PATH} ${CMAKE_CURRENT_BINARY_DIR}/binaryninja-api)

# ============================================================================
# HTTP Server Support (optional, uses cpp-httplib via libxsql thinclient)
# ============================================================================

option(BNSQL_WITH_HTTP "Build with HTTP REST server support" ON)

if(BNSQL_WITH_HTTP)
    message(STATUS "bnsql: Building with HTTP server support")
    set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)
endif()

# ============================================================================
# libxsql dependency
# ============================================================================
# NOTE: this must stay AHEAD of the MCP block below. libxsql is what creates the
# httplib::httplib target, and fastmcpp only consumes that target if it already
# exists when fastmcpp is configured. Configure fastmcpp first and it falls back
# to fetching its own private cpp-httplib copy, putting two sets of header-only
# inline definitions into one binary — an ODR violation that shows up as a crash
# inside httplib's mutexes rather than as a link error.

if(TARGET xsql::xsql)
    message(STATUS "bnsql: Using existing xsql::xsql target")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "bnsql: Added libxsql from sibling directory")
else()
    message(STATUS "bnsql: Fetching libxsql from GitHub...")
    include(FetchContent)
    # Pinned to the libxsql release this bnsql was built and tested against.
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        v1.0.18
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# libxsql's thin client pulls cpp-httplib, which since libxsql v1.0.15 fetches
# zlib for gzip response compression. zlib's own CMakeLists does not mark
# zlibstatic position-independent, so linking that archive into bnsql.so fails
# on ELF x86_64 with "relocation R_X86_64_PC32 against symbol `_length_code'
# can not be used when making a shared object". Windows (PE) and macOS do not
# care, which is why this only ever breaks the Linux plugin build. zlibstatic
# is third-party, so set the property here rather than patching the fetched
# tree; it is a no-op where the target does not exist (thin client disabled, or
# an httplib supplied by the parent project).
if(TARGET zlibstatic)
    set_target_properties(zlibstatic PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# ============================================================================
# MCP Server Support (optional, uses fastmcpp)
# ============================================================================

option(BNSQL_WITH_MCP "Build with MCP server support" ON)

if(BNSQL_WITH_MCP)
    if(NOT TARGET fastmcpp_core)
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_POST_STREAMING OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_SAMPLING_HTTP_HANDLERS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_FETCH_CURL OFF CACHE BOOL "" FORCE)
        message(STATUS "bnsql: Fetching fastmcpp from GitHub...")
        include(FetchContent)
        FetchContent_Declare(fastmcpp
            GIT_REPOSITORY https://github.com/0xeb/fastmcpp.git
            GIT_TAG        main
            GIT_SHALLOW    TRUE
        )
        FetchContent_MakeAvailable(fastmcpp)
    endif()
    # Keep fastmcpp's cpp-httplib feature macros identical to everyone else's.
    if(TARGET fastmcpp_core AND TARGET httplib::httplib)
        target_link_libraries(fastmcpp_core PUBLIC httplib::httplib)
    endif()
    message(STATUS "bnsql: Building with MCP server support")
endif()

# ============================================================================
# bnsql library (compiled STATIC library)
# ============================================================================
# Compiled STATIC library (mirrors idasql). Every table/UDF is split into its own
# translation unit under src/lib/src/: the core entity tables grouped by domain
# namespace (code/symbols/memory/xrefs/meta), decompiler, types_*, and the scalar/
# search UDFs. The QueryEngine is PIMPL'd (database.cpp) so consumers never
# instantiate the builders. The per-table split keeps every TU small enough that
# /bigobj is no longer needed anywhere (plugin, CLI, or library).

add_library(bnsql STATIC
    # shared infra + PIMPL'd engine
    src/lib/src/core_common.cpp
    src/lib/src/database.cpp
    # core registry + entity-domain tables
    src/lib/src/core_registry.cpp
    src/lib/src/code_funcs.cpp
    src/lib/src/code_blocks.cpp
    src/lib/src/code_cfg.cpp
    src/lib/src/code_switch_tables.cpp
    src/lib/src/code_function_frames.cpp
    src/lib/src/code_data_items.cpp
    src/lib/src/code_graph_tables.cpp
    src/lib/src/code_instructions.cpp
    src/lib/src/code_operands.cpp
    src/lib/src/symbols_names.cpp
    src/lib/src/symbols_exports.cpp
    src/lib/src/symbols_imports.cpp
    src/lib/src/symbols_comments.cpp
    src/lib/src/symbols_bookmarks.cpp
    src/lib/src/memory_segments.cpp
    src/lib/src/memory_strings.cpp
    src/lib/src/memory_bytes.cpp
    src/lib/src/xrefs.cpp
    src/lib/src/meta_binary.cpp
    src/lib/src/meta_capabilities.cpp
    src/lib/src/meta_true_believers.cpp
    # decompiler domain
    src/lib/src/decompiler.cpp
    # types domain
    src/lib/src/types_registry.cpp
    src/lib/src/types_types.cpp
    src/lib/src/types_members.cpp
    src/lib/src/types_enum_values.cpp
    src/lib/src/types_func_signatures.cpp
    src/lib/src/types_patches.cpp
    # scalar / search UDFs
    src/lib/src/functions.cpp
    src/lib/src/bnsql_python_exec.cpp   # BN-Python exec engine (bnsql_python + ui-context)
    src/lib/src/search_bytes.cpp
    src/lib/src/true_believers.cpp   # vendored true_believers decoder
)
add_library(bnsql::bnsql ALIAS bnsql)

target_include_directories(bnsql
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common   # bnsql_version.hpp (binary table tool_version)
)

target_link_libraries(bnsql PUBLIC
    xsql::xsql
    binaryninjaapi
)

if(MSVC)
    # No /bigobj: the per-table split keeps every translation unit well under the
    # COFF section limit.
    target_compile_definitions(bnsql PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# Avoid name collision with bnsql_plugin's import lib (bnsql.lib)
set_target_properties(bnsql PROPERTIES OUTPUT_NAME "libbnsql")

# Position-independent code so this STATIC lib can be linked into the
# bnsql_plugin SHARED object on Linux. Without it, ELF x86_64 rejects the
# thread_local g_context TLS relocation (R_X86_64_TPOFF32) when pulling the
# archive into a .so. No-op on Windows (PE has no -fPIC distinction); the CLI
# and test executables link the same PIC archive fine.
set_target_properties(bnsql PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Precompile the Binary Ninja SDK superset once for the whole library.
target_precompile_headers(bnsql PRIVATE src/lib/src/bn_headers.hpp)

# The vendored true_believers decoder is engine-agnostic — keep the BN PCH out
# of it so it compiles standalone with no Binary Ninja dependency.
set_source_files_properties(src/lib/src/true_believers.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# The `capabilities` table (meta_capabilities.cpp) bakes feature.http_server /
# feature.mcp_server from these defines. It now compiles once inside the library,
# so drive them from the library's own build options.
if(BNSQL_WITH_HTTP)
    target_compile_definitions(bnsql PRIVATE BNSQL_HAS_HTTP)
endif()
if(BNSQL_WITH_MCP)
    target_compile_definitions(bnsql PRIVATE BNSQL_HAS_MCP)
endif()

# ============================================================================
# bnsql plugin (Binary Ninja plugin)
# ============================================================================

option(BNSQL_BUILD_PLUGIN "Build bnsql Binary Ninja plugin" ON)

if(BNSQL_BUILD_PLUGIN)
    add_library(bnsql_plugin SHARED
        src/plugin/plugin.cpp
        src/plugin/ui_context_capture.cpp
    )

    target_link_libraries(bnsql_plugin PRIVATE
        bnsql::bnsql
    )

    # Include common headers (for bnsql_http_routes.hpp, etc.) + the lib's private
    # src (for bnsql_python_exec.hpp used by ui_context_capture.cpp).
    target_include_directories(bnsql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/src
    )

    # plugin.cpp no longer needs /bigobj: the SQL table surface is compiled into
    # the bnsql library now, so it no longer instantiates in this translation unit.
    # (It hit the COFF section limit purely from that surface before the refactor.)

    # Plugin-specific build flag (enables UI context UDF)
    target_compile_definitions(bnsql_plugin PRIVATE BNSQL_PLUGIN_BUILD)

    # Add HTTP server support to plugin
    if(BNSQL_WITH_HTTP)
        target_compile_definitions(bnsql_plugin PRIVATE BNSQL_HAS_HTTP)
    endif()

    # Set plugin output name
    set_target_properties(bnsql_plugin PROPERTIES
        OUTPUT_NAME "bnsql"
        PREFIX ""
    )

    # Windows VS_VERSION_INFO resource
    xsql_add_versioninfo(bnsql_plugin
        FILETYPE          VFT_DLL
        DESCRIPTION       "bnsql plugin for Binary Ninja"
        ORIGINAL_FILENAME "bnsql.dll")

    # Platform-specific plugin extension
    if(WIN32)
        set_target_properties(bnsql_plugin PROPERTIES SUFFIX ".dll")
    elseif(APPLE)
        set_target_properties(bnsql_plugin PROPERTIES SUFFIX ".dylib")
    else()
        set_target_properties(bnsql_plugin PROPERTIES SUFFIX ".so")
    endif()

    # Install plugin into the Binary Ninja user plugins directory
    bn_install_plugin(bnsql_plugin)
endif()

# ============================================================================
# bnsql CLI tool
# ============================================================================

option(BNSQL_BUILD_CLI "Build bnsql command-line tool" ON)

if(BNSQL_BUILD_CLI)
    set(BNSQL_CLI_SOURCES
        src/cli/main.cpp
    )

    # Add Windows manifest for UTF-8 support (Windows 10 1903+)
    if(WIN32)
        list(APPEND BNSQL_CLI_SOURCES
            src/cli/bnsql.manifest
        )
    endif()

    add_executable(bnsql-cli ${BNSQL_CLI_SOURCES})

    target_link_libraries(bnsql-cli PRIVATE
        bnsql::bnsql
    )


    # Common headers (bnsql_commands.hpp, bnsql_http_routes.hpp, etc.)
    target_include_directories(bnsql-cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    )

    # Add HTTP server support
    if(BNSQL_WITH_HTTP)
        target_compile_definitions(bnsql-cli PRIVATE BNSQL_HAS_HTTP)
    endif()

    # Add MCP server support
    if(BNSQL_WITH_MCP)
        target_sources(bnsql-cli PRIVATE src/common/mcp_server.cpp)
        target_link_libraries(bnsql-cli PRIVATE fastmcpp_core)
        target_compile_definitions(bnsql-cli PRIVATE BNSQL_HAS_MCP)
    endif()

    set_target_properties(bnsql-cli PROPERTIES
        OUTPUT_NAME "bnsql"
    )

    # Install CLI next to Binary Ninja so it can find libbinaryninjacore at runtime
    if(BN_INSTALL_DIR)
        get_filename_component(_BN_INSTALL_ABS "${BN_INSTALL_DIR}" ABSOLUTE)
        install(TARGETS bnsql-cli RUNTIME DESTINATION "${_BN_INSTALL_ABS}")
    endif()

    # Windows VS_VERSION_INFO resource
    xsql_add_versioninfo(bnsql-cli
        FILETYPE          VFT_APP
        DESCRIPTION       "bnsql command-line interface for Binary Ninja databases"
        ORIGINAL_FILENAME "bnsql.exe")

    # Delay-load Binary Ninja DLLs on Windows
    # Allows CLI to check for DLL presence before loading
    if(WIN32 AND MSVC)
        target_link_options(bnsql-cli PRIVATE
            "/DELAYLOAD:binaryninjacore.dll"
        )
        target_link_libraries(bnsql-cli PRIVATE delayimp.lib)
    endif()
endif()

# ============================================================================
# Examples
# ============================================================================

option(BNSQL_BUILD_EXAMPLES "Build bnsql library examples" ON)

if(BNSQL_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()
