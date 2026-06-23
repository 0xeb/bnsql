cmake_minimum_required(VERSION 3.20)
project(bnsql VERSION 0.0.11 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Windows VERSIONINFO wiring (version is from project() above)
set(TOOL_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(TOOL_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(TOOL_VERSION_PATCH ${PROJECT_VERSION_PATCH})
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

# Option to specify BN API path (defaults to external submodule)
set(BN_API_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external/binaryninja-api" CACHE PATH "Path to Binary Ninja API")

if(NOT EXISTS "${BN_API_PATH}/CMakeLists.txt")
    message(FATAL_ERROR "Binary Ninja API not found at ${BN_API_PATH}\n"
        "Initialize submodule: git submodule update --init --recursive")
endif()

# Keep the API checkout in sync with the INSTALLED Binary Ninja (issue #10).
# The API headers/static lib must be ABI-compatible with the libbinaryninjacore
# we link against, which in practice means the API submodule must match your
# installed Binary Ninja build. Every install records the exact API commit it
# was built from in "<BN_INSTALL_DIR>/api_REVISION.txt" -- read it and compare.
# On mismatch we warn with the precise checkout command; pass
# -DBNSQL_SYNC_BN_API=ON to have CMake check it out for you.
option(BNSQL_SYNC_BN_API "Auto-checkout the BN API submodule to match the installed Binary Ninja" OFF)

if(BN_INSTALL_DIR AND EXISTS "${BN_INSTALL_DIR}/api_REVISION.txt" AND EXISTS "${BN_API_PATH}/.git")
    find_package(Git QUIET)
    if(GIT_FOUND)
        # api_REVISION.txt holds the full commit hash on its own line.
        set(_bn_want_rev "")
        file(STRINGS "${BN_INSTALL_DIR}/api_REVISION.txt" _bn_rev_lines)
        foreach(_line IN LISTS _bn_rev_lines)
            string(STRIP "${_line}" _line)
            if(_line MATCHES "^[0-9a-fA-F]+$")
                string(TOLOWER "${_line}" _bn_want_rev)
            endif()
        endforeach()

        execute_process(
            COMMAND ${GIT_EXECUTABLE} -C "${BN_API_PATH}" rev-parse HEAD
            OUTPUT_VARIABLE _bn_have_rev OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _bn_rev_rc ERROR_QUIET)
        string(TOLOWER "${_bn_have_rev}" _bn_have_rev)

        if(_bn_want_rev AND _bn_rev_rc EQUAL 0 AND NOT _bn_have_rev STREQUAL _bn_want_rev)
            if(BNSQL_SYNC_BN_API)
                message(STATUS "bnsql: syncing BN API submodule to installed revision ${_bn_want_rev}")
                execute_process(COMMAND ${GIT_EXECUTABLE} -C "${BN_API_PATH}" fetch --quiet origin "${_bn_want_rev}" ERROR_QUIET)
                execute_process(
                    COMMAND ${GIT_EXECUTABLE} -C "${BN_API_PATH}" checkout --quiet "${_bn_want_rev}"
                    RESULT_VARIABLE _bn_co_rc ERROR_VARIABLE _bn_co_err)
                if(NOT _bn_co_rc EQUAL 0)
                    message(FATAL_ERROR "bnsql: failed to checkout BN API ${_bn_want_rev}:\n${_bn_co_err}")
                endif()
            else()
                message(WARNING
                    "bnsql: Binary Ninja API submodule (${_bn_have_rev})\n"
                    "       does not match your installed Binary Ninja (${_bn_want_rev}).\n"
                    "       The API must match the installed core or the build/link will fail.\n"
                    "       Fix it with:\n"
                    "         git -C \"${BN_API_PATH}\" fetch origin ${_bn_want_rev}\n"
                    "         git -C \"${BN_API_PATH}\" checkout ${_bn_want_rev}\n"
                    "       or re-run cmake with -DBNSQL_SYNC_BN_API=ON to do it automatically.")
            endif()
        elseif(_bn_want_rev AND _bn_rev_rc EQUAL 0)
            message(STATUS "bnsql: BN API submodule matches installed Binary Ninja (${_bn_want_rev})")
        endif()
    endif()
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
# MCP Server Support (optional, uses fastmcpp)
# ============================================================================

option(BNSQL_WITH_MCP "Build with MCP server support" ON)

if(BNSQL_WITH_MCP)
    if(NOT TARGET fastmcpp_core)
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
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
    message(STATUS "bnsql: Building with MCP server support")
endif()

# ============================================================================
# libxsql dependency
# ============================================================================

if(TARGET xsql::xsql)
    message(STATUS "bnsql: Using existing xsql::xsql target")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "bnsql: Added libxsql from sibling directory")
else()
    message(STATUS "bnsql: Fetching libxsql from GitHub...")
    include(FetchContent)
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# ============================================================================
# bnsql library (header-only with BN dependency)
# ============================================================================

add_library(bnsql INTERFACE)
add_library(bnsql::bnsql ALIAS bnsql)

target_include_directories(bnsql INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(bnsql INTERFACE
    xsql::xsql
    binaryninjaapi
)

# ============================================================================
# bnsql plugin (Binary Ninja plugin)
# ============================================================================

option(BNSQL_BUILD_PLUGIN "Build bnsql Binary Ninja plugin" ON)

if(BNSQL_BUILD_PLUGIN)
    add_library(bnsql_plugin SHARED
        src/plugin/plugin.cpp
    )

    target_link_libraries(bnsql_plugin PRIVATE
        bnsql::bnsql
    )

    # Include common headers (for bnsql_http_routes.hpp, etc.)
    target_include_directories(bnsql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    )

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

    # Detect BN plugins directory
    if(WIN32)
        set(BN_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    elseif(APPLE)
        set(BN_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    else()
        set(BN_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins" CACHE PATH "Binary Ninja plugins directory")
    endif()

    install(TARGETS bnsql_plugin
        LIBRARY DESTINATION "${BN_PLUGINS_DIR}"
        RUNTIME DESTINATION "${BN_PLUGINS_DIR}"
    )
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
