cmake_minimum_required(VERSION 3.20)
project(bnsql LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/fastmcpp/CMakeLists.txt")
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        add_subdirectory(external/fastmcpp)
        message(STATUS "bnsql: Building with MCP server support")
    else()
        message(WARNING "bnsql: fastmcpp not found, MCP support disabled. "
            "Initialize submodule: git submodule update --init external/fastmcpp")
        set(BNSQL_WITH_MCP OFF)
    endif()
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
