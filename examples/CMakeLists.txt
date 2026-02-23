# examples/CMakeLists.txt - BNSQL Example Programs
#
# Build standalone:
#   cmake -B build -DBN_INSTALL_DIR=/path/to/binaryninja
#   cmake --build build --config Release
#
# Build from parent (bnsql):
#   cmake -B build -DBNSQL_BUILD_EXAMPLES=ON -DBN_INSTALL_DIR=/path/to/binaryninja
#   cmake --build build --config Release
#
# Run:
#   Windows: set PATH=%BN_INSTALL_DIR%;%PATH%
#            build\Release\example_basic.exe database.bndb
#   Linux:   LD_LIBRARY_PATH=$BN_INSTALL_DIR ./build/example_basic database.bndb

cmake_minimum_required(VERSION 3.20)

# Only define project if building standalone
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(bnsql_examples VERSION 1.0 LANGUAGES C CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(BNSQL_EXAMPLES_STANDALONE ON)
else()
    set(BNSQL_EXAMPLES_STANDALONE OFF)
endif()

# ============================================================================
# Dependencies - only need to set up if standalone
# ============================================================================

if(BNSQL_EXAMPLES_STANDALONE)
    # Binary Ninja SDK
    if(NOT DEFINED BN_INSTALL_DIR)
        if(DEFINED ENV{BN_INSTALL_DIR})
            set(BN_INSTALL_DIR $ENV{BN_INSTALL_DIR})
        else()
            message(FATAL_ERROR "BN_INSTALL_DIR not set. Use -DBN_INSTALL_DIR=/path/to/binaryninja")
        endif()
    endif()

    # Binary Ninja API
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../external/binaryninja-api/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../external/binaryninja-api ${CMAKE_CURRENT_BINARY_DIR}/binaryninja-api)
    else()
        message(FATAL_ERROR "Binary Ninja API not found. Clone it to external/binaryninja-api")
    endif()

    # xsql
    if(TARGET xsql::xsql)
        message(STATUS "bnsql_examples: Using xsql::xsql from parent project")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../external/libxsql/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../external/libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "bnsql_examples: Added libxsql from external/libxsql")
    else()
        message(FATAL_ERROR "libxsql not found. Initialize submodule: git submodule update --init external/libxsql")
    endif()

    # Create bnsql interface library for standalone build
    add_library(bnsql_examples_lib INTERFACE)
    target_include_directories(bnsql_examples_lib INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
    )
    target_link_libraries(bnsql_examples_lib INTERFACE xsql::xsql binaryninjaapi)
    set(BNSQL_EXAMPLE_LIB bnsql_examples_lib)
else()
    # Use bnsql::bnsql from parent build
    set(BNSQL_EXAMPLE_LIB bnsql::bnsql)
endif()

# ============================================================================
# Helper function to create examples
# ============================================================================

function(add_bnsql_example name)
    if(TARGET bnsql_${name})
        return()
    endif()

    add_executable(bnsql_${name} ${name}.cpp)
    target_link_libraries(bnsql_${name} PRIVATE ${BNSQL_EXAMPLE_LIB})

    # Platform-specific settings
    if(MSVC)
        if(DEFINED BN_INSTALL_DIR)
            file(TO_NATIVE_PATH "${BN_INSTALL_DIR}" BN_NATIVE)
            set_target_properties(bnsql_${name} PROPERTIES
                VS_DEBUGGER_ENVIRONMENT "PATH=${BN_NATIVE};%PATH%"
            )
        endif()
    elseif(APPLE)
        set_target_properties(bnsql_${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "@executable_path;${BN_INSTALL_DIR}"
        )
    elseif(UNIX)
        set_target_properties(bnsql_${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN;${BN_INSTALL_DIR}"
        )
    endif()
endfunction()

# ============================================================================
# Example executables
# ============================================================================

add_bnsql_example(example_basic)
add_bnsql_example(example_functions)
add_bnsql_example(example_strings)
add_bnsql_example(example_decompiler)
