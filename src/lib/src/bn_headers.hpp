// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * bn_headers.hpp - Precompiled header for the bnsql library.
 *
 * Registered as the PCH via target_precompile_headers() in the bnsql
 * CMakeLists. Every .cpp in the bnsql library that touches the Binary Ninja
 * SDK should `#include "bn_headers.hpp"` rather than including the BN API
 * headers directly -- this keeps PCH hits consistent and confines the heavy
 * binaryninjaapi.h surface to the library's own translation units (it no
 * longer leaks into widely-included public headers).
 *
 * Aggregates the std headers used before the SDK and the Binary Ninja API
 * superset used across the library.
 *
 * NOT in this PCH:
 *   - the vendored true_believers.cpp decoder is engine-agnostic and opts out
 *     via SKIP_PRECOMPILE_HEADERS so it stays buildable with no BN dependency.
 */

#pragma once

// Standard library headers used across the library.
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// Binary Ninja API -- the superset used across the bnsql tables/UDFs.
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
