// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * bnsql_version.hpp - Version constants for BNSQL (single source of truth).
 *
 * This header is the ONE place the bnsql version is defined. CMakeLists.txt
 * parses BNSQL_VERSION_STRING from here to drive the build's TOOL_VERSION_*
 * values and Windows VERSIONINFO resource, and the CLI reads that same string.
 * Bump the version here only.
 *
 * The bnsql-skills plugin manifests (marketplace.json, plugin.json) live in a
 * separate repo and are not built here, so they must be kept in sync manually
 * (see the Plugin Versioning checklist).
 */

#pragma once

#define BNSQL_VERSION_STRING "0.0.13"

#define BNSQL_COPYRIGHT_STRING "Copyright (c) 2024-2026 Elias Bachaalany"
