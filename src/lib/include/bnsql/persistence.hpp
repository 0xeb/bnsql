// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * persistence.hpp - Shared save/persistence helpers for bnsql mutations
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <functional>
#include <string>

#include "binaryninjaapi.h"

namespace bnsql {
namespace persistence {

// Callback invoked by mutation handlers to invalidate decompiler caches.
// Set by DecompilerTableRegistry::register_all() to avoid circular includes.
// owner tracks which registry installed the callback, so only that registry clears it.
inline std::function<void()> on_decompiler_invalidate;
inline void* on_decompiler_invalidate_owner = nullptr;

using namespace BinaryNinja;

inline bool ends_with_bndb_case_insensitive(const std::string& path) {
    static constexpr const char* kExt = ".bndb";
    constexpr size_t kExtLen = 5;
    if (path.size() < kExtLen) return false;
    auto tail = path.substr(path.size() - kExtLen);
    std::transform(tail.begin(), tail.end(), tail.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return tail == kExt;
}

inline std::string derive_bndb_path(const std::string& source_path) {
    if (source_path.empty()) return {};
    if (ends_with_bndb_case_insensitive(source_path)) {
        return source_path;
    }

    const auto slash = source_path.find_last_of("/\\");
    const auto dot = source_path.find_last_of('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) {
        return source_path + ".bndb";
    }
    return source_path.substr(0, dot) + ".bndb";
}

inline bool save_binary_view(
    const Ref<BinaryView>& bv,
    std::string* error_out = nullptr,
    std::string* saved_path_out = nullptr)
{
    auto set_error = [&](const std::string& msg) {
        if (error_out) *error_out = msg;
    };

    if (!bv) {
        set_error("No BinaryView context");
        return false;
    }

    auto file = bv->GetFile();
    if (!file) {
        set_error("No FileMetadata for BinaryView");
        return false;
    }

    auto current_database_path = [&]() -> std::string {
        std::string filename = file->GetFilename();
        if (filename.empty()) filename = file->GetOriginalFilename();
        if (filename.empty()) return {};
        return derive_bndb_path(filename);
    };

    std::string created_path;
    bool created_database_this_call = false;
    if (!file->IsBackedByDatabase()) {
        std::string filename = current_database_path();
        if (filename.empty()) {
            set_error("Cannot save: BinaryView has no associated filename");
            return false;
        }

        created_path = filename;
        if (created_path.empty()) {
            set_error("Cannot save: failed to derive .bndb path");
            return false;
        }

        if (!bv->CreateDatabase(created_path)) {
            set_error("Failed to create database: " + created_path);
            return false;
        }
        created_database_this_call = true;
    }

    if (!bv->SaveAutoSnapshot()) {
        // Some BN runtime/config combinations do not expose autosnapshot writes
        // reliably. Fall back to full DB save on the actively opened path.
        std::string save_path;
        if (file->IsBackedByDatabase() && !created_database_this_call) {
            save_path = file->GetFilename();
            if (save_path.empty()) save_path = current_database_path();
        } else {
            save_path = current_database_path();
            if (save_path.empty()) save_path = created_path;
        }
        if (save_path.empty()) {
            set_error("SaveAutoSnapshot failed and no database path is available");
            return false;
        }

        if (!bv->CreateDatabase(save_path)) {
            set_error("SaveAutoSnapshot failed for: " + save_path + " (CreateDatabase fallback failed)");
            return false;
        }
        created_path = save_path;
    }

    if (saved_path_out) {
        std::string saved = file->GetFilename();
        if (saved.empty()) saved = file->GetOriginalFilename();
        if (saved.empty()) saved = created_path;
        *saved_path_out = saved;
    }

    return true;
}

} // namespace persistence
} // namespace bnsql
