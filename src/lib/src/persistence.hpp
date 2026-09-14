// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * persistence.hpp - Shared save/persistence helpers for bnsql mutations
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <utility>

#include "binaryninjaapi.h"

namespace bnsql {
namespace persistence {

using namespace BinaryNinja;

template <typename Builder, typename = void>
struct has_legacy_on_commit : std::false_type {};

template <typename Builder>
struct has_legacy_on_commit<
    Builder,
    std::void_t<decltype(std::declval<Builder&>().on_commit(
        std::declval<std::function<void()>>()))>> : std::true_type {};

template <typename MemberFunction>
struct member_function_argument;

template <typename Result, typename Owner, typename Arg>
struct member_function_argument<Result (Owner::*)(Arg)> {
    using type = std::decay_t<Arg>;
};

// Bridge libxsql's former on_commit(fn) builder API and its transaction-hooks
// replacement. Keeping this at the bnsql boundary preserves standalone builds
// across the supported libxsql API generations.
template <typename Builder, typename Fn>
void install_commit_hook(Builder& builder, Fn&& fn) {
    std::function<void()> hook(std::forward<Fn>(fn));
    if constexpr (has_legacy_on_commit<Builder>::value) {
        builder.on_commit(std::move(hook));
    } else {
        using Hooks = typename member_function_argument<
            decltype(&Builder::transaction_hooks)>::type;
        Hooks hooks;
        // TransactionHooks gained a connection-state argument after its initial
        // introduction. A generic adapter accepts either signature while the
        // bnsql action itself remains state-independent.
        hooks.commit =
            [hook = std::move(hook)](auto&&...) noexcept { hook(); };
        builder.transaction_hooks(std::move(hooks));
    }
}

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
