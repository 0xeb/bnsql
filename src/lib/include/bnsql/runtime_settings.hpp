// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/runtime_settings.hpp>

#include <atomic>
#include <cstddef>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace bnsql {

// bnsql adds no snapshot fields beyond the shared core, so the snapshot IS the
// core snapshot (inherited RuntimeSettingsCore::snapshot()).
using RuntimeSettingsSnapshot = xsql::runtime::RuntimeSettingsSnapshot;

namespace detail {

// libxsql's registry-backed runtime settings replace the former virtual
// enumerate/apply extension points. bnsql is also built standalone by fetching
// public libxsql main, so keep source compatibility across that transition:
// the old backend overrides the virtual hooks, while the new backend registers
// the product keys directly in RuntimeSettingsCore.
template <typename Core, typename = void>
struct has_runtime_setting_registry : std::false_type {};

template <typename Core>
struct has_runtime_setting_registry<
    Core,
    std::void_t<decltype(std::declval<Core&>().register_bool_setting(
        std::declval<const std::string&>(), false,
        std::declval<const std::string&>()))>> : std::true_type {};

template <typename Core, bool HasRegistry = has_runtime_setting_registry<Core>::value>
class RuntimeSettingsBackend;

template <typename Core>
class RuntimeSettingsBackend<Core, false> : public Core {
public:
    RuntimeSettingsBackend()
        : Core(xsql::runtime::RuntimeSettingsCoreOptions{64}) {}

    bool python_enabled() const { return python_enabled_.load(); }
    void set_python_enabled(bool value) { python_enabled_.store(value); }
    size_t python_output_max() const { return python_output_max_.load(); }
    void set_python_output_max(size_t value) {
        python_output_max_.store(value);
    }

    std::vector<xsql::runtime::RuntimeSettingEntry> enumerate() const override {
        auto rows = Core::enumerate();
        rows.push_back({"enable_python",
                        python_enabled() ? "1" : "0", "bool", "bnsql"});
        rows.push_back({"python_output_max",
                        std::to_string(python_output_max()), "int", "bnsql"});
        return rows;
    }

    xsql::runtime::RuntimePragmaReply apply(
            const std::string& key, const std::string& value,
            const std::string& prefix) override {
        if (key == "enable_python") {
            bool enabled = false;
            if (!xsql::runtime::parse_bool_value(value, enabled)) {
                return xsql::runtime::pragma_error(
                    "runtime_settings: invalid value for enable_python "
                    "(expected a boolean)");
            }
            set_python_enabled(enabled);
            return xsql::runtime::pragma_result(
                "enable_python", python_enabled() ? "1" : "0");
        }
        if (key == "python_output_max") {
            int n = 0;
            if (!xsql::runtime::parse_int_value(value, n) || n < 0) {
                return xsql::runtime::pragma_error(
                    "runtime_settings: invalid value for python_output_max "
                    "(bytes; 0 = unbounded)");
            }
            set_python_output_max(static_cast<size_t>(n));
            return xsql::runtime::pragma_result(
                "python_output_max", std::to_string(python_output_max()));
        }
        return Core::apply(key, value, prefix);
    }

private:
    std::atomic<bool> python_enabled_{false};
    std::atomic<size_t> python_output_max_{0};
};

template <typename Core>
class RuntimeSettingsBackend<Core, true> : public Core {
public:
    RuntimeSettingsBackend()
        : Core(xsql::runtime::RuntimeSettingsCoreOptions{64}) {
        (void)this->register_bool_setting(
            "enable_python", false, "bnsql");
        (void)this->register_integer_setting(
            "python_output_max", 0, 0,
            (std::numeric_limits<int>::max)(), "bnsql");
    }

    bool python_enabled() const {
        return this->bool_value("enable_python", false);
    }
    void set_python_enabled(bool value) {
        (void)this->apply("enable_python", value ? "1" : "0", "bnsql");
    }
    size_t python_output_max() const {
        return static_cast<size_t>(
            this->integer_value("python_output_max", 0));
    }
    void set_python_output_max(size_t value) {
        (void)this->apply(
            "python_output_max", std::to_string(value), "bnsql");
    }
};

}  // namespace detail

// bnsql's runtime-settings singleton IS-A shared RuntimeSettingsCore (common keys +
// validated setters + timeout stack for free), plus the two bnsql-only Python knobs.
// The shared writable `runtime_settings` table
// (xsql::runtime::define_runtime_settings_table) drives both.
class RuntimeSettings
    : public detail::RuntimeSettingsBackend<
          xsql::runtime::RuntimeSettingsCore> {
public:
    static RuntimeSettings& instance() {
        static RuntimeSettings settings;
        return settings;
    }

    // The object IS the core; kept so callers passing a RuntimeSettingsCore& are
    // unchanged.
    xsql::runtime::RuntimeSettingsCore& common_settings() { return *this; }
    const xsql::runtime::RuntimeSettingsCore& common_settings() const { return *this; }

private:
    RuntimeSettings() = default;
};

inline RuntimeSettings& runtime_settings() {
    return RuntimeSettings::instance();
}

}  // namespace bnsql
