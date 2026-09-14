// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// bnsql_python_exec.hpp - run Binary Ninja Python from bnsql (shared engine).
//
// Backs the bnsql_python()/bnsql_python_file() SQL functions AND the plugin's
// ui-context capture, so both share one ScriptingProvider/ScriptingInstance/
// ScriptingOutputListener path. Mirrors idasql's idapython_exec (ExecutionResult
// + sandbox-namespace wrapping), with a Binary Ninja scripting backend instead of
// IDA's extlang_t.

#pragma once

#include <cstddef>
#include <string>

namespace bnsql {
namespace python {

struct PyResult {
    bool success = false;   // false if the interpreter is unavailable or the code raised
    std::string output;     // captured stdout
    std::string error;      // captured stderr / traceback (populated when !success)
};

// Execute a Python snippet through Binary Ninja's Python ScriptingInstance.
// `sandbox` empty  -> the interpreter's global namespace (state persists per session).
// `sandbox` set    -> an isolated namespace stored under
//                     builtins.__bnsql_namespaces__[sandbox] (persists per key).
// `output_max` > 0 independently caps captured stdout and stderr while the
// script runs (0 = unbounded).
PyResult execute_snippet(const std::string& code, const std::string& sandbox,
                         std::size_t output_max = 0);

// Read `path` and execute its contents as a snippet (honors `sandbox`/`output_max`).
PyResult execute_file(const std::string& path, const std::string& sandbox,
                      std::size_t output_max = 0);

// True when a Binary Ninja Python ScriptingProvider is registered in THIS process,
// i.e. bnsql_python() can actually execute.
//
// This is deliberately separate from the enable_python runtime setting: the gate
// being on does not mean execution will work. The provider registers during
// InitPlugins() (headless included) but only into the ONE binaryninjacore.dll
// instance the Python side binds -- a process that loaded a second core copy has
// the gate but no visible provider. Without this, a caller can only discover
// that by attempting a snippet and reading the error, which makes "can I use
// Python here?" a destructive probe.
//
// Cheap and side-effect free: it looks the provider up, it does not create an
// interpreter instance.
bool provider_available();

}  // namespace python
}  // namespace bnsql
