// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#include "bnsql_python_exec.hpp"

#include "binaryninjaapi.h"
#include "core_common.hpp"  // core::get_bv() -- the session BinaryView

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

using namespace BinaryNinja;

namespace bnsql {
namespace python {
namespace {

// Accumulates the ScriptingInstance's stdout/stderr for one execution.
class CaptureListener : public ScriptingOutputListener {
  public:
    CaptureListener(std::size_t max_bytes, std::string completion_marker)
        : max_bytes_(max_bytes),
          completion_marker_(std::move(completion_marker)) {}

    std::string output;
    std::string error;

    void NotifyOutput(const std::string& text) override {
        // Keep enough trailing data to recognize a marker split across listener
        // callbacks. Marker bytes are control traffic and never enter SQL output.
        pending_output_ += text;
        for (;;) {
            const auto marker = pending_output_.find(completion_marker_);
            if (marker == std::string::npos) break;
            append_bounded(
                output, pending_output_.substr(0, marker), output_truncated_);
            pending_output_.erase(0, marker + completion_marker_.size());
            completion_seen_ = true;
        }
        const std::size_t keep =
            completion_marker_.empty() ? 0 : completion_marker_.size() - 1;
        if (pending_output_.size() > keep) {
            const std::size_t flush = pending_output_.size() - keep;
            append_bounded(
                output, pending_output_.substr(0, flush), output_truncated_);
            pending_output_.erase(0, flush);
        }
    }
    void NotifyError(const std::string& text) override {
        append_bounded(error, text, error_truncated_);
    }

    void append_truncation_markers() {
        if (!pending_output_.empty()) {
            append_bounded(output, pending_output_, output_truncated_);
            pending_output_.clear();
        }
        if (output_truncated_)
            output += "\n...[bnsql python output truncated]...\n";
        if (error_truncated_)
            error += "\n...[bnsql python stderr truncated]...\n";
    }

    bool completion_seen() const { return completion_seen_; }

  private:
    void append_bounded(std::string& target, const std::string& text,
                        bool& truncated) {
        if (max_bytes_ == 0) {
            target += text;
            return;
        }
        if (target.size() >= max_bytes_) {
            truncated = true;
            return;
        }
        const std::size_t room = max_bytes_ - target.size();
        const std::size_t take = std::min(room, text.size());
        target.append(text.data(), take);
        if (take != text.size()) truncated = true;
    }

    std::size_t max_bytes_ = 0;
    std::string completion_marker_;
    std::string pending_output_;
    bool completion_seen_ = false;
    bool output_truncated_ = false;
    bool error_truncated_ = false;
};

std::string hex_encode(const std::string& s) {
    static const char* k = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out += k[c >> 4];
        out += k[c & 0xF];
    }
    return out;
}

// Wrap `code` so it exec()s inside an isolated, persistent namespace keyed by
// `sandbox` (hex-encoded so arbitrary source can't break the wrapper). Mirrors
// idasql's build_namespaced_snippet.
std::string build_namespaced(
        const std::string& code, const std::string& sandbox,
        const std::string& source_name) {
    std::ostringstream w;
    w << "import builtins\n"
      << "__bnsql_sb = bytes.fromhex('" << hex_encode(sandbox) << "').decode('utf-8')\n"
      << "if not hasattr(builtins, '__bnsql_namespaces__'):\n"
      << "    builtins.__bnsql_namespaces__ = {}\n"
      << "if __bnsql_sb not in builtins.__bnsql_namespaces__:\n"
      << "    builtins.__bnsql_namespaces__[__bnsql_sb] = {'__name__': '__bnsql__'}\n"
      << "__bnsql_code = bytes.fromhex('" << hex_encode(code) << "')\n"
      << "__bnsql_source = bytes.fromhex('" << hex_encode(source_name)
      << "').decode('utf-8')\n"
      << "exec(compile(__bnsql_code, __bnsql_source, 'exec'), "
         "builtins.__bnsql_namespaces__[__bnsql_sb])\n"
      << "del __bnsql_source\n"
      << "del __bnsql_code\n"
      << "del __bnsql_sb\n";
    return w.str();
}

// ScriptingInstance::ExecuteScriptInput is an interactive-input API. Binary
// Ninja's Python provider uses code.compile_command(), which reports a valid
// compound-only input such as "def f():\n    pass" as incomplete until it sees
// an additional blank statement. Put every user payload inside one complete
// expression so snippets and file bodies use normal file semantics. The bound
// stdout writer survives user reassignment of sys.stdout and emits the private
// completion marker only after successful execution. This distinguishes a real
// exception from a successful script that intentionally writes to stderr.
std::string build_complete_input(
        const std::string& code, const std::string& source_name,
        const std::string& completion_marker) {
    return "(lambda __bnsql_done=__import__('sys').stdout.write: "
           "(exec(compile(bytes.fromhex('" + hex_encode(code) +
           "'), bytes.fromhex('" + hex_encode(source_name) +
           "').decode('utf-8'), 'exec'), globals()), "
           "__bnsql_done(bytes.fromhex('" + hex_encode(completion_marker) +
           "').decode('ascii')), None)[-1])()";
}

std::mutex g_mutex;
Ref<ScriptingInstance> g_instance;  // created lazily, reused across calls
std::atomic<uint64_t> g_execution_id{0};

Ref<ScriptingInstance> get_instance() {
    if (!g_instance) {
        // The provider's API name is version-suffixed: BN's own
        // python/binaryninja/scriptingprovider.py sets
        //   apiName = f"python{sys.version_info.major}"
        // so it registers as "python3", never plain "python". Enumerating it from
        // a live process confirms: name="Python", api="python3". The bare "python"
        // lookup below therefore never matched -- it was dead, masked by the
        // GetByName fallback. Try the versioned names first, then fall back.
        static const char* kApiNames[] = {"python3", "python4", "python"};
        Ref<ScriptingProvider> prov;
        for (const char* api : kApiNames) {
            prov = ScriptingProvider::GetByAPIName(api);
            if (prov) break;
        }
        if (!prov) prov = ScriptingProvider::GetByName("Python");
        if (prov) g_instance = prov->CreateNewInstance();
    }
    return g_instance;
}

PyResult run(const std::string& script, const std::string& completion_marker,
             std::size_t output_max) {
    PyResult r;
    std::lock_guard<std::mutex> lock(g_mutex);

    Ref<ScriptingInstance> inst = get_instance();
    if (!inst) {
        // No Python ScriptingProvider is registered -- an environment defect,
        // not an expected headless state. Measured, not assumed: InitPlugins()
        // alone registers the python3 provider headlessly, PROVIDED the process
        // holds exactly one binaryninjacore.dll. The one way this reliably
        // breaks is a copied core beside the executable: the exe binds the
        // copy while BN's Python side (_binaryninjacore.py) binds the
        // install-dir core by absolute ctypes path, two same-basename modules
        // load as two instances, and the provider registers into the registry
        // this process never reads.
        //
        // It is NOT a license limitation: on a validated license the plugin
        // loads with no refusal and CPython initialises completely. Say so,
        // because "provider missing" reliably prompts "would a better license
        // fix it?" and the honest answer is no.
        r.error = "Python interpreter not available: no Binary Ninja scripting provider "
                  "in this process. Headless Python DOES work when the process holds a "
                  "single binaryninjacore.dll (the install-dir one). The usual cause is "
                  "a copied binaryninjacore.dll next to the executable splitting the "
                  "provider registry -- remove the copy and set BN_INSTALL_DIR to the "
                  "Binary Ninja install directory. It is not a license limitation -- a "
                  "different license tier will not change it.";
        return r;
    }

    // Bind the session BinaryView so the snippet sees the analysis: BN exposes the
    // current view to the Python console as `bv`/`current_view`. Without this the
    // snippet's `bv` is None (the instance has no current view), so every
    // bv-dependent snippet silently fails. get_bv() is empty in the headless
    // CLI/server (no live view) -- there we simply run without one.
    if (Ref<BinaryView> bv = ::bnsql::core::get_bv())
        inst->SetCurrentBinaryView(bv);

    CaptureListener listener(output_max, completion_marker);
    inst->RegisterOutputListener(&listener);
    const BNScriptingProviderExecuteResult execute_result =
        inst->ExecuteScriptInput(script);
    if (execute_result != SuccessfulScriptExecution) {
        inst->UnregisterOutputListener(&listener);
        switch (execute_result) {
            case IncompleteScriptInput:
                r.error = "python input is incomplete";
                break;
            case ScriptExecutionCancelled:
                r.error = "python execution was cancelled";
                break;
            case InvalidScriptInput:
            default:
                r.error = "python interpreter rejected the script input";
                break;
        }
        return r;
    }

    // BN Python executes asynchronously; wait (bounded) for the instance to
    // become ready again, which signals the script finished. Track whether we
    // actually observed completion -- a break on the loop bound alone is a
    // TIMEOUT, not success, and must not be reported as a clean run.
    bool timed_out = true;
    for (int i = 0; i < 1000; ++i) {  // ~10s ceiling
        if (inst->GetInputReadyState() == ReadyForScriptExecution) {
            timed_out = false;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    bool cancelled_after_timeout = false;
    if (timed_out) {
        // Do not leave the process-global interpreter busy: otherwise the next
        // SQL call is rejected, then can accidentally capture output from this
        // still-running script and report it as the second call's result.
        inst->CancelScriptInput();
        for (int i = 0; i < 100; ++i) {  // bounded ~1s cancellation grace
            if (inst->GetInputReadyState() == ReadyForScriptExecution) {
                cancelled_after_timeout = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        inst->UnregisterOutputListener(&listener);
        if (!cancelled_after_timeout) {
            // Quarantine an interpreter that ignored cancellation. A subsequent
            // query gets a fresh instance instead of reusing the busy one.
            inst->Stop();
            g_instance = nullptr;
        }
    } else {
        inst->UnregisterOutputListener(&listener);
    }

    listener.append_truncation_markers();
    // append_truncation_markers updates the listener strings, so move them only
    // after the markers have been applied.
    r.output = std::move(listener.output);
    r.error = std::move(listener.error);
    if (timed_out) {
        // Still running after the ceiling -- surface it as a failure with an
        // explicit message (append any partial stderr) rather than a false success.
        r.success = false;
        const char* timeout_message = cancelled_after_timeout
            ? "python execution timed out after ~10s and was cancelled"
            : "python execution timed out after ~10s; interpreter was reset";
        r.error = r.error.empty()
                      ? timeout_message
                      : std::string(timeout_message) + "; stderr: " + r.error;
    } else if (listener.completion_seen()) {
        // stderr is a normal Python stream, not an exception indicator. The
        // wrapper's out-of-band completion marker is authoritative.
        r.success = true;
        r.error.clear();
    } else {
        r.success = false;
        if (r.error.empty())
            r.error = "python execution failed before completion";
    }
    return r;
}

PyResult execute_code(
        const std::string& code, const std::string& sandbox,
        std::size_t output_max, const std::string& source_name) {
    const std::string payload = sandbox.empty()
        ? code
        : build_namespaced(code, sandbox, source_name);
    const std::string wrapper_source =
        sandbox.empty() ? source_name : "<bnsql sandbox wrapper>";
    const std::string completion_marker =
        "\x1e__BNSQL_PYTHON_COMPLETE_" +
        std::to_string(g_execution_id.fetch_add(1, std::memory_order_relaxed)) +
        "__\x1e";
    return run(
        build_complete_input(payload, wrapper_source, completion_marker),
        completion_marker, output_max);
}

}  // namespace

PyResult execute_snippet(const std::string& code, const std::string& sandbox,
                         std::size_t output_max) {
    return execute_code(code, sandbox, output_max, "<bnsql>");
}

PyResult execute_file(const std::string& path, const std::string& sandbox,
                      std::size_t output_max) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        PyResult r;
        r.error = "cannot open file: " + path;
        return r;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return execute_code(ss.str(), sandbox, output_max, path);
}

bool provider_available() {
    // Same lookup get_instance() uses, but without creating an interpreter -- so a
    // caller can ask "will Python work here?" without executing anything.
    static const char* kApiNames[] = {"python3", "python4", "python"};
    for (const char* api : kApiNames) {
        if (ScriptingProvider::GetByAPIName(api)) return true;
    }
    return ScriptingProvider::GetByName("Python") != nullptr;
}

}  // namespace python

// Public re-export (declared in bnsql/bnsql.hpp) so /status and other callers can
// query availability without reaching into the library's private headers.
bool python_provider_available() { return python::provider_available(); }
}  // namespace bnsql
