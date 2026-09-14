// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// Live UI-context capture for the bnsql Binary Ninja GUI plugin.
//
// Binary Ninja's complete UI state (selection, highlighted token) lives only in
// the Qt `binaryninjaui` layer, so we capture it through BN's bundled Python
// `binaryninjaui` module — via the shared bnsql Python engine
// (bnsql_python_exec). The snapshot runs on the UI thread and PRINTS a
// sentinel-tagged JSON envelope; the engine's stdout capture returns it (no
// temp file, no cross-scope result dict). The result is installed into the
// shared library's get_ui_context_json() provider slot, so the SQL function
// returns live data in the GUI and the stable {available:false} envelope
// everywhere else.

#include <bnsql/fwd.hpp>

#include "bnsql_python_exec.hpp"

#include <string>

namespace {

// Captures live UIContext state on the UI thread and prints
// "__BNSQL_UICTX__<json>". Defensive per-field: any piece binaryninjaui can't
// supply records its error in capture.error rather than aborting the whole
// capture (which keeps the exact Python method names easy to iterate on).
const char* const k_capture_py = R"PY(
import json
def _bnsql_uictx_emit():
    env = {'available': False, 'capture': {'source': 'plugin', 'fresh': True, 'error': None}, 'code_context': {'has_address': False}}
    try:
        from binaryninjaui import UIContext
        ctx = UIContext.activeContext()
        if ctx is None:
            # activeContext() is FOCUS-dependent: it returns None whenever Binary
            # Ninja is not the foreground window. That is the normal case for this
            # capture, not an edge case -- whoever asks "what is the user looking
            # at" (a terminal, an MCP client, an agent) holds focus at the moment
            # it asks, so BN never does. Reported available:false while
            # allContexts() held the live cursor, selection and function.
            # source distinguishes the two paths; context_count tells a caller
            # whether picking [0] was unambiguous.
            contexts = UIContext.allContexts() or []
            env['capture']['context_count'] = len(contexts)
            if contexts:
                ctx = contexts[0]
                env['capture']['source'] = 'all_contexts'
        if ctx is None:
            env['capture']['source'] = 'no_ui_context'
        else:
            view = ctx.getCurrentView()
            vf = ctx.getCurrentViewFrame()
            if view is None:
                env['capture']['source'] = 'no_view'
            else:
                env['available'] = True
                try:
                    # 'type' and 'il' are ORTHOGONAL and both are needed. type is
                    # Linear:PE / Graph:PE and does not move when the IL dropdown
                    # changes; il is the function-graph type and does not move when
                    # the view changes. Reporting only type made HLIL, LLIL and
                    # disassembly indistinguishable.
                    env['view'] = {'type': (vf.getCurrentView() if vf else None), 'name': (vf.getShortFileName() if vf else None)}
                    try:
                        ilt = view.getILViewType()
                        env['view']['il'] = str(getattr(ilt, 'view_type', ilt)).split('.')[-1]
                    except Exception:
                        pass
                except Exception as e:
                    env['capture']['error'] = 'view:' + str(e)
                off = view.getCurrentOffset()
                env['code_context'] = {'has_address': True, 'addr': hex(off)}
                try:
                    data = view.getData()
                    if data is not None:
                        fns = data.get_functions_containing(off)
                        if fns:
                            f = fns[0]
                            end = hex(f.address_ranges[-1].end) if f.address_ranges else hex(f.start)
                            env['code_context']['function'] = {'name': f.name, 'start': hex(f.start), 'end': end}
                        seg = data.get_segment_at(off)
                        if seg is not None:
                            env['code_context']['segment'] = {'start': hex(seg.start), 'end': hex(seg.end)}
                        secs = data.get_sections_at(off)
                        if secs:
                            env['code_context']['section'] = {'name': secs[0].name, 'start': hex(secs[0].start), 'end': hex(secs[0].end)}
                except Exception as e:
                    env['capture']['error'] = 'code_context:' + str(e)
                try:
                    sel = view.getSelectionOffsets()
                    env['selection'] = {'start': hex(sel[0]), 'end': hex(sel[1])}
                except Exception as e:
                    env['capture']['error'] = 'selection:' + str(e)
                try:
                    tok = view.getHighlightTokenState()
                    if tok and getattr(tok, 'valid', False):
                        txt = tok.token.text if getattr(tok, 'token', None) else None
                        # NOTE: addr is the token's REFERENT, not the cursor. Clicking
                        # a data symbol in code reports the data address, not the
                        # instruction. They coincide only when the symbol is clicked
                        # at its own definition.
                        env['highlight'] = {'valid': True, 'addr': hex(getattr(tok, 'addr', 0)), 'text': txt}
                except Exception as e:
                    env['capture']['error'] = 'highlight:' + str(e)
                try:
                    # A UIContext is a WINDOW, not a pane: a split view still yields
                    # one context and getCurrentViewFrame() returns only the focused
                    # half, so the other pane -- often a second location at a
                    # different IL level, which is the point of splitting -- was
                    # invisible. Enumerate every frame and mark the current one. The
                    # fields above still describe the current pane, unchanged.
                    panes = []
                    for tab in (ctx.getTabs() or []):
                        for vfr in (ctx.getAllViewFramesForTab(tab) or []):
                            p = {'is_current': (vfr == vf)}
                            try:
                                p['type'] = vfr.getCurrentView()
                                pv = vfr.getCurrentViewInterface()
                                if pv is not None:
                                    p['addr'] = hex(pv.getCurrentOffset())
                                    psel = pv.getSelectionOffsets()
                                    p['selection'] = {'start': hex(psel[0]), 'end': hex(psel[1])}
                                    try:
                                        pilt = pv.getILViewType()
                                        p['il'] = str(getattr(pilt, 'view_type', pilt)).split('.')[-1]
                                    except Exception:
                                        pass
                            except Exception as e:
                                p['error'] = str(e)
                            panes.append(p)
                    if panes:
                        env['panes'] = panes
                except Exception as e:
                    env['capture']['error'] = 'panes:' + str(e)
    except Exception as e:
        env['available'] = False
        env['capture']['error'] = str(e)
    print('__BNSQL_UICTX__' + json.dumps(env))

import binaryninja
binaryninja.execute_on_main_thread_and_wait(_bnsql_uictx_emit)
)PY";

std::string capture_ui_context() {
    auto r = bnsql::python::execute_snippet(k_capture_py, /*sandbox=*/std::string());
    static const std::string marker = "__BNSQL_UICTX__";
    const auto pos = r.output.rfind(marker);
    if (pos == std::string::npos) return "";  // -> shared lib returns {available:false}
    std::string json = r.output.substr(pos + marker.size());
    // strip trailing whitespace/newline from print()
    while (!json.empty() && (json.back() == '\n' || json.back() == '\r' ||
                             json.back() == ' ' || json.back() == '\t')) {
        json.pop_back();
    }
    return json;
}

}  // namespace

namespace bnsql {

// Called once from CorePluginInit (GUI plugin only).
void install_ui_context_capture() {
    functions::set_ui_context_provider([]() { return capture_ui_context(); });
}

}  // namespace bnsql
