// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "meta_capabilities.hpp"

namespace bnsql {
namespace meta {

using namespace BinaryNinja;
using core::get_bv;

VTableDef define_capabilities() {
    static const std::vector<CapabilityItem> kCaps = {
        // Mutation capabilities
        {"mutation.table_first_default", "true", "bool", "Mutations should prefer table UPDATE/DELETE/INSERT surfaces."},
        {"mutation.funcs.prototype_clear", "false", "bool", "Clearing user prototype override is not exposed safely by BN API here."},
        {"mutation.funcs.insert", "true", "bool", "Functions can be created via INSERT INTO funcs (addr)."},
        {"mutation.funcs.delete", "true", "bool", "Functions can be removed via DELETE FROM funcs."},
        {"mutation.funcs.name", "true", "bool", "Function names writable via funcs.name."},
        {"mutation.funcs.prototype", "true", "bool", "Function prototypes writable via funcs.prototype."},
        {"mutation.funcs.comment", "true", "bool", "Function comments writable via funcs.comment."},
        {"mutation.names.insert", "true", "bool", "User symbols can be defined via INSERT INTO names."},
        {"mutation.names.name", "true", "bool", "User symbols can be renamed via UPDATE names SET name."},
        {"mutation.names.delete", "true", "bool", "Matching symbols can be undefined via DELETE FROM names."},
        {"mutation.segments.insert", "true", "bool", "User segments can be added via INSERT INTO segments (start_addr, end_addr, perm)."},
        {"mutation.segments.delete", "true", "bool", "User segments can be removed via DELETE FROM segments."},
        {"mutation.segments.rebase", "true", "bool", "UPDATE segments.start_addr moves (rebases) a user segment; end_addr resizes it."},
        {"mutation.segments.perm", "true", "bool", "Segment permissions writable via UPDATE segments.perm."},
        {"mutation.comments.insert", "true", "bool", "Address comments writable via INSERT INTO comments."},
        {"mutation.comments.comment", "true", "bool", "Address comments writable via UPDATE comments SET comment."},
        {"mutation.comments.delete", "true", "bool", "Address comments clearable via DELETE FROM comments."},
        {"mutation.bookmarks.insert", "true", "bool", "Bookmarks writable via INSERT INTO bookmarks (BN CreateUserDataTag; default tag type 'Bookmarks')."},
        {"mutation.bookmarks.comment", "true", "bool", "Bookmark comment writable via UPDATE bookmarks SET comment (BN Tag::SetData)."},
        {"mutation.bookmarks.delete", "true", "bool", "Bookmarks removable via DELETE FROM bookmarks (BN RemoveUserDataTag)."},
        {"mutation.pseudocode.comment", "true", "bool", "Pseudocode line comments writable via pseudocode.comment."},
        {"mutation.pseudocode.delete_clear", "true", "bool", "DELETE FROM pseudocode clears line comment for matching line."},
        {"mutation.hlil_vars.name", "true", "bool", "Variable names writable via hlil_vars.name."},
        {"mutation.hlil_vars.type", "true", "bool", "Variable types writable via hlil_vars.type."},
        {"mutation.hlil_vars.delete_clear", "true", "bool", "DELETE FROM hlil_vars clears user variable override."},
        {"mutation.hlil_vars.comment", "true", "bool", "Variable comments writable via hlil_vars.comment using persistent BN metadata keyed by variable identity."},
        {"mutation.types.insert", "true", "bool", "Empty named types can be created via INSERT INTO types (name, kind) with kind struct/union/enum."},
        {"mutation.types.name", "true", "bool", "Types are renamable via UPDATE types SET name = <new>."},
        {"mutation.types.delete", "true", "bool", "Types are removable via DELETE FROM types WHERE name = <name>."},
        {"mutation.type_members.insert", "true", "bool", "Struct/union members can be added via INSERT INTO type_members (type_name, member_name, member_type[, offset])."},
        {"mutation.type_members.name", "true", "bool", "Struct members are renamable via UPDATE type_members SET member_name = <new>."},
        {"mutation.type_members.member_type", "true", "bool", "Struct members are retypable via UPDATE type_members SET member_type = <decl>."},
        {"mutation.type_members.delete", "true", "bool", "Struct members are removable via DELETE FROM type_members."},
        {"mutation.type_enum_values.insert", "true", "bool", "Enum constants can be added via INSERT INTO type_enum_values (type_name, value_name[, value])."},
        {"mutation.type_enum_values.name", "true", "bool", "Enum constants are renamable via UPDATE type_enum_values SET value_name = <new>."},
        {"mutation.type_enum_values.value", "true", "bool", "Enum constant values are writable via UPDATE type_enum_values SET value = <n>."},
        {"mutation.type_enum_values.delete", "true", "bool", "Enum constants are removable via DELETE FROM type_enum_values."},
        {"mutation.runtime_settings.write", "true", "bool", "runtime_settings.value is writable via UPDATE runtime_settings SET value=... WHERE key=...; timeout_push/timeout_pop remain dispatch-only PRAGMAs."},
        // Negative mutation rows — genuinely read-only tables. Emitted explicitly
        // (value false) so a client can gate up-front instead of by trial-and-error;
        // an INSERT/UPDATE/DELETE here is rejected with a capability-scoped error
        // (mutation.<table>.*), not a generic "readonly database". These surfaces
        // reflect derived analysis or fixed metadata with no writable BN mapping.
        {"mutation.binary.write", "false", "bool", "binary is a read-only orientation/metadata view (derived from the analysis); no columns are writable."},
        {"mutation.capabilities.write", "false", "bool", "capabilities is a read-only self-description of the build; no columns are writable."},
        {"mutation.entries.write", "false", "bool", "entries is a read-only view of entry points / exports; no writable columns."},
        {"mutation.strings.write", "false", "bool", "strings is a read-only view of detected strings; no writable columns."},
        {"mutation.xrefs.write", "false", "bool", "xrefs is a read-only view of cross-references derived from analysis; no writable columns."},
        {"mutation.blocks.write", "false", "bool", "blocks is a read-only view of basic blocks derived from analysis; no writable columns."},
        {"mutation.cfg_edges.write", "false", "bool", "cfg_edges is a read-only view of intra-function control-flow edges derived from analysis; no writable columns."},
        {"mutation.switch_tables.write", "false", "bool", "switch_tables is a read-only view of reconstructed switch/case jump tables (HLIL_SWITCH); no writable columns. table_addr/default_addr are NULL (not exposed by BN)."},
        {"mutation.function_frames.write", "false", "bool", "function_frames is a read-only view of per-function stack-frame layout (GetStackLayout + arch SP reg); no writable columns. saved_reg_size/has_frame_pointer are NULL (not exposed by BN)."},
        {"mutation.data_items.write", "false", "bool", "data_items is a read-only view of defined data items (GetDataVariables); no writable columns. name/data_type/value_repr are NULL when unknown."},
        {"mutation.dominators.write", "false", "bool", "dominators is a read-only dominator tree over CFG blocks (computed via xsql::graph); no writable columns."},
        {"mutation.post_dominators.write", "false", "bool", "post_dominators is a read-only post-dominator tree (computed via xsql::graph); no writable columns."},
        {"mutation.loops.write", "false", "bool", "loops is a read-only natural-loop view (computed via xsql::graph); no writable columns."},
        {"mutation.imports.write", "false", "bool", "imports is a read-only view of imported symbols; no writable columns."},
        {"mutation.instructions.write", "false", "bool", "instructions is a read-only disassembly view; no writable columns."},
        {"mutation.instruction_operands.write", "false", "bool", "instruction_operands is a read-only operand-decomposition view; no writable columns."},
        {"mutation.func_signatures.write", "false", "bool", "func_signatures is a read-only signature view; no writable columns."},
        // Discovery capabilities
        {"discovery.entities", "true", "bool", "Unified discovery surface via entities view."},
        // UDF capabilities
        {"udf.decompiler_helper_mutators", "false", "bool", "rename_var/set_var_type/set_func_prototype/set_pseudocode_comment removed in favor of table mutations."},
        {"udf.legacy.set_name", "true", "bool", "Legacy helper preserved; table names/funcs updates remain preferred."},
        {"udf.legacy.set_comment", "true", "bool", "Legacy helper preserved; table comments/pseudocode/funcs updates remain preferred."},
        // Feature-level capabilities
        {"feature.decompiler", "true", "bool", "HLIL decompiler tables available."},
        {"feature.types", "true", "bool", "Type intelligence tables (types, type_members, type_enum_values, func_signatures) available."},
        {"feature.byte_search", "true", "bool", "byte_search table available (canonical cross-tool byte-pattern search; WHERE pattern = '<FlexHex>' or byte_search('<FlexHex>'))."},
        {"feature.write_ops", "true", "bool", "Table-first write operations available."},
        {"feature.entities_search", "true", "bool", "entities_search() UDF available."},
        {"feature.disasm_calls", "true", "bool", "disasm_calls view available."},
        {"feature.patches", "true", "bool", "patches table available (read-write)."},
        {"mutation.patches.insert", "true", "bool", "New patches can be applied via INSERT INTO patches (addr, patched_byte)."},
        {"mutation.patches.delete", "true", "bool", "Patches can be reverted via DELETE FROM patches WHERE addr = <addr>."},
        {"mutation.patches.patched_byte", "true", "bool", "Patch bytes writable via UPDATE patches SET patched_byte = <byte>."},
        {"feature.runtime_settings", "true", "bool", "Runtime knobs via the writable runtime_settings table (UPDATE value); timeout_push/timeout_pop remain dispatch-only PRAGMAs."},
        {"feature.query_timeout", "true", "bool", "Query timeout enforcement via xsql::QueryOptions::timeout_ms."},
        {"feature.instruction_operands", "true", "bool", "instruction_operands table available."},
        {"feature.python", "true", "bool", "bnsql_python()/bnsql_python_file() UDFs available; OFF by default -- enable via UPDATE runtime_settings SET value='1' WHERE key='enable_python'. Works headlessly (CLI/--http/--mcp) and in the GUI plugin: InitPlugins() registers the python3 scripting provider, provided the process holds a single binaryninjacore.dll (a copied core beside the executable splits the provider registry and hides it -- check python_available in /status)."},
        {"feature.ui_context", "true", "bool", "get_ui_context_json() UDF available; live capture in the GUI plugin (works whether or not BN is the focused window), a stable {available:false} envelope in CLI/headless."},
#ifdef BNSQL_HAS_HTTP
        {"feature.http_server", "true", "bool", "HTTP query server available."},
#else
        {"feature.http_server", "false", "bool", "HTTP query server not compiled in."},
#endif
#ifdef BNSQL_HAS_MCP
        {"feature.mcp_server", "true", "bool", "MCP server available."},
#else
        {"feature.mcp_server", "false", "bool", "MCP server not compiled in."},
#endif
    };

    return table("capabilities")
        .row_count([]() {
            return kCaps.size();
        })
        .column_text("key", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].key : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].value : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].type : "";
        })
        .column_text("note", [](size_t i) -> std::string {
            return i < kCaps.size() ? kCaps[i].note : "";
        })
        .build();
}

} // namespace meta
} // namespace bnsql
