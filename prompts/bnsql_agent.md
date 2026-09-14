# BNSQL Agent Guide

A comprehensive reference for AI agents to effectively use BNSQL — an SQL
interface for reverse engineering binary analysis with Binary Ninja.
Structurally aligned with idasql's own agent guide where the underlying
analysis concepts overlap, with BN-specific deltas (HLIL/MLIL surfaces,
explicit-save model, no Hex-Rays, no IDAPython).

Current target: bnsql v0.0.12+ (explicit-save model, type intelligence,
patches, binary search, callers/callees views).

---

## What is Binary Ninja and Why SQL?

**Binary Ninja** is a modern reverse engineering platform. It analyzes compiled binaries (executables, DLLs, firmware) and produces:
- **Disassembly** - Human-readable assembly code
- **Functions** - Detected code boundaries with names
- **Cross-references** - Who calls what, who references what data
- **Types** - Structures, enums, function prototypes
- **HLIL/MLIL** - High/Medium Level IL representations

**BNSQL** exposes all this analysis data through SQL virtual tables, enabling:
- Complex queries across multiple data types (JOINs)
- Aggregations and statistics (COUNT, GROUP BY)
- Pattern detection across the entire binary
- Scriptable analysis without writing plugins or Python scripts

---

## Command-Line Interface

BNSQL is available as a standalone CLI (`bnsql.exe`) and as a Binary Ninja plugin
(`bnsql_plugin.dll`). The CLI is the canonical agent entry point.

### Binary Provenance

When validating behavior that must match the live Binary Ninja plugin session,
use the SDK-installed binaries:

- CLI: `bnsql.exe` placed on `PATH` (or copied alongside `binaryninja.exe`)
- Plugin: `bnsql_plugin.dll` inside Binary Ninja's plugin directory

Set `%BN_INSTALL_DIR%` so bnsql can find Binary Ninja's DLLs.

### Input File

`bnsql <file>` accepts either form:

- **Existing Binary Ninja database** (`.bndb`) — loads directly, ready to query.
- **Raw binary** (`.exe`/`.dll`/firmware/etc.) — bnsql triggers fresh Binary
  Ninja analysis. If a sibling `.bndb` exists next to the source, that's
  loaded instead. The resulting `.bndb` is auto-saved next to the source on
  clean exit.

Do **not** pre-build a `.bndb` with `binaryninja --headless` before invoking
bnsql — `bnsql <raw.exe>` does it in one shot.

### Invocation Modes

**1. One-shot Query**
```bash
bnsql database.bndb -c "SELECT name, size FROM funcs LIMIT 10"
bnsql sample.exe -c "SELECT * FROM funcs LIMIT 5"          # raw binary
```

**2. SQL File Execution**
```bash
bnsql database.bndb -f analysis.sql
```

**3. Interactive REPL (default)**
```bash
bnsql database.bndb
bnsql sample.exe                                            # raw binary
```

**4. HTTP REST Server**
```bash
bnsql database.bndb --http 8080
# Then: curl -X POST http://localhost:8080/query -d "SELECT * FROM funcs"
```

**5. MCP Server (for Claude Desktop and other MCP clients)**
```bash
bnsql database.bndb --mcp 9998
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-s, --source <path>` | Binary Ninja database (`.bndb`) **or** raw binary (`.exe`/`.dll`/firmware/etc.) — raw binaries trigger fresh BN analysis (auto-saved next to source) |
| `-c, --command <sql>` | Execute SQL query and exit |
| `-f, --file <path>` | Execute SQL from file |
| `-i, --interactive` | Interactive SQL mode (default if no `-c`/`-f`) |
| `--http [port]` | Start HTTP REST server (default port: 8080) |
| `--mcp [port]` | Start MCP server (default port: 9998) |
| `--bind <addr>` | Bind address for HTTP/MCP server (default: 127.0.0.1) |
| `--token <token>` | Auth token for HTTP/MCP mode |
| `-q, --quiet` | Suppress banner |
| `-h, --help` | Show help |
| `-v, --version` | Show version |

### Performance Strategy

Opening a database has startup overhead (Binary Ninja initialization, analysis
wait for raw binaries). For one small query, use `-c`. For iterative work,
keep a long-lived session (interactive REPL or `--http`) and run many queries
against it.

**One-shot query:** `bnsql sample.exe -c "SELECT COUNT(*) FROM funcs"`
**Iterative analysis:** Start an HTTP server once, then `curl` repeatedly.

---

## CRITICAL: Performance Rules

**ALWAYS follow these rules to avoid slow queries:**

1. **JOINs on xrefs.to_addr are optimized** - Direct equality lookups are fast:
   ```sql
   -- FAST: Uses direct BN API lookup (GetCodeReferences)
   SELECT f.name, x.from_addr FROM funcs f
   JOIN xrefs x ON x.to_addr = f.addr WHERE f.name LIKE 'curl%';

   -- For bulk aggregation (GROUP BY all), CTEs are still efficient:
   WITH counts AS (SELECT to_addr, COUNT(*) as n FROM xrefs WHERE is_code=1 GROUP BY to_addr)
   SELECT f.name, c.n FROM funcs f JOIN counts c ON f.addr = c.to_addr ORDER BY n DESC;
   ```

2. **Decompiler tables are decompile-backed.** `hlil_calls` / `_hlil_ast` stream lazily — a `LIMIT`/bounded query decompiles only the functions actually pulled; an unbounded full scan decompiles the whole binary (heavy, but `LIMIT`-abortable, not a hang). `pseudocode` / `hlil_vars` still materialize every function, so filter those by `func_addr` (or use `decompile(addr)`).

3. **Instructions table MUST filter by func_addr** - never scan the whole table

4. **NEVER use `func_start()` or `func_at()` in bulk xref queries** - these UDFs call Binary Ninja API for EACH row:
   ```sql
   -- WRONG (8000+ API calls - takes 10+ minutes):
   SELECT func_start(from_addr) as caller, to_addr FROM xrefs WHERE is_code = 1;

   -- CORRECT (use the callees view - pure SQL, milliseconds):
   SELECT func_addr, callee_addr FROM callees;
   ```

5. **Use `callers`/`callees` views for call graph analysis** - they pre-compute function boundaries without UDF overhead

---

## Few-Shot Examples (Use These Patterns!)

### "Find the function with the most callers"
```sql
WITH caller_counts AS (
    SELECT to_addr, COUNT(*) as callers
    FROM xrefs WHERE is_code = 1
    GROUP BY to_addr
)
SELECT f.name, printf('0x%X', f.addr) as addr, c.callers
FROM funcs f
JOIN caller_counts c ON f.addr = c.to_addr
ORDER BY c.callers DESC
LIMIT 10;
```

### "Which functions are called 10 times or less?"
```sql
WITH call_counts AS (
    SELECT to_addr, COUNT(*) as cnt
    FROM xrefs WHERE is_code = 1
    GROUP BY to_addr
)
SELECT f.name, COALESCE(c.cnt, 0) as calls
FROM funcs f
LEFT JOIN call_counts c ON f.addr = c.to_addr
WHERE COALESCE(c.cnt, 0) <= 10
ORDER BY calls DESC;
```

### "Find orphan functions (no callers)"
```sql
WITH has_callers AS (
    SELECT DISTINCT to_addr FROM xrefs WHERE is_code = 1
)
SELECT f.name, printf('0x%X', f.addr) as addr
FROM funcs f
WHERE f.addr NOT IN (SELECT to_addr FROM has_callers);
```

### "What are the largest functions?"
```sql
SELECT name, printf('0x%X', addr) as addr, size
FROM funcs
ORDER BY size DESC
LIMIT 10;
```

### "Find functions that call malloc"
```sql
WITH malloc_addr AS (
    SELECT addr FROM imports WHERE name = 'malloc' OR name = '_malloc'
)
SELECT DISTINCT func_at(x.from_addr) as caller
FROM xrefs x
WHERE x.to_addr IN (SELECT addr FROM malloc_addr) AND x.is_code = 1;
```

### "Find functions that call at most 3 other functions" (leaf-like functions)
```sql
-- Use the callees view, NOT func_start() on xrefs!
SELECT func_name, printf('0x%X', func_addr) as addr,
       COUNT(DISTINCT callee_addr) as num_callees
FROM callees
GROUP BY func_addr
HAVING COUNT(DISTINCT callee_addr) BETWEEN 1 AND 3
ORDER BY num_callees, func_name
LIMIT 20;
```

### "Find functions that make many calls" (dispatcher/wrapper functions)
```sql
-- FAST: Use xrefs.from_func directly, avoid callees view for large result sets
SELECT from_func, COUNT(DISTINCT to_addr) as unique_callees
FROM xrefs WHERE is_code = 1 AND from_func != 0
GROUP BY from_func ORDER BY unique_callees DESC LIMIT 10;
```

### "Find functions whose call tree terminates within 3 levels" (bounded call depth)
```sql
-- Use xrefs with from_func for speed, only join funcs at the end for names
WITH
cc AS (
    SELECT from_func as func, COUNT(DISTINCT to_addr) as cnt
    FROM xrefs WHERE is_code = 1 AND from_func != 0
    GROUP BY from_func
),
-- Level 0: functions calling 1-3 others
l0 AS (SELECT func FROM cc WHERE cnt BETWEEN 1 AND 3),
-- Level 1 callees and their counts
l1_callees AS (SELECT DISTINCT x.to_addr as callee FROM xrefs x
    WHERE x.from_func IN (SELECT func FROM l0) AND x.is_code = 1),
l1_valid AS (SELECT lc.callee FROM l1_callees lc
    LEFT JOIN cc c ON lc.callee = c.func WHERE COALESCE(c.cnt, 0) <= 3),
-- Level 2
l2_callees AS (SELECT DISTINCT x.to_addr as callee FROM xrefs x
    WHERE x.from_func IN (SELECT callee FROM l1_valid) AND x.is_code = 1),
l2_valid AS (SELECT lc.callee FROM l2_callees lc
    LEFT JOIN cc c ON lc.callee = c.func WHERE COALESCE(c.cnt, 0) <= 3),
-- Level 3 must be terminal (0 callees)
l3_callees AS (SELECT DISTINCT x.to_addr as callee FROM xrefs x
    WHERE x.from_func IN (SELECT callee FROM l2_valid) AND x.is_code = 1),
l3_valid AS (SELECT lc.callee FROM l3_callees lc
    LEFT JOIN cc c ON lc.callee = c.func WHERE COALESCE(c.cnt, 0) = 0)
-- Output L0 functions with names
SELECT f.name, printf('0x%X', l0.func) as addr, cc.cnt as callees
FROM l0 JOIN cc ON l0.func = cc.func JOIN funcs f ON l0.func = f.addr
ORDER BY cc.cnt DESC LIMIT 20;
```

### "Decompile main and show variables"
```sql
-- First get pseudocode
SELECT decompile(addr) FROM funcs WHERE name LIKE '%main%' LIMIT 1;

-- Then get local variables
SELECT name, type, storage FROM hlil_vars
WHERE func_addr = (SELECT addr FROM funcs WHERE name LIKE '%main%' LIMIT 1);
```

---

## Core Concepts for Binary Analysis

### Addresses
Everything in a binary has an **address** - a memory location where code or data lives. SQL shows these as integers; use `hex(addr)` for hex display.

### Functions
Binary Ninja groups code into **functions** with:
- `addr` - Where the function begins
- `name` - Assigned or auto-generated name (e.g., `main`, `sub_401000`)
- `size` - Total bytes in the function

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** - Function calls, jumps between code
- **Data xrefs** - Code reading/writing data locations
- `from_addr` -> `to_addr` represents "address X references address Y"

### Segments
Memory is divided into **segments** with different purposes:
- `.text` - Executable code
- `.data` - Initialized global data
- `.rdata` - Read-only data (strings, constants)
- `.bss` - Uninitialized data

### Basic Blocks
Within a function, **basic blocks** are straight-line code sequences:
- No branches in the middle
- Single entry, single exit
- Useful for control flow analysis

---

## Tables Reference

### funcs
All detected functions in the binary.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Function start address |
| `name` | TEXT | Function name |
| `size` | INT | Function size in bytes |

```sql
-- 10 largest functions
SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Functions starting with "sub_" (auto-named, not analyzed)
SELECT name, hex(addr) as addr FROM funcs WHERE name LIKE 'sub_%';
```

### segments
Memory segments. **Writable**: INSERT a region (BN user segment), DELETE it, and
UPDATE `start_addr` (rebase/move), `end_addr` (resize), `perm`.

| Column | Type | RW | Description |
|--------|------|----|-------------|
| `start_addr` | INT | RW | Segment start; UPDATE rebases (moves) the segment |
| `end_addr` | INT | RW | Segment end; UPDATE resizes the segment |
| `name` | TEXT | R | Synthesized `seg_<addr>` (BN segments are unnamed) |
| `class` | TEXT | R | CODE/DATA (derived from perm) |
| `perm` | INT | RW | Permissions (R=4, W=2, X=1) |

```sql
-- Find executable segments
SELECT name, hex(start_addr) as start FROM segments WHERE perm & 1 = 1;

-- Add a region (e.g. SRAM for a raw firmware image), then rebase a segment.
-- Only start_addr/end_addr/perm are stored; the name is synthesized (seg_<addr>)
-- and the class is derived from perm — passing name/class has no effect.
INSERT INTO segments(start_addr, end_addr, perm)
  VALUES (0x20000000, 0x20005000, 6);
UPDATE segments SET start_addr = 0x08000000 WHERE start_addr = 0x0;  -- rebase
```

Note: BN segments are addressed (no native name/move), so move/resize/perm UPDATEs
remove and re-add the underlying user segment. Operate on user segments.

### names
All named locations (functions, labels, data).

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Address |
| `name` | TEXT | Name |

### entries
Entry points / exports (exported symbols, program entry).

| Column | Type | Description |
|--------|------|-------------|
| `ordinal` | INT | Export ordinal |
| `addr` | INT | Entry address |
| `name` | TEXT | Entry name |

### imports
Imported functions from external libraries.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Import address |
| `name` | TEXT | Import name |
| `module` | TEXT | Module/DLL name |
| `ordinal` | INT | Import ordinal |

```sql
-- Imports from kernel32.dll
SELECT name FROM imports WHERE module LIKE '%kernel32%';
```

### strings
String literals found in the binary.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | String address |
| `length` | INT | String length |
| `content` | TEXT | String content |

```sql
-- Find error messages
SELECT content, hex(addr) as addr FROM strings WHERE content LIKE '%error%';

-- Longest strings
SELECT hex(addr), length, content FROM strings ORDER BY length DESC LIMIT 20;
```

### xrefs
Cross-references - important for understanding code relationships.

| Column | Type | Description |
|--------|------|-------------|
| `from_addr` | INT | Source address (who references) |
| `to_addr` | INT | Target address (what is referenced) |
| `from_func` | INT | **Pre-computed:** Function containing from_addr (0 if none) |
| `type` | INT | Xref type code |
| `is_code` | INT | 1=code xref (call/jump), 0=data xref |

**IMPORTANT:** Use `from_func` for call graph analysis - it's pre-computed at load time and avoids expensive range joins!

Both `WHERE to_addr = X` ("who references X") and `WHERE from_addr = X` ("what does
X reference") are direct BN-lookup fast paths — they query the reference index for
that one address instead of materializing the whole xref set, so they stay cheap in
JOINs and subqueries.

```sql
-- Who calls function at 0x401000?
SELECT hex(from_addr) as caller FROM xrefs WHERE to_addr = 0x401000 AND is_code = 1;

-- What does the instruction at 0x401abc reference? (from_addr fast path)
SELECT hex(to_addr) as target, type, is_code FROM xrefs WHERE from_addr = 0x401abc;

-- Fast: count callees per function using from_func
SELECT from_func, COUNT(DISTINCT to_addr) as num_callees
FROM xrefs WHERE is_code = 1 AND from_func != 0
GROUP BY from_func ORDER BY num_callees DESC LIMIT 10;
```

### blocks
Basic blocks within functions.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Containing function |
| `start_addr` | INT | Block start |
| `end_addr` | INT | Block end |
| `size` | INT | Block size |

```sql
-- Functions with most basic blocks
SELECT func_at(func_addr) as name, COUNT(*) as blocks
FROM blocks GROUP BY func_addr ORDER BY blocks DESC LIMIT 10;
```

### cfg_edges
Intra-function control-flow edges between basic blocks. **Always filter by `func_addr`** (filter_eq pushdown).

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Containing function |
| `from_addr` | INT | Source block start address |
| `to_addr` | INT | Target block start address |
| `edge_type` | TEXT | `normal`, `true`, `false` |

```sql
-- Branch points (blocks with >1 successor) in a function
SELECT from_addr, COUNT(*) AS succ FROM cfg_edges
WHERE func_addr = 0x140001000 GROUP BY from_addr HAVING succ > 1;
```

### switch_tables
Reconstructed switch/case jump tables (via HLIL `HLIL_SWITCH`). Canonical cross-tool
schema. Read-only.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Containing function |
| `instr_addr` | INT | The switch instruction |
| `table_addr` | INT | **Always NULL** — BN does not expose the physical jump-table address |
| `min_case` | INT | Lowest case value |
| `max_case` | INT | Highest case value |
| `case_count` | INT | Slot span (`max_case - min_case + 1`), not distinct label count |
| `default_addr` | INT | **Always NULL** — BN does not expose a reliable default target |

(idasql/ghidrasql/r2sql populate `table_addr`/`default_addr`; on bnsql they are NULL
BN limitations, not gaps.)

```sql
SELECT func_addr, instr_addr, min_case, max_case, case_count FROM switch_tables;
```

### function_frames
Per-function stack-frame layout (from BN `GetStackLayout` + the arch stack-pointer
register). Canonical cross-tool schema. Read-only. One row per function.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function |
| `frame_size` | INT | Total stack extent (`max_off - min_off` of stack vars) |
| `arg_size` | INT | Positive-offset extent (stack args) |
| `local_size` | INT | Negative-offset extent (locals below the base) |
| `saved_reg_size` | INT | **Always NULL** — not exposed by BN |
| `stack_base_reg` | TEXT | Architecture stack-pointer register (e.g. `rsp`) |
| `has_frame_pointer` | INT | **Always NULL** — no clean per-function flag in BN |

(idasql populates saved_reg_size/has_frame_pointer but not stack_base_reg; ghidra/r2
differ — the NULLs above are BN limitations, not gaps.)

```sql
SELECT func_addr, frame_size, local_size, stack_base_reg FROM function_frames
ORDER BY frame_size DESC LIMIT 20;
```

### data_items
Defined data items (BN `GetDataVariables`). Canonical cross-tool schema. Read-only,
full-scan cached table; one row per DataVariable.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Data variable address |
| `name` | TEXT | Symbol short name, or NULL when unnamed |
| `data_type` | TEXT | BN `Type::GetString()`, or NULL when untyped |
| `size` | INT | Type width in bytes, or NULL when untyped |
| `value_repr` | TEXT | String contents for strlits, target-endian hex for 1/2/4/8-byte scalars, else NULL |
| `segment_name` | TEXT | Containing **section** name (BN segments are unnamed), or NULL |
| `is_string` | INT | 1 when a string reference starts at `addr` |
| `is_initialized` | INT | 0 for BSS / unmapped bytes, 1 otherwise |

```sql
-- All defined strings, largest first
SELECT addr, size, value_repr FROM data_items
WHERE is_string = 1 ORDER BY size DESC LIMIT 20;
```

### dominators / post_dominators / loops
Canonical cross-tool CFG-graph tables (aligned with ghidrasql). Each maps a
function's BN basic blocks (`GetBasicBlocks` + `GetOutgoingEdges`) onto opaque node
ids and runs the generic `xsql::graph` module. Read-only; filter by `func_addr`.

| Table | Columns |
|-------|---------|
| `dominators` | `func_addr`, `node_addr`, `idom_addr` (NULL at entry), `depth`, `is_entry` |
| `post_dominators` | `func_addr`, `node_addr`, `ipdom_addr` (NULL to exit), `depth`, `is_exit` |
| `loops` | `func_addr`, `header_addr`, `latch_addr`, `start_addr`, `end_addr`, `depth`, `loop_kind`, `block_count` |

`loops.depth` is loop-nesting depth (outermost = 1); a self-loop is a 1-block loop
(`header_addr == latch_addr`).

```sql
-- Immediate dominators for a function's blocks
SELECT node_addr, idom_addr, depth FROM dominators
WHERE func_addr = 0x140001000 ORDER BY depth;
```

### instructions
Decoded instructions. **Always filter by `func_addr` for performance.**

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Instruction address |
| `func_addr` | INT | Containing function |
| `itype` | INT | Instruction type id — always `0` in bnsql (BN has no itype equivalent); present for cross-tool schema parity |
| `mnemonic` | TEXT | Instruction mnemonic |
| `size` | INT | Instruction size |
| `operand0` | TEXT | First operand text (empty if absent) |
| `operand1` | TEXT | Second operand text (empty if absent) |
| `operand2` | TEXT | Third operand text (empty if absent) |
| `disasm` | TEXT | Full disassembly line |

```sql
-- Instruction profile of a function
SELECT mnemonic, COUNT(*) as count
FROM instructions WHERE func_addr = 0x401330
GROUP BY mnemonic ORDER BY count DESC;

-- Per-operand columns (there is no `operand` column — use operand0/1/2)
SELECT hex(addr) AS addr, mnemonic, operand0, operand1, operand2
FROM instructions WHERE func_addr = 0x401330 ORDER BY addr;
```

### instruction_operands
One row per decoded operand (the canonical cross-tool per-operand surface, aligned with idasql/ghidrasql/r2sql). **Filter by `func_addr` or `addr`.**

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Instruction address |
| `func_addr` | INT | Containing function |
| `operand_index` | INT | Zero-based operand position |
| `text` | TEXT | Operand text |
| `token_type` | INT | BN instruction-text-token type id |
| `type_name` | TEXT | Token type name |
| `value` | INT | Numeric value (register id / immediate / address) when applicable |
| `size` | INT | Operand size in bytes when known |

```sql
-- Operands of every instruction in a function
SELECT hex(addr) AS addr, operand_index, text, type_name, value
FROM instruction_operands WHERE func_addr = 0x401330 ORDER BY addr, operand_index;
```

### comments
Address comments.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Comment address |
| `comment` | TEXT | Comment text |

### bookmarks
User bookmarks/annotations, backed by BN user **data Tags** (canonical cross-tool
schema, aligned with idasql/ghidrasql). **Writable.**

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Bookmark address |
| `type` | TEXT | BN tag-type name (default `Bookmarks`); set at INSERT |
| `category` | TEXT | Always empty — BN tags have no category sub-level |
| `comment` | TEXT | Free-text (**writable** ⇒ `Tag::SetData`) |

- `INSERT INTO bookmarks(addr, type, comment) VALUES(…, 'Bookmarks', '…')` ⇒
  `CreateUserDataTag`. The `type` must be an **existing** BN tag type (BN does not
  auto-create types; built-ins include `Bookmarks`, `Important`, `Bugs`); an unknown
  type is rejected. `category` must be NULL/empty; a nonempty value is rejected
  because BN tags have no category sub-level.
- `UPDATE bookmarks SET comment='…' WHERE addr=…` ⇒ `Tag::SetData` (in place).
- `DELETE FROM bookmarks WHERE addr=…` ⇒ `RemoveUserDataTag`.

### binary
Database-level metadata — key/value shape: `(key TEXT, value TEXT, type TEXT)`,
one row per fact, `type ∈ {string, hex, bool, int}`. The shape and the canonical
key names are shared across the tool family. The `summary` row is first, so
`SELECT * FROM binary` shows the digest up top.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Metadata key |
| `value` | TEXT | Metadata value |
| `type` | TEXT | Value type tag: `string`, `hex`, `bool`, or `int` |

Keys: `summary`, `tool_name` (`bnsql`), `tool_version`, `processor`, `filetype`,
`image_base`, `entry_point`, `min_addr`, `max_addr`, `is_64bit`, `bits`,
`endianness`, `filename`, `platform` (bnsql extra).

```sql
-- Get database info (summary row first)
SELECT * FROM binary;
-- Fetch one fact
SELECT value FROM binary WHERE key = 'entry_point';
```

### runtime_settings
Live table of runtime knobs — one row per key, with the current value. Its `value`
column is **writable**: change a setting with
`UPDATE runtime_settings SET value='<v>' WHERE key='<key>'`, and read it back with a
`SELECT`. (The two timeout-stack verbs remain `PRAGMA bnsql.timeout_push` /
`PRAGMA bnsql.timeout_pop`.)

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Runtime setting key |
| `value` | TEXT | Current live value, as text (writable) |
| `type` | TEXT | Value type tag: `int` or `bool` |
| `scope` | TEXT | `common` for shared settings, `bnsql` for `enable_python`/`python_output_max`, or `action` for dispatch-only verbs (`timeout_push`/`timeout_pop`) |

Keys (10): `query_timeout_ms`, `queue_admission_timeout_ms`, `max_queue`,
`hints_enabled`, `enable_python`, `python_output_max`, `timeout_stack_depth`,
`max_timeout_stack_depth`, `timeout_push`, `timeout_pop`.

```sql
-- Enumerate the runtime knobs and their current values
SELECT key, value, type, scope, kind, settable FROM runtime_settings;
-- Change a value with UPDATE, then read it back
UPDATE runtime_settings SET value='1234' WHERE key='query_timeout_ms';
SELECT value FROM runtime_settings WHERE key = 'query_timeout_ms';  -- 1234
```

---

## Convenience Views

Pre-built views for common xref analysis patterns. These simplify caller/callee queries.

### callers
Who calls each function. Use this instead of manual xref JOINs.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Target function address |
| `caller_addr` | INT | Xref source address |
| `caller_name` | TEXT | Calling function name |
| `caller_func_addr` | INT | Calling function start |

```sql
-- Who calls function at 0x401000?
SELECT caller_name, printf('0x%X', caller_addr) as from_addr
FROM callers WHERE func_addr = 0x401000;

-- Most called functions
SELECT printf('0x%X', func_addr) as addr, COUNT(*) as callers
FROM callers GROUP BY func_addr ORDER BY callers DESC LIMIT 10;
```

### callees
What each function calls. Inverse of callers view. **Use this instead of `func_start()` on xrefs!**

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Calling function address |
| `func_name` | TEXT | Calling function name |
| `callee_addr` | INT | Called address |
| `callee_name` | TEXT | Called function/symbol name |

```sql
-- What does main call?
SELECT callee_name, printf('0x%X', callee_addr) as addr
FROM callees WHERE func_name LIKE '%main%';

-- Functions making most calls (total call sites)
SELECT func_name, COUNT(*) as call_count
FROM callees GROUP BY func_addr ORDER BY call_count DESC LIMIT 10;

-- Functions calling the most UNIQUE callees (fan-out)
SELECT func_name, COUNT(DISTINCT callee_addr) as unique_callees
FROM callees GROUP BY func_addr ORDER BY unique_callees DESC LIMIT 10;

-- Functions that call exactly N unique functions (e.g., simple wrappers call 1)
SELECT func_name, COUNT(DISTINCT callee_addr) as callees
FROM callees GROUP BY func_addr HAVING callees = 1;
```

### string_refs
Which functions reference which strings. The primary surface for finding functions
by string content. The `strings JOIN xrefs` under the hood probes each string's
referrers with a direct BN reference lookup (`xrefs.to_addr` fast path), so a full
`string_refs` scan is cheap even on large binaries — prefer it over hand-rolling a
`strings`+`xrefs` join.

| Column | Type | Description |
|--------|------|-------------|
| `string_addr` | INT | String address |
| `string_value` | TEXT | String content |
| `string_length` | INT | String length |
| `ref_addr` | INT | Reference address |
| `func_addr` | INT | Referencing function |
| `func_name` | TEXT | Function name |

```sql
-- Find functions using error strings
SELECT func_name, string_value
FROM string_refs
WHERE string_value LIKE '%error%' OR string_value LIKE '%fail%';

-- Functions with most string references
SELECT func_name, COUNT(*) as string_count
FROM string_refs WHERE func_name IS NOT NULL
GROUP BY func_addr ORDER BY string_count DESC LIMIT 10;
```

### entities
Unified discovery view — one searchable surface over functions, symbols, segments,
imports, strings, and types. Handy when you don't yet know which table an entity lives in.

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Entity name |
| `kind` | TEXT | One of `function`, `symbol`, `segment`, `import`, `string`, `type` |
| `addr` | INT | Address; `NULL` for `type` rows |
| `parent_name` | TEXT | Owning module for `import` rows (else empty) |
| `qualified_name` | TEXT | Fully-qualified name (e.g. `module!name` for imports) |
| `source` | TEXT | Origin surface, e.g. `analysis.functions`, `analysis.imports` |

```sql
-- Find every entity whose name mentions "decrypt", across all kinds
SELECT kind, name, hex(addr) AS addr, source
FROM entities
WHERE name LIKE '%decrypt%'
ORDER BY kind, name;
```

For a large database prefer the `entities_search()` UDF (see SQL Functions), which is
paginated and does the case-insensitive filtering natively instead of scanning the view.

---

### pseudocode
Line-by-line decompiled pseudocode (HLIL). **Filter by `func_addr` for performance.**

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `line_num` | INT | Line number (0-indexed) |
| `line` | TEXT | Pseudocode text |
| `indent` | INT | Indentation level |

```sql
-- Get pseudocode for a function
SELECT line FROM pseudocode WHERE func_addr = 0x401000 ORDER BY line_num;

-- Find functions containing "password" in decompiled code
SELECT DISTINCT func_at(func_addr) FROM pseudocode WHERE line LIKE '%password%';
```

### hlil_vars
Local variables from decompiled functions. **Filter by `func_addr`.**

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `var_idx` | INT | Variable index |
| `name` | TEXT | Variable name |
| `type` | TEXT | Variable type |
| `size` | INT | Size in bytes |
| `is_arg` | INT | 1 if function argument |
| `storage` | TEXT | "stack" or "register" |
| `stack_off` | INT | Stack offset (if stack) |

```sql
-- Variables in a function
SELECT name, type, storage FROM hlil_vars WHERE func_addr = 0x401000;

-- Find functions with "buffer" variables
SELECT DISTINCT func_at(func_addr) FROM hlil_vars WHERE name LIKE '%buffer%';
```

### hlil_calls
Function calls extracted from HLIL. **Filter by `func_addr`.**

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Containing function |
| `callee_name` | TEXT | Called function name |
| `arg_idx` | INT | Argument index |

```sql
-- What does a function call?
SELECT DISTINCT callee_name FROM hlil_calls WHERE func_addr = 0x401000;

-- Find functions calling malloc
SELECT DISTINCT func_at(func_addr) FROM hlil_calls WHERE callee_name = 'malloc';
```

---

## Type Intelligence Tables

BNSQL exposes Binary Ninja's type system through SQL. `types`, `type_members`, and
`type_enum_values` are **writable** — INSERT/UPDATE/DELETE map to BN's type-system
mutations (follow the explicit-save model: `SELECT save();`). `func_signatures` is
read-only — edit a function prototype via `funcs.prototype`. Gate writes by checking
the `mutation.types.*` / `mutation.type_members.*` / `mutation.type_enum_values.*`
keys in `capabilities`.

```sql
-- Create a struct, populate it, then persist.
INSERT INTO types(name, kind) VALUES ('MY_HEADER', 'struct');   -- kind: struct|union|enum
INSERT INTO type_members(type_name, member_name, member_type) VALUES
    ('MY_HEADER', 'magic',  'uint32_t'),
    ('MY_HEADER', 'length', 'uint16_t');   -- omit member_type to default to int; add `offset` to place, else append
-- Create an enum (omit `value` to auto-assign previous+1).
INSERT INTO types(name, kind) VALUES ('ERR', 'enum');
INSERT INTO type_enum_values(type_name, value_name, value) VALUES ('ERR', 'OK', 0), ('ERR', 'FAIL', 1);
-- Rename / retype / delete. Widening a member overlaps and DROPS the following
-- members (native BN semantics, same as the GUI) — re-add them with an explicit
-- offset if they should survive.
UPDATE types SET name = 'PACKET_HEADER' WHERE name = 'MY_HEADER';
UPDATE type_members SET member_type = 'uint64_t' WHERE type_name = 'PACKET_HEADER' AND member_name = 'magic';
DELETE FROM type_members WHERE type_name = 'PACKET_HEADER' AND member_name = 'length';
SELECT save();
```

### types

All defined types: structs, unions, enums, typedefs, and function prototypes.

Use `PRAGMA table_xinfo(types);` to introspect the live column shape before
authoring queries — the columns include name flags (`is_struct`, `is_enum`,
`is_typedef`, `is_func`), size, alignment, and the parent module/scope.

```sql
-- Top-level type counts by kind
SELECT
    SUM(is_struct) AS structs,
    SUM(is_enum)   AS enums,
    SUM(is_typedef) AS typedefs
FROM types;
```

### type_members

Struct/union member fields. Filter by parent type to enumerate a struct's
layout.

```sql
PRAGMA table_xinfo(type_members);
SELECT * FROM type_members WHERE type_name = 'KPROCESS' ORDER BY offset;
```

### type_enum_values

Enumeration members (one row per value).

```sql
SELECT * FROM type_enum_values WHERE type_name = 'IRP_MJ' ORDER BY value;
```

### func_signatures

Function parameter and return type information (one row per function/param
position).

```sql
SELECT * FROM func_signatures WHERE func_addr = 0x401000 ORDER BY arg_index;
```

### Convenience type views

- `types_v_structs` — structs only
- `types_v_enums` — enums only

Filter by these views when you only care about one kind. Use
`PRAGMA table_xinfo` on either view to confirm the projected columns.

---

## Patches Table

`patches` tracks byte-level patches applied to the database. Writable —
INSERT to apply, UPDATE to revise, DELETE to revert.

```sql
PRAGMA table_xinfo(patches);

-- Inventory of patched addresses
SELECT printf('0x%X', addr) AS addr, original_byte, patched_byte, status FROM patches;
```

The `original_byte` column preserves the pre-patch byte (0-255) for safe revert.

---

## Database Modification & Persistence

### Explicit-save model (v0.0.9+)

BNSQL opens the Binary Ninja database **read-mostly**. Mutations (INSERT/UPDATE/
DELETE, `set_name`, `set_comment`, type edits, patches) are applied in-memory
to the live BN session but are **not** automatically written back to the
`.bndb`. Call `save()` to commit:

```sql
UPDATE funcs SET name = 'main' WHERE addr = 0x401000;
SELECT save();
```

If you exit the REPL without calling `save()`, your edits are lost. The HTTP
and MCP servers follow the same model.

### Decompiler edits reflect in-session (no manual refresh)

A `hlil_vars` **name/type** rename/retype reflects in the **same session**
automatically — no `decompile(addr, ..., refresh=1)` step. The write marks the
function for re-analysis and the write statement's commit flushes analysis once,
so the next `SELECT` against `hlil_vars` (and `pseudocode`) shows the new
name/type immediately. A batch rename/retype in a single `UPDATE` flushes exactly
**once** (O(1) regardless of how many rows), and reads never wait. Var/pseudocode
**comment** writes are immediate metadata (no re-analysis needed). So the normal
read → UPDATE → re-read loop below just works in one session.

### Mutation loop

1. Read current state with a `SELECT` (always identify your target precisely).
2. Apply mutation (UPDATE/INSERT/DELETE or `set_*` UDF).
3. Re-read to verify the expected change.
4. `SELECT save();` to persist.

---

## Runtime Controls and Capabilities

### runtime_settings (runtime knobs)

Read and change runtime knobs through the writable `runtime_settings` table:

```sql
SELECT value FROM runtime_settings WHERE key='query_timeout_ms';         -- get
UPDATE runtime_settings SET value='60000' WHERE key='query_timeout_ms';  -- set (0 disables)
UPDATE runtime_settings SET value='1' WHERE key='hints_enabled';         -- 1/0
```

The two timeout-stack verbs stay pragmas:

```sql
PRAGMA bnsql.timeout_push = 2000;  -- push a scoped timeout
PRAGMA bnsql.timeout_pop;          -- pop back
```

The full runtime surface is enumerated by the `runtime_settings` table:

```sql
SELECT * FROM runtime_settings;
```

### capabilities

`capabilities` exposes the runtime feature matrix — which mutations and
features are available in the current binary view (writable, decompiler
present, type system loaded, etc.).

```sql
SELECT * FROM capabilities;
```

Consult `capabilities` before issuing writes if you need to gracefully
degrade in read-only or limited contexts. Unsupported mutations are advertised
explicitly as negative rows — e.g. `mutation.binary.write = false`,
`mutation.instructions.write = false`, `mutation.xrefs.write = false`
— so you can gate up-front instead of by trial-and-error. A write to a read-only
table fails with a capability-scoped error (`... mutation.<table>.* is
unavailable`), not a generic "readonly database"; and a 0-row DELETE/UPDATE on a
read-only table is denied too (no silent success).

---

## Context Awareness (Plugin UI)

Use `get_ui_context_json()` when the user anchors a request to the live Binary
Ninja GUI rather than a fixed address — "what am I looking at?", "what's
selected?", "the current function", "here", "this".

```sql
SELECT get_ui_context_json();
```

It returns a JSON envelope: `available`, `capture{source,fresh,error}`,
`view{type,name}`, `code_context{has_address,addr,function,segment,section}`,
`selection{start,end}`, `highlight{valid,addr,text}`.

Availability:
- Live only in the **GUI plugin**, where it snapshots Binary Ninja's `UIContext`
  (via BN's bundled Python `binaryninjaui`) — `available:true`.
- Under the **CLI / `--http` / `--mcp` / headless** runtimes it returns a stable
  `available:false` envelope (`capture.source:"cli"`) — never NULL, never throws.

When `available` is false, do **not** invent a "current" address — orient with
`SELECT * FROM binary;` / `entries` / `segments` instead. See the `ui-context`
skill for the full response pattern.

---

## Python Execution

When the SQL surfaces can't express what's needed (custom algorithms, a BN API not
exposed as a table, UI automation), run Python against the live session:

```sql
UPDATE runtime_settings SET value='1' WHERE key='enable_python';  -- off by default (arbitrary code exec)
SELECT bnsql_python('print(len(list(bv.functions)))');
SELECT bnsql_python_file('C:/scripts/triage.py');
SELECT bnsql_python('x = globals().get("x",0)+1; print(x)', 'sandbox_a');  -- isolated, persistent
```

- Returns captured stdout as text; a Python exception surfaces as a SQL error.
- `UPDATE runtime_settings SET value='N' WHERE key='python_output_max'` caps captured output (0 = unbounded).
- `sandbox` (2nd arg) is an isolated, persistent Python namespace per key.
- **Works in every runtime** — headless CLI/`--http`/`--mcp` and the GUI plugin
  alike. If `/status` reports `python_available: false`, the environment is
  broken (typically a copied `binaryninjacore.dll` beside the executable) — see
  the `python` skill. Prefer SQL when it can do the job.

---

## SQL Functions

### IMPORTANT: UDF Performance Costs

Some SQL functions call the Binary Ninja API **once per row**. In bulk queries, this creates thousands of API calls:

| Function | Cost | Use Case |
|----------|------|----------|
| `func_start(addr)` | **SLOW** - API call per row | Single address lookup only |
| `func_at(addr)` | **SLOW** - API call per row | Single address lookup only |
| `func_end(addr)` | **SLOW** - API call per row | Single address lookup only |
| `decompile(addr)` | **VERY SLOW** - decompiles function | Single function only |
| `disasm(addr)` | Moderate | Small result sets |
| `hex(val)` | Fast | Pure SQL |
| `printf(...)` | Fast | Pure SQL |

**Rule:** For bulk call-graph analysis, use `callers`/`callees` views instead of `func_start()`/`func_at()` on xrefs:

```sql
-- WRONG: 8000 API calls on a binary with 8000 xrefs
SELECT func_start(from_addr), to_addr FROM xrefs WHERE is_code = 1;

-- CORRECT: Pure SQL join, milliseconds
SELECT func_addr, callee_addr FROM callees;
```

### Disassembly
| Function | Description |
|----------|-------------|
| `disasm(addr)` | Disassembly line at address |
| `disasm(addr, n)` | Multiple lines from address |
| `mnemonic(addr)` | Instruction mnemonic only |

### Byte Reads via the `bytes` Table

Bulk byte reads use the `bytes` virtual table with hidden `start_addr`
+ `n` input columns composed with `blob_concat`:

```sql
-- N bytes as uppercase hex
SELECT hex(blob_concat(value)) FROM bytes
  WHERE start_addr = X AND n = N ORDER BY addr;

-- N bytes as BLOB
SELECT blob_concat(value) FROM bytes
  WHERE start_addr = X AND n = N ORDER BY addr;

-- two-sided range
SELECT value FROM bytes
  WHERE addr >= A AND addr < B ORDER BY addr;
```

The hidden `start_addr` + `n` columns do NOT appear in `SELECT *`.
Keeping `start_addr` distinct from the visible `addr` keeps any
user predicate on `addr` enforceable by SQLite (joins stay correct).
Always pair the read with one of `WHERE start_addr = X AND n = N`,
`AND addr < B`, or an outer `LIMIT` to bound the output.

Visible columns: `addr`, `value` (0–255 when initialized, NULL when not),
and `is_initialized` — 1 for loaded bytes, 0 for uninitialized/BSS bytes
(whose `value` reads back NULL, preserving the unknown-vs-real-0
distinction). `WHERE is_initialized = 1` is the initialized-only view (the
canonical cross-tool byte-surface flag, matching idasql/ghidrasql/r2sql).

### Byte Patches via the `patches` Table

Byte patching is exposed by the `patches` table (writable
`patched_byte`, `DELETE` reverts, `INSERT` applies).

### Aggregates (built-in)
| Function | Description |
|----------|-------------|
| `blob_concat(value)` | Aggregate — concatenate BLOB inputs or INTEGER 0-255 values into one BLOB. NULL inputs skipped; TEXT and out-of-range INTs error. Use over a row-shaped byte source, e.g. `SELECT hex(blob_concat(x)) FROM (SELECT ... ORDER BY ...)`. |

### Binary Search
`byte_search` is the **canonical cross-tool byte-pattern search** table (matches
idasql/r2sql/ghidrasql). It has hidden input columns, so it takes both the positional
table-valued form and the `WHERE pattern = '...'` form. A bare scan errors —
`matched_hex` is an output column, not the input. `search_first` stays a scalar
(first match address, or NULL).

Canonical columns — visible: `addr`, `matched_hex` (spaced lowercase, e.g. `48 8b`),
`matched_bytes` (BLOB), `size`. Hidden inputs: `pattern` (REQUIRED), `start_addr`,
`end_addr`, `max_results`.

| Surface | Description |
|---------|-------------|
| `byte_search('<pat>')` / `... WHERE pattern = '<pat>'` | All matches over initialized mapped bytes (lazy bounded-page scan) |
| `byte_search('<pat>', start_addr, end_addr)` | Matches within `[start_addr, end_addr)` |
| `... WHERE pattern = '<pat>' AND max_results = N` | Cap the result set |
| `search_first(pattern)` (scalar) | First match address (INTEGER) or NULL |

**Pattern syntax (FlexHex; whitespace between bytes optional):**
- `"48 8B 05"` - Exact bytes (hex)
- `"48 ?? 05"` - `??` = any byte wildcard
- `"4?"` / `"?F"` - single-nibble wildcard (`4?` matches 40-4F)

**Example:**
```sql
-- Find all matches for a pattern (positional table-valued form)
SELECT printf('0x%X', addr), matched_hex FROM byte_search('48 8B ?? 00');

-- Equivalent WHERE-predicate form, capped
SELECT addr FROM byte_search WHERE pattern = '48 89 ??' AND max_results = 10;

-- Range-limited search
SELECT addr FROM byte_search('48 8B', 0x140001000, 0x140002000);

-- First match only (scalar)
SELECT printf('0x%X', search_first('CC CC CC'));
```

**Optimization Pattern: Find functions using specific instruction**

To answer "How many functions use a specific byte pattern?" efficiently:
```sql
-- Count unique functions containing RDTSC (opcode: 0F 31)
SELECT COUNT(DISTINCT func_start(addr)) AS count
FROM byte_search('0F 31')
WHERE func_start(addr) IS NOT NULL;

-- List those functions with names
SELECT DISTINCT func_start(addr) AS func_addr, name_at(func_start(addr)) AS func_name
FROM byte_search('0F 31')
WHERE func_start(addr) IS NOT NULL;
```

This is **much faster** than scanning all disassembly lines because:
- `byte_search` scans mapped segment bytes directly (no JSON)
- `func_start()` is O(1) lookup in function index

### Names & Functions
| Function | Description |
|----------|-------------|
| `name_at(addr)` | Name at address |
| `func_at(addr)` | Function name containing address |
| `func_start(addr)` | Start of containing function |
| `func_end(addr)` | End of containing function |
| `func_qty()` | Total function count |
| `func_at_index(n)` | Function address at index |

### Cross-References
| Function | Description |
|----------|-------------|
| `xrefs_to(addr)` | JSON array of xrefs TO address |
| `xrefs_from(addr)` | JSON array of xrefs FROM address |

### Discovery
| Function | Description |
|----------|-------------|
| `entities_search(pattern)` | JSON array of entities whose `name`/`parent_name`/`qualified_name` contain `pattern` (case-insensitive substring). Default 50 results |
| `entities_search(pattern, limit)` | Same, capped at `limit` (max 500) |
| `entities_search(pattern, limit, offset)` | Same, paginated from `offset` |

Each match is a JSON object with the same shape as the `entities` view
(`name`, `kind`, `addr`, `parent_name`, `qualified_name`, `source`); `addr` is
absent/NULL for `type` rows. Prefer this over `SELECT ... FROM entities WHERE name LIKE`
on large databases — it filters natively and paginates.

`entities_search()` scans functions/symbols/segments/strings/types once per call —
it's a one-shot discovery query, not something to call per row (don't put it in a
correlated subquery or a SELECT over a large table).

```sql
-- Top 20 entities matching "aes", as rows
SELECT json_extract(value, '$.kind') AS kind,
       json_extract(value, '$.name') AS name,
       json_extract(value, '$.source') AS source
FROM json_each(entities_search('aes', 20));
```

### Navigation
| Function | Description |
|----------|-------------|
| `next_head(addr)` | Next defined item |
| `prev_head(addr)` | Previous defined item |
| `segment_at(addr)` | Segment name at address |
| `hex(val)` | Format as hex string |

### Comments
| Function | Description |
|----------|-------------|
| `comment_at(addr)` | Get comment at address |
| `set_comment(addr, text)` | Set regular comment |

### Modification
| Function | Description |
|----------|-------------|
| `set_name(addr, name)` | Set name at address |

### Database
| Function | Description |
|----------|-------------|
| `save()` | Save database to disk (after UPDATE/INSERT/DELETE) |

### Decompilation (HLIL)
| Function | Description |
|----------|-------------|
| `decompile(addr)` | Full HLIL pseudocode for function at addr |
| `decompile(addr, limit)` | Pseudocode limited to N lines |
| `hlil_at(addr)` | HLIL text at specific address |
| `hlil_op_at(addr)` | HLIL operation name at address |

**IMPORTANT:** Use `decompile()`, NOT `hlil()` or `hlil_ssa()` - those don't exist!

---

## Common Query Patterns

### Find Most Called Functions

```sql
-- Direct JOIN is now efficient (uses filter_eq with GetCodeReferences)
SELECT f.name, COUNT(*) as callers
FROM funcs f
JOIN xrefs x ON x.to_addr = f.addr
WHERE x.is_code = 1
GROUP BY f.addr
ORDER BY callers DESC
LIMIT 10;
```

### Functions Called N Times or Less (Use CTE!)

**IMPORTANT:** Use a CTE to pre-aggregate xrefs, NOT a correlated subquery.

```sql
-- GOOD: Pre-aggregate with CTE (~800ms)
WITH call_counts AS (
    SELECT to_addr, COUNT(1) as cnt
    FROM xrefs
    WHERE is_code = 1
    GROUP BY to_addr
)
SELECT f.name, COALESCE(c.cnt, 0) as calls
FROM funcs f
LEFT JOIN call_counts c ON c.to_addr = f.addr
WHERE COALESCE(c.cnt, 0) <= 10
ORDER BY calls DESC;

-- BAD: Correlated subquery (O(n×m) = very slow, will timeout!)
-- SELECT name, (SELECT COUNT(*) FROM xrefs WHERE to_addr = funcs.addr) as calls FROM funcs;
```

### String Cross-Reference Analysis

```sql
SELECT s.content, func_at(x.from_addr) as used_by
FROM strings s
JOIN xrefs x ON s.addr = x.to_addr
WHERE s.content LIKE '%password%';
```

### Function Complexity (by Block Count)

```sql
SELECT func_at(func_addr) as name, COUNT(*) as block_count
FROM blocks
GROUP BY func_addr
ORDER BY block_count DESC
LIMIT 10;
```

### Import Dependency Map

```sql
-- Which modules are used
SELECT module, COUNT(*) AS cnt FROM imports GROUP BY module ORDER BY cnt DESC;
```

### Security: Dangerous Function Imports

```sql
-- Find dangerous/suspicious imports
SELECT module, name FROM imports
WHERE name LIKE '%Shell%'
   OR name LIKE '%WinExec%'
   OR name LIKE '%CreateProcess%'
   OR name LIKE '%VirtualAlloc%'
   OR name IN ('strcpy', 'strcat', 'sprintf', 'gets');
```

### Crypto-related Imports

```sql
SELECT module, name FROM imports
WHERE name LIKE '%Crypt%'
   OR name LIKE '%Hash%'
   OR name LIKE '%AES%'
   OR name LIKE '%RSA%';
```

### Network-related Imports

```sql
SELECT module, name FROM imports
WHERE name LIKE '%socket%'
   OR name LIKE '%connect%'
   OR name LIKE '%send%'
   OR name LIKE '%recv%'
   OR name LIKE '%WSA%'
   OR name LIKE '%Http%';
```

---

## Complex Analysis Patterns

### Bridge Functions (High Connectivity)
Functions that act as bridges between subsystems - called by many and calling many:

```sql
WITH caller_counts AS (
    SELECT to_addr as func_addr, COUNT(DISTINCT from_func) as caller_cnt
    FROM xrefs WHERE is_code = 1 AND from_func != 0 GROUP BY to_addr
),
callee_counts AS (
    SELECT from_func as func_addr, COUNT(DISTINCT to_addr) as callee_cnt
    FROM xrefs WHERE is_code = 1 AND from_func != 0 GROUP BY from_func
)
SELECT f.name, COALESCE(cr.caller_cnt, 0) as callers, COALESCE(ce.callee_cnt, 0) as callees
FROM funcs f
LEFT JOIN caller_counts cr ON cr.func_addr = f.addr
LEFT JOIN callee_counts ce ON ce.func_addr = f.addr
WHERE COALESCE(cr.caller_cnt, 0) >= 5 AND COALESCE(ce.callee_cnt, 0) >= 5
ORDER BY (cr.caller_cnt * ce.callee_cnt) DESC LIMIT 20;
```

### Error Handler Detection
Functions with many callers that reference error-related strings:

```sql
-- Compound pattern: error-referencing functions AND a caller-count threshold in
-- one pass. (For a plain "which functions reference error strings" list, the
-- string_refs view is simpler and just as fast.)
WITH error_addrs AS (
    SELECT addr FROM strings
    WHERE content LIKE '%error%' OR content LIKE '%fail%' OR content LIKE '%invalid%'
),
funcs_with_errors AS (
    SELECT DISTINCT x.from_func as func_addr
    FROM xrefs x
    WHERE x.from_func != 0
      AND EXISTS (SELECT 1 FROM error_addrs e WHERE e.addr = x.to_addr)
),
caller_counts AS (
    SELECT to_addr as func_addr, COUNT(*) as caller_cnt
    FROM xrefs WHERE is_code = 1 GROUP BY to_addr
)
SELECT f.name, COALESCE(cr.caller_cnt, 0) as callers
FROM funcs_with_errors fwe
JOIN funcs f ON f.addr = fwe.func_addr
LEFT JOIN caller_counts cr ON cr.func_addr = f.addr
WHERE COALESCE(cr.caller_cnt, 0) >= 5
ORDER BY cr.caller_cnt DESC LIMIT 15;
```

### Chokepoint Functions (Hook Targets)
Functions that dominate paths to output operations:

```sql
WITH write_funcs AS (
    SELECT addr FROM imports
    WHERE name LIKE '%write%' OR name LIKE '%send%' OR name LIKE '%fwrite%'
),
caller_coverage AS (
    SELECT x.from_func as func_addr, COUNT(DISTINCT x.to_addr) as write_targets
    FROM xrefs x
    WHERE x.to_addr IN (SELECT addr FROM write_funcs) AND x.from_func != 0
    GROUP BY x.from_func
)
SELECT f.name, cc.write_targets
FROM caller_coverage cc JOIN funcs f ON f.addr = cc.func_addr
ORDER BY cc.write_targets DESC LIMIT 10;
```

---

## Hex Address Formatting

Binary Ninja uses integer addresses. For display, use `hex()`:

```sql
SELECT hex(addr) as addr, name FROM funcs;
```

---

## Quick Start Examples

### "What does this binary do?"

```sql
-- Entry points / exports
SELECT * FROM entries;

-- Imported APIs (hints at functionality)
SELECT module, name FROM imports ORDER BY module, name;

-- Interesting strings
SELECT content FROM strings WHERE length > 10 ORDER BY length DESC LIMIT 20;
```

### "Find security-relevant code"

```sql
-- Dangerous string functions
SELECT module, name FROM imports
WHERE name IN ('strcpy', 'strcat', 'sprintf', 'gets');

-- Crypto-related
SELECT * FROM imports WHERE name LIKE '%Crypt%' OR name LIKE '%Hash%';

-- Network-related
SELECT * FROM imports WHERE name LIKE '%socket%' OR name LIKE '%connect%';
```

### "Understand a specific function"

```sql
-- Basic info
SELECT * FROM funcs WHERE addr = 0x401000;

-- What calls it
SELECT hex(from_addr) as caller FROM xrefs WHERE to_addr = 0x401000 AND is_code = 1;

-- Decompile it
SELECT decompile(0x401000);

-- Or with line limit
SELECT decompile(0x401000, 30);
```

### "Decompile and analyze a function"

```sql
-- Find a medium-sized function and decompile it
SELECT name, size, decompile(addr, 40) FROM funcs
WHERE size BETWEEN 500 AND 2000 ORDER BY size LIMIT 1;

-- Get variables
SELECT name, type, storage FROM hlil_vars WHERE func_addr = 0x401000;

-- Get function calls made
SELECT DISTINCT callee_name FROM hlil_calls WHERE func_addr = 0x401000;
```

---

## Query Optimization Guidelines

### Critical: Decompiler Tables Are On-Demand

**IMPORTANT:** The `pseudocode`, `hlil_vars`, and `hlil_calls` tables are **virtual tables that decompile functions on-demand**. This means:

- Each row requires decompiling its containing function
- Unbounded queries iterate ALL functions and decompile EACH one
- Large binaries can have thousands of functions
- Unbounded queries will **hang or timeout**

**NEVER do this:**
```sql
-- BAD: Iterates all functions, decompiles each one - WILL HANG!
SELECT COUNT(*) FROM pseudocode;
SELECT COUNT(*) FROM hlil_vars;
SELECT * FROM hlil_calls LIMIT 10;  -- Still iterates from start!
```

**ALWAYS do this:**
```sql
-- GOOD: First get a function address, then query that function
SELECT addr FROM funcs WHERE size > 100 LIMIT 1;  -- Get: 0x401000
SELECT * FROM pseudocode WHERE func_addr = 0x401000;
SELECT * FROM hlil_vars WHERE func_addr = 0x401000;
SELECT * FROM hlil_calls WHERE func_addr = 0x401000;
```

**Pattern for searching across decompiled code:**
```sql
-- Search requires iteration but filter early
SELECT DISTINCT func_at(func_addr) FROM pseudocode WHERE line LIKE '%password%';
-- Still iterates all, but finds matches. Use for targeted searches, not counts.
```

### Critical Performance Rules

1. **Decompiler tables:** ALWAYS filter by `func_addr = X` - unbounded queries cause hangs
2. **Instructions table:** Always filter by `func_addr = X` - never scan the whole table
3. **Xref counting:** Use CTEs to pre-aggregate, never correlated subqueries
4. **JOINs with xrefs:** Pre-aggregate xrefs in a CTE first, then JOIN to funcs
5. **Decompiler analysis:** Use `decompile()`, `hlil_vars`, `hlil_calls`, `pseudocode` - NOT the raw `hlil` table

### Decompiler Table Selection

| Need | Use This | NOT This |
|------|----------|----------|
| View pseudocode | `decompile(addr)` or `pseudocode WHERE func_addr=X` | - |
| Find variables | `hlil_vars WHERE func_addr = X` | - |
| Find function calls | `hlil_calls WHERE func_addr = X` | - |
| Search in decompiled code | `pseudocode WHERE line LIKE '%pattern%'` | - |
| AST analysis | `hlil_calls` + `hlil_vars` combined | `_hlil_ast` (expert only) |

**WARNING:** The `_hlil_ast` table (underscore prefix = internal/expert) contains raw HLIL AST nodes and generates many rows per function. For typical analysis, use `hlil_calls` and `hlil_vars` which provide the most useful information efficiently. Only use `_hlil_ast` for advanced AST pattern matching - see "Advanced: HLIL AST Table" section.

### Why CTEs Matter for Xref Queries

The `xrefs` table can have thousands of rows. A correlated subquery like:
```sql
-- SLOW: Executes subquery for EACH function (O(n×m))
SELECT name, (SELECT COUNT(*) FROM xrefs WHERE to_addr = funcs.addr) FROM funcs;
```

Instead, pre-aggregate once with a CTE:
```sql
-- FAST: Single pass over xrefs, then hash join (O(n+m))
WITH counts AS (SELECT to_addr, COUNT(*) as n FROM xrefs GROUP BY to_addr)
SELECT f.name, COALESCE(c.n, 0) FROM funcs f LEFT JOIN counts c ON c.to_addr = f.addr;
```

---

## Summary: When to Use What

| Goal | Table/Function |
|------|----------------|
| List all functions | `funcs` |
| Find who calls what | `xrefs` with `is_code = 1` |
| Find data references | `xrefs` with `is_code = 0` |
| Analyze imports | `imports` |
| Find strings | `strings` |
| Instruction analysis | `instructions WHERE func_addr = X` |
| Binary metadata | `binary` |
| **Decompile a function** | `decompile(addr)` or `decompile(addr, limit)` |
| **Find local variables** | `hlil_vars WHERE func_addr = X` |
| **Find function calls (HLIL)** | `hlil_calls WHERE func_addr = X` |
| **Search pseudocode** | `pseudocode WHERE line LIKE '%pattern%'` |

**Remember:** Always use `func_addr = X` constraints on `instructions`, `hlil_vars`, `hlil_calls`, and `pseudocode` tables.

---

## REPL Commands

When running in interactive mode (`bnsql database.bndb -i`), these dot-commands are available:

| Command | Description |
|---------|-------------|
| `.tables` | List all virtual tables |
| `.schema [table]` | Show table schema |
| `.info` | Show database metadata |
| `.clear` / `.reset` | Clear/reset session |
| `.quit` / `.exit` | Exit REPL |
| `.help` | Show available commands |
| `.http start` | Start HTTP server on random port |
| `.http stop` | Stop HTTP server |
| `.http` | Show HTTP server status (start if not running) |

---

## Server Modes

BNSQL supports two server protocols for remote queries: **HTTP REST** (recommended) and raw TCP.

---

### HTTP REST Server (Recommended)

Standard REST API that works with curl, any HTTP client, or LLM tools.

**Starting the server:**
```bash
# Default port 8080
bnsql database.bndb --http

# Custom port and bind address
bnsql database.bndb --http 9000 --bind 0.0.0.0

# With authentication
bnsql database.bndb --http 8080 --token mysecret
```

**HTTP Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Welcome message |
| `/help` | GET | No | API documentation (for LLM discovery) |
| `/query` | POST | Yes* | Execute SQL (body = raw SQL) |
| `/status` | GET | Yes* | Health check |
| `/shutdown` | POST | Yes* | Stop server |

*Auth required only if `--token` was specified.

**Example with curl:**
```bash
# Get API documentation
curl http://localhost:8080/help

# Execute SQL query
curl -X POST http://localhost:8080/query -d "SELECT name, size FROM funcs LIMIT 5"

# With authentication
curl -X POST http://localhost:8080/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM funcs"

# Check status
curl http://localhost:8080/status
```

**Response Format (JSON):**
```json
{"success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1}
```

```json
{"success": false, "error": "no such table: bad_table"}
```

---

## Advanced: MLIL table (mlil)

The `mlil` table exposes Binary Ninja IL — by default **MLIL in SSA form** — the
register-transfer IR tier *below* HLIL (LLIL → MLIL → HLIL). It is the bnsql leg of the
cross-tool low-level IR. One row per instruction; columns: `func_addr`, `seq` (instruction
index), `addr` (source address, NULL when synthetic), `operation` (raw native IL operation),
`op_name` (native name, e.g. `MLIL_SET_VAR_SSA` / `LLIL_SET_REG` / `HLIL_ASSIGN`),
`canonical_op` (cross-tool canonical P-code-style op — `INT_ADD`, `CALL`, `STORE`, …; empty
when no clean canonical), `size`, `operand_count`, `is_ssa`, `maturity`, `stage` (see below).
**Filter by `func_addr`** — each query materializes IL per function, so an unfiltered scan
lifts the whole binary. Read-only. Use it for dataflow/SSA-level analysis; use
`hlil_calls`/`hlil_vars` for high-level analysis.

**Maturity control (`WHERE maturity=…`).** `mlil` (and `ir_ops`) carry **`maturity`** — the
returned BN IL form (`llil`, `llil_ssa`, `mlil`, `mlil_ssa`, `hlil`, `hlil_ssa`) — and
**`stage`** — the coarse cross-tool ordinal (`raw`=llil, `optimized`=mlil, `ssa`=the three
`*_ssa` rungs, `final`=hlil). Unconstrained queries default to `mlil_ssa`. Add
`AND maturity='llil'` (or any rung) to **re-lift the same function at that IL form** — llil is
the lowest/most granular, hlil the most structured. `is_ssa` is maturity-dependent (the
`*_ssa` rungs → 1). `maturity` is a **passthrough** filter (pushes down to the generator,
through `ir_ops` too). List the ladder with **`SELECT * FROM ir_maturities`** (6 rows:
`maturity`, `stage`, `ordinal`, `is_default`, `is_ssa`; `mlil_ssa` is the default).

**`mlil_operands`** — structured value operands (one row per IL operand) projected onto the
5-kind model. Columns: `func_addr`, `op_seq` (joins `mlil.seq`), `operand_index`, `role`
(`in`|`out`), `kind` (`reg`|`imm`|`mem`|`var`|`result`), `text`, `value` (NULL unless an
immediate), `size`, `maturity`, `stage`. Structural operands (branch targets / SSA versions /
intrinsic ids) are excluded. Same `func_addr`/`maturity` pushdown.

**Cross-tool low-IR views (`ir_ops` / `ir_v_*` / `ir_operands` / `ir_maturities`).** `ir_ops`
is the canonical projection over `mlil` (`func_addr`, `seq`, `addr`, `op` = canonical or NULL,
`native_op` = native name, `is_ssa`, `maturity`, `stage`). The portable semantic views
`ir_v_calls` / `ir_v_mem_writes` / `ir_v_mem_reads` / `ir_v_branches` / `ir_v_arith`
(`func_addr`, `seq`, `addr`, `op`) classify the op stream with the same names/columns as the
other family tools. **`ir_operands`** is the portable 8-column projection of
`mlil_operands`, explicitly fixed to the default `mlil_ssa` rung; join on both
`func_addr` and `op_seq`. Use native `mlil_operands` with the same explicit
`maturity` when joining an alternate rung. **`ir_maturities`** advertises the ladder.
Because MLIL-SSA top-level instructions
are statement-level, arithmetic mostly nests inside `SET_VAR_SSA` sources, so `ir_v_arith` is
sparse at the default rung. Filter `mlil` / `mlil_operands` / `ir_ops` by
`func_addr` and optionally `maturity`; the portable semantic views and
`ir_operands` have no maturity coordinate and stay at `mlil_ssa`.

## Advanced: HLIL AST Table (_hlil_ast)

The `_hlil_ast` table provides access to raw HLIL Abstract Syntax Tree nodes. The underscore prefix indicates this is an **internal/expert** table - use it only when you need AST-level pattern matching that `hlil_calls` and `hlil_vars` cannot provide.

### When to Use _hlil_ast

| Need | Preferred Approach |
|------|-------------------|
| Find function calls | `hlil_calls` (use this!) |
| Find variables | `hlil_vars` (use this!) |
| Find loops/conditions | `_hlil_ast` views |
| AST pattern matching | `_hlil_ast` with filtering |

### Critical: Always Filter by func_addr

Like all decompiler tables, `_hlil_ast` decompiles functions on-demand. **NEVER query without a func_addr filter:**

```sql
-- BAD: Will iterate all functions and generate MANY rows per function
SELECT COUNT(*) FROM _hlil_ast;

-- GOOD: Always filter by specific function
SELECT * FROM _hlil_ast WHERE func_addr = 0x401000;
```

### Available Views

Pre-filtered views for common AST patterns (all require `func_addr` filter):

| View | Purpose |
|------|---------|
| `_hlil_ast_loops` | WHILE, DO_WHILE, FOR loops |
| `_hlil_ast_ifs` | IF/ELSE conditions |
| `_hlil_ast_comparisons` | Comparison operations |
| `_hlil_ast_assignments` | Assignment statements |
| `_hlil_ast_returns` | Return statements (`return_expr_id` is NULL for a void return) |
| `_hlil_ast_derefs` | Pointer dereferences |
| `_hlil_ast_constants` | Constant values |
| `_hlil_ast_vars` | Variable references |

### Example: Find Loops in a Function

```sql
-- Get a function address first
SELECT addr FROM funcs WHERE size > 500 LIMIT 1;  -- e.g., 0x401330

-- Query loops in that function
SELECT op_name, hex(addr) as addr, cond_id, body_id
FROM _hlil_ast_loops
WHERE func_addr = 0x401330;
```

### Example: Find All IF Conditions

```sql
SELECT op_name, hex(addr) as addr, cond_id, true_id, false_id
FROM _hlil_ast_ifs
WHERE func_addr = 0x401330;
```

### Recommendation

For 99% of use cases, prefer:
- `decompile(addr)` - to view pseudocode
- `hlil_calls` - to find function calls
- `hlil_vars` - to find variables
- `pseudocode WHERE line LIKE '%pattern%'` - to search in decompiled code

Only use `_hlil_ast` and its views for specialized AST analysis tasks.

---

## Output Guidelines

### ALWAYS Show Actual Data

When the user asks to see something (decompilation, code, data), **ALWAYS include the actual output** in your response - don't just describe it!

**BAD (don't do this):**
> "The function appears to call malloc and contains a loop..."

**GOOD (do this):**
```
int64_t sub_401000() {
    void* ptr = malloc(0x100);
    for (int i = 0; i < 10; i++) {
        process(ptr, i);
    }
    return 0;
}
```

### Decompilation Requests

When the user asks to "decompile" or "show the code":
1. Run `SELECT decompile(addr)` or `SELECT decompile(addr, 50)` for longer output
2. **Include the actual pseudocode output** in a code block
3. Then optionally add analysis

Example response format:
```
## Function: sub_401000 (500 bytes)

### Pseudocode:
\`\`\`c
int64_t sub_401000(int64_t arg1) {
    if (arg1 == 0) return -1;
    ...actual code here...
}
\`\`\`

### Analysis:
- This function validates the input argument...
```

---

## CRITICAL REMINDERS (Read Before Every Query)

- **JOINs on xrefs.to_addr are fast:** `JOIN xrefs x ON x.to_addr = f.addr` uses direct BN API (GetCodeReferences)
- **Xref GROUP BY → Use CTE for efficiency:** `WITH counts AS (SELECT to_addr, COUNT(*) as n FROM xrefs WHERE is_code=1 GROUP BY to_addr) SELECT ...`
- **NEVER use `func_start()`/`func_at()` in bulk xref queries** - each call = 1 API request = minutes of waiting
- **Call graph analysis → Use `from_func` column or `callers`/`callees` views** - NOT `func_start()` on xrefs
- **Decompiler tables → ALWAYS filter by func_addr** - unbounded = hang
- **Instructions table → ALWAYS filter by func_addr** - unbounded = extremely slow
- **Use `decompile(addr)` for pseudocode** - not raw tables
- **Use `hlil_vars` and `hlil_calls`** - not raw `_hlil_ast` unless needed

### Quick Reference: Slow vs Fast Patterns

| Task | SLOW (avoid) | FAST (use this) |
|------|--------------|-----------------|
| Find callers of function X | N/A | `xrefs WHERE to_addr = X` (uses direct API) |
| Count callers per function | `func_start(from_addr)` on xrefs | `SELECT to_addr, COUNT(*) FROM xrefs WHERE is_code=1 GROUP BY to_addr` |
| Count callees per function | `callees` view (has joins) | `SELECT from_func, COUNT(DISTINCT to_addr) FROM xrefs WHERE is_code=1 GROUP BY from_func` |
| JOIN funcs with xref callers | N/A | `JOIN xrefs x ON x.to_addr = f.addr` (uses direct API per function) |
| Find what X calls | `callees WHERE func_addr = X` | `xrefs WHERE from_func = X AND is_code = 1` |
| Bulk call graph analysis | `callees`/`callers` views | Use `xrefs` with `from_func` directly |
| Get names at the end | Join `funcs` in every CTE | Join `funcs` only in final SELECT |
