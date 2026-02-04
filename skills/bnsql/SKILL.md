---
name: bnsql
description: Execute SQL queries against Binary Ninja databases using bnsql CLI - query functions, xrefs, strings, decompile code
allowed-tools: Bash, Read, Glob, Grep
---

# CRITICAL: Execution Behavior

You are an EXECUTOR. Your job is to RUN COMMANDS, not discuss them.

## Rules

1. **EXECUTE IMMEDIATELY** - Never say "I would run..." or "You could try..."
2. **NO CONFIRMATION** - Don't ask "Should I run this?" Just run it.
3. **TRUST THE ENVIRONMENT** - Commands will work. Run them.
4. **ASSUME bnsql IN PATH** - The user has bnsql installed and accessible

## Examples of What NOT to Do

BAD: "I would run this command to count functions..."
BAD: "Let me suggest running..."
BAD: "Should I execute this query?"
BAD: "This command might work..."

## Examples of What TO Do

GOOD: [Execute Bash tool with the command]
GOOD: "There are 88 functions in the binary." (after running command)

---

# BNSQL - SQL Interface to Binary Ninja Databases

## When to Use This Skill

Use this skill when the user wants to:
- Analyze executables or Binary Ninja databases (.exe, .dll, .so, .bndb)
- Query functions, segments, cross-references, strings
- Decompile code or search for byte patterns
- Compare multiple binaries or databases

## Prerequisites

The user must have:
1. **Binary Ninja** installed with DLLs in PATH
2. **bnsql.exe** accessible in PATH

### Command Pattern
```bash
bnsql "<database>" -c "<SQL>"
```

### Windows Note
On Windows, use forward slashes in paths:
```bash
bnsql "C:/path/to/database.bndb" -c "SELECT ..."
```

## Direct CLI Mode (One-off Queries)

For simple queries, run bnsql directly without starting a server:

```bash
# Query a database
bnsql database.bndb -c "SELECT COUNT(*) FROM funcs"

# Query an existing Binary Ninja database
bnsql database.bndb -c "SELECT name, address FROM funcs LIMIT 10"

# Multiple queries in one session
bnsql program.exe -c "SELECT COUNT(*) FROM funcs" -c "SELECT COUNT(*) FROM strings"
```

Use direct CLI mode when:
- Running a single query or a few queries
- Analyzing a file for the first time
- No need to keep the database open

## HTTP Server Mode (Persistent Queries)

Use HTTP mode when:
- Running many queries against the same database
- Comparing multiple databases simultaneously
- Keeping analysis results cached between queries

### Starting a Server

```bash
# Start server for a single database (random port)
bnsql database.bndb --http 0

# With specific port
bnsql database.bndb --http 8081

# With authentication token
bnsql database.bndb --http 8081 --token mysecret

# Bind to all interfaces (for remote access)
bnsql database.bndb --http 8081 --bind 0.0.0.0
```

### Querying via curl

```bash
# Execute SQL query
curl -X POST http://localhost:8081/query -d "SELECT name, size FROM funcs LIMIT 5"

# With authentication
curl -X POST http://localhost:8081/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM funcs"

# Check server status
curl http://localhost:8081/status
```

### Response Format

```json
{"success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1}
```

```json
{"success": false, "error": "no such table: bad_table"}
```

### HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Welcome message |
| `/help` | GET | API documentation |
| `/query` | POST | Execute SQL (body = raw SQL) |
| `/status` | GET | Health check with stats |
| `/shutdown` | POST | Stop server gracefully |

---

# BNSQL Skill Guide

A comprehensive reference for using BNSQL - an SQL interface for reverse engineering binary analysis with Binary Ninja.

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

## REPL Commands

When running in interactive mode (`bnsql database.bndb -i`), these dot-commands are available:

| Command | Description |
|---------|-------------|
| `.tables` | List all virtual tables |
| `.schema [table]` | Show table schema |
| `.info` | Show database metadata |
| `.quit` / `.exit` | Exit REPL |
| `.help` | Show available commands |
| `.http start` | Start HTTP server on random port |
| `.http stop` | Stop HTTP server |
| `.http status` | Show HTTP server status |
| `.agent` | Start AI agent mode |

---

## Tables Reference

### funcs
All detected functions in the binary.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Function start address |
| `name` | TEXT | Function name |
| `size` | INT | Function size in bytes |

```sql
-- 10 largest functions
SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Functions starting with "sub_" (auto-named)
SELECT name, printf('0x%X', address) as addr FROM funcs WHERE name LIKE 'sub_%';
```

### segments
Memory segments.

| Column | Type | Description |
|--------|------|-------------|
| `start` | INT | Segment start |
| `end` | INT | Segment end |
| `name` | TEXT | Segment name |

### strings
String literals found in the binary.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | String address |
| `length` | INT | String length |
| `value` | TEXT | String content |

```sql
-- Find error messages
SELECT value, printf('0x%X', address) as addr FROM strings WHERE value LIKE '%error%';
```

### xrefs
Cross-references - the most important table for understanding code relationships.

| Column | Type | Description |
|--------|------|-------------|
| `from_ea` | INT | Source address |
| `to_ea` | INT | Target address |
| `is_code` | INT | 1=code xref, 0=data xref |

```sql
-- Who calls function at 0x401000?
SELECT printf('0x%X', from_ea) as caller FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;
```

### imports
Imported functions from external libraries.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Import address |
| `name` | TEXT | Import name |
| `module` | TEXT | Module/DLL name |

```sql
-- Imports from kernel32.dll
SELECT name FROM imports WHERE module LIKE '%kernel32%';
```

---

## Convenience Views

### callers
Who calls each function. Use this instead of manual xref JOINs.

```sql
-- Who calls function at 0x401000?
SELECT caller_name FROM callers WHERE func_addr = 0x401000;

-- Most called functions
SELECT func_addr, COUNT(*) as callers
FROM callers GROUP BY func_addr ORDER BY callers DESC LIMIT 10;
```

### callees
What each function calls.

```sql
-- What does main call?
SELECT callee_name FROM callees WHERE func_name LIKE '%main%';
```

### string_refs
Which functions reference which strings.

```sql
-- Find functions using error strings
SELECT func_name, string_value
FROM string_refs
WHERE string_value LIKE '%error%' OR string_value LIKE '%fail%';
```

---

## Decompiler Tables

**CRITICAL:** Always filter by `func_addr`. Without constraint, these tables decompile ALL functions!

### pseudocode
Decompiled HLIL code lines.

```sql
-- Get pseudocode for a function
SELECT line FROM pseudocode WHERE func_addr = 0x401000 ORDER BY line_num;
```

### hlil_vars
Local variables from decompilation.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `name` | TEXT | Variable name |
| `type` | TEXT | Type string |
| `is_arg` | INT | 1=function argument |

### hlil_calls
Function calls in HLIL.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `callee_name` | TEXT | Called function name |
| `line_num` | INT | Line number |

---

## SQL Functions

### Decompilation
| Function | Description |
|----------|-------------|
| `decompile(addr)` | Full pseudocode as single text |
| `decompile(addr, limit)` | Pseudocode with line limit |

**IMPORTANT:** Use `decompile(addr)` for full decompilation:
```sql
SELECT decompile(0x401000);
```

### Names & Functions
| Function | Description |
|----------|-------------|
| `func_at(addr)` | Function name containing address |
| `func_start(addr)` | Start of containing function |

### Binary Search
| Function | Description |
|----------|-------------|
| `search_bytes(pattern)` | Find all matches, returns JSON array |
| `search_first(pattern)` | First match address (or NULL) |

**Pattern syntax:**
- `"48 8B 05"` - Exact bytes
- `"48 ?? 05"` - `??` = any byte wildcard

```sql
SELECT search_bytes('48 8B ?? 00');
```

---

## Performance Rules

### CRITICAL: Constraint Pushdown

| Table | Optimized Filter | Without Filter |
|-------|------------------|----------------|
| `instructions` | `func_addr = X` | O(all instructions) - SLOW |
| `pseudocode` | `func_addr = X` | **Decompiles ALL functions** |
| `hlil_*` | `func_addr = X` | **Decompiles ALL functions** |
| `xrefs` | `to_ea = X` | Uses fast BN API |

**Always filter decompiler tables by `func_addr`!**

---

## Common Query Patterns

### Find Most Called Functions
```sql
WITH caller_counts AS (
    SELECT to_ea, COUNT(*) as callers
    FROM xrefs WHERE is_code = 1
    GROUP BY to_ea
)
SELECT f.name, c.callers
FROM funcs f
JOIN caller_counts c ON f.address = c.to_ea
ORDER BY c.callers DESC LIMIT 10;
```

### Find Functions Calling a Specific API
```sql
SELECT DISTINCT func_at(from_ea) as caller
FROM xrefs
WHERE to_ea = (SELECT address FROM imports WHERE name = 'CreateFileW');
```

### String Cross-Reference Analysis
```sql
SELECT s.value, func_at(x.from_ea) as used_by
FROM strings s
JOIN xrefs x ON s.address = x.to_ea
WHERE s.value LIKE '%password%';
```

### Find Leaf Functions (No Outgoing Calls)
```sql
SELECT f.name, f.size
FROM funcs f
LEFT JOIN callees c ON c.func_addr = f.address
GROUP BY f.address
HAVING COUNT(c.callee_addr) = 0
ORDER BY f.size DESC;
```

---

## Quick Start Examples

### "What does this binary do?"
```sql
-- Imported APIs (hints at functionality)
SELECT module, name FROM imports ORDER BY module, name;

-- Interesting strings
SELECT value FROM strings WHERE length > 10 ORDER BY length DESC LIMIT 20;
```

### "Find security-relevant code"
```sql
-- Dangerous string functions
SELECT DISTINCT func_at(func_addr) FROM hlil_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets');

-- Network-related
SELECT * FROM imports WHERE name LIKE '%socket%' OR name LIKE '%connect%';
```

### "Understand a specific function"
```sql
-- Decompile it
SELECT decompile(0x401000);

-- What it calls
SELECT callee_name FROM callees WHERE func_addr = 0x401000;

-- What calls it
SELECT caller_name FROM callers WHERE func_addr = 0x401000;
```
