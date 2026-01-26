# BNSQL Agent Guide

A comprehensive reference for AI agents to effectively use BNSQL - an SQL interface for reverse engineering binary analysis with Binary Ninja.

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

## Core Concepts for Binary Analysis

### Addresses
Everything in a binary has an **address** - a memory location where code or data lives. SQL shows these as integers; use `hex(address)` for hex display.

### Functions
Binary Ninja groups code into **functions** with:
- `address` - Where the function begins
- `name` - Assigned or auto-generated name (e.g., `main`, `sub_401000`)
- `size` - Total bytes in the function

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** - Function calls, jumps between code
- **Data xrefs** - Code reading/writing data locations
- `from_ea` -> `to_ea` represents "address X references address Y"

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
| `address` | INT | Function start address |
| `name` | TEXT | Function name |
| `size` | INT | Function size in bytes |

```sql
-- 10 largest functions
SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Functions starting with "sub_" (auto-named, not analyzed)
SELECT name, hex(address) as addr FROM funcs WHERE name LIKE 'sub_%';
```

### segments
Memory segments.

| Column | Type | Description |
|--------|------|-------------|
| `start_ea` | INT | Segment start |
| `end_ea` | INT | Segment end |
| `name` | TEXT | Segment name (.text, .data, etc.) |
| `perm` | INT | Permissions (R=4, W=2, X=1) |

```sql
-- Find executable segments
SELECT name, hex(start_ea) as start FROM segments WHERE perm & 1 = 1;
```

### names
All named locations (functions, labels, data).

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Address |
| `name` | TEXT | Name |

### entries
Entry points (exports, program entry).

| Column | Type | Description |
|--------|------|-------------|
| `ordinal` | INT | Export ordinal |
| `address` | INT | Entry address |
| `name` | TEXT | Entry name |

### imports
Imported functions from external libraries.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Import address |
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
| `address` | INT | String address |
| `length` | INT | String length |
| `content` | TEXT | String content |

```sql
-- Find error messages
SELECT content, hex(address) as addr FROM strings WHERE content LIKE '%error%';

-- Longest strings
SELECT hex(address), length, content FROM strings ORDER BY length DESC LIMIT 20;
```

### xrefs
Cross-references - important for understanding code relationships.

| Column | Type | Description |
|--------|------|-------------|
| `from_ea` | INT | Source address (who references) |
| `to_ea` | INT | Target address (what is referenced) |
| `type` | INT | Xref type code |
| `is_code` | INT | 1=code xref (call/jump), 0=data xref |

```sql
-- Who calls function at 0x401000?
SELECT hex(from_ea) as caller FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;
```

### blocks
Basic blocks within functions.

| Column | Type | Description |
|--------|------|-------------|
| `func_ea` | INT | Containing function |
| `start_ea` | INT | Block start |
| `end_ea` | INT | Block end |
| `size` | INT | Block size |

```sql
-- Functions with most basic blocks
SELECT func_at(func_ea) as name, COUNT(*) as blocks
FROM blocks GROUP BY func_ea ORDER BY blocks DESC LIMIT 10;
```

### instructions
Decoded instructions. **Always filter by `func_addr` for performance.**

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Instruction address |
| `func_addr` | INT | Containing function |
| `mnemonic` | TEXT | Instruction mnemonic |
| `size` | INT | Instruction size |
| `disasm` | TEXT | Full disassembly line |

```sql
-- Instruction profile of a function
SELECT mnemonic, COUNT(*) as count
FROM instructions WHERE func_addr = 0x401330
GROUP BY mnemonic ORDER BY count DESC;
```

### comments
Address comments.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Comment address |
| `comment` | TEXT | Comment text |

### db_info
Database-level metadata.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Metadata key |
| `value` | TEXT | Metadata value |

```sql
-- Get database info
SELECT * FROM db_info;
```

---

## SQL Functions

### Disassembly
| Function | Description |
|----------|-------------|
| `disasm(addr)` | Disassembly line at address |
| `disasm(addr, n)` | Multiple lines from address |
| `bytes(addr, n)` | Bytes as hex string |
| `bytes_raw(addr, n)` | Raw bytes as BLOB |
| `mnemonic(addr)` | Instruction mnemonic only |
| `operand(addr, n)` | Operand text (n=0-5) |

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

---

## Common Query Patterns

### Find Most Called Functions

```sql
SELECT f.name, COUNT(*) as callers
FROM funcs f
JOIN xrefs x ON f.address = x.to_ea
WHERE x.is_code = 1
GROUP BY f.address
ORDER BY callers DESC
LIMIT 10;
```

### Functions Called N Times or Less (Use CTE!)

**IMPORTANT:** Use a CTE to pre-aggregate xrefs, NOT a correlated subquery.

```sql
-- GOOD: Pre-aggregate with CTE (~800ms)
WITH call_counts AS (
    SELECT to_ea, COUNT(1) as cnt
    FROM xrefs
    WHERE is_code = 1
    GROUP BY to_ea
)
SELECT f.name, COALESCE(c.cnt, 0) as calls
FROM funcs f
LEFT JOIN call_counts c ON c.to_ea = f.address
WHERE COALESCE(c.cnt, 0) <= 10
ORDER BY calls DESC;

-- BAD: Correlated subquery (O(n×m) = very slow, will timeout!)
-- SELECT name, (SELECT COUNT(*) FROM xrefs WHERE to_ea = funcs.address) as calls FROM funcs;
```

### String Cross-Reference Analysis

```sql
SELECT s.content, func_at(x.from_ea) as used_by
FROM strings s
JOIN xrefs x ON s.address = x.to_ea
WHERE s.content LIKE '%password%';
```

### Function Complexity (by Block Count)

```sql
SELECT func_at(func_ea) as name, COUNT(*) as block_count
FROM blocks
GROUP BY func_ea
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

## Hex Address Formatting

Binary Ninja uses integer addresses. For display, use `hex()`:

```sql
SELECT hex(address) as addr, name FROM funcs;
```

---

## Quick Start Examples

### "What does this binary do?"

```sql
-- Entry points
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
SELECT * FROM funcs WHERE address = 0x401000;

-- What calls it
SELECT hex(from_ea) as caller FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;
```

---

## Query Optimization Guidelines

### Critical Performance Rules

1. **Instructions table:** Always filter by `func_addr = X` - never scan the whole table
2. **Xref counting:** Use CTEs to pre-aggregate, never correlated subqueries
3. **JOINs with xrefs:** Pre-aggregate xrefs in a CTE first, then JOIN to funcs

### Why CTEs Matter for Xref Queries

The `xrefs` table can have thousands of rows. A correlated subquery like:
```sql
-- SLOW: Executes subquery for EACH function (O(n×m))
SELECT name, (SELECT COUNT(*) FROM xrefs WHERE to_ea = funcs.address) FROM funcs;
```

Instead, pre-aggregate once with a CTE:
```sql
-- FAST: Single pass over xrefs, then hash join (O(n+m))
WITH counts AS (SELECT to_ea, COUNT(*) as n FROM xrefs GROUP BY to_ea)
SELECT f.name, COALESCE(c.n, 0) FROM funcs f LEFT JOIN counts c ON c.to_ea = f.address;
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
| Binary metadata | `db_info` |

**Remember:** Always use `func_addr = X` constraints on instruction tables for acceptable performance.
