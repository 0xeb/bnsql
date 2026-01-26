# BNSQL

**SQL interface for Binary Ninja** - Query your reverse engineering database using SQL and natural language.

## Features

- **SQL Queries** - Full SQLite syntax for complex analysis
- **Natural Language** - AI-powered agent understands questions in plain English
- **11 Virtual Tables** - Functions, strings, imports, xrefs, segments, and more
- **20+ SQL Functions** - `disasm()`, `hex()`, `func_at()`, `xrefs_to()`, etc.
- **Fast Startup** - ~5s for pre-analyzed databases (skips re-analysis)
- **Plugin + CLI** - Use inside Binary Ninja or from command line

## Quick Start

```bash
# Interactive SQL mode
bnsql database.bndb

# Single query
bnsql database.bndb -c "SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10"

# Natural language (AI agent)
bnsql database.bndb --prompt "what are the 5 largest functions?"
bnsql database.bndb --prompt "which functions are called no more than 10 times?"
bnsql database.bndb --prompt "find strings containing 'password'"
```

## Natural Language Examples

Ask questions in plain English:

| Question | What it does |
|----------|--------------|
| "what are the 5 largest functions?" | Sorts functions by size |
| "which functions are called no more than 10 times?" | Counts xrefs to each function |
| "show me strings containing 'error'" | Searches string table |
| "which modules does this binary import from?" | Groups imports by DLL |
| "find crypto-related imports" | Filters for Crypt/Hash/AES patterns |
| "what does this binary do?" | Summarizes entry points, imports, strings |

### Call Graph Visualization

Complex queries with visual output:

```
bnsql database.bndb --prompt "Find the busiest function. Show its callers (1 level, max 15) and callees (5 levels deep). Visualize as a tree."
```

Output:
```
╔═══════════════════════════╗
║    ⭐ sub_140013350 ⭐     ║
║     (377 calls)           ║
║    BUSIEST FUNCTION       ║
╚═══════════════════════════╝
            │
    ┌───────┴───────┐
    ▼               ▼
 CALLERS         CALLEES
 (7 funcs)       (3 levels)
    │               │
    ▼               ▼
sub_1400012d0   sub_14001d0d8
sub_140004bf0       │
sub_14001b0a0       ▼
...             sub_14001ddc0
                    │
                    ▼
                  free
                 (leaf)
```

The agent analyzes xrefs, builds the call hierarchy, and renders ASCII visualization.

## SQL Examples

```sql
-- 10 largest functions
SELECT hex(address) as addr, name, size
FROM funcs ORDER BY size DESC LIMIT 10;

-- Find password-related strings
SELECT content, hex(address) as addr
FROM strings WHERE content LIKE '%password%';

-- Import analysis by module
SELECT module, COUNT(*) as count
FROM imports GROUP BY module ORDER BY count DESC;

-- Functions called <= 10 times (uses CTE for performance)
WITH call_counts AS (
    SELECT to_ea, COUNT(1) as cnt
    FROM xrefs WHERE is_code = 1
    GROUP BY to_ea
)
SELECT f.name, COALESCE(c.cnt, 0) as calls
FROM funcs f
LEFT JOIN call_counts c ON c.to_ea = f.address
WHERE COALESCE(c.cnt, 0) <= 10
ORDER BY calls DESC;

-- Security: dangerous function imports
SELECT module, name FROM imports
WHERE name IN ('strcpy', 'strcat', 'sprintf', 'gets')
   OR name LIKE '%Shell%' OR name LIKE '%WinExec%';
```

## Tables

| Table | Description |
|-------|-------------|
| `funcs` | Functions (address, name, size) |
| `segments` | Memory segments (.text, .data, etc.) |
| `names` | All named locations |
| `entries` | Entry points and exports |
| `imports` | Imported functions |
| `strings` | String literals |
| `xrefs` | Cross-references (from_ea, to_ea, is_code) |
| `blocks` | Basic blocks |
| `instructions` | Decoded instructions |
| `comments` | Address comments |
| `db_info` | Database metadata |

## SQL Functions

| Function | Description |
|----------|-------------|
| `hex(addr)` | Format address as hex |
| `disasm(addr)` | Disassembly at address |
| `bytes(addr, n)` | Read n bytes as hex |
| `name_at(addr)` | Name at address |
| `func_at(addr)` | Function name containing address |
| `func_start(addr)` | Start of containing function |
| `xrefs_to(addr)` | JSON array of xrefs to address |
| `xrefs_from(addr)` | JSON array of xrefs from address |

## Building

```bash
cmake -B build -DBUILD_WITH_BNSQL=ON \
      -DBN_INSTALL_DIR=/path/to/binaryninja \
      -DBNSQL_WITH_AI_AGENT=ON
cmake --build build --config Release
```

## Performance Tips

1. **Instructions table**: Always filter by `func_addr` - never scan full table
2. **Xref counting**: Use CTEs to pre-aggregate, not correlated subqueries
3. **Pre-analyzed databases**: ~5s startup vs 15s+ for fresh analysis

## Author

Elias Bachaalany ([@0xeb](https://github.com/0xeb))

## License

MIT License - Copyright (c) 2025 Elias Bachaalany
