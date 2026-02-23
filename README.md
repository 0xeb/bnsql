# BNSQL

> **Status:** Pre-release Alpha | **Platform:** Windows only (for now)

**SQL interface for Binary Ninja** - Query your reverse engineering database using SQL and natural language.

## Features

- **SQL Queries** - Full SQLite syntax for complex analysis
- **Natural Language** - AI-powered agent understands questions in plain English
- **11 Virtual Tables** - Functions, strings, imports, xrefs, segments, and more
- **20+ SQL Functions** - `disasm()`, `hex()`, `func_at()`, `xrefs_to()`, etc.
- **Decompilation** - `decompile()` function, `pseudocode`, `hlil_vars`, `hlil_calls` tables for HLIL analysis
- **Fast Startup** - ~5s for pre-analyzed databases (skips re-analysis)
- **Plugin + CLI** - Use inside Binary Ninja or from command line

## Quick Start

**Requirements:** Binary Ninja must be in your PATH, or place `bnsql.exe` in your Binary Ninja installation folder.

```bash
# Windows: Add BN to PATH
set PATH=C:\Program Files\Vector35\BinaryNinja;%PATH%

# Or copy bnsql.exe to BN folder
copy bnsql.exe "C:\Program Files\Vector35\BinaryNinja\"
```

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

### For LLM/AI Agent Integration

If you're building an AI agent or tool that needs to query Binary Ninja databases, use the **HTTP REST server**:

```bash
# Start HTTP server
bnsql database.bndb --http 8080

# Query from your agent (simple curl)
curl -X POST http://localhost:8080/query -d "SELECT name, size FROM funcs LIMIT 10"
```

See [Server Modes](#server-modes) for full HTTP API documentation, authentication, and MCP protocol support.

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
║      sub_140013350        ║
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

### Security Audit

```
bnsql database.bndb --prompt "What dangerous APIs does this binary use? Rate the risk."
```

Output:
```
## Dangerous/Suspicious API Analysis

### Summary: Low Risk Binary

| Category | API | Module | Risk Level |
|----------|-----|--------|------------|
| Anti-Debugging | IsDebuggerPresent | KERNEL32 | Medium |
| Process Termination | TerminateProcess | KERNEL32 | Medium |

### What's NOT Present (Good Signs):

| Category | Missing APIs |
|----------|--------------|
| Shell Execution | No ShellExecute, WinExec, CreateProcess |
| Code Injection | No VirtualAlloc, WriteProcessMemory |
| Networking | No sockets, HTTP, or internet APIs |

Verdict: This binary does not appear to contain dangerous API usage patterns.
```

### Decompilation Analysis

```
bnsql database.bndb --prompt "Decompile main and explain what it does step by step"
```

Output:
```
## Main Function Analysis (5,682 bytes)

int32_t main(int32_t argc, char** argv, char** envp)
{
    if (argc != 2) {
        printf("Usage: %s <path_to_bndb_or_binary>
", *argv);
        return 1;
    }

    BNSetBundledPluginDirectory(pluginPath);
    BNInitPlugins(true);

    Ref<BinaryView> bv = BNOpenExistingDatabase(argv[1]);
    // ... enumerate functions, strings, imports ...
}

| Step | Action | Code Pattern |
|------|--------|--------------|
| 1 | Validate args | if (argc != 2) -> print usage |
| 2 | Init BN runtime | BNInitPlugins |
| 3 | Load binary | Try .bndb first, fall back to raw |
| 4 | Enumerate | Print functions, strings, imports |
```

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
| `save()` | Save database to disk |

## CLI Reference

### Modes

```bash
# Interactive SQL mode (default)
bnsql database.bndb

# One-shot SQL query
bnsql database.bndb -c "SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10"

# Execute SQL file
bnsql database.bndb -f queries.sql

# Interactive agent mode (natural language)
bnsql database.bndb --agent

# One-shot natural language query
bnsql database.bndb --prompt "Find the largest functions and show their callers"
```

### Prerequisites for AI Features

The natural language features require one of these CLI tools installed and authenticated:

| Provider | CLI Tool | Install | Login |
|----------|----------|---------|-------|
| Claude (default) | [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm install -g @anthropic-ai/claude-code` | Run `claude`, then `/login` |
| GitHub Copilot | [Copilot CLI](https://github.com/features/copilot/cli/) | `npm install -g @github/copilot` | Run `copilot`, then `/login` |

**Important:** You must be logged in before using AI features.

### AI Provider Settings

Switch between AI providers and configure BYOK (Bring Your Own Key):

```bash
# Use Claude (default)
bnsql database.bndb --provider claude --prompt "What does this binary do?"

# Use GitHub Copilot
bnsql database.bndb --provider copilot --prompt "Find suspicious API calls"

# View all settings
bnsql --config

# Set default provider
bnsql --config agent.provider copilot

# Set response timeout (milliseconds)
bnsql --config agent.timeout 120000
```

### BYOK Configuration

Use your own API key instead of Claude Code or Copilot CLI:

```bash
# Enable BYOK for Claude
bnsql --config agent.byok.claude.enabled true
bnsql --config agent.byok.claude.key sk-ant-api03-...

# Enable BYOK for Copilot with Azure OpenAI
bnsql --config agent.byok.copilot.enabled true
bnsql --config agent.byok.copilot.key your-api-key
bnsql --config agent.byok.copilot.endpoint https://your-resource.openai.azure.com
bnsql --config agent.byok.copilot.model gpt-4
bnsql --config agent.byok.copilot.type azure
```

### Interactive Commands

In agent mode, use dot commands:

```
agent> .help               Show help
agent> .agent provider     Show/set provider
agent> .agent byok         Show BYOK status
agent> .tables             List tables
agent> .schema funcs       Show table schema
agent> .clear              Clear conversation
agent> .sql                Switch to SQL mode
agent> .quit               Exit
```

## Server Modes

BNSQL supports two server protocols: **HTTP REST** (recommended) and raw TCP.

### HTTP REST Server (Recommended)

Standard REST API that works with curl, Postman, and any HTTP client:

```bash
# Start HTTP server (default port 8080)
bnsql database.bndb --http

# Custom port and bind address
bnsql database.bndb --http 9000 --bind 0.0.0.0

# With authentication
bnsql database.bndb --http 8080 --token mysecret
```

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/help` | GET | API documentation (for LLM discovery) |
| `/query` | POST | Execute SQL (body = raw SQL) |
| `/status` | GET | Health check |
| `/shutdown` | POST | Stop server |

**Example with curl:**

```bash
# Get API help
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

**Response Format:**
```json
{"success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1}
```

### MCP Server (Model Context Protocol)

For integration with Claude Desktop, Cursor, and other MCP-compatible AI tools:

```bash
# Start MCP server (default port 9998)
bnsql database.bndb --mcp

# Custom port
bnsql database.bndb --mcp 9999
```

**MCP Tools Exposed:**

| Tool | Description |
|------|-------------|
| `query` | Execute SQL query, returns JSON results |
| `ask` | Natural language query (uses AI agent) |

**Usage:** Start the MCP server, then configure your MCP client to connect to `http://localhost:9998/sse`.

The server uses HTTP/SSE transport. For Claude Desktop or other MCP clients, add the server URL to your MCP configuration after starting bnsql.

### Building with HTTP Support

HTTP mode requires the thinclient component:

```bash
cmake -B build -DBNSQL_WITH_HTTP=ON ...
```

The server can also be started from the Binary Ninja plugin:
- Menu: `BNSQL > HTTP Server > Start HTTP Server...`

## Building

```bash
cmake -B build -DBUILD_WITH_BNSQL=ON \
      -DBN_INSTALL_DIR=/path/to/binaryninja \
      -DBNSQL_WITH_AI_AGENT=ON
cmake --build build --config Release

# Optional: build the Binary Ninja UI plugin
cmake -B build -DBNSQL_BUILD_PLUGIN=ON ...
```

## AI Agent Prompt

For standalone AI agents (Claude, etc.), use the comprehensive agent prompt:

- [`prompts/bnsql_agent.md`](prompts/bnsql_agent.md) - Complete reference for tables, functions, and query patterns


## Performance Tips

1. **Instructions table**: Always filter by `func_addr` - never scan full table
2. **Xref counting**: Use CTEs to pre-aggregate, not correlated subqueries
3. **Pre-analyzed databases**: ~5s startup vs 15s+ for fresh analysis

## Library Examples

Use BNSQL as a library in your own C++ tools. See [`examples/`](examples/) for complete code:

```cpp
#include <bnsql/bnsql.hpp>

int main(int argc, char* argv[]) {
    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

    // Load binary (auto-creates .bndb if needed)
    auto loaded = bnsql::loader::load_binary("program.exe");
    if (!loaded) return 1;

    // Create SQL query engine
    bnsql::QueryEngine qe(loaded.bv);

    // Get single value
    std::string count = qe.scalar("SELECT COUNT(*) FROM funcs");

    // Query with results
    auto result = qe.query("SELECT name, size FROM funcs ORDER BY size DESC LIMIT 5");
    for (const auto& row : result) {
        std::cout << row[0] << ": " << row[1] << " bytes\n";
    }
}
```

### Available Examples

| Example | Description |
|---------|-------------|
| `example_basic.cpp` | QueryEngine basics, scalar queries, iteration |
| `example_functions.cpp` | Function analysis, xrefs, call graphs |
| `example_strings.cpp` | String searching, pattern matching, statistics |
| `example_decompiler.cpp` | HLIL analysis, pseudocode, variables, calls |

Build examples:
```bash
cd examples
cmake -B build -DBN_INSTALL_DIR=/path/to/binaryninja
cmake --build build --config Release
```

## Screenshots

<table>
<tr>
<td><a href="assets/bnsql_interactive_agent.jpg"><img src="assets/bnsql_interactive_agent.jpg" width="400"/></a></td>
<td><a href="assets/bnsql_hlil.jpg"><img src="assets/bnsql_hlil.jpg" width="400"/></a></td>
</tr>
<tr>
<td><a href="assets/bnsql_imports.jpg"><img src="assets/bnsql_imports.jpg" width="400"/></a></td>
<td><a href="assets/bnsql_main_calls.jpg"><img src="assets/bnsql_main_calls.jpg" width="400"/></a></td>
</tr>
<tr>
<td><a href="assets/bnsql_getversion.jpg"><img src="assets/bnsql_getversion.jpg" width="400"/></a></td>
<td><a href="assets/bnsql_busy.jpg"><img src="assets/bnsql_busy.jpg" width="400"/></a></td>
</tr>
</table>

## Claude Code Plugin

BNSQL is available as a Claude Code plugin, allowing Claude to query Binary Ninja databases directly within your coding workflow.

### Prerequisites

1. **Binary Ninja** installed with its DLL directory in your PATH
2. **bnsql.exe** in your PATH
3. Verify setup: `bnsql --version` should work from command line

### Installation

```bash
# Add the marketplace (one-time)
/plugin marketplace add 0xeb/anthropic-xsql-tools-plugin

# Install bnsql plugin
/plugin install bnsql@0xeb-tools
```

### Usage

Once installed, the skill is automatically available:

```
"Using bnsql, count functions in malware.bndb"
"Using bnsql, find strings containing 'error' in malware.bndb"
```

### Updating

```bash
/plugin update bnsql
```

## Author

Elias Bachaalany ([@0xeb](https://github.com/0xeb))

## License

MIT License - Copyright (c) 2025 Elias Bachaalany
