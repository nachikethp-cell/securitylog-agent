[README.md](https://github.com/user-attachments/files/27559552/README.md)
# securitylog-agent

An agentic tool that runs natural-language security queries against OCI Audit logs stored in an Oracle Autonomous Database (ADB). The agent uses an LLM to translate security questions into SQL, execute them via SQLcl MCP, and return formatted answers — no manual SQL required. This agent can be extended to run queries on other security logs

## How it works

The agent runs in two stages:

1. **Profile load** — feeds the audit log schema and workflow instructions to the LLM and stores them in an MCP memory server so subsequent queries can retrieve them.
2. **Query execution** — for each security query, the LLM retrieves the profile from memory, constructs a SQL query against the audit log table, executes it via the SQLcl MCP server, and formats the results.

```
securitylog_agent.py
    │
    ├── OCI API MCP server  (oracle.oci-api-mcp-server via uvx)  ← OCI resource lookups
    ├── SQLcl MCP server    (oracle.sqlcl via sql -mcp)           ← SQL execution on ADB
    └── MCP Memory server   (@modelcontextprotocol/server-memory) ← audit profile store
```

## Example queries

The default queries in `securitylog_agent.py` demonstrate what the agent can answer:

| Query | What it does |
|-------|-------------|
| List tables | Discovers which `AUDIT_LOGS_*` tables exist in the ADB instance |
| IP addresses | Lists all source IP addresses seen in audit events |
| Identity principals | Lists all users and service principals that generated audit events |

Add your own entries to the `security_prompts` dict to ask anything the audit log schema supports — failed logins, resource deletions, privilege escalations, etc.

## Audit log data

OCI Audit logs must be exported to an ADB instance before running the agent. The agent expects:

- Tables named `AUDIT_LOGS_*` in the ADB schema
- A SQLcl named connection called `oci_adb` (see [ADB setup](#adb-setup) below)
- The full table schema is documented in `schema.txt`

Key audit log fields used in queries:

| Field | Description |
|-------|-------------|
| `CE_TIME` | Event timestamp |
| `EVENTNAME` | OCI API operation name |
| `IDENTITY_PRINCIPALNAME` | User or service that triggered the event |
| `IDENTITY_IPADDRESS` | Source IP address |
| `COMPARTMENTNAME` | OCI compartment of the resource |
| `RESPONSE_STATUS` | HTTP status code of the API call |

## Project structure

```
adb_mcp/
├── securitylog_agent.py     # Main agent entry point
├── llm_functions.py         # Helper functions for printing LLM responses and token usage
|-- oci_audit_parser.py      # Transforms OCI Audit log nested JSON to filtered and normalized format 
└── .env                     # Environment variables (not committed)
```

## Prerequisites

- Python 3.13+
- [Oracle SQLcl](https://www.oracle.com/database/sqldeveloper/technologies/sqlcl/) with MCP support (`sql -mcp`)
- ADB wallet files for your Autonomous Database instance
- [uvx](https://docs.astral.sh/uv/) for running the OCI MCP server
- [npx](https://docs.npmjs.com/cli/v8/commands/npx) for running the MCP memory server
- Anthropic and/or OpenAI API keys

## Installation

```bash
# Create and activate virtual environment
python3.13 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install aisuite
pip install 'aisuite[anthropic]'
pip install 'aisuite[openai]'
pip install 'aisuite[mcp]'
pip install python-dotenv
```

## ADB setup

The agent connects to ADB using a SQLcl named connection. Set this up once before running:

**1. Note the ADB TNS NAME and connection string**. Download the ADB wallet and get the tnsnames.ora file

**2. Start SQLcl** with `TNS_ADMIN` set to the location of tnsnames.ora file:

```bash
export TNS_ADMIN=/path/to/tnsnames
sql /nolog
```

**3. Save a named connection** (replace with your credentials and TNS name). Below use 'oci_adb' for the CONNECTION_NAME:

```sql
conn -savepwd -save CONNECTION_NAME <username>/<password>@<TNS_NAME>
```

**4. Verify** the connection was saved:

```sql
connmgr list
```

The agent uses the connection name `oci_adb` — update `securitylog_agent.py` if you use a different name.

## Configuration

Create a `.env` file:

```bash
# Required: LLM API keys
ANTHROPIC_API_KEY=your_anthropic_key
OPENAI_API_KEY=your_openai_key

# Required: path to ADB wallet directory (used as TNS_ADMIN)
TNS_PATH=/path/to/tnsnames

# Optional: tool paths (defaults to PATH lookup)
UVX_PATH=uvx
SQL_PATH=sql
```

## Usage

```bash
source .venv/bin/activate
python securitylog_agent.py
```

The agent will:
1. Connect to the OCI API, SQLcl, and memory MCP servers
2. Load the audit log schema and workflow into memory
3. Run each query in `security_prompts`, printing colour-coded SQL and results
4. Print token usage after each step
5. Close all MCP connections on exit (even if a query fails)

## Models

The agent defaults to `claude-sonnet-4-6`. To switch to GPT-4.1, change `models[0]` to `models[1]` in `securitylog_agent.py`:

```python
models = ["anthropic:claude-sonnet-4-6", "openai:gpt-4.1"]
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `aisuite` | Multi-LLM abstraction and MCP client |
| `anthropic` | Claude API |
| `openai` | OpenAI API |
| `mcp` | Model Context Protocol |
| `python-dotenv` | `.env` file loading |
