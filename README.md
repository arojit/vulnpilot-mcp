<p align="center">
  <h1 align="center">🛡️ VulnPilot</h1>
  <p align="center">
    <strong>An MCP server that gives AI assistants the ability to check open-source packages for known vulnerabilities - powered by the <a href="https://osv.dev">OSV</a> database.</strong>
  </p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> · <a href="#how-it-works">How It Works</a> · <a href="#tool-reference">Tool Reference</a> · <a href="#development">Development</a>
  </p>
</p>

---

## Why VulnPilot?

Modern AI coding assistants can write, refactor, and review code - but they're blind to the security posture of the dependencies they recommend. VulnPilot bridges that gap.

By exposing a single, focused [Model Context Protocol (MCP)](https://modelcontextprotocol.io) tool, VulnPilot lets any MCP-compatible client - Claude Desktop, Cursor, VS Code Copilot, and others - query the [OSV.dev](https://osv.dev) vulnerability database in real time before suggesting a dependency.

**No API keys. No configuration files. Just install and connect.**

---

## Quickstart

### Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.10 |
| [uv](https://docs.astral.sh/uv/) | latest (recommended) |

### Install

```bash
# Clone the repository
git clone https://github.com/arojit/vulnpilot-mcp.git
cd vulnpilot-mcp

# Create the virtual environment and install dependencies
uv sync
```

### Run

```bash
# Start the server (STDIO transport)
uv run vulnpilot-mcp
```

The server launches on **STDIO**, ready to be connected to any MCP client.

---

## Connecting to MCP Clients

Add VulnPilot to your client's MCP configuration:

<details>
<summary><strong>Claude Desktop</strong></summary>

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulnpilot": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/vulnpilot-mcp",
        "run", "vulnpilot-mcp"
      ]
    }
  }
}
```

</details>

<details>
<summary><strong>Cursor</strong></summary>

Add to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vulnpilot": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/vulnpilot-mcp",
        "run", "vulnpilot-mcp"
      ]
    }
  }
}
```

</details>

<details>
<summary><strong>VS Code / Copilot</strong></summary>

Add to your `.vscode/mcp.json`:

```json
{
  "servers": {
    "vulnpilot": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/vulnpilot-mcp",
        "run", "vulnpilot-mcp"
      ]
    }
  }
}
```

</details>

> **Note:** Replace `/absolute/path/to/vulnpilot-mcp` with the actual path where you cloned the repository.

---

## How It Works

```
┌──────────────┐       STDIO        ┌──────────────┐      HTTPS       ┌───────────┐
│  MCP Client  │ ◄──────────────► │  VulnPilot   │ ──────────────► │  OSV.dev  │
│  (Claude,    │   MCP Protocol     │  MCP Server  │   REST API       │  Database │
│   Cursor…)   │                    └──────────────┘                  └───────────┘
└──────────────┘
```

1. Your AI assistant decides it needs to verify a dependency.
2. It calls the `check_package` tool via the MCP protocol.
3. VulnPilot queries the [OSV API](https://osv.dev/docs/) and returns a structured result.
4. The assistant uses the response to inform its recommendation.

---

## Tool Reference

### `check_package`

Check a specific package version for known vulnerabilities.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `package_name` | `string` | *required* | Package name (e.g. `django`, `lodash`, `org.apache.logging.log4j:log4j-core`) |
| `version` | `string` | *required* | Exact version to check (e.g. `2.2.0`) |
| `ecosystem` | `string` | `"PyPI"` | One of `PyPI`, `npm`, `Maven`, or `Gradle` |

> **Maven & Gradle:** Use the `groupId:artifactId` format for package names (e.g. `org.apache.logging.log4j:log4j-core`). Gradle packages are queried against the Maven ecosystem in OSV.

#### Example Request

```
Check django version 2.2.0 for vulnerabilities
```

#### Example Response

```json
{
  "package_name": "django",
  "version": "2.2.0",
  "ecosystem": "PyPI",
  "vulnerable": true,
  "vulnerability_count": 1,
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-yyyy-zzzz",
      "summary": "Django SQL injection vulnerability",
      "aliases": ["CVE-2024-XXXXX"],
      "severity": "HIGH",
      "fixed_versions": ["2.2.10"],
      "references": ["https://github.com/advisories/..."]
    }
  ]
}
```

### Response Schema

| Field | Type | Description |
|---|---|---|
| `package_name` | `string` | The queried package name |
| `version` | `string` | The queried version |
| `ecosystem` | `string` | The ecosystem used for the query |
| `vulnerable` | `boolean` | `true` if any vulnerabilities were found |
| `vulnerability_count` | `integer` | Number of known vulnerabilities |
| `vulnerabilities` | `array` | List of vulnerability objects |

Each **vulnerability** contains:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Vulnerability identifier (e.g. `GHSA-…`, `PYSEC-…`) |
| `summary` | `string` | Human-readable description |
| `aliases` | `string[]` | Cross-references (e.g. CVE IDs) |
| `severity` | `string \| null` | Severity level when available |
| `fixed_versions` | `string[]` | Versions that resolve the issue |
| `references` | `string[]` | Links to advisories and patches |

---

## Supported Ecosystems

| Ecosystem | Package Name Format | Example |
|---|---|---|
| **PyPI** | `package-name` | `django` |
| **npm** | `package-name` | `lodash` |
| **Maven** | `groupId:artifactId` | `org.apache.logging.log4j:log4j-core` |
| **Gradle** | `groupId:artifactId` | `com.google.guava:guava` |

---

## Development

### Setup

```bash
# Install all dependencies including dev tools
uv sync --all-groups
```

### Running Tests

```bash
uv run pytest
```

### MCP Inspector

Launch the interactive [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) to test and debug the server in your browser:

```bash
uv run mcp dev src/vulnpilot/server.py
```

### Project Structure

```
vulnpilot-mcp/
├── src/vulnpilot/
│   ├── __init__.py        # Package marker
│   ├── server.py          # MCP server & tool definitions
│   ├── models.py          # Pydantic response models
│   └── osv_client.py      # OSV API client & response normalizer
├── tests/
│   └── test_server.py     # Test suite
├── pyproject.toml         # Project metadata & dependencies
└── README.md
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| MCP Framework | [FastMCP](https://github.com/modelcontextprotocol/python-sdk) (`mcp[cli]`) |
| Data Validation | [Pydantic v2](https://docs.pydantic.dev) |
| HTTP Client | [httpx](https://www.python-httpx.org) |
| Vulnerability Data | [OSV.dev API](https://osv.dev) |
| Build System | [Hatchling](https://hatch.pypa.io) |
| Package Manager | [uv](https://docs.astral.sh/uv/) |
| Testing | [pytest](https://docs.pytest.org) + [pytest-asyncio](https://pytest-asyncio.readthedocs.io) |

---

## License

This project is currently unlicensed. See the repository for updates.
