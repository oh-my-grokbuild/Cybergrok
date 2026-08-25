# 🔌 Cybergrok MCP Server — Universal AI Client Setup & Integration Guide

The **Cybergrok MCP Server** implements the official **Model Context Protocol (MCP) JSON-RPC 2.0** standard over `stdio` transport. It is **100% Provider-Agnostic and Model-Agnostic** — compatible with any AI foundation model (**Claude 3.7/3.5, GPT-4o/o3, DeepSeek R1/V3, Gemini 2.0/1.5 Pro, Llama 3.3, Qwen 2.5 Coder**) and any MCP-enabled client (**OpenCode, Cursor, Claude Desktop, Windsurf, Cline, Roo Code, Claude Code, Continue.dev, Zed, Kilo, Grok Build, Codex**, etc.).

---

## 🚀 Method 0: 1-Click Universal Auto-Installer (Recommended)

Cybergrok includes an intelligent, non-destructive **Universal Auto-Injector** that automatically detects your installed AI clients across **Windows, macOS, and Linux**, creates timestamped backups of your configurations (`.bak`), and cleanly wires Cybergrok into all of them.

### Local repository setup
```bash
./setup.sh
# project MCP: node mcp/launch.cjs  (cwd = this checkout)
# installed plugin MCP: ${GROK_PLUGIN_ROOT}/mcp/launch.cjs
```

There is no published `npx cybergrok-mcp` package. Use `mcp/launch.cjs` or `scripts/cybergrok-mcp.sh`.

### Or via Local Repository Setup:
```bash
python scripts/setup_mcp.py
```

### Auto-Installer Options:
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--dry-run` | Preview configuration changes without touching disk | `python scripts/setup_mcp.py --dry-run` |
| `--status` | Display discovery matrix & wiring status for all AI clients | `python scripts/setup_mcp.py --status` |
| `--local` | Wire directly to `mcp/launch.cjs` | `python scripts/setup_mcp.py --local` |
| `--clients=` | Target specific clients (comma-separated) | `python scripts/setup_mcp.py --clients=cursor,claude-desktop` |
| `--uninstall`| Cleanly remove Cybergrok from all client configs | `python scripts/setup_mcp.py --uninstall` |
| `--force` | Generate config files even if AI client is not yet detected | `python scripts/setup_mcp.py --force` |

---

## ⚡ Method 1: Manual stdio launch

```bash
node mcp/launch.cjs
# or
bash scripts/cybergrok-mcp.sh
```

---

### 1. OpenCode Interpreter / OpenCode CLI
Add to your OpenCode configuration (`opencode.json` or `~/.config/opencode/config.json`):

```json
{
  "mcp_servers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 2. Kilo Code / Kilo AI (VS Code Extension / Agent)
In **Kilo MCP Settings** or in `.kilo/mcp.json`:

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 3. Cursor IDE
1. Open **Cursor Settings** (`Ctrl + Shift + J` / `Cmd + Shift + J`) -> **Features** -> **MCP Servers**.
2. Click **+ Add New MCP Server**.
3. Configure:
   - **Name**: `cybergrok`
   - **Type**: `command`
   - **Command**: `node mcp/launch.cjs`

Or add `.cursor/mcp.json` to your project workspace root:
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 4. Claude Desktop
Add to your `claude_desktop_config.json`:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 5. Windsurf IDE (Codeium)
Add to `~/.codeium/windsurf/mcp_config.json` or workspace `mcp_config.json`:

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 6. Cline & Roo Code (VS Code Extensions)
Open the MCP Servers extension tab, select **Edit Settings**, and add:

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"],
      "disabled": false,
      "autoApprove": [
        "cybergrok_search_knowledge",
        "cybergrok_list_skills",
        "cybergrok_get_skill",
        "cybergrok_scan_secrets",
        "cybergrok_validate_scope"
      ]
    }
  }
}
```

---

### 7. Continue.dev (VS Code / JetBrains)
Add to `~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "cybergrok",
        "transport": {
          "type": "stdio",
          "command": "node",
          "args": ["mcp/launch.cjs"]
        }
      }
    ]
  }
}
```

---

### 8. Zed Editor
Add to `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 9. Claude Code CLI (`claude mcp`)
Run via CLI or add to `~/.claude.json`:

```bash
claude mcp add cybergrok node -- mcp/launch.cjs
```
Or in `~/.claude.json`:
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

### 10. Grok Build
Add to `~/.grok/config.yaml` or `.grok/config.yaml`:

```yaml
mcp_servers:
  cybergrok:
    command: "node"
    args: ["mcp/launch.cjs"]
```

---

### 11. Codex CLI
Add to `~/.codex/config.toml`:

```toml
[mcp_servers.cybergrok]
command = "node"
args = ["mcp/launch.cjs"]
```

---

### 12. Google Antigravity & Gemini Assistants
Add to your Antigravity MCP settings or configuration JSON:

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["mcp/launch.cjs"]
    }
  }
}
```

---

## 🛠️ Method 2: Absolute path to launch.cjs (offline / air-gapped)

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "node",
      "args": ["C:\\\\path\\\\to\\\\Cybergrok\\\\mcp\\\\launch.cjs"]
    }
  }
}
```

### 3. Configure Client (Linux/macOS Example)
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "/path/to/Cybergrok/tools/bin/cybergrok-mcp",
      "args": ["-workspace", "/path/to/Cybergrok"]
    }
  }
}
```

---

## 🧰 Available Capabilities Summary (10 Native Tools + 2 Resources + 2 Prompts)

| Type | Name | Purpose |
| :--- | :--- | :--- |
| **Tool** | `cybergrok_validate_scope` | Scope Guard: Target evaluation against `scope.yaml` (Wildcard, CIDR, Exclude rules). |
| **Tool** | `cybergrok_http_probe` | HTTP inspection, TLS certificate extraction, and framework fingerprinting. |
| **Tool** | `cybergrok_recon_crawl` | Endpoint discovery & JS bundle mining with Smart Pipe token budgeting. |
| **Tool** | `cybergrok_search_knowledge`| Sub-50ms query against 50,000+ curated payloads (PayloadsAllTheThings, HackTricks, Strix). |
| **Tool** | `cybergrok_list_skills` | Catalog and filter 200+ offensive security playbooks. |
| **Tool** | `cybergrok_get_skill` | Read complete offensive playbook SOPs or specific section headings. |
| **Tool** | `cybergrok_scan_secrets` | 48-pattern credential leak detector with automated masking. |
| **Tool** | `cybergrok_record_finding` | Record verified findings to `reports/<target>/findings/` and generate PoCs. |
| **Tool** | `cybergrok_aggregate_report` | Executive summary generator (`SUMMARY.md` & `metadata.json`). |
| **Tool** | `cybergrok_list_findings` | List confirmed findings and severity breakdown per target. |
| **Resource** | `skills://{skill_name}` | Direct read-only URI access to offensive playbook SOPs. |
| **Resource** | `reports://{target_slug}/summary` | Direct read-only URI access to executive engagement summaries. |
| **Prompt** | `cybergrok_hunt` & `cybergrok_triage` | Zero-false-positive reasoning workflow templates for AI agents. |

---

## 🧪 Verification & Health Check

After saving the configuration and restarting your AI client:
1. In your AI client chat, ask:
   > *"List all available Cybergrok MCP tools and search the knowledge base for 'JWT algorithm confusion'."*
2. The AI model will execute `cybergrok_search_knowledge` and return validated payload snippets with zero latency.
