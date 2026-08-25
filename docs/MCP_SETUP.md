# 🔌 Cybergrok MCP Server — Universal AI Client Setup & Integration Guide

The **Cybergrok MCP Server** implements the official **Model Context Protocol (MCP) JSON-RPC 2.0** standard over `stdio` transport. It is **100% Provider-Agnostic and Model-Agnostic** — compatible with any AI foundation model (**Claude 3.7/3.5, GPT-4o/o3, DeepSeek R1/V3, Gemini 2.0/1.5 Pro, Llama 3.3, Qwen 2.5 Coder**) and any MCP-enabled client (**OpenCode, Cursor, Claude Desktop, Windsurf, Cline, Roo Code, Claude Code, Continue.dev, Zed, Kilo, Grok Build, Codex**, etc.).

---

## 🚀 Method 0: 1-Click Universal Auto-Installer (Recommended)

Cybergrok includes an intelligent, non-destructive **Universal Auto-Injector** that automatically detects your installed AI clients across **Windows, macOS, and Linux**, creates timestamped backups of your configurations (`.bak`), and cleanly wires Cybergrok into all of them.

### Instant Global Installation (Zero-Go NPX)
```bash
npx -y cybergrok-mcp install
```

### Or via Local Repository Setup:
```bash
python scripts/setup_mcp.py
```

### Auto-Installer Options:
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--dry-run` | Preview configuration changes without touching disk | `npx cybergrok-mcp install --dry-run` |
| `--status` | Display discovery matrix & wiring status for all AI clients | `npx cybergrok-mcp status` |
| `--local` | Wire directly to local compiled binary (`tools/bin/cybergrok-mcp`) | `python scripts/setup_mcp.py --local` |
| `--clients=` | Target specific clients (comma-separated) | `npx cybergrok-mcp install --clients=cursor,claude-desktop` |
| `--uninstall`| Cleanly remove Cybergrok from all client configs | `npx cybergrok-mcp uninstall` |
| `--force` | Generate config files even if AI client is not yet detected | `npx cybergrok-mcp install --force` |

---

## ⚡ Method 1: Manual Zero-Go NPX Setup (Instant)

If you prefer manual configuration, Node.js (v18+) automatically downloads the verified binary from GitHub Releases:

```bash
npx -y cybergrok-mcp
```

---

### 1. OpenCode Interpreter / OpenCode CLI
Add to your OpenCode configuration (`opencode.json` or `~/.config/opencode/config.json`):

```json
{
  "mcp_servers": {
    "cybergrok": {
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
   - **Command**: `npx -y cybergrok-mcp`

Or add `.cursor/mcp.json` to your project workspace root:
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"],
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
          "command": "npx",
          "args": ["-y", "cybergrok-mcp"]
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
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
    }
  }
}
```

---

### 9. Claude Code CLI (`claude mcp`)
Run via CLI or add to `~/.claude.json`:

```bash
claude mcp add cybergrok npx -- -y cybergrok-mcp
```
Or in `~/.claude.json`:
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
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
    command: "npx"
    args: ["-y", "cybergrok-mcp"]
```

---

### 11. Codex CLI
Add to `~/.codex/config.toml`:

```toml
[mcp_servers.cybergrok]
command = "npx"
args = ["-y", "cybergrok-mcp"]
```

---

### 12. Google Antigravity & Gemini Assistants
Add to your Antigravity MCP settings or configuration JSON:

```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "npx",
      "args": ["-y", "cybergrok-mcp"]
    }
  }
}
```

---

## 🛠️ Method 2: Direct Native Go Binary (Offline / Air-Gapped / Enterprise)

If you have cloned the Cybergrok repository or want to run the native pre-compiled Go binary directly without Node.js/npx:

### 1. Build Local Binary
```bash
go build -o tools/bin/cybergrok-mcp.exe ./cmd/cybergrok-mcp
```

### 2. Configure Client with Absolute Path (Windows Example)
```json
{
  "mcpServers": {
    "cybergrok": {
      "command": "C:\\path\\to\\Cybergrok\\tools\\bin\\cybergrok-mcp.exe",
      "args": ["-workspace", "C:\\path\\to\\Cybergrok"]
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
