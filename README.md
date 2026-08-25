# Cybergrok

Autonomous offensive security, bug bounty, and red-teaming **plugin for [Grok Build](https://docs.x.ai/build/overview)**.

Cybergrok is an autonomous offensive-security agent for **Grok Build**: 200+ hunt playbooks, a token-efficient recon pipeline, and structured reporting.

The native engine is **Python + TypeScript** (no Go):

| Layer | Language | Role |
| :--- | :--- | :--- |
| Grok Build | — | Agent runtime (`grok` CLI / TUI) |
| Plugin | Markdown + hooks | Skills, agents, slash commands |
| Core tools | **Python** | `smart_pipe`, `secret_scan`, `search_knowledge`, `aggregate_reports`, recon/probe/scope |
| MCP server | **TypeScript** | `cybergrok-mcp` — 10 tools + 2 prompts over stdio |

---

## What it does

Six-phase assessment on an authorized target:

1. **Passive recon** — subdomains, historical URLs  
2. **Active probe** — live hosts, tech fingerprint, crawl  
3. **Skill execution** — 200+ SOP playbooks (`skills/hunt-idor`, `hunt-xss`, …)  
4. **Zero-false-positive PoC** — HTTP proof before anything is “confirmed”  
5. **Secret mining** — 48-pattern scanner on JS/dumps  
6. **Reporting** — `SUMMARY.md`, `metadata.json`, HTML/PDF  

Findings require raw request/response (or a differential). INFO noise goes to `evidence/recon_notes.md`, not `findings/`.

---

## Install as a Grok Build plugin

```bash
git clone <this-repo> Cybergrok
cd Cybergrok
./setup.sh                 # venv, TS build, optional grok plugin install --trust

# From another workspace, after install + enable in /plugins:
#   grok --agent cybergrok:Cybergrok
# or copy .grok/agents/cybergrok.md to ~/.grok/agents/
```

Or work inside this checkout:

```bash
# add the host to scope.yaml first (fail-closed allowlist)
./cybergrok          # grok --agent .grok/agents/cybergrok.md --trust
# then:
/assess https://in-scope.example
/recon  https://in-scope.example
/cybergrok-hunt https://in-scope.example idor
/report example_com
/cybergrok-doctor
```

`./cybergrok` selects the **Cybergrok session agent**. Project plugins/hooks/MCP need folder trust (`--trust` / `/hooks-trust`). A model-chosen URL is not in scope until you add it to `scope.yaml`.

The plugin ships:

- **Skills** — `skills/` playbooks plus `cybergrok-assess`  
- **Agents** — `Cybergrok`, `recon-scout`, `vuln-hunter`, `reporter`  
- **Commands** — `/assess` `/recon` `/cybergrok-hunt` `/report` `/cybergrok-doctor`  
- **Hooks** — session workspace prep + destructive-shell deny  
- **MCP** — `.mcp.json` → `mcp/launch.cjs` → TypeScript server → Python RPC  

---

## Toolchain

After `./setup.sh`:

| Command | Implementation |
| :--- | :--- |
| `smart_pipe` | Python — filter recon stdout, archive raw log |
| `secret_scan` | Python — 48-pattern credential miner |
| `search_knowledge` | Python — offline KB search |
| `aggregate_reports` | Python — SUMMARY.md + metadata.json |
| `cybergrok-mcp` | TypeScript MCP (calls Python) |
| `subfinder` `httpx` `katana` `nuclei` | Downloaded by `tools/update_tools.sh` when available |

```bash
subfinder -d example.com -silent | smart_pipe --target example_com --tool subfinder
python3 -m cybergrok search "jwt none algorithm" --limit 3
aggregate_reports example_com
python3 tools/generate_pdf.py example_com
```

sqlmap / dalfox / nmap are **optional host tools**. They are not vendored here.

---

## Architecture

```
Operator ──► Grok Build (Cybergrok agent)
                 │
                 ├─ skills/ + AGENTS.md
                 ├─ spawn recon-scout / vuln-hunter / reporter
                 │
                 ├─ Python CLIs (PATH)
                 └─ TypeScript MCP
                        └── python -m cybergrok rpc {op, args}
```

Deliverables:

```
reports/<slug>/
├── SUMMARY.md
├── metadata.json
├── findings/          # confirmed low|medium|high|critical
├── pocs/
└── evidence/
```

---

## Development

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
./lint.sh
./typecheck.sh
./test.sh

cd mcp && npm install && npm run build
```

Legal use only: authorized assessments, bug-bounty programs you are invited to, and your own systems. See `scope.yaml` and `AGENTS.md`.

This repository credits methodology and knowledge sources in `ATTRIBUTION.md` (HackTricks, PayloadsAllTheThings, ProjectDiscovery, and others).
