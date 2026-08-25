#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GROK_HOME="${GROK_HOME:-$HOME/.grok}"
AGENTS=(cybergrok recon-scout vuln-hunter reporter)

echo "========================================================"
echo "  Cybergrok setup (Grok Build + Python)"
echo "========================================================"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3.14+ is required."
    exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 14) else 1)'; then
    echo "Error: Python 3.14+ is required (found $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'))."
    exit 1
fi

mkdir -p "$ROOT"/{reports,recon,output,logs,targets,tools/bin}

install_grok_agents() {
    local src="$ROOT/agents"
    local dest="$1"
    local label="$2"
    mkdir -p "$dest"
    local name
    for name in "${AGENTS[@]}"; do
        if [ ! -f "$src/${name}.md" ]; then
            echo "  missing agents/${name}.md" >&2
            return 1
        fi
        cp "$src/${name}.md" "$dest/${name}.md"
        echo "  ${label}: ${dest}/${name}.md"
    done
}

link_plugin_tree() {
    local plugin="$ROOT/.grok/plugins/cybergrok"
    mkdir -p "$plugin"
    cp "$ROOT/plugin.json" "$plugin/plugin.json"
    local name
    for name in agents commands hooks skills scripts python AGENTS.md knowledge templates; do
        ln -sfn "../../../${name}" "$plugin/${name}"
    done
}

stage_plugin_package() {
    # Slim tree for `grok plugin install` — no .git, venv, .env, or engagement data.
    local stage="$ROOT/.grok/plugin-stage"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$ROOT/plugin.json" "$stage/plugin.json"
    local name
    for name in agents commands hooks skills scripts python AGENTS.md knowledge templates; do
        if [ -e "$ROOT/$name" ]; then
            cp -a "$ROOT/$name" "$stage/$name"
        fi
    done
    printf '%s\n' "$stage"
}

echo ""
echo "Installing Grok Build agents..."
install_grok_agents "$ROOT/.grok/agents" "project"
install_grok_agents "$GROK_HOME/agents" "user"
link_plugin_tree
echo "Project plugin tree: $ROOT/.grok/plugins/cybergrok"
echo "User agents dir:     $GROK_HOME/agents"
echo "  Session agent:     Cybergrok"
echo "  Spawn types:       recon-scout, vuln-hunter, reporter"

if [ ! -d "$ROOT/venv" ]; then
    echo "Creating Python virtualenv..."
    python3 -m venv "$ROOT/venv"
fi
# shellcheck disable=SC1091
source "$ROOT/venv/bin/activate"
pip install --upgrade pip --quiet
pip install -e "$ROOT" --quiet
echo "Installed Python package (smart_pipe, secret_scan, search_knowledge, aggregate_reports)"

if command -v playwright >/dev/null 2>&1; then
    playwright install chromium 2>/dev/null || true
fi

if [ ! -f "$ROOT/.env" ] && [ -f "$ROOT/.env.example" ]; then
    cp "$ROOT/.env.example" "$ROOT/.env"
    echo "Initialized .env from .env.example"
fi

if [ -f "$ROOT/tools/update_tools.sh" ]; then
    bash "$ROOT/tools/update_tools.sh" || true
fi

chmod +x "$ROOT/cybergrok" "$ROOT/env.sh" \
         "$ROOT/lint.sh" "$ROOT/typecheck.sh" "$ROOT/test.sh" \
         "$ROOT/hooks/bin/"*.sh 2>/dev/null || true

if command -v grok >/dev/null 2>&1; then
    echo "Registering the Cybergrok plugin with Grok Build..."
    STAGE="$(stage_plugin_package)"
    grok plugin uninstall cybergrok 2>/dev/null || true
    if grok plugin install "$STAGE" --trust; then
        grok plugin enable cybergrok 2>/dev/null || true
        echo "  plugin install --trust: ok (slim package, no .env/venv/.git)"
    else
        echo "  plugin install skipped — enable cybergrok in /plugins and run /hooks-trust"
    fi
    if grok inspect --json >/tmp/cybergrok-setup-inspect.json 2>/dev/null; then
        python3 - <<'PY'
import json
from pathlib import Path
p = Path("/tmp/cybergrok-setup-inspect.json")
try:
    data = json.loads(p.read_text())
except Exception:
    raise SystemExit(0)
wanted = {"cybergrok", "recon-scout", "vuln-hunter", "reporter"}
found = set()
for agent in data.get("agents") or []:
    name = agent.get("name") if isinstance(agent, dict) else str(agent)
    leaf = name.split(":")[-1].lower()
    if leaf in wanted:
        found.add(leaf)
missing = sorted(wanted - found)
print("  grok inspect agents:", ", ".join(sorted(found)) or "(none)")
if missing:
    print("  not yet visible:", ", ".join(missing), "(open a new grok session or /hooks-trust)")
else:
    print("  all Cybergrok agents are visible to Grok Build")
plugins = data.get("plugins") or []
names = []
for plug in plugins:
    if isinstance(plug, dict):
        names.append(str(plug.get("name") or ""))
    else:
        names.append(str(plug))
if any("cybergrok" in n.lower() for n in names):
    print("  grok inspect plugins: cybergrok present")
PY
    fi
else
    echo "grok CLI not on PATH — agents are installed on disk; install Grok Build to register the plugin."
fi

echo ""
echo "Setup complete."
echo "  1. Authenticate Grok Build:  grok login"
echo "  2. Add the target host to scope.yaml (fail-closed allowlist)"
echo "  3. Health check:             ./venv/bin/python tools/doctor.py"
echo "  4. Run as Cybergrok:         ./cybergrok"
echo "                               (uses --agent .grok/agents/cybergrok.md)"
echo "                               then /assess https://in-scope.example"
echo ""
