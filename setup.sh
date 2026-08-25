#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "========================================================"
echo "  Cybergrok setup (Grok Build + Python + TypeScript)"
echo "========================================================"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3.10+ is required."
    exit 1
fi

mkdir -p "$ROOT"/{reports,recon,output,logs,targets,tools/bin}

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

if command -v npm >/dev/null 2>&1; then
    echo "Building TypeScript MCP server..."
    (cd "$ROOT/mcp" && npm install --silent && npm run build)
else
    echo "npm not found — skip TypeScript MCP build (install Node 18+ and re-run)."
fi

if [ ! -f "$ROOT/.env" ] && [ -f "$ROOT/.env.example" ]; then
    cp "$ROOT/.env.example" "$ROOT/.env"
    echo "Initialized .env from .env.example"
fi

if [ -f "$ROOT/tools/update_tools.sh" ]; then
    bash "$ROOT/tools/update_tools.sh" || true
fi

chmod +x "$ROOT/cybergrok" "$ROOT/env.sh" "$ROOT/scripts/cybergrok-mcp.sh" \
         "$ROOT/hooks/bin/"*.sh 2>/dev/null || true

echo ""
echo "Setup complete."
echo "  1. Authenticate Grok Build:  grok login"
echo "  2. Health check:             python3 tools/doctor.py"
echo "  3. Install this plugin:      grok plugin install \"$ROOT\" --trust"
echo "  4. Run an assessment:        ./cybergrok"
echo "                               then /assess https://example.com"
echo ""
