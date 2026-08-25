#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CYBERGROK_DIR="$SCRIPT_DIR"
export CYBERGROK_ROOT="$SCRIPT_DIR"
export PATH="$SCRIPT_DIR/tools/bin:$SCRIPT_DIR/bin:$SCRIPT_DIR/venv/bin:$PATH"
umask 0002

if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/venv/bin/activate"
fi

echo "Cybergrok environment: $SCRIPT_DIR"
if command -v grok >/dev/null 2>&1; then
    echo "  Grok Build: $(grok --version 2>&1 | head -n 1)"
else
    echo "  Grok Build: not on PATH"
fi
echo "  Plugin: $SCRIPT_DIR/plugin.json"
echo "  Tools: tools/bin (smart_pipe, secret_scan, search_knowledge, aggregate_reports, cybergrok-mcp)"
