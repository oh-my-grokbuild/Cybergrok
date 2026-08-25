#!/usr/bin/env bash
# Launch the TypeScript Cybergrok MCP server (stdio).
set -euo pipefail

ROOT="${CYBERGROK_ROOT:-${GROK_PLUGIN_ROOT:-}}"
if [ -z "${ROOT}" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

export CYBERGROK_ROOT="$ROOT"
export PYTHONPATH="${ROOT}/python${PYTHONPATH:+:$PYTHONPATH}"

if [ -x "${ROOT}/venv/bin/python3" ]; then
  export PATH="${ROOT}/venv/bin:${PATH}"
fi

JS="${ROOT}/mcp/dist/index.js"
if [ ! -f "$JS" ]; then
  if command -v npm >/dev/null 2>&1; then
    (cd "${ROOT}/mcp" && npm install --silent && npm run build)
  fi
fi

if [ ! -f "$JS" ]; then
  echo "cybergrok-mcp TypeScript build missing. Run ./setup.sh" >&2
  exit 1
fi

exec node "$JS" "$@"
