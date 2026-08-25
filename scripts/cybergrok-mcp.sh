#!/usr/bin/env bash
# Launch the TypeScript Cybergrok MCP server (stdio). Never npm-installs at spawn.
set -euo pipefail

ROOT="${CYBERGROK_ROOT:-${GROK_PLUGIN_ROOT:-}}"
if [ -z "${ROOT}" ] || [ ! -d "${ROOT}/python/cybergrok" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

export CYBERGROK_ROOT="$ROOT"
export PYTHONPATH="${ROOT}/python${PYTHONPATH:+:$PYTHONPATH}"

if [ -x "${ROOT}/venv/bin/python3" ]; then
  export PATH="${ROOT}/venv/bin:${PATH}"
fi

if [ ! -f "${ROOT}/mcp/dist/index.js" ]; then
  echo "cybergrok-mcp TypeScript build missing (${ROOT}/mcp/dist/index.js). Run ./setup.sh" >&2
  exit 1
fi

exec node "${ROOT}/mcp/launch.cjs" "$@"
