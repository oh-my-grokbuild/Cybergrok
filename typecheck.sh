#!/usr/bin/env bash
# Static types: ty (Python engine + tests) and tsc (TypeScript MCP).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./typecheck.sh [--python] [--ts]

  (no flags)     Python (ty + basedpyright) and TypeScript tsc
  --python, -p   ty check + basedpyright on first-party Python
  --ts, --typescript, -t
                 npm run typecheck in mcp/

Install Python tools with:  pip install -e ".[dev]"
Install MCP types with:     (cd mcp && npm ci)
EOF
}

need() {
  local name="$1"
  if [ -x "$ROOT/venv/bin/$name" ]; then
    printf '%s\n' "$ROOT/venv/bin/$name"
  elif [ -x "$ROOT/.venv/bin/$name" ]; then
    printf '%s\n' "$ROOT/.venv/bin/$name"
  elif command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
  else
    echo "error: $name not found. Install with: pip install -e \".[dev]\"" >&2
    exit 127
  fi
}

RUN_PY=1
RUN_TS=1
if [ "$#" -gt 0 ]; then
  RUN_PY=0
  RUN_TS=0
fi
for arg in "$@"; do
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
    --python | -p)
      RUN_PY=1
      ;;
    --typescript | --ts | -t)
      RUN_TS=1
      ;;
    *)
      echo "error: unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$RUN_PY" -eq 1 ]; then
  TY="$(need ty)"
  "$TY" check python/cybergrok python/tests --error-on-warning
  BPR="$(need basedpyright)"
  "$BPR" python tools scripts examples
fi

if [ "$RUN_TS" -eq 1 ]; then
  if [ ! -d "$ROOT/mcp/node_modules" ]; then
    echo "error: mcp/node_modules missing. Run: (cd mcp && npm ci)" >&2
    exit 1
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "error: npm not found (need Node 18+ for mcp typecheck)" >&2
    exit 127
  fi
  (cd "$ROOT/mcp" && npm run typecheck)
fi
