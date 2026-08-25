#!/usr/bin/env bash
# Static types: ty + basedpyright on first-party Python.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./typecheck.sh

  ty check + basedpyright on first-party Python

Install Python tools with:  pip install -e ".[dev]"
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

for arg in "$@"; do
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
    --python | -p)
      ;;
    *)
      echo "error: unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TY="$(need ty)"
"$TY" check python/cybergrok python/tests --error-on-warning
BPR="$(need basedpyright)"
"$BPR" python tools scripts examples
