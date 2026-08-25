#!/usr/bin/env bash
# First-party Python lint (ruff). Same scope as CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./lint.sh [--fix] [extra ruff check args...]

  ruff check  python tools scripts examples
  ruff format python/cybergrok python/tests   (--check unless --fix)

Install tools with:  pip install -e ".[dev]"
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

FIX=0
CHECK_ARGS=()
for arg in "$@"; do
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
    --fix)
      FIX=1
      ;;
    *)
      CHECK_ARGS+=("$arg")
      ;;
  esac
done

RUFF="$(need ruff)"

if [ "$FIX" -eq 1 ]; then
  "$RUFF" check --fix python tools scripts examples "${CHECK_ARGS[@]+"${CHECK_ARGS[@]}"}"
  "$RUFF" format python/cybergrok python/tests
else
  "$RUFF" check python tools scripts examples "${CHECK_ARGS[@]+"${CHECK_ARGS[@]}"}"
  "$RUFF" format --check python/cybergrok python/tests
fi
