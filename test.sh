#!/usr/bin/env bash
# First-party Python tests (pytest). Extra args are forwarded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./test.sh [pytest args...]

  Default: pytest python/tests -q
  Example: ./test.sh -k test_scope -vv

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

for arg in "$@"; do
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
  esac
done

PYTEST="$(need pytest)"
export PYTHONPATH="${ROOT}/python${PYTHONPATH:+:$PYTHONPATH}"

if [ "$#" -eq 0 ]; then
  set -- -q
fi

exec "$PYTEST" python/tests "$@"
