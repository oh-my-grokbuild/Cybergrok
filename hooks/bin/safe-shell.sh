#!/usr/bin/env bash
# Deny obviously destructive shell commands. Fail-open on parse errors.
set -euo pipefail

INPUT="$(cat || true)"
CMD="$(printf '%s' "${INPUT}" | python3 -c 'import sys,json
try:
    data=json.load(sys.stdin)
    print(data.get("toolInput",{}).get("command") or "")
except Exception:
    pass' 2>/dev/null || true)"

if [ -z "${CMD}" ]; then
  echo '{"decision":"allow"}'
  exit 0
fi

if printf '%s' "${CMD}" | grep -Eqi '(rm[[:space:]]+-rf[[:space:]]+/($| )|mkfs(\.| )|dd[[:space:]]+if=|: \(\)\{ :\|:& \};:|fork\s*\(\s*\)\s*;)'; then
  echo '{"decision":"deny","reason":"Cybergrok blocked a destructive command (disk wipe / fork bomb / rm -rf /)."}'
  exit 2
fi

echo '{"decision":"allow"}'
exit 0
