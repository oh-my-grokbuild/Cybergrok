#!/usr/bin/env bash
# Deny destructive shell commands. Fail closed on parse errors.
set -euo pipefail

INPUT="$(cat || true)"
CMD="$(printf '%s' "${INPUT}" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    sys.exit(2)
tool = data.get("toolInput") or data.get("tool_input") or data.get("arguments") or {}
if not isinstance(tool, dict):
    sys.exit(2)
print(tool.get("command") or "")
' 2>/dev/null)" || {
  echo '{"decision":"deny","reason":"Cybergrok hook could not parse the shell command; refusing."}'
  exit 2
}

if [ -z "${CMD}" ]; then
  echo '{"decision":"deny","reason":"Cybergrok hook received an empty command; refusing."}'
  exit 2
fi

if printf '%s' "${CMD}" | grep -Eqi \
  '(rm[[:space:]]+-rf[[:space:]]+(/|~|\$HOME)|mkfs|dd[[:space:]]+(if=|of=)|: \(\)\{ :\|:& \};:|curl[^|;]*\|[[:space:]]*(ba)?sh|wget[^|;]*\|[[:space:]]*(ba)?sh|chmod[[:space:]]+-R[[:space:]]+777)'; then
  echo '{"decision":"deny","reason":"Cybergrok blocked a destructive or pipe-to-shell command."}'
  exit 2
fi

echo '{"decision":"allow"}'
exit 0
