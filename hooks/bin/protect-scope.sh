#!/usr/bin/env bash
# Deny writes that replace the workspace allowlist. Fail closed on parse errors.
set -euo pipefail
INPUT="$(cat || true)"
PATHS="$(printf '%s' "${INPUT}" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    sys.exit(2)
tool = data.get("toolInput") or data.get("tool_input") or data.get("arguments") or {}
if not isinstance(tool, dict):
    sys.exit(2)
vals = []
for key in ("path", "file_path", "target_file"):
    v = tool.get(key)
    if isinstance(v, str):
        vals.append(v)
print("\n".join(vals))
' 2>/dev/null)" || {
  echo '{"decision":"deny","reason":"Cybergrok hook could not parse the write path; refusing."}'
  exit 2
}

if printf '%s' "${PATHS}" | grep -Eqi '(^|/)scope\.ya?ml$'; then
  echo '{"decision":"deny","reason":"Cybergrok refuses writes to scope.yaml; the operator owns the allowlist."}'
  exit 2
fi
echo '{"decision":"allow"}'
exit 0
