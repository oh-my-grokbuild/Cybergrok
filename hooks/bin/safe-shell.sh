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
cmd = tool.get("command")
if not isinstance(cmd, str) or not cmd.strip():
    sys.exit(2)
print(cmd)
' 2>/dev/null)" || {
  echo '{"decision":"deny","reason":"Cybergrok hook could not parse the shell command; refusing."}'
  exit 2
}

if [ -z "${CMD}" ]; then
  echo '{"decision":"deny","reason":"Cybergrok hook received an empty command; refusing."}'
  exit 2
fi

if printf '%s' "${CMD}" | grep -Eqi \
  '(rm[[:space:]]+(-[a-zA-Z]*r[a-zA-Z]*f|-rf/|--recursive|--force)|rm[[:space:]]+-[a-zA-Z]*f[a-zA-Z]*r|rm[[:space:]]+--no-preserve-root|mkfs|dd[[:space:]]+(if=|of=)|:\(\)\{|:[[:space:]]*\|[[:space:]]*:|curl[^|;]*\|[[:space:]]*(/bin/)?(ba)?sh|wget[^|;]*\|[[:space:]]*(/bin/)?(ba)?sh|curl[^|;]*\|[[:space:]]*(python|zsh)|wget[^|;]*\|[[:space:]]*(python|zsh)|chmod([[:space:]]+-R|[[:space:]].*-R)|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|node[[:space:]]+-e|ruby[[:space:]]+-e)'; then
  echo '{"decision":"deny","reason":"Cybergrok blocked a destructive or pipe-to-shell command."}'
  exit 2
fi

if printf '%s' "${CMD}" | grep -Eqi \
  '(>|>>).*scope\.ya?ml|tee[[:space:]].*scope\.ya?ml|(cp|mv|install|install[[:space:]])[[:space:]].*scope\.ya?ml'; then
  echo '{"decision":"deny","reason":"Cybergrok refuses shell writes to scope.yaml; the operator owns the allowlist."}'
  exit 2
fi

echo '{"decision":"allow"}'
exit 0
