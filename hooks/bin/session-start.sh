#!/usr/bin/env bash
# Prepare a Cybergrok workspace when a Grok Build session starts.
set -euo pipefail

ROOT="${GROK_PLUGIN_ROOT:-${CYBERGROK_ROOT:-}}"
WS="${GROK_WORKSPACE_ROOT:-${PWD}}"

if [ -z "${ROOT}" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

mkdir -p \
  "${WS}/reports" \
  "${WS}/recon" \
  "${WS}/output" \
  "${WS}/logs" \
  "${WS}/targets"

BIN_DIR="${ROOT}/tools/bin"
if [ -d "${BIN_DIR}" ]; then
  case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) export PATH="${BIN_DIR}:${PATH}" ;;
  esac
fi

# SessionStart is observe-only; additionalContext is best-effort.
cat <<EOF
{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"Cybergrok plugin loaded. Workspace dirs ready under ${WS}. Native tools live in ${BIN_DIR}. Authorized assessments: /assess <target>. Report only confirmed findings with HTTP proof."}}
EOF
exit 0
