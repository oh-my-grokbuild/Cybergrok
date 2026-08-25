#!/usr/bin/env bash
# Prepare workspace directories. Does not change the session agent or PATH.
set -euo pipefail

WS="${GROK_WORKSPACE_ROOT:-${PWD}}"
mkdir -p \
  "${WS}/reports" \
  "${WS}/recon" \
  "${WS}/output" \
  "${WS}/logs" \
  "${WS}/targets"
exit 0
