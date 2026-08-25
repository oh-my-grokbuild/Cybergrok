#!/usr/bin/env bash
set -euo pipefail
umask 0002

mkdir -p /workspace/{reports,recon,output,logs,targets}
export PATH="/opt/cybergrok-venv/bin:/workspace/tools/bin:/usr/local/bin:${PATH}"
export PYTHONPATH="/workspace/python${PYTHONPATH:+:$PYTHONPATH}"
export CYBERGROK_ROOT=/workspace

if [ -f /workspace/.env ]; then
  set -a
  # shellcheck disable=SC1091
  source /workspace/.env
  set +a
fi

if [ "$#" -eq 0 ]; then
  exec bash
fi
exec "$@"
