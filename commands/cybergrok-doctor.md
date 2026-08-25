---
name: cybergrok-doctor
description: Diagnose the Cybergrok toolchain, plugin files, and Grok Build readiness.
---

Run the Cybergrok health check.

1. `python3 tools/doctor.py --fix` if the operator wants repairs, else without `--fix`.
2. Confirm `plugin.json`, `AGENTS.md`, `skills/`, and `tools/bin` exist.
3. Check that `grok` is on PATH (the agent runtime).
4. Report what is missing (Go tools, ProjectDiscovery binaries, Playwright).
