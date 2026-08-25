---
name: recon
description: Passive and active reconnaissance only. Writes recon/<slug>/, no findings files.
argument-hint: "<url-or-domain>"
---

Perform discovery-only recon on `$ARGUMENTS`.

Read workspace `scope.yaml` first. Only hosts under `in_scope` are authorized.
If the named target is missing, stop and tell the operator to add it. Do not
treat `$ARGUMENTS` as authorization.

Follow `skills/cybergrok-recon/SKILL.md`. Use `subfinder`, `httpx`, `katana`,
`gau`, `ffuf` with `smart_pipe` only against in-scope hosts. Do not write
`findings/`. Return the ranked attack surface and file paths.
