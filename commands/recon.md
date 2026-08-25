---
name: recon
description: Passive and active reconnaissance only. Writes recon/<slug>/, no findings files.
argument-hint: "<url-or-domain>"
---

Perform discovery-only recon on `$ARGUMENTS`.

Follow `skills/cybergrok-recon/SKILL.md`. Use `subfinder`, `httpx`, `katana`,
`gau`, `ffuf` with `smart_pipe`. Do not write `findings/`. Return the ranked
attack surface and file paths.
