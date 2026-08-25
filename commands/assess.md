---
name: assess
description: Run a full authorized Cybergrok assessment against a target (recon → hunt → report).
argument-hint: "<url-or-domain> [focus]"
---

Run **Cybergrok** end-to-end against `$ARGUMENTS`.

1. Treat the named target as authorized. Read `scope.yaml` for restrictions.
2. Follow `skills/cybergrok-assess/SKILL.md` and `AGENTS.md`.
3. Create `recon/<SLUG>` and `reports/<SLUG>/{findings,pocs,evidence}`.
4. Phase 1–2: recon-scout work (or do it yourself if small).
5. Phase 3–4: select playbooks; validate with proof; write findings + PoCs.
6. Phase 5: `secret_scan` on collected JS/dumps.
7. Phase 6: `aggregate_reports <SLUG>` and summarize.

Do not claim vulns without HTTP proof. Pipe noisy tools through `smart_pipe`.
