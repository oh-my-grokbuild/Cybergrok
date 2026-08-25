---
name: cybergrok-assess
description: >
  End-to-end Cybergrok assessment on Grok Build. Use when the user asks to
  assess, pentest, bug-bounty, red-team, or hunt a named target, or runs /assess.
---

# Cybergrok Assessment (Grok Build)

This is the autoload orchestrator for a full Cybergrok assessment on Grok Build.

## 1. Authorization

Read workspace `scope.yaml`. Only hosts under `in_scope` are authorized. If the
named target is missing, stop and tell the operator to add it. Do not treat a
URL you selected as authorization.

## 2. Pipeline

```
Passive recon → Active probe → Skill execution → PoC validation
      → Secret mining → Executive report
```

1. Slug the target (`example.com` → `example_com`).
2. `mkdir -p recon/<SLUG> reports/<SLUG>/{findings,pocs,evidence}`
3. Recon with `subfinder`, `gau`, `httpx`, `katana`, `ffuf`.
   Always: `<cmd> | smart_pipe --target <SLUG> --tool <name>`
4. Choose playbooks from `skills/` using surface signals (Next.js → `hunt-nextjs`,
   GraphQL → `hunt-graphql`, IDs in APIs → `hunt-idor`).
5. Validate with A/B or auth/unauth differentials. Write only confirmed
   `low|medium|high|critical` files under `findings/`.
6. `secret_scan` collected JS and dumps.
7. `aggregate_reports <SLUG>` then optional `python3 tools/generate_pdf.py <SLUG>`.

## 3. Proof bar

| Class | Proof |
| --- | --- |
| IDOR / BOLA | User B reads/writes User A object; both HTTP pairs |
| Auth bypass | Privileged body without valid creds |
| SQLi | Banner or deterministic differential |
| XSS | Browser/console or reflected execution context |
| SSRF | Callback or internal metadata in response |

## 4. Grok primitives

- You (Cybergrok) stay primary.
- Spawn `recon-scout` / `vuln-hunter` / `reporter` only for bounded slices.
- MCP: `cybergrok_list_skills`, `cybergrok_get_skill`, `cybergrok_search_knowledge`,
  `cybergrok_http_probe`, `cybergrok_recon_crawl`, `cybergrok_record_finding`.
- Knowledge search: `search_knowledge "<query>" --limit 3`.

See also `skills/autonomous-godmode-hunter/SKILL.md` for the longer SOP.
