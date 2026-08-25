---
name: cybergrok-recon
description: >
  Cybergrok reconnaissance playbook. Use for /recon, subdomain mapping, HTTP
  probing, crawling, and content discovery without writing findings.
---

# Cybergrok Recon

Discovery only. No `findings/` files.

Read workspace `scope.yaml`. Only hosts under `in_scope` are authorized. If
the named target is missing, stop. Do not treat a user-named URL as authorization.

## Steps

1. Slug the target. `mkdir -p recon/<SLUG> reports/<SLUG>/evidence`
2. Passive: `subfinder -d <domain> -silent | tee recon/<SLUG>/subdomains.txt`
3. Historical: `gau <domain> | smart_pipe --target <SLUG> --tool gau`
4. Probe: `httpx -silent -status-code -title -tech-detect`
5. Crawl: `katana -u <url> -silent -depth 3 | smart_pipe --target <SLUG> --tool katana`
6. Fuzz: `ffuf -u <url>/FUZZ -w tools/wordlists/common.txt -mc 200,301,302,403`
7. Notes (headers, 401/403, tech) → `reports/<SLUG>/evidence/recon_notes.md`

On 429: back off 1–3s, drop concurrency. On WAF 403: try
`tools/wordlists/bypass-headers.txt`.
