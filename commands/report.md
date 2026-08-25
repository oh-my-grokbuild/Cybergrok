---
name: report
description: Aggregate Cybergrok findings into SUMMARY.md, metadata.json, HTML, and PDF.
argument-hint: "<target-slug>"
---

Build deliverables for `$ARGUMENTS`.

Run `aggregate_reports <SLUG>`. If Playwright is available, run
`python3 tools/generate_pdf.py <SLUG>`. List finding counts and output paths.
Do not invent findings.
