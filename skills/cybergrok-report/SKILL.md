---
name: cybergrok-report
description: >
  Build Cybergrok executive deliverables (SUMMARY.md, metadata.json, HTML, PDF).
  Use when the user asks for /report or after an assessment.
---

# Cybergrok Reporting

1. Findings only in `reports/<SLUG>/findings/<severity>_<name>.md`
2. INFO / headers / negatives → `evidence/recon_notes.md`
3. Redact secrets in evidence
4. `aggregate_reports <SLUG>`
5. `python3 tools/generate_pdf.py <SLUG>` (or `--no-pdf`)
6. Return severity counts and paths

Template: `templates/report_template.md`.
