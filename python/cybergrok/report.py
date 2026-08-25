"""Finding parser and executive SUMMARY.md aggregator."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

FRONTMATTER_RE = re.compile(r"(?s)^---\s*\n(.*?)\n---")
FM_TITLE_RE = re.compile(r"(?m)^title:\s*['\"]?(.+?)['\"]?$")
FM_SEV_RE = re.compile(r"(?mi)^severity:\s*['\"]?([A-Za-z]+)['\"]?$")
HEADING_TITLE_RE = re.compile(
    r"(?m)^#\s+(?:(?:Vulnerability Report|Finding|Vuln):\s*)?(?:\[[A-Z]+\]\s*[-:]?\s*)?(?:[0-9]+\.\s*)?(.+)$"
)
TABLE_SEV_RE = re.compile(r"(?i)\|\s*\*{0,2}(?:Severity|Severity Rating|Risk Level)\*{0,2}\s*\|\s*[`*]?([A-Za-z]+)")
KV_SEV_RE = re.compile(r"(?i)\*{0,2}(?:Severity|Severity Rating|Risk Level)\*{0,2}\s*[:=]\s*[`*]*([A-Za-z]+)")
TABLE_CVSS_RE = re.compile(
    r"(?i)\|\s*\*{0,2}CVSS(?:\s*v?3(?:\.1)?)?(?:\s*Score)?\*{0,2}\s*\|\s*[`*]?([0-9.]+(?:\s*\([^)|\n]+\))?)"
)
KV_CVSS_RE = re.compile(r"(?i)CVSS(?:\s*v?3(?:\.1)?)?(?:\s*Score)?\s*[:=]\s*[`*]?([0-9.]+(?:\s*\([^)|\n]+\))?)")
TABLE_CWE_RE = re.compile(r"(?i)\|\s*\*{0,2}CWE\*{0,2}\s*\|\s*[`*]?((?:CWE-)?\d+[^|*`\n]*)")
KV_CWE_RE = re.compile(r"(?i)CWE\s*[:=]\s*[`*]?((?:CWE-)?\d+[^|*`\n]*)")
TABLE_EP_RE = re.compile(
    r"(?i)\|\s*\*{0,2}(?:Affected Endpoint|Affected Asset|Target|Endpoint|URL/Host|URL)\*{0,2}\s*\|\s*[`*]?([^|*`\n]+)"
)
KV_EP_RE = re.compile(
    r"(?i)(?:Affected Endpoint|Affected Asset|Target|Endpoint|URL/Host|URL)\s*[:=]\s*[`*]?([^|*`\n]+)"
)
PREFIX_SEV_RE = re.compile(r"(?i)^(?:\[)?(CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)(?:\])?[-_]")
CLEAN_VAL_RE = re.compile(r"[`*_]")
CUSTOM_SECTIONS_RE = re.compile(
    r"(?si)(##\s+(?:Verified Working Controls|Executive Narrative|Recommendations|Priority Action Items|Attack Path Narrative).*)$"
)
SLUG_RE = re.compile(r"[^a-z0-9]+")

SEVERITY_WEIGHTS = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFORMATIONAL": 5,
    "UNKNOWN": 6,
}


def clean_value(val: str) -> str:
    return CLEAN_VAL_RE.sub("", val).strip()


def sanitize_slug(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw or raw.startswith("http"):
        from urllib.parse import urlparse

        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        host = (parsed.hostname or "").lower()
        port = f"_{parsed.port}" if parsed.port else ""
        raw = f"{host}{port}" if host else raw
    slug = SLUG_RE.sub("_", raw.lower()).strip("_")
    return slug or "target"


@dataclass
class FindingMeta:
    file_name: str
    relative_path: str
    title: str
    severity: str
    cvss: str
    cwe: str
    endpoint: str
    last_modified: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SummaryData:
    target: str
    scan_time: str
    total_findings: int
    severity_summary: dict[str, int]
    findings: list[FindingMeta] = field(default_factory=list)
    pocs: list[str] = field(default_factory=list)
    evidence_files: list[str] = field(default_factory=list)
    recon_notes: str | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "total_findings": self.total_findings,
            "severity_summary": self.severity_summary,
            "findings": [f.to_dict() for f in self.findings],
            "pocs": self.pocs,
            "evidence_files": self.evidence_files,
            "recon_notes": self.recon_notes,
        }


def parse_finding_file(file_path: Path) -> FindingMeta:
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    filename = file_path.name
    title = ""
    fm = FRONTMATTER_RE.search(content)
    if fm:
        tm = FM_TITLE_RE.search(fm.group(1))
        if tm:
            title = tm.group(1).strip()
    if not title:
        hm = HEADING_TITLE_RE.search(content)
        title = hm.group(1).strip() if hm else filename.removesuffix(".md").replace("_", " ").replace("-", " ")

    severity = ""
    if fm:
        sm = FM_SEV_RE.search(fm.group(1))
        if sm:
            severity = sm.group(1).strip().upper()
    if not severity:
        m = TABLE_SEV_RE.search(content) or KV_SEV_RE.search(content)
        if m:
            severity = m.group(1).strip().upper()
        else:
            pm = PREFIX_SEV_RE.search(filename)
            severity = pm.group(1).upper() if pm else "UNKNOWN"
    if severity in {"INFO", "NOTE"}:
        severity = "INFORMATIONAL"
    if severity not in SEVERITY_WEIGHTS:
        severity = "UNKNOWN"

    cm = TABLE_CVSS_RE.search(content) or KV_CVSS_RE.search(content)
    cvss = clean_value(cm.group(1)) if cm else "N/A"
    wm = TABLE_CWE_RE.search(content) or KV_CWE_RE.search(content)
    if wm:
        raw = clean_value(wm.group(1))
        cwe = raw if raw.upper().startswith("CWE-") else f"CWE-{raw}"
    else:
        cwe = "N/A"
    em = TABLE_EP_RE.search(content) or KV_EP_RE.search(content)
    endpoint = clean_value(em.group(1)) if em else "N/A"
    mtime = datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    return FindingMeta(filename, f"findings/{filename}", title, severity, cvss, cwe, endpoint, mtime)


def extract_custom_sections(existing: str) -> str:
    if not existing:
        return ""
    m = CUSTOM_SECTIONS_RE.search(existing)
    return m.group(1).strip() if m else ""


def generate_summary_md(target_dir: Path, data: SummaryData, custom: str) -> None:
    lines = [
        f"# 🛡️ Security Assessment Summary: `{data.target}`",
        "",
        f"- **Generated At**: {data.scan_time}",
        f"- **Total Confirmed Findings**: {data.total_findings}",
        (
            f"- **Severity Breakdown**: 🔴 Critical: {data.severity_summary['CRITICAL']} | "
            f"🟠 High: {data.severity_summary['HIGH']} | "
            f"🟡 Medium: {data.severity_summary['MEDIUM']} | "
            f"🔵 Low: {data.severity_summary['LOW']} | "
            f"⚪ Info: {data.severity_summary['INFORMATIONAL']}"
        ),
        "",
        "---",
        "",
        "## 📑 Findings Matrix",
        "",
        "| Severity | Title / Vulnerability | CVSS v3.1 | CWE | Affected Endpoint | Report Link |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if not data.findings:
        lines.append("| - | *No confirmed vulnerabilities reported* | - | - | - | - |")
    else:
        badges = {
            "CRITICAL": "🔴 `CRITICAL`",
            "HIGH": "🟠 `HIGH`",
            "MEDIUM": "🟡 `MEDIUM`",
            "LOW": "🔵 `LOW`",
            "INFORMATIONAL": "⚪ `INFO`",
        }
        for f in data.findings:
            badge = badges.get(f.severity, f"`{f.severity}`")
            lines.append(
                f"| {badge} | {f.title} | {f.cvss} | {f.cwe} | `{f.endpoint}` | [{f.file_name}]({f.relative_path}) |"
            )

    lines += ["", "---", "", "## 🧪 Proof of Concept Scripts (`pocs/`)", ""]
    if data.pocs:
        lines.extend(f"- [`pocs/{p}`](pocs/{p})" for p in data.pocs)
    else:
        lines.append("- *No standalone PoC scripts attached.*")

    lines += ["", "## 📁 Evidence & Recon Notes (`evidence/`)", ""]
    if data.recon_notes:
        lines.append(f"- 📝 **[Reconnaissance & Informational Notes]({data.recon_notes})**")
    if data.evidence_files:
        lines.extend(f"- [`evidence/{e}`](evidence/{e})" for e in data.evidence_files)
    else:
        lines.append("- *No visual or trace evidence attached.*")

    if custom:
        lines += ["", "---", "", custom]
    lines.append("")
    (target_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def aggregate_target(target_dir: Path) -> SummaryData:
    target_dir = Path(target_dir)
    findings_dir = target_dir / "findings"
    pocs_dir = target_dir / "pocs"
    evidence_dir = target_dir / "evidence"
    findings: list[FindingMeta] = []
    if findings_dir.is_dir():
        for p in findings_dir.iterdir():
            if p.is_file() and p.suffix.lower() == ".md" and p.name.lower() not in {"summary.md", "readme.md"}:
                try:
                    findings.append(parse_finding_file(p))
                except OSError:
                    continue
    findings.sort(key=lambda f: (SEVERITY_WEIGHTS.get(f.severity, 9), f.title))
    pocs = sorted(p.name for p in pocs_dir.iterdir() if p.is_file()) if pocs_dir.is_dir() else []
    evidence = sorted(p.name for p in evidence_dir.iterdir() if p.is_file()) if evidence_dir.is_dir() else []
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        if f.severity in sev:
            sev[f.severity] += 1
    recon = "evidence/recon_notes.md" if (evidence_dir / "recon_notes.md").is_file() else None
    data = SummaryData(
        target=target_dir.name,
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_findings=len(findings),
        severity_summary=sev,
        findings=findings,
        pocs=pocs,
        evidence_files=evidence,
        recon_notes=recon,
    )
    (target_dir / "metadata.json").write_text(json.dumps(data.to_dict(), indent=2) + "\n", encoding="utf-8")
    existing = (target_dir / "SUMMARY.md").read_text(encoding="utf-8") if (target_dir / "SUMMARY.md").is_file() else ""
    generate_summary_md(target_dir, data, extract_custom_sections(existing))
    return data


def aggregate_all(reports_dir: Path) -> list[SummaryData]:
    reports_dir = Path(reports_dir)
    results: list[SummaryData] = []
    if not reports_dir.is_dir():
        return results
    for child in sorted(reports_dir.iterdir()):
        if child.is_dir():
            results.append(aggregate_target(child))
    return results


def record_finding(
    reports_dir: Path,
    target_slug: str,
    severity: str,
    title: str,
    endpoint: str,
    description: str,
    reproduction_steps: str,
    poc_script: str = "",
    remediation: str = "Implement strict authorization checks and validate user access permissions.",
) -> dict:
    slug = sanitize_slug(target_slug)
    sev = severity.lower().strip()
    target_dir = reports_dir / slug
    findings_dir = target_dir / "findings"
    pocs_dir = target_dir / "pocs"
    evidence_dir = target_dir / "evidence"
    for d in (findings_dir, pocs_dir, evidence_dir):
        d.mkdir(parents=True, exist_ok=True)

    if sev in {"info", "informational"}:
        note = evidence_dir / "recon_notes.md"
        block = (
            f"\n## {title}\n\n- **Endpoint**: `{endpoint}`\n\n{description}\n\n"
            f"{reproduction_steps}\n"
        )
        with note.open("a", encoding="utf-8") as fh:
            fh.write(block)
        aggregate_target(target_dir)
        return {
            "file": f"reports/{slug}/evidence/recon_notes.md",
            "target": slug,
            "severity": "INFORMATIONAL",
            "summary": f"reports/{slug}/SUMMARY.md",
            "routed": "evidence",
        }

    vuln = sanitize_slug(title)[:40] or "finding"
    finding_name = f"{sev}_{vuln}.md"
    body = [
        f"# {title}",
        "",
        f"- **Severity**: {sev.upper()}",
        f"- **Endpoint**: `{endpoint}`",
        f"- **Date**: {datetime.now().strftime('%Y-%m-%d')}",
        "",
        "## Description",
        "",
        description,
        "",
        "## Steps to Reproduce",
        "",
        reproduction_steps,
        "",
    ]
    if poc_script:
        poc_name = f"poc_{vuln}.py"
        (pocs_dir / poc_name).write_text(poc_script, encoding="utf-8")
        body += ["## Proof of Concept", "", f"Standalone script: [`pocs/{poc_name}`](../pocs/{poc_name})", ""]
    body += ["## Remediation", "", remediation, ""]
    (findings_dir / finding_name).write_text("\n".join(body), encoding="utf-8")
    aggregate_target(target_dir)
    return {
        "file": f"reports/{slug}/findings/{finding_name}",
        "target": slug,
        "severity": sev.upper(),
        "summary": f"reports/{slug}/SUMMARY.md",
    }
