"""48-pattern credential and secret scanner."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"

SEVERITY_RANK = {SEV_LOW: 0, SEV_MEDIUM: 1, SEV_HIGH: 2, SEV_CRITICAL: 3}

_RAW_PATTERNS: list[tuple[str, str, str, str]] = [
    ("AWS_ACCESS_KEY", SEV_CRITICAL, "aws", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED", SEV_CRITICAL, "aws", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE", SEV_HIGH, "aws", r"(?i)aws(.{0,20})?(secret|sk)['\"=: ]+([0-9a-z/+=]{40})"),
    ("GCP_SERVICE_ACCOUNT", SEV_CRITICAL, "gcp", r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY", SEV_HIGH, "gcp", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GH_PAT_CLASSIC", SEV_CRITICAL, "github", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED", SEV_CRITICAL, "github", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH", SEV_HIGH, "github", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_S2S", SEV_HIGH, "github", r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),
    ("STRIPE_LIVE", SEV_CRITICAL, "stripe", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST", SEV_LOW, "stripe", r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("SLACK_TOKEN", SEV_HIGH, "slack", r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK", SEV_MEDIUM, "slack", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SENDGRID", SEV_HIGH, "email_svc", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_V1", SEV_HIGH, "email_svc", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MAILGUN_LOOSE", SEV_HIGH, "email_svc", r"\bkey-[0-9a-f]{32}\b"),
    ("TWILIO_API", SEV_HIGH, "twilio", r"\bSK[0-9a-fA-F]{32}\b"),
    ("TWILIO_SID", SEV_MEDIUM, "twilio", r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_AUTH", SEV_HIGH, "twilio", r"(?i)twilio(.{0,20})?(auth|token)['\"=: ]+([a-f0-9]{32})"),
    ("HEROKU_API", SEV_MEDIUM, "paas", r"(?i)heroku(.{0,20})?api['\"=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    ("FIREBASE_URL", SEV_LOW, "firebase", r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),
    ("JWT", SEV_MEDIUM, "jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH", SEV_MEDIUM, "bearer", r"(?i)authorization['\"=: ]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL", SEV_MEDIUM, "basic_auth", r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("RSA_PRIVKEY", SEV_CRITICAL, "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY", SEV_CRITICAL, "private_key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY", SEV_CRITICAL, "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY", SEV_CRITICAL, "private_key", r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),
    ("GENERIC_API_KEY", SEV_MEDIUM, "generic", r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
    ("ANTHROPIC_API", SEV_CRITICAL, "ai_api", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    ("OPENAI_LEGACY", SEV_CRITICAL, "ai_api", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("OPENAI_PROJECT", SEV_CRITICAL, "ai_api", r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b"),
    ("OPENAI_SESSION", SEV_HIGH, "ai_api", r"\bsess-[A-Za-z0-9]{40}\b"),
    ("HUGGINGFACE", SEV_HIGH, "ai_api", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("CLOUDFLARE_API", SEV_CRITICAL, "infra_api", r"(?i)cf[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{37})"),
    ("DIGITALOCEAN", SEV_HIGH, "infra_api", r"\bdop_v1_[a-f0-9]{64}\b"),
    ("NPM_TOKEN", SEV_HIGH, "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN", SEV_HIGH, "package_registry", r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b"),
    ("DOCKER_HUB_PAT", SEV_HIGH, "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),
    ("ATLASSIAN_TOKEN", SEV_HIGH, "saas_api", r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("LINEAR_API", SEV_MEDIUM, "saas_api", r"\blin_api_[A-Za-z0-9]{40}\b"),
    ("NEWRELIC_LICENSE", SEV_MEDIUM, "observability", r"\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b"),
    ("DATADOG_API", SEV_HIGH, "observability", r"(?i)dd[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{32})"),
    ("SENTRY_DSN", SEV_LOW, "observability", r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+"),
    ("NGROK_AUTH", SEV_MEDIUM, "tunneling", r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b"),
    ("DISCORD_BOT", SEV_HIGH, "bot_token", r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("TELEGRAM_BOT", SEV_HIGH, "bot_token", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
]

_COMPILED = [(n, s, c, re.compile(expr)) for n, s, c, expr in _RAW_PATTERNS]


@dataclass
class Finding:
    pattern: str
    severity: str
    category: str
    match: str
    source: str
    line: int

    def to_dict(self) -> dict:
        return asdict(self)


def scan_line(line: str, line_no: int, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, severity, category, cre in _COMPILED:
        for m in cre.finditer(line):
            match_text = m.group(0)
            if m.lastindex and m.group(1):
                match_text = m.group(1)
            findings.append(Finding(name, severity, category, match_text, source, line_no))
    return findings


def scan_text(text: str, source: str = "raw_content") -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, i, source))
    return findings


def scan_file(path: str | Path) -> list[Finding]:
    p = Path(path)
    try:
        data = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(data, str(p))


def scan_directory(dir_path: str | Path, max_workers: int = 8) -> list[Finding]:
    root = Path(dir_path)
    files = [p for p in root.rglob("*") if p.is_file()]
    findings: list[Finding] = []
    workers = max(1, max_workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_file, f): f for f in files}
        for fut in as_completed(futs):
            findings.extend(fut.result())
    return findings


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_RANK.get(min_severity.lower(), 0)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "…" if value else value
    return value[:4] + "…" + value[-3:]
