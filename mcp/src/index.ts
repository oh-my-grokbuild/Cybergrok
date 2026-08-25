#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { findPluginRoot, rpc } from "./python.js";

const SERVER_NAME = "cybergrok-mcp";
const SERVER_VERSION = "1.0.0";

function text(body: string) {
  return { content: [{ type: "text" as const, text: body }] };
}

function asMarkdownSearch(query: string, snippets: Array<Record<string, unknown>>): string {
  if (!snippets.length) {
    return `🔍 No high-signal knowledge snippets found for query: '${query}'.`;
  }
  const lines = [`### 📚 Cybergrok Knowledge Base: \`${query}\` (Found ${snippets.length} snippets)`, ""];
  snippets.forEach((s, i) => {
    lines.push(`#### Snippet #${i + 1} | Score: ${s.score} | Source: \`[${s.source_kb}]\``);
    lines.push(`- **Location**: \`${s.file}:${s.start_line}\``);
    if (s.heading) {
      lines.push(`- **Section**: ${s.heading}`);
    }
    lines.push("", "```markdown", String(s.content || "").trim(), "```", "");
  });
  return lines.join("\n");
}

const server = new McpServer({
  name: SERVER_NAME,
  version: SERVER_VERSION,
});

server.tool(
  "cybergrok_search_knowledge",
  "Search the Cybergrok knowledge base for payloads, bypasses, and methodology snippets.",
  {
    query: z.string(),
    source: z.enum(["all", "payloads", "hacktricks", "claude", "strix", "hack"]).optional(),
    limit: z.number().int().min(1).max(10).optional(),
    max_len: z.number().int().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<{ query: string; snippets: Array<Record<string, unknown>> }>("search_knowledge", args);
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    return text(asMarkdownSearch(args.query, result.snippets || []));
  },
);

server.tool(
  "cybergrok_list_skills",
  "List and filter 200+ Cybergrok offensive security playbooks.",
  {
    filter: z.string().optional(),
    limit: z.number().int().min(1).max(200).optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<{ total: number; skills: Array<{ name: string; description: string; report_count: number }> }>(
      "list_skills",
      args,
    );
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    const rows = (result.skills || []).map((s) => {
      const desc = (s.description || "").replace(/\|/g, "\\|");
      const clipped = desc.length > 80 ? `${desc.slice(0, 77)}...` : desc;
      const reports = s.report_count > 0 ? `📊 ${s.report_count} BB reports` : "-";
      return `| **\`${s.name}\`** | ${reports} | ${clipped} |`;
    });
    return text(
      [
        `### 🛡️ Cybergrok Offensive Skills Library (Showing ${rows.length} of ${result.total})`,
        "",
        "| Skill Name | Reports / Evidence | Description |",
        "| :--- | :--- | :--- |",
        ...rows,
        "",
        '💡 *Tip: Call `cybergrok_get_skill(skill_name="<name>")` to view the full playbook.*',
      ].join("\n"),
    );
  },
);

server.tool(
  "cybergrok_get_skill",
  "Retrieve a Cybergrok SKILL.md playbook, optionally a single section.",
  {
    skill_name: z.string(),
    section: z.string().optional(),
  },
  async (args) => {
    const result = rpc<{ content: string }>("get_skill", args);
    return text(result.content);
  },
);

server.tool(
  "cybergrok_scan_secrets",
  "Scan text or a file/directory with the 48-pattern secret detector.",
  {
    content: z.string().optional(),
    path: z.string().optional(),
    min_severity: z.enum(["low", "medium", "high", "critical"]).optional(),
    mask_secrets: z.boolean().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<{
      total: number;
      reported: number;
      findings: Array<{ severity: string; pattern: string; category: string; source: string; line: number; match: string }>;
    }>("scan_secrets", args);
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    if (!result.findings?.length) {
      return text("✅ No secrets or credential leaks detected matching criteria.");
    }
    const rows = result.findings.map(
      (f) => `| \`${f.severity}\` | ${f.pattern} | ${f.category} | ${f.source}:${f.line} | \`${f.match}\` |`,
    );
    return text(
      [
        `### 🚨 Cybergrok Secret Scan: Found ${result.reported} Leaked Credential(s)`,
        "",
        "| Severity | Pattern Type | Category | Location | Masked Match |",
        "| :--- | :--- | :--- | :--- | :--- |",
        ...rows,
      ].join("\n"),
    );
  },
);

server.tool(
  "cybergrok_validate_scope",
  "Check whether a URL, domain, or IP is inside the engagement scope.yaml.",
  {
    target: z.string(),
    target_slug: z.string().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<Record<string, unknown>>("validate_scope", args);
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    const allowed = Boolean(result.allowed);
    return text(
      [
        "# 🎯 Cybergrok Scope Guard Validation",
        "",
        `- **Target**: \`${result.target}\``,
        `- **Status**: ${allowed ? "🟢 **IN SCOPE / AUTHORIZED**" : "🔴 **OUT OF SCOPE / BLOCKED**"}`,
        `- **Host**: \`${result.host || ""}\``,
        result.port ? `- **Port**: \`${result.port}\`` : "",
        result.path ? `- **Path**: \`${result.path}\`` : "",
        result.matched_by ? `- **Rule Matched**: \`${result.matched_by}\`` : "",
        `- **Details**: ${result.reason}`,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  },
);

server.tool(
  "cybergrok_http_probe",
  "Probe an HTTP/HTTPS target: status, headers, TLS, and tech fingerprints.",
  {
    target_url: z.string(),
    target_slug: z.string().optional(),
    follow_redirects: z.boolean().optional(),
    timeout_seconds: z.number().optional(),
    prefer_httpx: z.boolean().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<Record<string, unknown>>("http_probe", args);
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    const techs = Array.isArray(result.technologies) ? (result.technologies as string[]).join(", ") : "";
    const tls = (result.tls_info || {}) as Record<string, string>;
    return text(
      [
        `# 🌐 HTTP Probe Inspection: \`${result.url}\``,
        "",
        "| Attribute | Value |",
        "| :--- | :--- |",
        `| **Status Code** | \`${result.status_code} ${result.status_text || ""}\` |`,
        result.title ? `| **Page Title** | ${result.title} |` : "",
        result.web_server ? `| **Web Server** | \`${result.web_server}\` |` : "",
        result.content_type ? `| **Content Type** | \`${result.content_type}\` |` : "",
        `| **Response Time** | \`${result.response_time_ms} ms\` |`,
        `| **Engine Used** | \`${result.engine_used}\` |`,
        techs ? `| **Detected Tech** | ${techs} |` : "",
        tls.version ? `| **TLS Version** | \`${tls.version}\` |` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
  },
);

server.tool(
  "cybergrok_recon_crawl",
  "Crawl a web app for endpoints and API routes, with smart-pipe ranking.",
  {
    target_url: z.string(),
    target_slug: z.string().optional(),
    depth: z.number().int().optional(),
    max_endpoints: z.number().int().optional(),
    timeout_seconds: z.number().optional(),
    prefer_katana: z.boolean().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<{
      target_url: string;
      total_endpoints_found: number;
      engine_used: string;
      duration_ms: number;
      saved_file_path?: string;
      top_endpoints: Array<{ text: string; score: number }>;
    }>("recon_crawl", args);
    if (args.format === "json") {
      return text(JSON.stringify(result, null, 2));
    }
    const rows = (result.top_endpoints || []).map((e) => `- \`${e.text}\` _(score ${e.score})_`);
    return text(
      [
        `# 🕸️ Recon Crawl: \`${result.target_url}\``,
        "",
        `- **Engine**: \`${result.engine_used}\``,
        `- **Duration**: ${result.duration_ms} ms`,
        `- **Total endpoints**: ${result.total_endpoints_found}`,
        result.saved_file_path ? `- **Raw dump**: \`${result.saved_file_path}\`` : "",
        "",
        "## Top endpoints",
        "",
        ...rows,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  },
);

server.tool(
  "cybergrok_aggregate_report",
  "Rebuild SUMMARY.md and metadata.json for one target or all targets.",
  {
    target_slug: z.string().optional(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<Record<string, unknown>>("aggregate_report", args);
    return text(JSON.stringify(result, null, 2));
  },
);

server.tool(
  "cybergrok_list_findings",
  "List confirmed findings for a target slug.",
  {
    target_slug: z.string(),
    format: z.enum(["markdown", "json"]).optional(),
  },
  async (args) => {
    const result = rpc<{
      target: string;
      total_findings: number;
      findings: Array<{ severity: string; title: string; endpoint: string; file_name: string }>;
    }>("list_findings", args);
    if (args.format === "json") {
      return text(JSON.stringify(result.findings || [], null, 2));
    }
    if (!result.findings?.length) {
      return text(`ℹ️ No confirmed findings recorded yet for target \`${args.target_slug}\`.`);
    }
    const rows = result.findings.map(
      (f) => `| \`${f.severity}\` | **${f.title}** | \`${f.endpoint}\` | \`${f.file_name}\` |`,
    );
    return text(
      [
        `### 🎯 Confirmed Findings for Target: \`${result.target}\` (${result.total_findings} total)`,
        "",
        "| Severity | Title | Vulnerable Endpoint | File |",
        "| :--- | :--- | :--- | :--- |",
        ...rows,
      ].join("\n"),
    );
  },
);

server.tool(
  "cybergrok_record_finding",
  "Write a confirmed finding (and optional PoC) then re-aggregate the target report.",
  {
    target_slug: z.string(),
    severity: z.enum(["critical", "high", "medium", "low", "informational"]),
    title: z.string(),
    endpoint: z.string(),
    description: z.string(),
    reproduction_steps: z.string(),
    poc_script: z.string().optional(),
    remediation: z.string().optional(),
  },
  async (args) => {
    const result = rpc<Record<string, string>>("record_finding", args);
    return text(
      [
        "✅ Finding successfully recorded and aggregated:",
        `- **File**: \`${result.file}\``,
        `- **Target**: \`${result.target}\``,
        `- **Severity**: \`${result.severity}\``,
        `- **Summary Updated**: \`${result.summary}\``,
      ].join("\n"),
    );
  },
);

server.prompt(
  "cybergrok_hunt",
  "Start an authorized Cybergrok hunt on Grok Build.",
  {
    target: z.string(),
    scope_notes: z.string().optional(),
    focus_area: z.string().optional(),
  },
  ({ target, scope_notes, focus_area }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: [
            `## 🛡️ Cybergrok Security Research Directive: \`${target}\``,
            "",
            "You are **Cybergrok** on Grok Build. Target is authorized. Non-destructive. Zero false positives.",
            scope_notes ? `\n### Scope notes\n${scope_notes}` : "",
            focus_area ? `\n### Focus\n\`${focus_area}\`` : "",
            "",
            "Start with `cybergrok_list_skills` and `cybergrok_search_knowledge`.",
          ]
            .filter(Boolean)
            .join("\n"),
        },
      },
    ],
  }),
);

server.prompt(
  "cybergrok_triage",
  "Zero-false-positive triage checklist for an observed anomaly.",
  {
    target: z.string(),
    vulnerability_type: z.string(),
    raw_observation: z.string(),
  },
  ({ target, vulnerability_type, raw_observation }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: [
            "## 🔍 Cybergrok Zero-False-Positive Triage",
            `- **Target**: \`${target}\``,
            `- **Hypothesis**: \`${vulnerability_type}\``,
            "```",
            raw_observation,
            "```",
            "Confirm differential, auth state, real impact, and a 10-minute PoC before `cybergrok_record_finding`.",
          ].join("\n"),
        },
      },
    ],
  }),
);

async function main() {
  process.stderr.write(`[${SERVER_NAME}] v${SERVER_VERSION} root=${findPluginRoot()}\n`);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`[${SERVER_NAME}] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
