import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function findPluginRoot(): string {
  const env = process.env.CYBERGROK_ROOT || process.env.GROK_PLUGIN_ROOT;
  if (env && existsSync(env)) {
    return env;
  }
  // mcp/dist -> mcp -> repo
  return join(here, "..", "..");
}

export function findPython(): string {
  const root = findPluginRoot();
  const venvUnix = join(root, "venv", "bin", "python3");
  const venvWin = join(root, "venv", "Scripts", "python.exe");
  if (existsSync(venvUnix)) {
    return venvUnix;
  }
  if (existsSync(venvWin)) {
    return venvWin;
  }
  return process.platform === "win32" ? "python" : "python3";
}

export function rpc<T = Record<string, unknown>>(op: string, args: Record<string, unknown> = {}): T {
  const root = findPluginRoot();
  const python = findPython();
  const payload = JSON.stringify({
    op,
    args: { ...args, workspace: args.workspace || process.env.GROK_WORKSPACE_ROOT || process.cwd() },
  });
  const result = spawnSync(python, ["-m", "cybergrok", "rpc", payload], {
    cwd: root,
    encoding: "utf-8",
    env: {
      ...process.env,
      PYTHONPATH: [join(root, "python"), process.env.PYTHONPATH || ""].filter(Boolean).join(
        process.platform === "win32" ? ";" : ":",
      ),
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`Failed to start Python core: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const err = (result.stderr || result.stdout || "").trim();
    throw new Error(err || `Python RPC exited with ${result.status}`);
  }
  const parsed = JSON.parse(result.stdout) as { ok: boolean; result?: T; error?: string };
  if (!parsed.ok) {
    throw new Error(parsed.error || "Python RPC failed");
  }
  return parsed.result as T;
}
