import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function findPluginRoot(): string {
  for (const envName of ["CYBERGROK_ROOT", "GROK_PLUGIN_ROOT"]) {
    const env = process.env[envName];
    if (env && existsSync(join(env, "python", "cybergrok"))) {
      return env;
    }
  }
  return join(here, "..", "..");
}

export function findWorkspaceRoot(): string {
  return process.env.GROK_WORKSPACE_ROOT || process.env.CYBERGROK_WORKSPACE || process.cwd();
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
  const pluginRoot = findPluginRoot();
  const workspace = args.workspace || findWorkspaceRoot();
  const python = findPython();
  const payload = JSON.stringify({
    op,
    args: { ...args, workspace, plugin_root: pluginRoot },
  });
  const result = spawnSync(python, ["-m", "cybergrok", "rpc"], {
    cwd: pluginRoot,
    encoding: "utf-8",
    input: payload,
    timeout: 120_000,
    env: {
      ...process.env,
      CYBERGROK_ROOT: pluginRoot,
      GROK_WORKSPACE_ROOT: String(workspace),
      PYTHONPATH: [join(pluginRoot, "python"), process.env.PYTHONPATH || ""].filter(Boolean).join(
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
  let parsed: { ok: boolean; result?: T; error?: string };
  try {
    parsed = JSON.parse(result.stdout) as { ok: boolean; result?: T; error?: string };
  } catch {
    throw new Error(`Python RPC returned non-JSON: ${(result.stdout || "").slice(0, 200)}`);
  }
  if (!parsed.ok) {
    throw new Error(parsed.error || "Python RPC failed");
  }
  return parsed.result as T;
}
