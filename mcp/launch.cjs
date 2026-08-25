#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

function findRoot(start) {
  let dir = path.resolve(start);
  for (;;) {
    const plugin = path.join(dir, "plugin.json");
    const py = path.join(dir, "python", "cybergrok");
    if (fs.existsSync(plugin) && fs.existsSync(py)) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return path.resolve(start, "..");
    }
    dir = parent;
  }
}

const envRoot = process.env.CYBERGROK_ROOT || process.env.GROK_PLUGIN_ROOT;
const root =
  envRoot && fs.existsSync(path.join(envRoot, "python", "cybergrok"))
    ? envRoot
    : findRoot(path.join(__dirname, ".."));

const workspace =
  process.env.GROK_WORKSPACE_ROOT || process.env.CYBERGROK_WORKSPACE || process.cwd();

process.env.CYBERGROK_ROOT = root;
process.env.GROK_WORKSPACE_ROOT = workspace;
const entry = path.join(root, "mcp", "dist", "index.js");
if (!fs.existsSync(entry)) {
  process.stderr.write(
    `cybergrok-mcp: missing ${entry}. Run ./setup.sh (npm run build in mcp/).\n`,
  );
  process.exit(1);
}

const child = spawn(process.execPath, [entry, ...process.argv.slice(2)], {
  stdio: "inherit",
  env: process.env,
  cwd: workspace,
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
