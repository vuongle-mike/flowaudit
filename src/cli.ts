#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chromium } from "playwright";
import { runSimpleCli } from "./simple.js";
if (process.argv[2] === "doctor") {
  const checks: { name: string; ok: boolean; detail: string }[] = [];
  checks.push({
    name: "Node >=20.19",
    ok: Number(process.versions.node.split(".")[0]) >= 20,
    detail: process.versions.node,
  });
  const browser = process.env.CHROMIUM_PATH || chromium.executablePath();
  checks.push({ name: "Chromium", ok: existsSync(browser), detail: browser });
  try {
    checks.push({
      name: "Docker",
      ok: true,
      detail: execFileSync(
        "docker",
        ["version", "--format", "{{.Server.Version}}"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 10000 },
      ).trim(),
    });
  } catch {
    checks.push({
      name: "Docker",
      ok: false,
      detail: "Docker daemon unavailable; local mode still supported",
    });
  }
  if (process.env.ZAP_API_URL) {
    try {
      const u = new URL("/JSON/core/view/version/", process.env.ZAP_API_URL);
      u.searchParams.set("apikey", process.env.ZAP_API_KEY || "");
      const r = await fetch(u, {
        headers: { host: "zap" },
        signal: AbortSignal.timeout(5000),
      });
      const data = await r.json();
      checks.push({
        name: "ZAP",
        ok: !!data.version,
        detail: JSON.stringify(data),
      });
    } catch {
      checks.push({ name: "ZAP", ok: false, detail: "API unavailable" });
    }
  }
  console.log(JSON.stringify(checks, null, 2));
  if (checks.some((x) => !x.ok)) process.exitCode = 1;
} else {
  await runSimpleCli(process.argv.slice(2));
}
