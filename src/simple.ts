import { execFile, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { createInterface } from "node:readline/promises";
import { chromium, type BrowserContext } from "playwright";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ProjectConfig } from "./types.js";
import { exploreProject, runChecks, type ToolCaller } from "./autopilot.js";
import { findProjectRoot, projectDirectory, slugify } from "./project.js";

type Flags = Record<string, string | boolean>;

function parse(argv: string[]) {
  const positional: string[] = [];
  const flags: Flags = {};
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index];
    if (!value.startsWith("--")) positional.push(value);
    else {
      const [raw, inline] = value.slice(2).split("=", 2);
      const next = argv[index + 1];
      if (inline !== undefined) flags[raw] = inline;
      else if (next && !next.startsWith("--")) {
        flags[raw] = next;
        index++;
      } else flags[raw] = true;
    }
  }
  return { positional, flags };
}

function csv(value: string | boolean | undefined, fallback: string[] = []) {
  return typeof value === "string"
    ? value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    : fallback;
}

function uniqueMarker(
  authenticated: string,
  anonymous: string,
): string | undefined {
  const publicLines = new Set(
    anonymous
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );
  return authenticated
    .split("\n")
    .map((line) => line.trim())
    .find(
      (line) =>
        line.length >= 6 && line.length <= 160 && !publicLines.has(line),
    );
}

function ensureComposeEnvironment(root: string) {
  const path = join(root, ".env");
  if (!existsSync(path))
    writeFileSync(
      path,
      `ZAP_API_KEY=${randomBytes(24).toString("hex")}\nFIXTURE_MODE=vulnerable\n`,
      { mode: 0o600 },
    );
}

function bearerFromState(
  state: Awaited<ReturnType<BrowserContext["storageState"]>>,
) {
  for (const origin of state.origins) {
    for (const entry of origin.localStorage) {
      if (!/token|authorization|access.?key/i.test(entry.name)) continue;
      let value = entry.value;
      try {
        const parsed = JSON.parse(value);
        value =
          parsed.access_token ||
          parsed.accessToken ||
          parsed.token ||
          parsed.jwt ||
          value;
      } catch {}
      if (typeof value === "string") return value.replace(/^Bearer\s+/i, "");
    }
  }
}

async function captureSession(target: string, role: string) {
  if (!process.stdin.isTTY)
    throw Error("Interactive browser login requires a terminal");
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto(target, { waitUntil: "domcontentloaded" });
    console.log(
      `\nBrowser opened for role '${role}'. Log in completely, including MFA.`,
    );
    const prompt = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    await prompt.question(
      "When the protected page is visible, press Enter here: ",
    );
    prompt.close();
    await page.waitForLoadState("domcontentloaded").catch(() => {});
    const current = new URL(page.url());
    const configured = new URL(target);
    if (current.origin !== configured.origin)
      throw Error(
        "Login finished on another origin; cross-origin SSO capture is not supported",
      );
    const authenticatedText = await page.locator("body").innerText();
    const state = await context.storageState();
    const anonymous = await browser.newContext();
    const anonymousPage = await anonymous.newPage();
    await anonymousPage.goto(current.href, { waitUntil: "domcontentloaded" });
    const anonymousText = await anonymousPage.locator("body").innerText();
    await anonymous.close();
    let marker = uniqueMarker(authenticatedText, anonymousText);
    if (!marker) {
      const markerPrompt = createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      marker = await markerPrompt.question(
        "Enter a short text visible only after login: ",
      );
      markerPrompt.close();
    }
    if (!marker)
      throw Error("Could not determine an authenticated-page marker");
    return {
      profile: {
        secretRef: role,
        type: "storageState" as const,
        probePath: `${current.pathname}${current.search}`,
        probeContains: marker,
      },
      credential: { storageState: state, bearer: bearerFromState(state) },
    };
  } finally {
    await browser.close();
  }
}

async function publicSession(target: string, role: string, flags: Flags) {
  const response = await fetch(target, { signal: AbortSignal.timeout(15000) });
  const body = await response.text();
  const final = new URL(response.url);
  if (final.origin !== new URL(target).origin)
    throw Error("Public target redirected to another origin");
  const marker =
    (typeof flags["probe-contains"] === "string" && flags["probe-contains"]) ||
    body.match(/<title[^>]*>([^<]{3,160})<\/title>/i)?.[1]?.trim() ||
    body
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 80);
  if (!marker) throw Error("Public page did not provide a stable probe marker");
  return {
    profile: {
      secretRef: role,
      type: "storageState" as const,
      probePath:
        (typeof flags["probe-path"] === "string" && flags["probe-path"]) ||
        `${final.pathname}${final.search}`,
      probeContains: marker,
    },
    credential: { storageState: { cookies: [], origins: [] } },
  };
}

export async function initProject(
  argv: string[],
  root = findProjectRoot(),
): Promise<{ slug: string; configPath: string }> {
  const { positional, flags } = parse(argv);
  const targetValue = positional[0];
  if (!targetValue)
    throw Error(
      "Usage: flowaudit init <url> [--name project] [--roles user,admin]",
    );
  const target = new URL(targetValue).href;
  if (!["http:", "https:"].includes(new URL(target).protocol))
    throw Error("Target must use HTTP or HTTPS");
  const slug = slugify(
    typeof flags.name === "string" ? flags.name : new URL(target).hostname,
  );
  const directory = projectDirectory(root, slug);
  if (existsSync(join(directory, "project.json")) && !flags.force)
    throw Error(
      `Project '${slug}' already exists; use --force to recapture it`,
    );
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  ensureComposeEnvironment(root);
  const roles = [
    ...new Set(flags.public ? ["anonymous"] : csv(flags.roles, ["user"])),
  ];
  if (!roles.length) throw Error("At least one role is required");
  const profiles: ProjectConfig["roles"] = {};
  const credentials: Record<string, unknown> = {};
  for (const role of roles) {
    const captured = flags.public
      ? await publicSession(target, role, flags)
      : await captureSession(target, role);
    profiles[role] = captured.profile;
    credentials[role] = captured.credential;
  }
  const loginTestPath = flags["login-test"];
  if (loginTestPath === true)
    throw Error(
      "--login-test requires the exact POST path, for example /authenticate",
    );
  const loginRole =
    (typeof flags["login-role"] === "string" && flags["login-role"]) ||
    roles[0];
  if (loginTestPath && !roles.includes(loginRole))
    throw Error(`Login test role '${loginRole}' is not configured`);
  const maxLoginAttempts = Number(flags["max-login-attempts"] || 5);
  if (
    loginTestPath &&
    (!Number.isInteger(maxLoginAttempts) ||
      maxLoginAttempts < 2 ||
      maxLoginAttempts > 10)
  )
    throw Error("--max-login-attempts must be an integer from 2 to 10");
  const config: ProjectConfig = {
    name: typeof flags.name === "string" ? flags.name : slug,
    target,
    includePaths: csv(flags.scope, ["/"]),
    excludePaths: csv(flags.exclude, [
      "/logout",
      "/delete",
      "/payment",
      "/checkout",
      "/admin/reset",
    ]),
    roles: profiles,
    secretsFile: "./secrets.json",
    mode: flags.active || loginTestPath ? "active" : "passive",
    allowedActions: csv(flags.allow),
    sensitiveSelectors: csv(flags.sensitive),
    limits: {
      statesPerRole: 100,
      actions: 300,
      minutes: 30,
      requestsPerSecond: 3,
    },
    zap: {
      apiUrl: "http://zap:8080",
      proxyUrl: "http://zap:8080",
      apiKeyEnv: "ZAP_API_KEY",
    },
    tests: loginTestPath
      ? {
          login: {
            role: loginRole,
            loginPath:
              (typeof flags["login-path"] === "string" &&
                flags["login-path"]) ||
              profiles[loginRole].probePath,
            submitPath: loginTestPath,
            usernameField:
              (typeof flags["username-field"] === "string" &&
                flags["username-field"]) ||
              "email",
            passwordField:
              (typeof flags["password-field"] === "string" &&
                flags["password-field"]) ||
              "password",
            csrfField:
              typeof flags["csrf-field"] === "string"
                ? flags["csrf-field"]
                : undefined,
            maxAttempts: maxLoginAttempts,
            successPath:
              typeof flags["success-path"] === "string"
                ? flags["success-path"]
                : undefined,
            successContains:
              typeof flags["success-contains"] === "string"
                ? flags["success-contains"]
                : undefined,
            failureContains:
              typeof flags["failure-contains"] === "string"
                ? flags["failure-contains"]
                : undefined,
          },
        }
      : undefined,
  };
  if (flags["public-checks"]) {
    if (!flags.public)
      throw Error("--public-checks requires --public (anonymous state)");
    config.mode = "active";
    config.tests ??= {};
    const login = config.tests.login;
    config.tests.publicSurface = {
      role: loginRole,
      files: ["/.gitignore"],
      maxRequests: 30,
      forms: login
        ? [
            {
              pagePath: login.loginPath,
              submitPath: login.submitPath,
              fields: [login.usernameField, login.passwordField],
              headerMutation: true,
            },
          ]
        : [],
    };
  }
  const configPath = join(directory, "project.json");
  const secretsPath = join(directory, "secrets.json");
  writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  writeFileSync(secretsPath, JSON.stringify(credentials, null, 2), {
    mode: 0o600,
  });
  chmodSync(secretsPath, 0o600);
  console.log(`Project '${slug}' is ready.`);
  console.log(`Run: flowaudit run ${slug}`);
  return { slug, configPath };
}

async function connect(root: string) {
  const client = new Client({ name: "flowaudit-cli", version: "0.3.0" });
  const transport = new StdioClientTransport({
    command: "docker",
    args: [
      "compose",
      "--project-directory",
      root,
      "exec",
      "-T",
      "scanner",
      "node",
      "dist/src/mcp.js",
    ],
    cwd: root,
    stderr: "inherit",
  });
  await client.connect(transport);
  const tools: ToolCaller = {
    async call<T>(name: string, args: Record<string, unknown> = {}) {
      const response = await client.callTool({ name, arguments: args });
      const text = (response.content as Array<{ type: string; text?: string }>)
        .filter((item) => item.type === "text")
        .map((item) => item.text || "")
        .join("\n");
      if (response.isError) throw Error(text || `${name} failed`);
      return JSON.parse(text) as T;
    },
  };
  return { client, tools };
}

function loadProject(root: string, value?: string) {
  const projects = join(root, "projects");
  if (!value) throw Error("Usage: flowaudit run <project>");
  const slug = slugify(value);
  const directory = projectDirectory(root, slug);
  const path = join(directory, "project.json");
  if (!existsSync(path))
    throw Error(`Unknown project '${slug}'; run flowaudit init first`);
  return {
    slug,
    directory,
    path,
    config: JSON.parse(readFileSync(path, "utf8")) as ProjectConfig,
  };
}

function hostReport(root: string, containerPath: string) {
  return containerPath.startsWith("/data/")
    ? join(root, "scan-data", containerPath.slice("/data/".length))
    : containerPath;
}

export async function runProject(argv: string[], root = findProjectRoot()) {
  const { positional } = parse(argv);
  const project = loadProject(root, positional[0]);
  console.log("Starting scanner and ZAP…");
  ensureComposeEnvironment(root);
  const services = ["zap", "scanner"];
  if (new URL(project.config.target).hostname === "fixture")
    services.push("fixture");
  await promisify(execFile)(
    "docker",
    [
      "compose",
      "--project-directory",
      root,
      "up",
      "--build",
      "-d",
      "--wait",
      ...services,
    ],
    { cwd: root, timeout: 300000 },
  );
  const { client, tools } = await connect(root);
  let scanId: string | undefined;
  try {
    const created = await tools.call<{ id: string }>("create_scan", {
      configPath: `/projects/${project.slug}/project.json`,
    });
    scanId = created.id;
    console.log(`Scan ${scanId}`);
    await exploreProject(tools, scanId, project.config, console.log);
    await runChecks(tools, scanId, project.config, console.log);
    await tools.call("finish_scan", { scanId });
    const findings = await tools.call<
      Array<{ status: string; severity: string; source: string }>
    >("list_findings", { scanId });
    const report = await tools.call<{ html: string; json: string }>(
      "generate_report",
      { scanId },
    );
    const result = {
      scanId,
      completedAt: new Date().toISOString(),
      confirmed: findings.filter((finding) => finding.status === "confirmed")
        .length,
      review: findings
        .filter((finding) => finding.status === "needs-review")
        .filter((finding) => finding.severity !== "info").length,
      informational: findings.filter(
        (finding) =>
          finding.status === "needs-review" && finding.severity === "info",
      ).length,
      notReproduced: findings.filter(
        (finding) => finding.status === "not-reproduced",
      ).length,
      html: hostReport(root, report.html),
      json: hostReport(root, report.json),
    };
    writeFileSync(
      join(project.directory, "last-run.json"),
      JSON.stringify(result, null, 2),
    );
    console.log(`\nReport: ${result.html}`);
    console.log(
      `Confirmed: ${result.confirmed}; needs review: ${result.review}`,
    );
    console.log(`Informational observations: ${result.informational}`);
    console.log(`Not reproduced: ${result.notReproduced}`);
    return result;
  } catch (error) {
    if (scanId) {
      await tools.call("cancel_scan", { scanId }).catch(() => {});
      const report = await tools
        .call<{ html: string; json: string }>("generate_report", { scanId })
        .catch(() => undefined);
      if (report)
        console.error(`Partial report: ${hostReport(root, report.html)}`);
    }
    throw error;
  } finally {
    await client.close();
  }
}

export function showReport(argv: string[], root = findProjectRoot()) {
  const { positional, flags } = parse(argv);
  const project = loadProject(root, positional[0]);
  const path = join(project.directory, "last-run.json");
  if (!existsSync(path))
    throw Error(`Project '${project.slug}' has no completed run`);
  const result = JSON.parse(readFileSync(path, "utf8"));
  console.log(result.html);
  if (flags.open) {
    const command = process.platform === "darwin" ? "open" : "xdg-open";
    execFileSync(command, [result.html], { stdio: "ignore" });
  }
  return result;
}

export function simpleHelp() {
  console.log(`flowaudit

  flowaudit init <url> [--name NAME] [--roles user,admin]
  flowaudit init <url> --public
  flowaudit init <url> --public --login-test /authenticate [--csrf-field _token]
  flowaudit init <url> --public --public-checks [--login-test /authenticate]
  flowaudit run <project>
  flowaudit report <project> [--open]
  flowaudit doctor

init opens a local browser for each role and captures its authenticated session.
Add --active only for a target explicitly approved for active testing.
--login-test enables 2-10 bounded SQLi/XSS/auth-bypass login attempts and active mode.
Use project.json for advanced scope, verifier and ASVS configuration.`);
}

export async function runSimpleCli(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (command === "init") return initProject(rest);
  if (command === "run") return runProject(rest);
  if (command === "report") return showReport(rest);
  if (!command || command === "help" || command === "--help")
    return simpleHelp();
  throw Error(`Unknown command '${command}'`);
}
