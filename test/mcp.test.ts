import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { chromium } from "playwright";
import { demoConfig } from "../scripts/demo-config.js";
import { startFixture } from "../src/fixture.js";
import type { Assessment, Evidence, ScanData, Screen } from "../src/types.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const browserAvailable = existsSync(
  process.env.CHROMIUM_PATH || chromium.executablePath(),
);

async function connect(store: string, name: string) {
  const client = new Client({ name, version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "dist/src/mcp.js")],
    cwd: root,
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      ),
      SECURITY_SCAN_DATA: store,
    },
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });
  await client.connect(transport);
  return { client, stderr: () => stderr };
}

async function call<T>(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  const response = await client.callTool({ name, arguments: args });
  const text = (response.content as Array<{ type: string; text?: string }>)
    .filter((item) => item.type === "text")
    .map((item) => item.text ?? "")
    .join("\n");
  assert.equal(response.isError, undefined, `${name}: ${text}`);
  return JSON.parse(text) as T;
}

async function stopWorker(store: string) {
  const metaPath = join(store, "worker.json");
  if (!existsSync(metaPath)) return;
  const meta = JSON.parse(await readFile(metaPath, "utf8")) as {
    port: number;
    token: string;
  };
  await fetch(`http://127.0.0.1:${meta.port}/rpc`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${meta.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ method: "shutdown", args: [] }),
    signal: AbortSignal.timeout(10000),
  }).catch(() => {});
  for (let attempt = 0; attempt < 100 && existsSync(metaPath); attempt++)
    await delay(50);
  assert.equal(
    existsSync(metaPath),
    false,
    "Worker must shut down and release its metadata file",
  );
}

test.before(async () => {
  // Exercise the actual compiled stdio process, including its persistent worker.
  await promisify(execFile)(
    process.execPath,
    [join(root, "node_modules/typescript/bin/tsc")],
    { cwd: root },
  );
  await promisify(execFile)(
    process.execPath,
    [join(root, "scripts/build-report.mjs")],
    { cwd: root },
  );
});

test(
  "stdio MCP supports scan, graph, evidence, ASVS and offline export while browser sessions survive client reconnect",
  {
    timeout: 90000,
    skip: !browserAvailable
      ? "Install Playwright Chromium to run MCP browser integration"
      : false,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "security-mcp-"));
    const store = join(directory, "runs");
    const fixture = await startFixture({ mode: "fixed" });
    const configPath = demoConfig(fixture.url, directory);
    let connection: Awaited<ReturnType<typeof connect>> | undefined;
    try {
      connection = await connect(store, "integration-client-first");
      const listed = await connection.client.listTools();
      const names = listed.tools.map((tool) => tool.name);
      for (const name of [
        "create_scan",
        "browser_open",
        "browser_observe",
        "browser_act",
        "browser_screenshot",
        "get_graph",
        "replay_flow",
        "run_zap",
        "run_verifiers",
        "list_asvs",
        "assess_requirement",
        "attach_evidence",
        "generate_report",
      ])
        assert.ok(names.includes(name), `${name} must be discoverable`);
      const created = await call<{ id: string; roles: string[] }>(
        connection.client,
        "create_scan",
        { configPath },
      );
      const scanId = created.id;
      assert.deepEqual(created.roles, ["userA", "userB", "admin"]);
      const duplicate = await connection.client.callTool({
        name: "create_scan",
        arguments: { configPath },
      });
      assert.equal(
        duplicate.isError,
        true,
        "Only one scan may remain active in one worker",
      );
      const overview = await call<Screen>(connection.client, "browser_open", {
        scanId,
        role: "userA",
      });
      const invoice = overview.actions.find((action) =>
        action.label.startsWith("INV-"),
      );
      assert.ok(invoice);
      const detail = await call<Screen>(connection.client, "browser_act", {
        scanId,
        role: "userA",
        actionId: invoice.id,
      });
      assert.notEqual(detail.id, overview.id);
      const metadata = JSON.parse(
        await readFile(join(store, "worker.json"), "utf8"),
      ) as { pid: number; port: number; token: string };
      const rejected = await fetch(`http://127.0.0.1:${metadata.port}/health`, {
        signal: AbortSignal.timeout(3000),
      });
      assert.equal(
        rejected.status,
        401,
        "Local worker must require its private bearer token",
      );
      await connection.client.close();
      connection = await connect(store, "integration-client-reconnected");
      const status = await call<{ status: string; screens: number }>(
        connection.client,
        "scan_status",
        { scanId },
      );
      assert.equal(status.status, "running");
      assert.equal(status.screens, 2);
      assert.equal(
        JSON.parse(await readFile(join(store, "worker.json"), "utf8")).pid,
        metadata.pid,
        "Reconnect should retain the same browser worker",
      );
      const resumed = await call<Screen>(connection.client, "browser_observe", {
        scanId,
        role: "userA",
      });
      assert.equal(
        resumed.id,
        detail.id,
        "Reconnected MCP client must observe its existing authenticated page",
      );
      const edit = resumed.actions.find((action) => action.label === "Edit");
      assert.ok(edit);
      const modal = await call<Screen>(connection.client, "browser_act", {
        scanId,
        role: "userA",
        actionId: edit.id,
      });
      const close = modal.actions.find((action) => action.label === "Close");
      assert.ok(close);
      const returned = await call<Screen>(connection.client, "browser_act", {
        scanId,
        role: "userA",
        actionId: close.id,
      });
      assert.equal(returned.id, detail.id);
      const screenshot = await connection.client.callTool({
        name: "browser_screenshot",
        arguments: { scanId, role: "userA" },
      });
      assert.equal(screenshot.isError, undefined);
      const image = (
        screenshot.content as Array<{
          type: string;
          mimeType?: string;
          data?: string;
        }>
      ).find((item) => item.type === "image");
      assert.ok(image?.data);
      assert.equal(image.mimeType, "image/png");
      assert.deepEqual(
        Buffer.from(image.data, "base64"),
        await readFile(join(store, scanId, returned.screenshot)),
        "Screenshot tool must return current screen after revisiting an earlier state",
      );
      const graph = await call<
        Pick<ScanData, "screens" | "transitions" | "observations">
      >(connection.client, "get_graph", { scanId });
      assert.equal(graph.screens.length, 3);
      assert.ok(graph.observations.length > graph.screens.length);
      assert.ok(
        graph.transitions.some(
          (edge) =>
            edge.from === overview.id &&
            edge.to === detail.id &&
            edge.evidenceIds.length > 0,
        ),
      );
      const checklist = await call<Assessment[]>(
        connection.client,
        "list_asvs",
        { scanId },
      );
      assert.equal(checklist.length, 70);
      assert.ok(checklist.every((item) => item.status === "not-tested"));
      const unsupportedPass = await connection.client.callTool({
        name: "assess_requirement",
        arguments: {
          scanId,
          requirementId: checklist[0].id,
          status: "pass",
          evidenceIds: [],
          rationale: "No alerts",
          scope: "/invoices",
        },
      });
      assert.equal(unsupportedPass.isError, true);
      const evidence = await call<Evidence>(
        connection.client,
        "attach_evidence",
        {
          scanId,
          note: "Inspected fixture output encoding. Test credential Demo-pass-123! must be removed.",
        },
      );
      assert.equal(evidence.note?.includes("Demo-pass-123!"), false);
      const assessment = await call<Assessment>(
        connection.client,
        "assess_requirement",
        {
          scanId,
          requirementId: checklist[0].id,
          status: "needs-review",
          evidenceIds: [evidence.id],
          rationale:
            "Fixture source inspected; production deployment scope remains unreviewed.",
          scope: "Local fixture invoices",
        },
      );
      assert.equal(assessment.status, "needs-review");
      await call(connection.client, "cancel_scan", { scanId });
      const report = await call<{ html: string; json: string }>(
        connection.client,
        "generate_report",
        { scanId },
      );
      const exported = JSON.parse(
        await readFile(report.json, "utf8"),
      ) as ScanData;
      assert.equal(exported.status, "cancelled");
      assert.equal(exported.coverage.complete, false);
      assert.equal(exported.screens.length, 3);
      assert.equal(JSON.stringify(exported).includes("Demo-pass-123!"), false);
      assert.match(
        await readFile(report.html, "utf8"),
        /Content-Security-Policy/,
      );
      const stopped = await connection.client.callTool({
        name: "browser_observe",
        arguments: { scanId, role: "userA" },
      });
      assert.equal(stopped.isError, true);
      const metrics = (await (
        await fetch(`${fixture.url}/api/metrics`, {
          signal: AbortSignal.timeout(3000),
        })
      ).json()) as {
        leakedCorrelationHeaders: number;
        deleteRequests: number;
        payRequests: number;
      };
      assert.equal(metrics.leakedCorrelationHeaders, 0);
      assert.equal(metrics.deleteRequests, 0);
      assert.equal(metrics.payRequests, 0);
      assert.equal(connection.stderr().includes("Demo-pass-123!"), false);
    } finally {
      await connection?.client.close().catch(() => {});
      await stopWorker(store);
      await fixture.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
