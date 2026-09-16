import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BrowserRecorder } from "../src/browser.js";
import { Redactor } from "../src/redact.js";
import { createAssessments } from "../src/asvs.js";
import type { ProjectConfig, ScanData } from "../src/types.js";

test("POST templates retain a usable token only in memory, with redacted evidence and cleanup", async () => {
  const token = "fresh-csrf-template-secret";
  let submitted = "";
  const server = createServer(async (req, res) => {
    if (req.method === "POST") {
      for await (const chunk of req) submitted += chunk;
      res.end("Saved test record");
      return;
    }
    res.setHeader("content-type", "text/html");
    res.end(
      `<h1>Authenticated fixture</h1><form method="post" action="/save"><input type="hidden" name="_token" value="${token}"><input name="name" value="scan-test"><button>Save</button></form>`,
    );
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const target = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const dir = await mkdtemp(join(tmpdir(), "live-templates-"));
  await mkdir(join(dir, "screens"));
  const config: ProjectConfig = {
    name: "templates",
    target,
    includePaths: ["/"],
    excludePaths: [],
    roles: {
      admin: {
        type: "cookie",
        secretRef: "admin",
        probePath: "/",
        probeContains: "Authenticated fixture",
      },
    },
    secretsFile: "unused",
    mode: "active",
    allowedActions: ["/save"],
    sensitiveSelectors: [],
    limits: {
      statesPerRole: 10,
      actions: 20,
      minutes: 2,
      requestsPerSecond: 20,
    },
  };
  const data: ScanData = {
    schemaVersion: 1,
    id: "template-test",
    name: "templates",
    target,
    status: "running",
    startedAt: new Date().toISOString(),
    screens: [],
    observations: [],
    transitions: [],
    evidence: [],
    findings: [],
    assessments: createAssessments(),
    blockers: [],
    jobs: [],
    coverage: { actions: 0, complete: false, notes: [] },
    asvsVersion: "5.0.0",
  };
  const recorder = new BrowserRecorder(
    config,
    data,
    dir,
    { admin: { cookies: [] } },
    new Redactor({}),
    () => {},
  );
  try {
    const screen = await recorder.open("admin");
    const save = screen.actions.find((a) => a.label === "Save");
    assert.ok(save);
    await recorder.act("admin", save.id);
    assert.equal(new URLSearchParams(submitted).get("_token"), token);
    const raw = [...recorder.liveRequests.values()].find(
      (e) => e.method === "POST",
    );
    assert.ok(raw);
    assert.ok(raw.requestBody?.includes(token));
    assert.ok(!JSON.stringify(data).includes(token));
    assert.ok(
      data.evidence.some(
        (e) => e.method === "POST" && e.requestBody?.includes("[REDACTED]"),
      ),
    );
    await recorder.close();
    assert.equal(recorder.liveRequests.size, 0);
  } finally {
    await recorder.close();
    await new Promise<void>((r) => server.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});
