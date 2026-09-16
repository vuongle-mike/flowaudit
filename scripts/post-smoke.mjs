import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { BrowserRecorder } from "../dist/src/browser.js";
import { ZapAdapter } from "../dist/src/zap.js";
import { Redactor } from "../dist/src/redact.js";
import { createAssessments } from "../dist/src/asvs.js";
let current = "",
  refreshes = 0,
  accepted = 0,
  rejected = 0;
const multipart = process.env.POST_SMOKE_MULTIPART === "1";
const tokens = [];
const server = createServer(async (req, res) => {
  res.setHeader("content-type", "text/html");
  if (!req.headers.cookie?.includes("fixture_session=smoke-session")) {
    res.writeHead(401);
    res.end("unauthenticated");
    return;
  }
  if (req.url === "/me") {
    res.end("AUTHENTICATED_fixture");
    return;
  }
  if (req.method === "POST" && req.url === "/save") {
    let body = "";
    for await (const part of req) body += part;
    const fields = new URLSearchParams(body);
    if (multipart) {
      const boundary = req.headers["content-type"].match(/boundary=(.+)$/)?.[1];
      for (const part of body.split("--" + boundary)) {
        const match = /name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n$/.exec(part);
        if (match) fields.set(match[1], match[2]);
      }
    }
    if (!current || fields.get("_token") !== current) {
      rejected++;
      res.writeHead(419);
      res.end("Invalid CSRF");
      return;
    }
    current = "";
    accepted++;
    res.end(`<html><body>Saved: ${fields.get("name")}</body></html>`);
    return;
  }
  current = randomUUID();
  tokens.push(current);
  refreshes++;
  res.end(
    `<html><body><h1>POST fixture</h1><form action="/save" method="POST" ${multipart ? 'enctype="multipart/form-data"' : ""}><input type="hidden" name="_token" value="${current}"><input name="name" value="smoke"><button>Save</button></form></body></html>`,
  );
});
await new Promise((r) => server.listen(0, "0.0.0.0", r));
const target = `http://scanner:${server.address().port}`;
const dir = await mkdtemp(join(tmpdir(), "post-smoke-"));
await mkdir(join(dir, "screens"));
const config = {
  name: "post-csrf-smoke",
  target,
  includePaths: ["/"],
  excludePaths: [],
  roles: {
    admin: {
      secretRef: "admin",
      type: "cookie",
      probePath: "/me",
      probeContains: "AUTHENTICATED_fixture",
    },
  },
  secretsFile: "unused",
  mode: "active",
  allowedActions: ["/save"],
  sensitiveSelectors: [],
  limits: { statesPerRole: 10, actions: 40, minutes: 3, requestsPerSecond: 20 },
  zap: {
    apiUrl: "http://zap:8080",
    proxyUrl: "http://zap:8080",
    apiKeyEnv: "ZAP_API_KEY",
  },
  tests: {
    activeScan: {
      profile: "deep",
      attackStrength: "LOW",
      scannerIds: ["40012"],
      methods: ["GET", "POST"],
      includePathEndpoints: false,
      maxEndpoints: 5,
      discoveryPaths: [],
    },
  },
};
const secrets = {
  admin: {
    cookies: [
      {
        name: "fixture_session",
        value: "smoke-session",
        domain: "scanner",
        path: "/",
      },
    ],
  },
};
const data = {
  schemaVersion: 1,
  id: randomUUID(),
  name: config.name,
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
const redactor = new Redactor(secrets),
  r = new BrowserRecorder(config, data, dir, secrets, redactor, () => {}),
  z = new ZapAdapter(config, data, r, redactor, () => {});
r.prepare = () => z.initialize();
try {
  let screen = await r.open("admin");
  const save = screen.actions.find((a) => a.label === "Save");
  assert.ok(save);
  await r.act("admin", save.id);
  assert.equal(accepted, 1);
  await z.run("admin", true);
  const result = data.findings;
  console.log(
    JSON.stringify({
      multipart,
      refreshes,
      accepted,
      rejected,
      findings: result.map((f) => ({ rule: f.ruleId, status: f.status })),
      notes: data.coverage.notes,
    }),
  );
  assert.ok(
    accepted >= 3,
    "Browser baseline plus active payloads must pass single-use CSRF validation",
  );
  assert.equal(rejected, 0, "No stale CSRF request may be submitted");
  assert.ok(refreshes >= accepted, "Fresh form fetches must accompany POSTs");
  assert.ok(
    result.some((f) => f.ruleId === "40012"),
    "Actual ZAP must detect reflected XSS in POST",
  );
  for (const t of tokens)
    assert.ok(!JSON.stringify(data).includes(t), "No token may be persisted");
} finally {
  await z.stop();
  await r.close();
  await new Promise((r) => server.close(() => r()));
  await rm(dir, { recursive: true, force: true });
}
