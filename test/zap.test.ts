import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { runInNewContext } from "node:vm";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ZapAdapter,
  allowedActiveUrl,
  buildZapGuardScript,
  interactiveActiveCandidate,
  selectActiveTargets,
} from "../src/zap.js";
import { Redactor } from "../src/redact.js";
import { BrowserRecorder } from "../src/browser.js";
import { startFixture } from "../src/fixture.js";
import type { Evidence, ProjectConfig, ScanData } from "../src/types.js";

const config = (target = "http://example.test"): ProjectConfig => ({
  name: "ZAP test",
  target,
  includePaths: ["/"],
  excludePaths: ["/private"],
  roles: {
    userA: {
      type: "form",
      secretRef: "a",
      loginPath: "/login",
      probePath: "/api/me",
      probeContains: "AUTHENTICATED_userA",
    },
  },
  secretsFile: "unused",
  mode: "active",
  allowedActions: [],
  sensitiveSelectors: [],
  limits: { statesPerRole: 10, actions: 30, minutes: 2, requestsPerSecond: 20 },
  zap: {
    apiUrl: "http://127.0.0.1:18090",
    proxyUrl: "http://127.0.0.1:18090",
    apiKeyEnv: "ZAP_TEST_KEY",
  },
  tests: { xss: { role: "userA", path: "/search", parameter: "q" } },
});
const data = (): ScanData => ({
  schemaVersion: 1,
  id: "test",
  name: "test",
  target: "http://example.test",
  status: "running",
  startedAt: new Date(Date.now() - 1000).toISOString(),
  screens: [],
  observations: [],
  transitions: [],
  evidence: [],
  findings: [],
  assessments: [],
  blockers: [],
  jobs: [],
  coverage: { actions: 0, complete: false, notes: [] },
  asvsVersion: "5.0.0",
});

test("active endpoint policy rejects origin changes, encoded forbidden paths and mutations", () => {
  const c = config();
  assert.equal(allowedActiveUrl(c, "http://example.test/search?q=test"), true);
  for (const url of [
    "https://example.test/search",
    "http://other.test/search",
    "http://example.test/private/info",
    "http://example.test/%6cogout",
    "http://example.test/invoices/42/pay",
  ])
    assert.equal(allowedActiveUrl(c, url), false, url);
});

test("active candidate selection ignores cache-busting static assets and keeps interactive parameters", () => {
  const candidate = (url: string, contentType: string): Evidence => ({
    id: "e",
    kind: "http",
    url,
    method: "GET",
    responseHeaders: { "content-type": contentType },
    at: new Date().toISOString(),
  });
  assert.equal(
    interactiveActiveCandidate(
      candidate("http://example.test/app.css?id=123", "text/css"),
    ),
    false,
  );
  assert.equal(
    interactiveActiveCandidate(
      candidate("http://example.test/page?id=123", "text/html"),
    ),
    false,
  );
  assert.equal(
    interactiveActiveCandidate(
      candidate("http://example.test/search?q=invoice", "text/html"),
    ),
    true,
  );
});

test("deep active profile deduplicates request shapes and requires exact POST allowlisting", () => {
  const c = config();
  c.allowedActions = ["/brands/save"];
  c.tests = {
    activeScan: {
      role: "userA",
      profile: "deep",
      attackStrength: "MEDIUM",
      scannerIds: [],
      methods: ["GET", "POST"],
      includePathEndpoints: true,
      maxEndpoints: 20,
      discoveryPaths: ["/.env"],
    },
  };
  const item = (
    method: string,
    url: string,
    requestBody?: string,
  ): Evidence => ({
    id: Math.random().toString(),
    kind: "http",
    role: "userA",
    method,
    url,
    requestBody,
    requestHeaders: requestBody
      ? { "content-type": "application/x-www-form-urlencoded" }
      : undefined,
    responseHeaders: { "content-type": "text/html" },
    at: new Date().toISOString(),
  });
  const selected = selectActiveTargets(c, [
    item("GET", "http://example.test/brands"),
    item("GET", "http://example.test/brands?name=one"),
    item("GET", "http://example.test/brands?name=two"),
    item("POST", "http://example.test/brands/save", "name=a&_token=one"),
    item("POST", "http://example.test/brands/save", "_token=two&name=b"),
    item("POST", "http://example.test/users/save", "name=a"),
    item("POST", "http://example.test/brands/save", "name=a&_token=[REDACTED]"),
  ]);
  assert.deepEqual(
    selected.map((target) => [target.method, new URL(target.url).pathname]),
    [
      ["GET", "/brands"],
      ["GET", "/brands"],
      ["POST", "/brands/save"],
      ["GET", "/.env"],
    ],
  );
  assert.equal(selected[1].url, "http://example.test/brands?name=two");
  assert.equal(selected[2].postData, "_token=two&name=b");
});

test("HTTP sender guard strips correlation, injects role credentials and prevents requests and redirect escapes", () => {
  const vars: Record<string, string> = {
    "unit.alive": String(Date.now()),
    "unit.auth": JSON.stringify({
      cookies: [
        {
          name: "session",
          value: "sensitive-value",
          domain: "example.test",
          path: "/",
          expires: -1,
        },
      ],
      bearer: "bearer-value",
    }),
  };
  class URI {
    constructor(public value: string) {}
    toString() {
      return this.value;
    }
    private url() {
      return new URL(this.value);
    }
    getScheme() {
      return this.url().protocol.slice(0, -1);
    }
    getPort() {
      return this.url().port ? Number(this.url().port) : -1;
    }
    getHost() {
      return this.url().hostname;
    }
    getRawUserInfo() {
      return this.url().username || null;
    }
    getRawPath() {
      return this.url().pathname;
    }
    getPath() {
      return decodeURIComponent(this.url().pathname);
    }
    resolve(location: string) {
      return new URI(new URL(location, this.value).href);
    }
  }
  const context: any = {
    Java: {
      type: (name: string) =>
        name.endsWith("ScriptVars")
          ? {
              getGlobalVar: (key: string) => vars[key],
              setGlobalVar: (key: string, value: string) => (vars[key] = value),
            }
          : name.endsWith("ReentrantLock")
            ? class {
                lock() {}
                unlock() {}
              }
            : name === "java.lang.Thread"
              ? { sleep: () => {} }
              : URI,
    },
  };
  runInNewContext(buildZapGuardScript(config(), "unit"), context);
  const message = (url: string, method = "GET") => {
    let uri = new URI(url);
    const h: Record<string, unknown> = {
      "x-flowaudit-correlation": "never-forward",
    };
    const response: Record<string, unknown> = {};
    return {
      h,
      response,
      getRequestHeader: () => ({
        getURI: () => uri,
        setURI: (u: URI) => (uri = u),
        getMethod: () => method,
        setHeader: (k: string, v: unknown) => (h[k] = v),
      }),
      getResponseHeader: () => ({
        getHeader: (k: string) => response[k],
        setHeader: (k: string, v: unknown) => (response[k] = v),
      }),
    };
  };
  const good = message("http://example.test/search?q=test");
  context.sendingRequest(good, 2, null);
  assert.equal(good.h.Cookie, "session=sensitive-value");
  assert.equal(good.h.Authorization, "Bearer bearer-value");
  assert.equal(good.h["x-flowaudit-correlation"], null);
  for (const [url, method] of [
    ["http://evil.test/", "GET"],
    ["http://example.test/logout", "GET"],
    ["http://example.test/search", "POST"],
  ]) {
    const bad = message(url, method);
    context.sendingRequest(bad, 2, null);
    assert.match(
      String(bad.getRequestHeader().getURI()),
      /^flowaudit-blocked:/,
    );
    assert.equal(bad.h.Cookie, null);
  }
  good.response.Location = "http://evil.test/";
  context.responseReceived(good, 2, null);
  assert.equal(good.response.Location, null);
  vars["unit.alive"] = "0";
  const stale = message("http://example.test/search");
  context.sendingRequest(stale, 2, null);
  assert.match(
    String(stale.getRequestHeader().getURI()),
    /^flowaudit-blocked:/,
  );
  assert.ok(!buildZapGuardScript(config(), "unit").includes("sensitive-value"));
});

test("initialization happens once before capture; passive alerts require current evidence and stay redacted and unconfirmed", async () => {
  const scan = data();
  let probeOk = true;
  let queue = 0;
  let resets = 0;
  const server = createServer(async (req, res) => {
    const endpoint = new URL(req.url!, "http://localhost");
    let body = "";
    for await (const part of req) body += part;
    const params = new URLSearchParams(body);
    assert.equal(params.get("apikey"), "test-api-secret");
    assert.equal(req.headers.host, "zap");
    let value: unknown = { Result: "OK" };
    if (endpoint.pathname.includes("/newSession/")) {
      resets++;
      assert.equal(params.get("name"), "");
      assert.equal(params.get("overwrite"), "true");
    }
    if (endpoint.pathname.includes("/version/")) value = { version: "2.17.0" };
    if (endpoint.pathname.includes("/recordsToScan/"))
      value = { recordsToScan: String(queue) };
    if (endpoint.pathname.includes("/alerts/"))
      value = {
        alerts: [
          {
            id: "1",
            pluginId: "40012",
            name: "Reflected XSS",
            risk: "High",
            url: "http://example.test/search?q=x",
            messageId: "1",
            description: "session-secret",
          },
          {
            id: "2",
            pluginId: "40012",
            url: "http://example.test/search?q=old",
            messageId: "2",
          },
          {
            id: "3",
            pluginId: "40012",
            url: "http://example.test/other?q=x",
            messageId: "3",
          },
        ],
      };
    if (endpoint.pathname.includes("/message/"))
      value = {
        message: {
          timestamp: params.get("id") === "2" ? "1" : String(Date.now()),
          requestHeader: `GET http://example.test/${params.get("id") === "3" ? "other" : "search"}?q=x HTTP/1.1\r\nCookie: session=session-secret\r\n\r\n`,
          responseHeader: "HTTP/1.1 200 OK\r\n\r\n",
          responseBody: "payload",
        },
      };
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(value));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const previousKey = process.env.ZAP_TEST_KEY;
  const c = config();
  c.zap!.apiUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  process.env.ZAP_TEST_KEY = "test-api-secret";
  const fakeSessions = new Map<string, any>();
  const fake = {
    sessions: fakeSessions,
    probe: async () => probeOk,
    blocker: (reason: string) =>
      scan.blockers.push({ reason, at: new Date().toISOString() }),
  } as unknown as BrowserRecorder;
  const adapter = new ZapAdapter(
    c,
    scan,
    fake,
    new Redactor({ secret: "session-secret" }),
    () => {},
  );
  try {
    await Promise.all([adapter.initialize(), adapter.initialize()]);
    assert.equal(resets, 1);
    fakeSessions.set("userA", {});
    const result = await adapter.run("userA", false);
    assert.equal(result.length, 1);
    assert.equal(result[0].status, "needs-review");
    assert.equal(result[0].occurrences, 2);
    assert.equal(result[0].locations?.length, 2);
    assert.equal(result[0].evidenceIds.length, 2);
    assert.equal(result[0].screenId, undefined);
    assert.ok(result[0].asvsIds.length > 0);
    assert.ok(!JSON.stringify(scan).includes("session-secret"));
    assert.equal(scan.jobs[0].status, "completed");
    await adapter.initialize();
    assert.equal(
      resets,
      1,
      "run and repeated initialize must preserve captured history",
    );
    await assert.rejects(
      new ZapAdapter(c, scan, fake, new Redactor({}), () => {}).initialize(),
      /before opening browser roles/,
    );
    probeOk = false;
    await assert.rejects(adapter.run("userA", false), /authentication expired/);
    assert.equal(scan.jobs[1].status, "failed");
    probeOk = true;
    queue = 1;
    const pending = adapter.run("userA", false);
    setTimeout(() => void adapter.stop(), 50);
    await assert.rejects(pending, /cancelled/);
    assert.equal(scan.jobs[2].status, "cancelled");
  } finally {
    if (previousKey === undefined) delete process.env.ZAP_TEST_KEY;
    else process.env.ZAP_TEST_KEY = previousKey;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test(
  "real dedicated ZAP authenticates, actively scans reflected XSS and exports review candidates",
  { skip: process.env.ZAP_INTEGRATION !== "1", timeout: 150000 },
  async () => {
    const fixture = await startFixture({ mode: "vulnerable", host: "0.0.0.0" });
    const outside = await startFixture({ mode: "fixed", host: "0.0.0.0" });
    const dir = await mkdtemp(join(tmpdir(), "flowaudit-zap-"));
    await mkdir(join(dir, "screens"));
    const c = config(fixture.url.replace("0.0.0.0", "host.docker.internal"));
    c.zap!.apiUrl = process.env.ZAP_TEST_API || c.zap!.apiUrl;
    c.zap!.proxyUrl = process.env.ZAP_TEST_PROXY || c.zap!.proxyUrl;
    process.env.ZAP_TEST_KEY = process.env.ZAP_TEST_KEY || "local-demo-zap-key";
    const scan = data();
    scan.target = c.target;
    const secrets = { a: { username: "userA", password: "Demo-pass-123!" } };
    const redactor = new Redactor(secrets);
    const recorder = new BrowserRecorder(
      c,
      scan,
      dir,
      secrets,
      redactor,
      () => {},
    );
    const adapter = new ZapAdapter(c, scan, recorder, redactor, () => {});
    try {
      await adapter.initialize();
      await recorder.open("userA");
      await recorder.navigate(
        "userA",
        new URL("/search?q=invoice", c.target).href,
      );
      const internal = adapter as unknown as {
        installGuard: (role: string) => Promise<void>;
        heartbeat: (role: string, force?: boolean) => Promise<void>;
        guardState: () => Promise<void>;
        cleanup: () => Promise<void>;
        guardKey: string;
        api: (
          component: string,
          type: string,
          name: string,
          params?: Record<string, string>,
        ) => Promise<any>;
      };
      const send = (url: string, method = "GET") =>
        internal.api("core", "action", "sendRequest", {
          request: `${method} ${url} HTTP/1.1\r\nHost: ${new URL(url).host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
          followRedirects: "false",
        });
      const metrics = async (base: string) =>
        (await (
          await fetch(`${base.replace("0.0.0.0", "127.0.0.1")}/api/metrics`)
        ).json()) as {
          requests: number;
          payRequests: number;
          leakedCorrelationHeaders: number;
        };
      await internal.installGuard("userA");
      try {
        await internal.heartbeat("userA", true);
        const before = await metrics(outside.url);
        await send(
          `${outside.url.replace("0.0.0.0", "host.docker.internal")}/health`,
        ).catch(() => {});
        assert.equal(
          (await metrics(outside.url)).requests,
          before.requests + 1,
          "out-of-scope origin must receive no scan request",
        );
        const invoices = (await recorder
          .session("userA")
          .page.evaluate(
            async () => await (await fetch("/api/invoices")).json(),
          )) as Array<{ id: string }>;
        await internal.heartbeat("userA", true);
        await send(
          new URL(`/api/invoices/${invoices[0].id}/pay`, c.target).href,
          "POST",
        ).catch(() => {});
        assert.equal(
          (await metrics(fixture.url)).payRequests,
          0,
          "forbidden payment request must not reach fixture",
        );
        const redirect = await send(
          new URL("/redirect-external", c.target).href,
        );
        assert.ok(
          !/\r?\nlocation:/i.test(
            redirect.sendRequest?.[0]?.responseHeader ?? "",
          ),
          "external redirect Location must be removed",
        );
        await internal.api("script", "action", "setGlobalVar", {
          varKey: `${internal.guardKey}.alive`,
          varValue: "0",
        });
        const beforeExpiry = await metrics(fixture.url);
        await send(new URL("/api/me", c.target).href).catch(() => {});
        assert.equal(
          (await metrics(fixture.url)).requests,
          beforeExpiry.requests + 1,
          "expired heartbeat must stop dispatch",
        );
        await internal.guardState();
      } finally {
        await internal.cleanup();
      }
      const findings = await adapter.run("userA", true);
      assert.equal(scan.jobs[0].status, "completed");
      assert.ok(findings.some((f) => f.ruleId === "40012"));
      assert.ok(findings.every((f) => f.status === "needs-review"));
      assert.ok(
        scan.evidence.some((e) =>
          e.note?.includes(
            "Independent ZAP authentication probe: authenticated",
          ),
        ),
      );
      assert.ok(!JSON.stringify(scan).includes("Demo-pass-123!"));
      assert.equal((await metrics(fixture.url)).leakedCorrelationHeaders, 0);
    } finally {
      await adapter.stop();
      await recorder.close();
      await fixture.close();
      await outside.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
