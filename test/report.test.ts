import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { chromium } from "playwright";
import { generateReport, scriptSafeJson } from "../src/report.js";
import type { ScanData } from "../src/types.js";

const malicious =
  '</script><script>window.reportPayloadExecuted=true</script><img src="https://example.invalid/leak" onerror="window.reportPayloadExecuted=true">';
const root = fileURLToPath(new URL("..", import.meta.url));
const image = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==",
  "base64",
);

function fixtureData(): ScanData {
  const at = "2026-09-11T12:00:00.000Z";
  return {
    schemaVersion: 1,
    id: "report-test",
    name: `Invoice scan ${malicious}`,
    target: "http://127.0.0.1:3000",
    status: "interrupted",
    startedAt: at,
    screens: [
      {
        id: "error",
        kind: "browser-response",
        role: "userA",
        url: "http://127.0.0.1:3000/invoices/1",
        title: "Live error response",
        text: malicious,
        fingerprint: "error",
        screenshot: "screen.png",
        actions: [],
        observedAt: at,
        captureNote: "Live browser screenshot; sensitive fields masked",
        evidenceIds: ["http-1"],
      },
      {
        id: "login",
        role: "userA",
        url: "http://127.0.0.1:3000/login",
        title: "Login",
        text: "Sign in",
        fingerprint: "1",
        screenshot: "screen.png",
        actions: [],
        observedAt: at,
      },
      {
        id: "invoice",
        role: "userA",
        url: "http://127.0.0.1:3000/invoices/1",
        title: "Invoice detail",
        text: malicious,
        fingerprint: "2",
        screenshot: "screen.png",
        actions: [
          { id: "edit", kind: "click", label: "Edit note", selector: "#edit" },
        ],
        observedAt: at,
      },
      {
        id: "other",
        role: "userB",
        url: "http://127.0.0.1:3000/",
        title: "Other organization",
        text: "Private",
        fingerprint: "3",
        screenshot: "missing.png",
        actions: [],
        observedAt: at,
      },
    ],
    observations: [
      { screenId: "login", at },
      { screenId: "invoice", at },
      { screenId: "other", at },
    ],
    transitions: [
      {
        id: "verify-error",
        kind: "verification",
        role: "userA",
        from: "invoice",
        to: "error",
        action: "Verify input",
        evidenceIds: ["http-1"],
        at,
      },
      {
        id: "entry",
        role: "userA",
        from: null,
        to: "login",
        action: "Open session",
        evidenceIds: [],
        at,
      },
      {
        id: "login-click",
        role: "userA",
        from: "login",
        to: "invoice",
        action: "Sign in",
        evidenceIds: ["http-1"],
        at,
      },
    ],
    evidence: [
      {
        id: "http-1",
        kind: "http",
        role: "userA",
        method: "GET",
        url: "http://127.0.0.1:3000/invoices/1",
        status: 200,
        responseBody: malicious,
        at,
      },
    ],
    findings: [
      {
        id: "finding-1",
        resultScreenId: "error",
        title: "Reflected XSS",
        severity: "high",
        status: "confirmed",
        source: "verifier",
        ruleId: "xss",
        role: "userA",
        screenId: "invoice",
        evidenceIds: ["http-1"],
        asvsIds: ["1.2.1"],
        steps: ["Login", malicious],
        description: malicious,
      },
      {
        id: "finding-2",
        title: "Unlinked observation",
        severity: "low",
        status: "needs-review",
        source: "zap",
        ruleId: "10000",
        evidenceIds: [],
        asvsIds: [],
        steps: [],
        description: "No known screen.",
      },
    ],
    assessments: [
      {
        id: "1.2.1",
        chapter: "Encoding",
        section: "Injection prevention",
        text: "Verify output encoding",
        level: 1,
        status: "not-tested",
        method: "Browser and source review",
        evidenceNeeded: "Source evidence",
        evidenceIds: [],
        rationale: "",
        scope: "",
      },
      {
        id: "7.2.1",
        chapter: "Session",
        section: "Invalidation",
        text: "Verify logout invalidates sessions",
        level: 1,
        status: "fail",
        method: "Replay session",
        evidenceNeeded: "HTTP evidence",
        evidenceIds: ["http-1"],
        rationale: "Replay succeeded",
        scope: "userA",
      },
    ],
    blockers: [
      {
        role: "userA",
        reason: "Action budget reached",
        action: "Next page",
        at,
      },
    ],
    jobs: [
      {
        id: "job-1",
        kind: "exploration",
        status: "interrupted",
        error: "Worker stopped",
      },
    ],
    coverage: {
      actions: 1,
      complete: false,
      notes: ["Only two paths were explored."],
    },
    asvsVersion: "5.0.0",
  };
}

test.before(async () => {
  await promisify(execFile)(
    process.execPath,
    [join(root, "scripts/build-report.mjs")],
    { cwd: root },
  );
});

test("script-safe serialization preserves data without allowing script termination", () => {
  const original = { text: `${malicious} & > \u2028 \u2029` };
  const encoded = scriptSafeJson(original);
  assert.equal(encoded.includes("<"), false);
  assert.equal(encoded.includes("&"), false);
  assert.deepEqual(JSON.parse(encoded), original);
});

test("offline export embeds only in-scope raster screenshots and preserves partial structured results", async () => {
  const directory = await mkdtemp(join(tmpdir(), "security-report-"));
  const outside = join(
    dirname(directory),
    `outside-${directory.split("/").at(-1)}.png`,
  );
  try {
    await writeFile(join(directory, "screen.png"), image);
    await writeFile(outside, "must-not-be-embedded");
    await symlink(outside, join(directory, "escape.png"));
    const data = fixtureData();
    data.screens.push({
      ...data.screens[0],
      id: "unsafe",
      kind: "browser",
      screenshot: "escape.png",
    });
    data.screens.push({
      ...data.screens[0],
      id: "legacy-preview",
      kind: "http-response",
    });
    data.findings[1].resultScreenId = "legacy-preview";
    const report = await generateReport(data, directory);
    const html = await readFile(report.html, "utf8");
    const payload = JSON.parse(
      html.match(/<script id="scan-data"[^>]*>([\s\S]*?)<\/script>/)![1],
    );
    assert.equal(
      payload.screenshots.login,
      `data:image/png;base64,${image.toString("base64")}`,
    );
    assert.equal(payload.screenshots.unsafe, undefined);
    assert.equal(payload.reportWarnings.length, 2);
    assert.equal(html.includes("must-not-be-embedded"), false);
    assert.equal(html.includes(malicious), false);
    assert.match(html, /connect-src 'none'/);
    assert.match(html, /script-src 'nonce-/);
    assert.equal((html.match(/<script id="scan-data"/g) ?? []).length, 1);
    const exported = JSON.parse(
      await readFile(report.json, "utf8"),
    ) as ScanData;
    assert.equal(
      exported.screens.filter((s) => s.kind === "browser-response").length,
      1,
    );
    assert.ok(exported.findings[0].resultScreenId);
    assert.equal(exported.findings[1].resultScreenId, undefined);
    assert.equal(
      exported.screens.some((s) => s.id === "legacy-preview"),
      false,
      "legacy synthetic images must not survive export",
    );
    assert.equal(
      data.findings[0].resultScreenId,
      "error",
      "export must not change live scan state",
    );
    assert.deepEqual(exported.evidence, data.evidence);
    assert.equal(payload.coverage.complete, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});

test(
  "report runs offline, filters graph and ASVS, exposes evidence, and does not execute captured payloads",
  {
    skip: !existsSync(chromium.executablePath())
      ? "Install Playwright Chromium to run report browser verification"
      : false,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "security-report-browser-"));
    const browser = await chromium.launch({ headless: true });
    try {
      await writeFile(join(directory, "screen.png"), image);
      const report = await generateReport(fixtureData(), directory);
      const page = await browser.newPage({
        viewport: { width: 1440, height: 1050 },
      });
      const network: string[] = [];
      const errors: string[] = [];
      page.on("request", (request) => {
        if (/^https?:/.test(request.url())) network.push(request.url());
      });
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(pathToFileURL(report.html).href);
      await page
        .getByRole("heading", { name: "Explore the application" })
        .waitFor();
      assert.equal(await page.locator(".react-flow__node").count(), 4);
      await page
        .locator(".react-flow__node")
        .first()
        .waitFor({ state: "visible" });
      assert.ok(
        await page.locator(".screenshot-library img").first().isVisible(),
      );
      await page.getByLabel("Filter graph by role").selectOption("userA");
      assert.equal(await page.locator(".react-flow__node").count(), 3);
      await page.getByLabel("Highlight finding path").selectOption("finding-1");
      assert.equal(await page.locator(".screen-node.highlighted").count(), 3);
      await page
        .getByRole("button", { name: "Findings", exact: false })
        .click();
      await page
        .getByRole("button", { name: /high confirmed Reflected XSS/ })
        .click();
      assert.equal(
        await page
          .locator(".finding-detail")
          .innerText()
          .then((text) => text.includes(malicious)),
        true,
      );
      assert.equal(
        await page.locator(".finding-detail .visual-card").count(),
        2,
      );
      await page
        .locator(".finding-detail .visual-card")
        .last()
        .getByRole("button")
        .click();
      await page.getByRole("dialog").waitFor({ state: "visible" });
      await page
        .getByRole("button", { name: "Close screenshot ×", exact: true })
        .click();
      await page.locator(".evidence-list summary").click();
      assert.equal(
        await page.locator(".evidence-body pre").last().textContent(),
        malicious,
      );
      await page
        .getByRole("button", { name: "ASVS checklist", exact: false })
        .click();
      await page.getByLabel("Search ASVS requirements").fill("logout");
      assert.equal(await page.locator(".requirement").count(), 1);
      await page.getByLabel("Filter ASVS status").selectOption("not-tested");
      await page
        .getByText("No matching requirements", { exact: true })
        .waitFor();
      await page
        .getByRole("button", { name: "Coverage & jobs", exact: false })
        .click();
      await page.getByText("Action budget reached", { exact: true }).waitFor();
      assert.equal(
        await page.evaluate(
          () =>
            (window as unknown as Record<string, unknown>)
              .reportPayloadExecuted,
        ),
        undefined,
      );
      assert.deepEqual(network, []);
      assert.deepEqual(errors, []);
      assert.equal(await page.locator("script").count(), 2);
      await page.setViewportSize({ width: 390, height: 844 });
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
        true,
        JSON.stringify(
          await page.evaluate(() =>
            [...document.querySelectorAll("*")]
              .filter(
                (element) =>
                  element.getBoundingClientRect().right > innerWidth + 1,
              )
              .map((element) => ({
                tag: element.tagName,
                class: element.className,
              }))
              .slice(0, 12),
          ),
        ),
      );
    } finally {
      await browser.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
