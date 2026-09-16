import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFixture } from "../src/fixture.js";
import { Scanner } from "../src/scanner.js";
import {
  runPublicChecks,
  debugDisclosure,
  gitignoreDisclosure,
} from "../src/public-checks.js";

test("debug detector requires stack and file/line evidence, looks beyond asset padding", () => {
  assert.equal(
    debugDisclosure(
      "<script>class na{constructor(t,n){this.parent=t}}</script>",
    ),
    undefined,
  );
  assert.equal(debugDisclosure("Stack Trace: no details available"), undefined);
  const evidence = debugDisclosure(
    "x".repeat(30000) +
      "Stack Trace\n0 - app/Handler.php:44\n## Headers\ncookie: NEVER_EXPORT",
  );
  assert.ok(evidence?.includes("app/Handler.php:44"));
  assert.ok(!evidence?.includes("NEVER_EXPORT"));
  assert.equal(
    gitignoreDisclosure("<html>/vendor\n/node_modules</html>", "text/html"),
    false,
  );
  assert.equal(
    gitignoreDisclosure("/vendor\n/node_modules\n.env", "text/plain"),
    true,
  );
  assert.equal(
    gitignoreDisclosure(
      "assets\nfonts\nmix-manifest.json\n!.gitignore\n",
      "application/octet-stream",
    ),
    true,
  );
});

for (const mode of ["vulnerable", "fixed"] as const)
  test(
    `public surface ${mode}: file and two mutations, fresh CSRF, repeat evidence and redaction`,
    { timeout: 60000 },
    async () => {
      const fixture = await startFixture({ mode });
      const dir = await mkdtemp(join(tmpdir(), "public-scan-"));
      let scanner: Scanner | undefined;
      try {
        await writeFile(
          join(dir, "secrets.json"),
          JSON.stringify({ anonymous: { cookies: [] } }),
        );
        const config = {
          name: "public-fixture",
          target: fixture.url,
          includePaths: ["/"],
          excludePaths: [],
          secretsFile: "./secrets.json",
          mode: "active",
          allowedActions: [],
          sensitiveSelectors: [],
          roles: {
            anonymous: {
              type: "cookie",
              secretRef: "anonymous",
              probePath: "/public-form",
              probeContains: "Public test form",
            },
          },
          limits: {
            requestsPerSecond: 20,
            statesPerRole: 100,
            actions: 100,
            minutes: 2,
          },
          tests: {
            publicSurface: {
              role: "anonymous",
              files: ["/.gitignore"],
              maxRequests: 20,
              forms: [
                {
                  pagePath: "/public-form",
                  submitPath: "/public-submit",
                  fields: ["email"],
                  headerMutation: true,
                },
              ],
            },
          },
        };
        await writeFile(join(dir, "project.json"), JSON.stringify(config));
        scanner = new Scanner(join(dir, "runs"));
        const scan = scanner.create(join(dir, "project.json"));
        const r = scanner.runtime(scan.id).recorder;
        const findings = await runPublicChecks(r);
        assert.equal(findings.length, 3);
        assert.ok(
          findings.every(
            (f) =>
              f.status ===
              (mode === "vulnerable" ? "confirmed" : "not-reproduced"),
          ),
        );
        assert.equal(
          r.data.evidence.some((e) => e.status === 419),
          false,
          "CSRF must be refreshed for every submission",
        );
        if (mode === "vulnerable")
          for (const f of findings) {
            assert.equal(
              f.evidenceIds.length,
              3,
              "control, candidate and confirm required",
            );
            assert.ok(f.detectionReason);
            assert.equal(
              f.asvsIds.length,
              0,
              "do not force L2 debug finding into L1",
            );
          }
        const csrfValues = (await r.session("anonymous").context.cookies()).map(
          (c) => c.value,
        );
        const serialized = JSON.stringify(r.data);
        assert.ok(!serialized.includes("Invalid-flowaudit-only"));
        for (const value of csrfValues) assert.ok(!serialized.includes(value));
        assert.ok(!findings.some((f) => f.ruleId.includes("sql")));
        const report = await scanner.report(scan.id);
        assert.ok(
          (await readFile(report.html, "utf8")).includes("Detection reason"),
        );
        const exported = JSON.parse(await readFile(report.json, "utf8"));
        const previews = exported.screens.filter(
          (s: any) => s.kind === "browser-response",
        );
        assert.equal(previews.length, mode === "vulnerable" ? 2 : 0);
        for (const finding of exported.findings.filter(
          (f: any) => f.status === "confirmed",
        )) {
          if (finding.ruleId === "public-file-disclosure") {
            assert.equal(finding.resultScreenId, undefined);
            continue;
          }
          const screen = previews.find(
            (s: any) => s.id === finding.resultScreenId,
          );
          assert.ok(screen?.captureNote.includes("Live browser screenshot"));
          const edge = exported.transitions.find(
            (t: any) => t.to === screen.id,
          );
          assert.equal(edge.kind, "verification");
          assert.deepEqual(edge.evidenceIds, finding.evidenceIds);
          assert.equal(
            edge.from,
            finding.screenId ?? null,
            "never invent a source screen for direct file requests",
          );
        }
        assert.equal(
          r.data.screens.filter((s) => s.kind === "browser-response").length,
          mode === "vulnerable" ? 2 : 0,
        );
        for (const e of r.data.evidence.filter((e) => e.browserCapture)) {
          assert.equal(e.browserCapture!.method, "browser-navigation");
          const received = fixture.publicResponses.find(
            (item) => item.sha256 === e.browserCapture!.responseSha256,
          );
          assert.ok(
            received,
            "capture hash must match the actual bytes returned by the fixture server",
          );
          assert.equal(received.method, "POST");
          assert.equal(received.fetchMode, "navigate");
          assert.match(received.accept, /text\/html/);
          const png = await readFile(join(r.dir, e.browserCapture!.screenshot));
          assert.equal(png.subarray(1, 4).toString(), "PNG");
          assert.equal(e.browserCapture!.status, 500);
          assert.match(e.browserCapture!.responseSha256, /^[a-f0-9]{64}$/);
        }
        const verification = r.data.transitions.find(
          (t) => t.kind === "verification",
        );
        if (verification)
          await assert.rejects(
            r.replay("anonymous", [verification.id]),
            /Verification transitions require/,
          );
        // Scope is enforced in the verifier even though APIRequestContext bypasses browser routes.
        r.config.tests!.publicSurface!.files = [
          "https://example.com/.gitignore",
        ];
        await assert.rejects(runPublicChecks(r), /outside configured scope/);
        r.config.tests!.publicSurface!.files = ["/.gitignore"];
        r.config.tests!.publicSurface!.maxRequests = 1;
        await assert.rejects(runPublicChecks(r), /request budget/);
        r.data.status = "cancelled";
        await assert.rejects(runPublicChecks(r), /cancelled/);
      } finally {
        await scanner?.close();
        await fixture.close();
        await rm(dir, { recursive: true, force: true });
      }
    },
  );
