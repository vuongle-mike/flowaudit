import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { chromium } from "playwright";
import { demoConfig } from "../scripts/demo-config.js";
import { startFixture } from "../src/fixture.js";
import { Scanner } from "../src/scanner.js";
import { Store } from "../src/store.js";
import type { ProjectConfig, Screen } from "../src/types.js";

const browserOptions = {
  timeout: 90000,
  skip: !existsSync(process.env.CHROMIUM_PATH || chromium.executablePath())
    ? "Install Playwright Chromium to run browser integration tests"
    : false,
};
async function setup(
  mode: "fixed" | "vulnerable" = "fixed",
  amend?: (config: ProjectConfig) => void,
) {
  const fixture = await startFixture({ mode });
  const directory = await mkdtemp(join(tmpdir(), "security-core-"));
  const path = demoConfig(fixture.url, directory);
  if (amend) {
    const config = JSON.parse(await readFile(path, "utf8")) as ProjectConfig;
    amend(config);
    await writeFile(path, JSON.stringify(config));
  }
  const scanner = new Scanner(join(directory, "runs"));
  const created = scanner.create(path);
  return {
    fixture,
    directory,
    path,
    scanner,
    id: created.id,
    recorder: scanner.runtime(created.id).recorder,
    close: async () => {
      await scanner.close();
      await fixture.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
function action(screen: Screen, match: string | RegExp) {
  const result = screen.actions.find((item) =>
    typeof match === "string" ? item.label === match : match.test(item.label),
  );
  assert.ok(
    result,
    `Expected action ${String(match)}; found ${screen.actions.map((item) => item.label).join(", ")}`,
  );
  return result;
}
async function completeJob(scanner: Scanner, id: string, jobId: string) {
  for (let attempt = 0; attempt < 600; attempt++) {
    const job = scanner.status(id).jobs.find((item) => item.id === jobId);
    assert.ok(job);
    if (job.status !== "running") {
      assert.equal(job.status, "completed", job.error);
      return;
    }
    await delay(100);
  }
  throw new Error("Verification job did not complete within 60 seconds");
}

for (const mode of ["vulnerable", "fixed"] as const) {
  test(
    `browser verifiers distinguish all four ${mode} scenarios using protected content and execution evidence`,
    browserOptions,
    async () => {
      const context = await setup(mode);
      try {
        const job = await context.scanner.verify(context.id);
        await completeJob(context.scanner, context.id, job.id);
        const data = context.scanner.data(context.id);
        assert.equal(data.findings.length, 4, JSON.stringify(data.blockers));
        const expected = mode === "vulnerable" ? "confirmed" : "not-reproduced";
        assert.deepEqual(
          data.findings.map((item) => [item.ruleId, item.status]).sort(),
          [
            ["reflected-xss", expected],
            ["authorization:Cross-tenant invoice access", expected],
            ["authorization:User accesses admin function", expected],
            ["session-logout", expected],
          ].sort(),
        );
        for (const finding of data.findings) {
          assert.ok(finding.steps.length >= 3);
          assert.ok(
            finding.screenId &&
              data.screens.some((screen) => screen.id === finding.screenId),
          );
          assert.ok(
            finding.evidenceIds.some((id) =>
              data.evidence.some(
                (evidence) =>
                  evidence.id === id && evidence.kind === "verification",
              ),
            ),
          );
          assert.ok(
            finding.evidenceIds.some((id) =>
              data.evidence.some(
                (evidence) => evidence.id === id && evidence.kind === "http",
              ),
            ),
            `${finding.ruleId} needs linked HTTP evidence`,
          );
          assert.ok(
            finding.asvsIds.every((id) =>
              data.assessments.some((item) => item.id === id),
            ),
          );
        }
        assert.equal(
          data.assessments.some((item) => item.status === "pass"),
          false,
          "Non-reproduction must not become ASVS pass",
        );
        const serialized = JSON.stringify(data);
        assert.equal(serialized.includes("Demo-pass-123!"), false);
        assert.equal(
          serialized.includes(encodeURIComponent("Demo-pass-123!")),
          false,
        );
        const metrics = (await (
          await fetch(`${context.fixture.url}/api/metrics`)
        ).json()) as {
          leakedCorrelationHeaders: number;
          deleteRequests: number;
          payRequests: number;
        };
        assert.equal(metrics.leakedCorrelationHeaders, 0);
        assert.equal(metrics.deleteRequests, 0);
        assert.equal(metrics.payRequests, 0);
        await context.scanner.finish(context.id);
        assert.equal(context.scanner.data(context.id).coverage.complete, false);
      } finally {
        await context.close();
      }
    },
  );
}

test(
  "bounded login-input verifier refreshes CSRF and tests SQLi and XSS without brute-force guesses",
  browserOptions,
  async () => {
    const context = await setup("fixed", (config) => {
      const secrets = JSON.parse(
        readFileSync(config.secretsFile, "utf8"),
      ) as Record<string, unknown>;
      secrets.anonymous = { cookies: [] };
      writeFileSync(config.secretsFile, JSON.stringify(secrets), {
        mode: 0o600,
      });
      config.roles = {
        anonymous: {
          secretRef: "anonymous",
          type: "cookie",
          probePath: "/login",
          probeContains: "Welcome back.",
        },
      };
      config.tests = {
        login: {
          role: "anonymous",
          loginPath: "/login",
          submitPath: "/login",
          usernameField: "username",
          passwordField: "password",
          csrfField: "csrf",
          maxAttempts: 5,
          successPath: "/invoices",
          successContains: "Recent invoices",
          failureContains: "Invalid username or password",
        },
      };
    });
    try {
      const job = await context.scanner.verify(context.id, "login-inputs");
      await completeJob(context.scanner, context.id, job.id);
      const data = context.scanner.data(context.id);
      assert.deepEqual(
        data.findings.map((finding) => [finding.ruleId, finding.status]).sort(),
        [
          ["login-reflected-xss", "not-reproduced"],
          ["login-sql-auth-bypass", "not-reproduced"],
        ],
      );
      assert.equal(
        data.evidence.filter(
          (evidence) => evidence.kind === "http" && evidence.method === "POST",
        ).length,
        5,
      );
      assert.equal(
        data.blockers.some((blocker) =>
          blocker.reason.includes("Mutating request requires"),
        ),
        false,
      );
      assert.equal(JSON.stringify(data).includes("Invalid-"), false);
    } finally {
      await context.close();
    }
  },
);

test(
  "screen graph distinguishes same-URL modal/tab states, deduplicates observations, and links action HTTP evidence",
  browserOptions,
  async () => {
    const context = await setup();
    try {
      const overview = await context.recorder.open("userA");
      assert.equal(overview.role, "userA");
      const detail = await context.recorder.act(
        "userA",
        action(overview, /^INV-/).id,
      );
      const repeated = await context.recorder.observe("userA");
      assert.equal(repeated.id, detail.id);
      const modal = await context.recorder.act(
        "userA",
        action(detail, "Edit").id,
      );
      assert.equal(modal.url, detail.url);
      assert.notEqual(modal.id, detail.id);
      const closed = await context.recorder.act(
        "userA",
        action(modal, "Close").id,
      );
      assert.equal(closed.id, detail.id);
      const history = await context.recorder.act(
        "userA",
        action(closed, "History").id,
      );
      assert.equal(history.url, detail.url);
      assert.notEqual(history.id, detail.id);
      assert.notEqual(history.id, modal.id);
      const summary = await context.recorder.act(
        "userA",
        action(history, "Summary").id,
      );
      assert.equal(summary.id, detail.id);
      const graph = context.scanner.data(context.id);
      assert.equal(
        graph.screens.filter((screen) => screen.url === detail.url).length,
        3,
      );
      assert.ok(
        graph.observations.filter((item) => item.screenId === detail.id)
          .length >= 3,
      );
      const transition = graph.transitions.find(
        (item) => item.from === overview.id && item.to === detail.id,
      );
      assert.ok(transition);
      assert.equal(transition.role, "userA");
      assert.ok(
        transition.evidenceIds.some((id) =>
          graph.evidence.some(
            (item) =>
              item.id === id && item.kind === "http" && item.status === 200,
          ),
        ),
      );
      const screenshot = await readFile(
        join(context.scanner.store.dir(context.id), modal.screenshot),
      );
      assert.equal(screenshot.subarray(1, 4).toString(), "PNG");
      const flow = graph.transitions
        .filter(
          (item) =>
            item.action.startsWith("click:") &&
            item.action !== "click: Summary",
        )
        .map((item) => item.id);
      const replayed = await context.recorder.replay("userA", flow);
      assert.equal(
        replayed.id,
        history.id,
        "Saved flow should rediscover current actions and return to history",
      );
    } finally {
      await context.close();
    }
  },
);

test(
  "scope and action policy block outgoing redirects, logout, dangerous requests and strip correlation headers",
  browserOptions,
  async () => {
    const context = await setup("fixed", (config) => {
      config.excludePaths = config.excludePaths.filter(
        (path) => path !== "/redirect-external",
      );
    });
    try {
      const screen = await context.recorder.open("userA");
      const logout = action(screen, "Log out");
      assert.ok(logout.blocked);
      await assert.rejects(
        context.recorder.act("userA", logout.id),
        /Action policy/,
      );
      await assert.rejects(
        context.recorder.navigate(
          "userA",
          "https://example.invalid/not-in-scope",
        ),
        /outside configured scope/,
      );
      await assert.rejects(
        context.recorder.navigate("userA", "/api/reset"),
        /outside configured scope/,
      );
      const session = context.recorder.session("userA");
      const detailHref = screen.actions.find((item) =>
        item.href?.includes("/invoices/"),
      )!.href!;
      const invoiceId = new URL(detailHref).pathname.split("/").at(-1)!;
      const blocked = await session.page.evaluate(async (id) => {
        const outcomes = [];
        for (const suffix of ["pay", "delete"]) {
          try {
            await fetch(`/api/invoices/${id}/${suffix}`, {
              method: "POST",
              signal: AbortSignal.timeout(5000),
            });
            outcomes.push(false);
          } catch {
            outcomes.push(true);
          }
        }
        await fetch("/api/me", {
          headers: {
            "x-flowaudit-correlation": "test-internal-correlation",
          },
          signal: AbortSignal.timeout(5000),
        });
        return outcomes;
      }, invoiceId);
      assert.deepEqual(blocked, [true, true]);
      const cookies = await session.context.cookies();
      const secretValues = cookies
        .map((cookie) => cookie.value)
        .filter(Boolean);
      const linked = await context.recorder.observe("userA");
      assert.equal(linked.id, screen.id);
      const evidenceJson = JSON.stringify(
        context.scanner.data(context.id).evidence,
      );
      for (const secret of secretValues)
        assert.equal(
          evidenceJson.includes(secret),
          false,
          "Session and CSRF cookie values must be redacted",
        );
      await assert.rejects(
        context.recorder.navigate("userA", "/redirect-external"),
        /ERR_FAILED|ERR_ABORTED|outside|net::/,
      );
      assert.ok(
        context.scanner
          .data(context.id)
          .blockers.some((blocker) => blocker.reason.includes("outside scope")),
      );
      const metrics = (await (
        await fetch(`${context.fixture.url}/api/metrics`)
      ).json()) as {
        leakedCorrelationHeaders: number;
        deleteRequests: number;
        payRequests: number;
      };
      assert.equal(metrics.leakedCorrelationHeaders, 0);
      assert.equal(metrics.deleteRequests, 0);
      assert.equal(metrics.payRequests, 0);
    } finally {
      await context.close();
    }
  },
);

test(
  "expired authentication stops protected actions and records a blocker",
  browserOptions,
  async () => {
    const context = await setup();
    try {
      const screen = await context.recorder.open("userA");
      await fetch(`${context.fixture.url}/api/reset`, { method: "POST" });
      await assert.rejects(
        context.recorder.act("userA", action(screen, /^INV-/).id),
        /Authentication expired/,
      );
      assert.equal(context.scanner.data(context.id).coverage.actions, 0);
      assert.ok(
        context.scanner
          .data(context.id)
          .blockers.some((blocker) =>
            /Authentication lost/.test(blocker.reason),
          ),
      );
      const authenticated = await context.recorder.open("userA");
      assert.ok(
        authenticated.text.includes("Recent invoices"),
        "Opening an expired configured session should authenticate again",
      );
      const detail = await context.recorder.act(
        "userA",
        action(authenticated, /^INV-/).id,
      );
      assert.ok(detail.text.includes("ORG_A_PRIVATE_INVOICE"));
    } finally {
      await context.close();
    }
  },
);

test(
  "repeated browser_open after invalid credentials never promotes the login page to authenticated coverage",
  browserOptions,
  async () => {
    const context = await setup("fixed", (config) => {
      config.secretsFile += ".invalid";
      config.roles = { userA: config.roles.userA };
      writeFileSync(
        config.secretsFile,
        JSON.stringify({
          userA: {
            username: "userA",
            password: "intentionally-wrong-password",
          },
        }),
      );
    });
    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        await assert.rejects(
          context.recorder.open("userA"),
          /Authentication probe failed/,
        );
        assert.equal(
          context.scanner.data(context.id).screens.length,
          0,
          "A failed login must not become an authenticated screen on retry",
        );
        assert.equal(
          context.recorder.sessions.has("userA"),
          false,
          "Failed authentication context must be released",
        );
      }
      assert.equal(
        JSON.stringify(context.scanner.data(context.id)).includes(
          "intentionally-wrong-password",
        ),
        false,
      );
    } finally {
      await context.close();
    }
  },
);

test(
  "cookie and bearer profiles authenticate without leaking credential values or redacting navigable origins",
  browserOptions,
  async () => {
    for (const type of ["cookie", "bearer"] as const) {
      const directory = await mkdtemp(join(tmpdir(), `security-${type}-`));
      const fixture = await startFixture({ mode: "fixed" });
      let scanner: Scanner | undefined;
      try {
        const response = await fetch(`${fixture.url}/login`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            username: "userA",
            password: "Demo-pass-123!",
          }),
          signal: AbortSignal.timeout(3000),
        });
        assert.equal(response.status, 200);
        const { token } = (await response.json()) as { token: string };
        const path = demoConfig(fixture.url, directory);
        const config = JSON.parse(
          await readFile(path, "utf8"),
        ) as ProjectConfig;
        config.roles = {
          userA: {
            secretRef: "userA",
            type,
            probePath: "/api/me",
            probeContains: "AUTHENTICATED_userA",
          },
        };
        await writeFile(path, JSON.stringify(config));
        await writeFile(
          config.secretsFile,
          JSON.stringify({
            userA:
              type === "cookie"
                ? {
                    cookies: [
                      {
                        name: "fixture_session",
                        value: token,
                        url: fixture.url,
                      },
                    ],
                  }
                : { token },
          }),
        );
        scanner = new Scanner(join(directory, "runs"));
        const { id } = scanner.create(path);
        const recorder = scanner.runtime(id).recorder;
        const screen = await recorder.open("userA");
        assert.equal(
          new URL(screen.url).origin,
          fixture.url,
          `${type} auth must preserve the origin needed for browser discovery`,
        );
        const detail = await recorder.act("userA", action(screen, /^INV-/).id);
        assert.ok(detail.text.includes("ORG_A_PRIVATE_INVOICE"));
        assert.equal(JSON.stringify(scanner.data(id)).includes(token), false);
        assert.ok(
          scanner
            .data(id)
            .evidence.some(
              (item) => item.role === "userA" && item.status === 200,
            ),
        );
      } finally {
        await scanner?.close();
        await fixture.close();
        await rm(directory, { recursive: true, force: true });
      }
    }
  },
);

test(
  "action, state and time budgets stop work and preserve partial scan data",
  browserOptions,
  async () => {
    const actions = await setup("fixed", (config) => {
      config.limits.actions = 1;
    });
    try {
      const screen = await actions.recorder.open("userA");
      const detail = await actions.recorder.act(
        "userA",
        action(screen, /^INV-/).id,
      );
      await assert.rejects(
        actions.recorder.act("userA", action(detail, "Edit").id),
        /Action budget reached/,
      );
      assert.equal(actions.scanner.data(actions.id).coverage.actions, 1);
      assert.equal(actions.scanner.data(actions.id).coverage.complete, false);
      assert.ok(
        actions.scanner
          .data(actions.id)
          .blockers.some(
            (blocker) => blocker.reason === "Action budget reached",
          ),
      );
      await actions.scanner.cancel(actions.id);
      await assert.rejects(actions.recorder.observe("userA"), /Scan cancelled/);
      assert.equal(actions.scanner.status(actions.id).status, "cancelled");
      assert.ok(actions.scanner.data(actions.id).screens.length > 0);
    } finally {
      await actions.close();
    }
    const states = await setup("fixed", (config) => {
      config.limits.statesPerRole = 1;
    });
    try {
      const screen = await states.recorder.open("userA");
      await assert.rejects(
        states.recorder.act("userA", action(screen, /^INV-/).id),
        /State budget reached/,
      );
      assert.equal(states.scanner.data(states.id).screens.length, 1);
    } finally {
      await states.close();
    }
    const time = await setup("fixed", (config) => {
      config.limits.minutes = 0.00001;
    });
    try {
      await delay(10);
      await assert.rejects(time.recorder.open("userA"), /Time budget reached/);
      assert.equal(time.scanner.status(time.id).screens, 0);
      assert.ok(
        time.scanner
          .data(time.id)
          .blockers.some((blocker) => blocker.reason === "Time budget reached"),
      );
    } finally {
      await time.close();
    }
  },
);

test("store rejects a second worker and recovers interrupted jobs while preserving evidence", async () => {
  const context = await setup();
  let reopened: Store | undefined;
  try {
    assert.throws(
      () => new Store(join(context.directory, "runs")),
      /Another scanner worker/,
    );
    assert.throws(
      () => context.scanner.create(context.path),
      /Only one active scan/,
    );
    const evidence = context.scanner.attach(
      context.id,
      "Manual evidence: Demo-pass-123!",
    );
    assert.equal(evidence.note?.includes("Demo-pass-123!"), false);
    const data = context.scanner.data(context.id);
    data.jobs.push({ id: "test-job", kind: "verification", status: "running" });
    context.scanner.store.save(data);
    // Closing only persistence models a worker exiting before it could finalize scan/job status.
    context.scanner.store.close();
    reopened = new Store(join(context.directory, "runs"));
    const preserved = reopened.get(context.id);
    assert.equal(preserved.status, "interrupted");
    assert.equal(preserved.jobs[0].status, "interrupted");
    assert.equal(preserved.evidence[0].id, evidence.id);
    assert.ok(
      preserved.coverage.notes.some((note) => note.includes("Worker stopped")),
    );
  } finally {
    reopened?.close();
    await context.recorder.close();
    await context.fixture.close();
    await rm(context.directory, { recursive: true, force: true });
  }
});
