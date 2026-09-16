import assert from "node:assert/strict";
import { existsSync, statSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { chromium } from "playwright";
import { demoConfig } from "../scripts/demo-config.js";
import { exploreProject, type ToolCaller } from "../src/autopilot.js";
import { startFixture } from "../src/fixture.js";
import { initProject, showReport } from "../src/simple.js";
import { Scanner } from "../src/scanner.js";
import type { ProjectConfig } from "../src/types.js";

test("simple public init creates a private storage-state project that opens without JSON editing", async () => {
  const fixture = await startFixture({ mode: "fixed" });
  const root = await mkdtemp(join(tmpdir(), "security-simple-init-"));
  try {
    const created = await initProject(
      [fixture.url, "--name", "Public fixture", "--public"],
      root,
    );
    assert.equal(created.slug, "public-fixture");
    const config = JSON.parse(
      await readFile(created.configPath, "utf8"),
    ) as ProjectConfig;
    assert.equal(config.roles.anonymous.type, "storageState");
    assert.equal(config.mode, "passive");
    assert.deepEqual(config.includePaths, ["/"]);
    const secrets = join(root, "projects/public-fixture/secrets.json");
    assert.equal(statSync(secrets).mode & 0o777, 0o600);
    delete config.zap;
    await writeFile(created.configPath, JSON.stringify(config));
    const scanner = new Scanner(join(root, "runs"));
    try {
      const { id } = scanner.create(created.configPath);
      const screen = await scanner.runtime(id).recorder.open("anonymous");
      assert.equal(screen.role, "anonymous");
      assert.match(screen.title, /Sign in/);
    } finally {
      await scanner.close();
    }
  } finally {
    await fixture.close();
    await rm(root, { recursive: true, force: true });
  }
});

const browserOptions = {
  timeout: 90000,
  skip: !existsSync(process.env.CHROMIUM_PATH || chromium.executablePath())
    ? "Install Playwright Chromium to run simple-controller integration"
    : false,
};

test(
  "simple controller explores links, a same-URL modal and tabs without direct MCP decisions",
  browserOptions,
  async () => {
    const fixture = await startFixture({ mode: "fixed" });
    const root = await mkdtemp(join(tmpdir(), "security-simple-run-"));
    const configPath = demoConfig(fixture.url, root);
    const config = JSON.parse(
      await readFile(configPath, "utf8"),
    ) as ProjectConfig;
    config.roles = { userA: config.roles.userA };
    config.mode = "passive";
    config.limits.actions = 160;
    delete config.zap;
    delete config.tests;
    await writeFile(configPath, JSON.stringify(config));
    const scanner = new Scanner(join(root, "runs"));
    const { id } = scanner.create(configPath);
    const tools: ToolCaller = {
      async call<T>(name: string, args: Record<string, any> = {}): Promise<T> {
        if (name === "browser_open")
          return scanner
            .exclusive(args.scanId, (recorder) => recorder.open(args.role))
            .then(structuredClone) as Promise<T>;
        if (name === "browser_act")
          return scanner
            .exclusive(args.scanId, (recorder) =>
              recorder.act(args.role, args.actionId, args.value),
            )
            .then(structuredClone) as Promise<T>;
        if (name === "browser_navigate")
          return scanner
            .exclusive(args.scanId, (recorder) =>
              recorder.navigate(args.role, args.url),
            )
            .then(structuredClone) as Promise<T>;
        if (name === "replay_flow")
          return scanner
            .exclusive(args.scanId, (recorder) =>
              recorder.replay(args.role, args.transitionIds),
            )
            .then(structuredClone) as Promise<T>;
        if (name === "get_graph") {
          const data = scanner.data(args.scanId);
          return {
            screens: data.screens,
            transitions: data.transitions,
            observations: data.observations,
            blockers: data.blockers,
          } as T;
        }
        throw Error(`Unexpected tool ${name}`);
      },
    };
    try {
      await exploreProject(tools, id, config);
      const data = scanner.data(id);
      assert.ok(data.screens.some((screen) => /INV-/.test(screen.title)));
      const grouped = new Map<string, typeof data.screens>();
      for (const screen of data.screens)
        grouped.set(screen.url, [...(grouped.get(screen.url) || []), screen]);
      assert.ok(
        [...grouped.values()].some((screens) => screens.length >= 3),
        "detail, modal and tab states should coexist at one URL",
      );
      assert.ok(data.transitions.length > 3);
      assert.equal(data.coverage.complete, false);
    } finally {
      await scanner.close();
      await fixture.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("report command resolves the latest project result and rejects missing runs", async () => {
  const root = await mkdtemp(join(tmpdir(), "security-simple-report-"));
  const directory = join(root, "projects/sample");
  await import("node:fs/promises").then(({ mkdir }) =>
    mkdir(directory, { recursive: true }),
  );
  await writeFile(
    join(directory, "project.json"),
    JSON.stringify({ name: "sample" }),
  );
  assert.throws(() => showReport(["sample"], root), /no completed run/);
  const expected = join(root, "scan-data/id/report/index.html");
  await writeFile(
    join(directory, "last-run.json"),
    JSON.stringify({ html: expected }),
  );
  assert.equal(showReport(["sample"], root).html, expected);
  await rm(root, { recursive: true, force: true });
});
