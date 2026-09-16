import { mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { startFixture } from "../src/fixture.js";
import { Scanner } from "../src/scanner.js";
import { demoConfig } from "./demo-config.js";
async function run(mode: "vulnerable" | "fixed") {
  const work = resolve(process.env.DEMO_OUTPUT || "demo-results", mode);
  mkdirSync(work, { recursive: true });
  const fixture = await startFixture({ mode, host: "0.0.0.0" });
  const useZap = process.env.DEMO_ZAP === "1";
  const target = process.env.FIXTURE_TARGET_HOST
    ? fixture.url.replace("0.0.0.0", process.env.FIXTURE_TARGET_HOST)
    : fixture.url.replace("0.0.0.0", "127.0.0.1");
  const configPath = demoConfig(target, join(work, "private"), useZap);
  const scanner = new Scanner(join(work, "runs"));
  try {
    const { id } = scanner.create(configPath);
    const r = scanner.runtime(id).recorder;
    for (const role of ["userA", "userB", "admin"]) {
      await r.open(role);
      await r.navigate(role, "/invoices");
      let screen = await r.observe(role);
      const link = screen.actions.find(
        (a) => a.href?.includes("/invoices/") && !a.blocked,
      );
      if (link) {
        await r.act(role, link.id);
        for (const label of ["History", "Summary", "Edit", "Close"]) {
          screen = await r.observe(role);
          const a = screen.actions.find(
            (a) => a.kind === "click" && a.label === label && !a.blocked,
          );
          if (a) await r.act(role, a.id);
        }
      }
      await r.navigate(role, "/search");
    }
    if (useZap) {
      const job = await scanner.runZap(id, "userA", true);
      while (job.status === "running")
        await new Promise((r) => setTimeout(r, 250));
      if (job.status !== "completed") throw Error(`ZAP: ${job.error}`);
    }
    const job = await scanner.verify(id);
    while (job.status === "running")
      await new Promise((r) => setTimeout(r, 100));
    if (job.status !== "completed") throw Error(`Verifiers: ${job.error}`);
    await scanner.finish(id);
    const report = await scanner.report(id);
    const d = scanner.data(id);
    console.log(
      JSON.stringify(
        {
          mode,
          scanId: id,
          screens: d.screens.length,
          findings: d.findings.map((f) => ({
            title: f.title,
            status: f.status,
          })),
          asvs: d.assessments.length,
          report,
        },
        null,
        2,
      ),
    );
    return report;
  } finally {
    await scanner.close();
    await fixture.close();
  }
}
for (const mode of ["vulnerable", "fixed"] as const) await run(mode);
