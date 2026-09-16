import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { readFileSync, statSync } from "node:fs";
import { withCoverage } from "./coverage.js";
import { Store } from "./store.js";
import { loadConfig, readSecrets } from "./config.js";
import { Redactor } from "./redact.js";
import { BrowserRecorder } from "./browser.js";
import { createAssessments, validateAssessmentUpdate } from "./asvs.js";
import { generateReport } from "./report.js";
import { runVerifiers } from "./verifiers.js";
import { ZapAdapter } from "./zap.js";
import type { ScanData, Evidence, Assessment } from "./types.js";
interface Runtime {
  data: ScanData;
  recorder: BrowserRecorder;
  zap?: ZapAdapter;
  busy: boolean;
  operation?: Promise<unknown>;
}
export class Scanner {
  store: Store;
  runtimes = new Map<string, Runtime>();
  constructor(
    root = process.env.FLOWAUDIT_DATA ||
      process.env.SECURITY_SCAN_DATA ||
      ".runs",
  ) {
    this.store = new Store(root);
  }
  create(configPath: string) {
    const config = loadConfig(resolve(configPath));
    const secrets = readSecrets(config),
      redactor = new Redactor(secrets);
    const data: ScanData = {
      schemaVersion: 1,
      id: randomUUID(),
      name: config.name,
      target: redactor.url(config.target),
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
      coverage: {
        actions: 0,
        complete: false,
        notes: [
          "Coverage is bounded by supplied accounts, reachable UI, action policy and budgets.",
        ],
      },
      asvsVersion: "5.0.0",
    };
    this.store.create(data, config);
    const save = () => this.store.save(data);
    const recorder = new BrowserRecorder(
      config,
      data,
      this.store.dir(data.id),
      secrets,
      redactor,
      save,
    );
    const rt: Runtime = { data, recorder, busy: false };
    if (config.zap) {
      rt.zap = new ZapAdapter(config, data, recorder, redactor, save);
      recorder.prepare = () => rt.zap!.initialize();
    }
    this.runtimes.set(data.id, rt);
    return {
      id: data.id,
      status: data.status,
      roles: Object.keys(config.roles),
    };
  }
  runtime(id: string) {
    const rt = this.runtimes.get(id);
    if (!rt)
      throw Error(
        "Scan has no live browser worker; read/export preserved artifacts or create a fresh scan",
      );
    return rt;
  }
  status(id: string) {
    const d = this.runtimes.get(id)?.data || this.store.get(id);
    return {
      id: d.id,
      status: d.status,
      screens: d.screens.length,
      actions: d.coverage.actions,
      jobs: d.jobs,
      blockers: d.blockers,
      findings: d.findings.length,
    };
  }
  data(id: string) {
    return this.runtimes.get(id)?.data || this.store.get(id);
  }
  async exclusive<T>(
    id: string,
    fn: (r: BrowserRecorder) => Promise<T>,
  ): Promise<T> {
    const rt = this.runtime(id);
    if (rt.busy) throw Error("Another browser/test operation is in progress");
    rt.busy = true;
    rt.operation = Promise.resolve().then(() => fn(rt.recorder));
    try {
      return (await rt.operation) as T;
    } finally {
      rt.busy = false;
      rt.operation = undefined;
    }
  }
  async job(id: string, kind: string, fn: () => Promise<unknown>) {
    const rt = this.runtime(id);
    if (rt.busy) throw Error("Another operation is in progress");
    rt.busy = true;
    const job = {
      id: randomUUID(),
      kind,
      status: "running",
      error: undefined as string | undefined,
    };
    rt.data.jobs.push(job);
    this.store.save(rt.data);
    rt.operation = fn()
      .then(() => {
        job.status = rt.data.status === "cancelled" ? "cancelled" : "completed";
      })
      .catch((e) => {
        job.status =
          rt.data.status === "cancelled"
            ? "cancelled"
            : rt.data.status === "interrupted"
              ? "interrupted"
              : "failed";
        job.error = rt.recorder.redactor.text(String(e));
        rt.recorder.blocker(`${kind}: ${job.error}`);
      })
      .finally(() => {
        rt.busy = false;
        this.store.save(rt.data);
        rt.operation = undefined;
      });
    return job;
  }
  async runZap(id: string, role: string, active = false) {
    const rt = this.runtime(id);
    if (!rt.zap) throw Error("ZAP not configured");
    return this.job(id, "zap", () => rt.zap!.run(role, active));
  }
  async verify(id: string, rule?: string) {
    return this.job(id, "verification", () =>
      runVerifiers(this.runtime(id).recorder, rule),
    );
  }
  async cancel(id: string) {
    const rt = this.runtime(id);
    rt.data.status = "cancelled";
    rt.data.finishedAt = new Date().toISOString();
    this.store.save(rt.data);
    await rt.zap?.stop();
    await rt.recorder.close();
    await rt.operation?.catch(() => {});
    await rt.recorder.close();
    return this.status(id);
  }
  async finish(id: string) {
    const rt = this.runtime(id);
    if (rt.busy) throw Error("Wait for running job before finishing");
    rt.data.status = "completed";
    rt.data.finishedAt = new Date().toISOString();
    rt.data.coverage.complete = false;
    rt.data.coverage.notes.push(
      "Finished by operator. Completion does not assert exhaustive discovery or ASVS compliance.",
    );
    await rt.recorder.close();
    this.store.save(rt.data);
    return this.status(id);
  }
  attach(id: string, note: string, filePath?: string) {
    const d = this.data(id),
      rt = this.runtimes.get(id);
    if (!rt)
      throw Error(
        "Attach evidence through a live scan so secrets can be redacted",
      );
    let text = note;
    if (filePath) {
      const st = statSync(resolve(filePath));
      if (!st.isFile() || st.size > 1024 * 1024)
        throw Error("Evidence must be a regular text file up to 1 MiB");
      const raw = readFileSync(resolve(filePath));
      text += "\n" + raw.toString("utf8");
    }
    if (!rt)
      throw Error(
        "Attach evidence through a live scan so secrets can be redacted",
      );
    const e: Evidence = {
      id: randomUUID(),
      kind: "manual",
      note: rt.recorder.redactor.text(text),
      at: new Date().toISOString(),
    };
    d.evidence.push(e);
    this.store.save(d);
    return e;
  }
  assess(id: string, requirementId: string, patch: Partial<Assessment>) {
    const d = this.data(id),
      index = d.assessments.findIndex((a) => a.id === requirementId);
    if (index < 0) throw Error("Unknown ASVS L1 requirement");
    const value = validateAssessmentUpdate(
      d.assessments[index],
      patch,
      new Set(d.evidence.map((e) => e.id)),
    );
    d.assessments[index] =
      this.runtimes.get(id)?.recorder.redactor.clean(value) || value;
    this.store.save(d);
    return d.assessments[index];
  }
  async report(id: string) {
    return generateReport(withCoverage(this.data(id)), this.store.dir(id));
  }
  async close() {
    for (const rt of this.runtimes.values()) {
      if (rt.data.status === "running") {
        rt.data.status = "interrupted";
        rt.data.coverage.notes.push("Worker stopped; live browser state lost.");
        this.store.save(rt.data);
      }
      await rt.zap?.stop().catch(() => {});
      await rt.recorder.close();
      await rt.operation?.catch(() => {});
      await rt.recorder.close();
      rt.data.jobs.forEach((j) => {
        if (j.status === "running") j.status = "interrupted";
      });
      this.store.save(rt.data);
    }
    this.store.close();
  }
}
