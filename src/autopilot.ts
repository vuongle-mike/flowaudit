import type { Action, ProjectConfig, Screen } from "./types.js";

export interface ToolCaller {
  call<T>(name: string, args?: Record<string, unknown>): Promise<T>;
}

type Step = Pick<Action, "kind" | "label"> & { value?: string };
type Frontier = {
  role: string;
  screen: Screen;
  baseUrl: string;
  steps: Step[];
};

function sameAction(screen: Screen, original: Action): Action | undefined {
  return screen.actions.find(
    (candidate) =>
      candidate.kind === original.kind && candidate.label === original.label,
  );
}

async function waitForJob(
  tools: ToolCaller,
  scanId: string,
  jobId: string,
): Promise<void> {
  for (let attempt = 0; attempt < 1800; attempt++) {
    const status = await tools.call<{
      jobs: Array<{ id: string; status: string; error?: string }>;
    }>("scan_status", { scanId });
    const job = status.jobs.find((candidate) => candidate.id === jobId);
    if (!job) throw Error(`Job disappeared: ${jobId}`);
    if (job.status !== "running") {
      if (job.status !== "completed")
        throw Error(job.error || `Job ended as ${job.status}`);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw Error(`Job timed out: ${jobId}`);
}

async function restore(
  tools: ToolCaller,
  scanId: string,
  item: Frontier,
): Promise<Screen> {
  let screen = await tools.call<Screen>("browser_navigate", {
    scanId,
    role: item.role,
    url: item.baseUrl,
  });
  for (const step of item.steps) {
    const action = screen.actions.find(
      (candidate) =>
        candidate.kind === step.kind && candidate.label === step.label,
    );
    if (!action) throw Error("Saved UI state requires rediscovery");
    screen = await tools.call<Screen>("browser_act", {
      scanId,
      role: item.role,
      actionId: action.id,
      value: step.value,
    });
  }
  return screen;
}

/** A conservative built-in controller for the simple CLI. The plugin skill remains
 * available when a person wants the LLM to make application-specific choices. */
export async function exploreProject(
  tools: ToolCaller,
  scanId: string,
  config: ProjectConfig,
  log: (message: string) => void = () => {},
): Promise<void> {
  const queue: Frontier[] = [];
  const queued = new Set<string>();
  const attempted = new Set<string>();

  for (const role of Object.keys(config.roles)) {
    log(`Opening role ${role}`);
    const screen = await tools.call<Screen>("browser_open", { scanId, role });
    queue.push({ role, screen, baseUrl: screen.url, steps: [] });
    queued.add(`${role}:${screen.id}`);
  }

  while (queue.length) {
    const item = queue.shift()!;
    const candidates = item.screen.actions
      .filter((action) => !action.blocked && action.inputType !== "password")
      .slice(0, 40);

    for (const original of candidates) {
      const key = original.href
        ? `${item.role}:href:${new URL(original.href, item.screen.url).href}`
        : `${item.role}:${item.screen.fingerprint}:${original.kind}:${original.label}`;
      if (attempted.has(key)) continue;
      attempted.add(key);
      try {
        const restored = await restore(tools, scanId, item);
        const action = sameAction(restored, original);
        if (!action?.id || action.blocked) continue;

        if (action.kind === "click" && action.inputType === "submit") continue;
        log(
          `${item.role}: ${action.kind} ${action.label || action.href || action.id}`,
        );
        let next = await tools.call<Screen>("browser_act", {
          scanId,
          role: item.role,
          actionId: action.id,
        });
        const steps = [
          ...item.steps,
          { kind: action.kind, label: action.label } satisfies Step,
        ];

        if (action.kind === "fill" || action.kind === "select") {
          const submit = next.actions.find(
            (candidate) =>
              !candidate.blocked &&
              candidate.kind === "click" &&
              /^(search|apply|filter|go)$/i.test(candidate.label),
          );
          if (submit) {
            next = await tools.call<Screen>("browser_act", {
              scanId,
              role: item.role,
              actionId: submit.id,
            });
            steps.push({ kind: submit.kind, label: submit.label });
          }
        }

        const stateKey = `${item.role}:${next.id}`;
        if (!queued.has(stateKey)) {
          queued.add(stateKey);
          queue.push({
            role: item.role,
            screen: next,
            baseUrl: next.url === item.screen.url ? item.baseUrl : next.url,
            steps: next.url === item.screen.url ? steps : [],
          });
        }
      } catch (error) {
        log(
          `${item.role}: skipped ${original.label}: ${(error as Error).message}`,
        );
      }
    }
  }
}

export async function runChecks(
  tools: ToolCaller,
  scanId: string,
  config: ProjectConfig,
  log: (message: string) => void = () => {},
): Promise<void> {
  const roles = Object.keys(config.roles);
  const activeRole =
    config.tests?.activeScan?.role || config.tests?.xss?.role || roles[0];
  const zapRuns =
    config.mode === "active"
      ? roles.map((role) => ({ role, active: role === activeRole }))
      : roles.slice(0, 1).map((role) => ({ role, active: false }));
  for (const { role, active } of zapRuns) {
    log(`Running ${active ? "active" : "passive"} ZAP checks as ${role}`);
    const job = await tools.call<{ id: string }>("run_zap", {
      scanId,
      role,
      active,
    });
    try {
      await waitForJob(tools, scanId, job.id);
    } catch (error) {
      if (
        active &&
        (error as Error).message.includes(
          "No observed or explicitly configured",
        )
      ) {
        log(
          `${role}: active ZAP skipped because no safe GET query was discovered`,
        );
        continue;
      }
      throw error;
    }
  }
  if (config.mode === "active" && config.tests) {
    log("Running configured business verifiers");
    const job = await tools.call<{ id: string }>("run_verifiers", { scanId });
    await waitForJob(tools, scanId, job.id);
  }
}
