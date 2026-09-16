import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import type { Evidence, Finding } from "./types.js";
import type { BrowserRecorder } from "./browser.js";
import { liveFormResponse } from "./live-response.js";
import { assertScope, dangerous } from "./config.js";

// A client-side script signature alone is never source/debug disclosure.
export function debugDisclosure(body: string): string | undefined {
  const text = body
    .replace(/\\\//g, "/")
    .replace(/\\n/g, "\n")
    .replace(/<[^>]*>/g, " ");
  const stack = /(?:stack\s*trace|traceback \(most recent call last\))/i.exec(
    text,
  );
  if (!stack) return;
  const context = text.slice(stack.index, stack.index + 7000);
  if (
    !/(?:[\w.-]+\/)+(?:[\w.-]+\.(?:php|py|js|ts|java|rb|cs))(?::\d+|[^\n]{0,80}line\s+\d+)|File "[^"\n]+", line \d+/i.test(
      context,
    )
  )
    return;
  // Do not export the request headers/cookies embedded in framework error pages.
  return context
    .split(
      /##\s*(?:Request|Headers|Environment)|Request Headers|Request information/i,
    )[0]
    .slice(0, 2200);
}

export function gitignoreDisclosure(
  body: string,
  contentType: string,
): boolean {
  if (/html/i.test(contentType) || /<!doctype|<html|<script/i.test(body))
    return false;
  const lines = body
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
  const patterns = lines.filter((s) =>
    /^(?:\/?(?:node_modules|vendor|\.env|\.idea|\.vscode|coverage|dist|build|storage)(?:\/.*|\..*)?|!?\.gitignore|[\w.-]+\.(?:json|lock|log|map)|\*\.[\w.-]+|!?\/[\w.*\/-]+)$/.test(
      s,
    ),
  );
  return patterns.length >= 2;
}

export async function runPublicChecks(r: BrowserRecorder): Promise<Finding[]> {
  const config = r.config.tests?.publicSurface;
  if (!config) return [];
  if (r.config.mode !== "active")
    throw Error("Public surface tests require active mode");
  const role = config.role;
  const profile = r.config.roles[role];
  const secret = profile && r.secrets[profile.secretRef];
  const anonymous =
    secret &&
    !secret.bearer &&
    ((profile.type === "cookie" &&
      Array.isArray(secret.cookies) &&
      secret.cookies.length === 0) ||
      (profile.type === "storageState" &&
        secret.storageState?.cookies?.length === 0 &&
        secret.storageState?.origins?.length === 0));
  if (!anonymous)
    throw Error(
      "Public surface checks require an anonymous role with empty cookie/storage state",
    );
  await r.open(role);
  const session = r.session(role);
  const out: Finding[] = [];
  let requests = 0;
  const initialCookies = await session.context.cookies();
  await session.context.clearCookies();
  const saveFinding = (f: Omit<Finding, "id" | "source" | "asvsIds">) => {
    const existing = r.data.findings.find(
      (x) =>
        x.ruleId === f.ruleId &&
        x.url === f.url &&
        x.role === role &&
        x.parameter === f.parameter,
    );
    const finding = r.redactor.clean({
      ...f,
      id: existing?.id ?? randomUUID(),
      source: "verifier" as const,
      asvsIds: [],
    });
    if (existing) Object.assign(existing, finding);
    else r.data.findings.push(finding);
    out.push(finding);
    r.save();
  };
  const reserve = () => {
    r.check();
    if (requests >= config.maxRequests)
      throw Error("Public surface request budget reached");
    if (r.data.coverage.actions >= r.config.limits.actions)
      throw Error("Action budget reached during public surface checks");
    requests++;
  };
  const send = async (
    path: string,
    label: string,
    fields?: URLSearchParams,
    headers: Record<string, string> = {},
  ) => {
    const url = new URL(path, r.config.target).href;
    assertScope(r.config, url);
    const pathname = new URL(url).pathname;
    if (
      fields
        ? !config.forms.some(
            (f) => new URL(f.submitPath, r.config.target).href === url,
          )
        : !config.files.includes(path) &&
          !/^\/flowaudit-missing-[\w-]+$/.test(path)
    )
      throw Error("Public check request is not in the explicit test allowlist");
    if (
      dangerous.test(decodeURIComponent(pathname)) &&
      !r.config.allowedActions.includes(pathname)
    )
      throw Error("Public check blocked by action policy");
    reserve();
    const wait = Math.max(0, r.nextRequest - Date.now());
    r.nextRequest =
      Math.max(Date.now(), r.nextRequest) +
      1000 / r.config.limits.requestsPerSecond;
    await sleep(wait);
    r.check();
    r.data.coverage.actions++;
    r.save();
    const live = fields
      ? await liveFormResponse(
          r,
          role,
          url,
          fields,
          headers,
          /confirmation/i.test(label),
        )
      : undefined;
    const response = live
      ? {
          status: () => live.status,
          headers: () => live.headers,
          text: async () => live.body,
          dispose: async () => {},
        }
      : await session.context.request.fetch(url, {
          method: "GET",
          headers,
          maxRedirects: 0,
          timeout: 12000,
          failOnStatusCode: false,
        });
    try {
      r.check();
      const responseHeaders = response.headers();
      for (const cookie of await session.context.cookies())
        r.redactor.add(cookie.value);
      const body = await response.text();
      const limited = body.length > 2_000_000;
      const text = body.slice(0, 2_000_000);
      const debug =
        debugDisclosure(live?.visibleText || "") || debugDisclosure(text);
      const location = responseHeaders.location;
      if (location) {
        // Retain redirect evidence, but never follow it or send a second mutation.
        try {
          assertScope(r.config, new URL(location, url).href);
        } catch {
          r.blocker(
            "Public check redirect outside scope; not followed",
            role,
            url,
          );
        }
      }
      // Keep exact request fields after redaction and a bounded response excerpt.
      // A debug excerpt deliberately excludes embedded request/environment dumps.
      const evidence: Evidence = r.redactor.clean({
        id: randomUUID(),
        kind: "http",
        role,
        url,
        method: fields ? "POST" : "GET",
        status: response.status(),
        requestHeaders: live?.sentHeaders ?? headers,
        requestBody: fields?.toString(),
        responseHeaders,
        responseBody: debug
          ? `[Debug evidence excerpt]\n${debug}`
          : text.slice(0, 12000),
        browserCapture: live?.screenshot
          ? {
              method: "browser-navigation",
              screenshot: live.screenshot,
              responseSha256: live.responseSha256,
              url: live.url,
              status: live.status,
              at: live.capturedAt,
              note: live.captureNote,
            }
          : undefined,
        note: `${label}; ${live ? "actual browser navigation" : "HTTP file request; no browser screenshot"}; redirects not followed; ${limited ? "response exceeds 2 MB analysis limit; result incomplete" : "response inspected up to 2 MB"}; ${debug ? "debug excerpt retained" : "body preview limited to 12 KB"}`,
        at: new Date().toISOString(),
      });
      r.data.evidence.push(evidence);
      r.save();
      return {
        evidence,
        body: text,
        debug,
        limited,
        status: response.status(),
        contentType: responseHeaders["content-type"] ?? "",
        live,
      };
    } finally {
      await response.dispose();
    }
  };
  const freshForm = async (form: (typeof config.forms)[number]) => {
    reserve();
    await session.context.clearCookies();
    await r.navigate(
      role,
      new URL(form.pagePath, r.config.target).href,
      "Refresh public form and CSRF",
    );
    const observed = await session.page.evaluate(
      ({ fields, submit }) => {
        const form = [...document.forms].find(
          (f) =>
            f.method.toUpperCase() === "POST" &&
            f.action === submit &&
            fields.every((name) =>
              [...f.elements].some((e) => e.getAttribute("name") === name),
            ),
        );
        if (!form) return null;
        return {
          encoding: form.enctype,
          entries: [...new FormData(form).entries()].filter(
            (e): e is [string, string] => typeof e[1] === "string",
          ),
          inputs: [...form.querySelectorAll("input")].map((i) => ({
            name: i.name,
            type: i.type,
            required: i.required,
          })),
        };
      },
      {
        fields: form.fields,
        submit: new URL(form.submitPath, r.config.target).href,
      },
    );
    if (!observed || observed.encoding !== "application/x-www-form-urlencoded")
      throw Error(
        "Configured public POST form not found or encoding unsupported",
      );
    const fields = new URLSearchParams(observed.entries);
    for (const input of observed.inputs) {
      if (/token|csrf|password|secret/i.test(input.name))
        r.redactor.add(fields.get(input.name) ?? "");
      if (input.type === "password")
        fields.set(input.name, "Invalid-flowaudit-only");
      else if (input.type === "email" || /email|username/i.test(input.name))
        fields.set(
          input.name,
          "flowaudit-" + randomUUID() + "@example.invalid",
        );
      else if (form.fields.includes(input.name))
        fields.set(input.name, "flowaudit");
      else if (
        input.required &&
        !fields.get(input.name) &&
        input.type !== "hidden"
      )
        throw Error(
          `Public form input requires configured test value: ${input.name}`,
        );
    }
    r.redactor.add("Invalid-flowaudit-only");
    return fields;
  };
  try {
    if (config.files.length) {
      const control = await send(
        "/flowaudit-missing-" + randomUUID(),
        "Public file negative control",
      );
      for (const path of config.files) {
        const first = await send(path, "Public file candidate");
        const match =
          first.status === 200 &&
          gitignoreDisclosure(first.body, first.contentType) &&
          first.body !== control.body &&
          !gitignoreDisclosure(control.body, control.contentType);
        const repeat = match
          ? await send(path, "Public file confirmation")
          : undefined;
        const confirmed =
          !!repeat &&
          repeat.status === 200 &&
          repeat.body === first.body &&
          gitignoreDisclosure(repeat.body, repeat.contentType);
        saveFinding({
          ruleId: "public-file-disclosure",
          title: "Public development file exposed",
          role,
          url: new URL(path, r.config.target).href,
          severity: "medium",
          status: confirmed
            ? "confirmed"
            : match || first.limited
              ? "needs-review"
              : "not-reproduced",
          parameterChannel: "path",
          evidenceIds: [
            control.evidence.id,
            first.evidence.id,
            ...(repeat ? [repeat.evidence.id] : []),
          ],
          description: confirmed
            ? "A development ignore file was retrievable twice and differed from the missing-path control. This discloses deployment metadata; it does not prove source repository access."
            : "The configured file was not confirmed as exposed.",
          detectionReason: confirmed
            ? "HTTP 200, recognizable ignore rules, non-HTML content, different negative control and identical confirmation response."
            : "No confirmed file signature or insufficient evidence.",
          steps: [
            "Request a unique missing-path control",
            `GET ${path}`,
            "Compare content signature and repeat any positive candidate",
          ],
        });
      }
    }
    for (const form of config.forms) {
      try {
        const baseline = await send(
          form.submitPath,
          "Public form baseline",
          await freshForm(form),
        );
        const sourceScreen = session.current?.id;
        const cases = [
          ...(form.headerMutation
            ? [{ channel: "header", parameter: "X-HTTP-METHOD-OVERRIDE" }]
            : []),
          ...form.fields.map((parameter) => ({
            channel: "form-name/type",
            parameter,
          })),
        ];
        for (const current of cases) {
          const attempt = async (label: string) => {
            const fields = await freshForm(form);
            const headers: Record<string, string> = {};
            if (current.channel === "header")
              headers["X-HTTP-METHOD-OVERRIDE"] = "SECURITY_SCAN_INVALID";
            else {
              const value = fields.get(current.parameter) ?? "flowaudit";
              fields.delete(current.parameter);
              fields.set(`${current.parameter}[$qe]`, value);
            }
            return send(form.submitPath, label, fields, headers);
          };
          const first = await attempt(
            `Public mutation: ${current.channel} ${current.parameter}`,
          );
          const repeat = first.debug
            ? await attempt("Public debug confirmation")
            : undefined;
          const confirmed = !!first.debug && !!repeat?.debug;
          const inconclusive =
            first.limited ||
            baseline.limited ||
            [401, 403, 419, 429].includes(first.status) ||
            [401, 403, 419, 429].includes(baseline.status) ||
            (!!first.debug && !repeat?.debug);
          let resultScreenId: string | undefined;
          if (confirmed && repeat?.live?.screenshot) {
            const capture = repeat.evidence.browserCapture!;
            resultScreenId = randomUUID();
            const transitionId = randomUUID();
            r.data.screens.push({
              id: resultScreenId,
              kind: "browser-response",
              role,
              url: capture.url,
              title: `HTTP ${capture.status} · ${current.parameter}`,
              text: r.redactor.text(repeat.debug || ""),
              fingerprint: resultScreenId,
              screenshot: capture.screenshot,
              actions: [],
              observedAt: capture.at,
              evidenceIds: [
                baseline.evidence.id,
                first.evidence.id,
                repeat.evidence.id,
              ],
              captureNote: capture.note,
            });
            r.data.transitions.push({
              id: transitionId,
              kind: "verification",
              role,
              from: sourceScreen ?? null,
              to: resultScreenId,
              action: `POST ${form.submitPath} · ${current.channel}: ${current.parameter}`,
              evidenceIds: [
                baseline.evidence.id,
                first.evidence.id,
                repeat.evidence.id,
              ],
              at: capture.at,
            });
            repeat.evidence.transitionId = transitionId;
          }
          saveFinding({
            resultScreenId,
            ruleId: "public-debug-disclosure",
            title: "Framework debug information exposed",
            role,
            url: new URL(form.submitPath, r.config.target).href,
            screenId: sourceScreen,
            parameter: current.parameter,
            parameterChannel: current.channel,
            severity: "medium",
            status: confirmed
              ? "confirmed"
              : inconclusive
                ? "needs-review"
                : "not-reproduced",
            evidenceIds: [
              baseline.evidence.id,
              first.evidence.id,
              ...(repeat ? [repeat.evidence.id] : []),
            ],
            description: confirmed
              ? `Two responses exposed a stack trace and source file locations. ${baseline.debug ? "The baseline also disclosed debug information." : "The invalid baseline did not contain the debug signature."} This confirms information disclosure, not SQL injection or authentication bypass.`
              : "No repeat-confirmed debug signature in this bounded mutation; this does not establish input validation or injection safety.",
            detectionReason: confirmed
              ? first.debug
              : inconclusive
                ? "Response blocked, truncated or not repeat-confirmed."
                : "No stack trace with source-file/line evidence detected.",
            steps: [
              `Open ${form.pagePath} and obtain fresh hidden fields/cookies`,
              "Submit unique invalid baseline",
              current.channel === "header"
                ? "Submit with invalid method-override header"
                : `Change ${current.parameter} to ${current.parameter}[$qe]`,
              "Inspect stack trace plus file/line context; repeat a positive candidate with fresh CSRF",
            ],
          });
        }
      } catch (error) {
        r.blocker(
          (error as Error).message,
          role,
          new URL(form.pagePath, r.config.target).href,
        );
        if (/budget|cancel|interrupt|Scan /.test((error as Error).message))
          throw error;
      }
    }
  } finally {
    await session.context.clearCookies().catch(() => {});
    if (initialCookies.length)
      await session.context.addCookies(initialCookies).catch(() => {});
    r.data.coverage.notes.push(
      `Public surface checks: ${requests}/${config.maxRequests} reserved HTTP requests including form refreshes, excluding page subresources. All traffic also uses global action/time/rate budgets. File list: ${config.files.join(", ")}. Debug disclosure has no ASVS L1 mapping (ASVS 5.0 error handling is L2).`,
    );
    r.save();
  }
  return out;
}
