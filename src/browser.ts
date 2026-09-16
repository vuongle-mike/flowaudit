import {
  chromium,
  type Browser,
  type BrowserContext,
  type Page,
  type Request,
} from "playwright";
import { randomUUID, createHash } from "node:crypto";
import { join } from "node:path";
import type {
  Action,
  ProjectConfig,
  ScanData,
  Screen,
  Transition,
  Evidence,
} from "./types.js";
import { assertScope, inScope, dangerous } from "./config.js";
import { Redactor } from "./redact.js";
const now = () => new Date().toISOString();
export interface Session {
  context: BrowserContext;
  page: Page;
  role: string;
  current?: Screen;
  transitionId?: string;
  allowLogout: boolean;
  authenticating: boolean;
  pending: Set<Promise<unknown>>;
}
export class BrowserRecorder {
  prepare?: () => Promise<void>;
  browser?: Browser;
  sessions = new Map<string, Session>();
  nextRequest = 0;
  // Volatile request templates. Never included in ScanData, SQLite or reports.
  liveRequests = new Map<string, Evidence>();
  constructor(
    public config: ProjectConfig,
    public data: ScanData,
    public dir: string,
    public secrets: Record<string, any>,
    public redactor: Redactor,
    public save: () => void,
  ) {}
  blocker(reason: string, role?: string, url?: string, action?: string) {
    const clean = this.redactor.clean({
      reason: reason.split("\n", 1)[0],
      role,
      url,
      action,
      at: now(),
    });
    const existing = this.data.blockers.find(
      (item) =>
        item.reason === clean.reason &&
        item.role === clean.role &&
        item.url === clean.url &&
        item.action === clean.action,
    );
    if (existing) {
      existing.occurrences = (existing.occurrences ?? 1) + 1;
      existing.at = clean.at;
    } else this.data.blockers.push({ ...clean, occurrences: 1 });
    this.save();
  }
  check() {
    if (this.data.status !== "running") throw Error(`Scan ${this.data.status}`);
    if (
      Date.now() - Date.parse(this.data.startedAt) >
      this.config.limits.minutes * 60000
    ) {
      this.blocker("Time budget reached");
      throw Error("Time budget reached");
    }
  }
  async init() {
    if (!this.browser) {
      await this.prepare?.();
      this.check();
      this.browser = await chromium.launch({
        headless: process.env.HEADED !== "1",
        executablePath: process.env.CHROMIUM_PATH || undefined,
        args: ["--disable-quic", "--proxy-bypass-list=<-loopback>"],
      });
      if (this.data.status !== "running") {
        await this.browser.close();
        this.browser = undefined;
        this.check();
      }
    }
  }
  async open(role: string) {
    this.check();
    await this.init();
    this.check();
    if (this.sessions.has(role)) {
      if (await this.probe(role)) return this.observe(role);
      await this.session(role).context.close();
      this.sessions.delete(role);
    }
    const profile = this.config.roles[role];
    if (!profile) throw Error("Unknown role");
    const credential = this.secrets[profile.secretRef];
    if (!credential) throw Error("Credential reference missing");
    const storageState =
      profile.type === "storageState" ? credential.storageState : undefined;
    if (profile.type === "storageState" && !storageState)
      throw Error(
        "storageState credentials require a captured browser session",
      );
    const context = await this.browser!.newContext({
      viewport: { width: 1280, height: 850 },
      storageState,
      serviceWorkers: "block",
      ignoreHTTPSErrors: !!this.config.zap,
      proxy: this.config.zap
        ? { server: this.config.zap.proxyUrl, bypass: "<-loopback>" }
        : undefined,
      acceptDownloads: false,
    });
    const page = await context.newPage();
    page.setDefaultTimeout(6000);
    page.setDefaultNavigationTimeout(12000);
    const s: Session = {
      context,
      page,
      role,
      allowLogout: false,
      authenticating: true,
      pending: new Set(),
      transitionId: randomUUID(),
    };
    this.sessions.set(role, s);
    context.on("page", (p) => {
      if (p !== page) {
        this.blocker(
          "Popup discovered; automatic popup traversal unavailable",
          role,
        );
        void p.close();
      }
    });
    page.on("dialog", (dialog) => void dialog.dismiss());
    const requestIds = new WeakMap<Request, string>();
    await context.routeWebSocket("**/*", (ws) => {
      this.blocker("WebSocket coverage unavailable", role, ws.url());
      ws.close();
    });
    await context.route("**/*", async (route) => {
      const req = route.request();
      try {
        this.check();
        if (!inScope(this.config, req.url()))
          throw Error("Request/redirect outside scope");
        const path = decodeURIComponent(new URL(req.url()).pathname);
        if (
          dangerous.test(path) &&
          !(s.allowLogout && /logout|signout/.test(path)) &&
          !this.config.allowedActions.some((a) => path === a)
        )
          throw Error("Request blocked by action policy");
        if (
          ["DELETE", "PUT", "PATCH", "POST"].includes(req.method()) &&
          !s.authenticating &&
          !this.config.allowedActions.some((a) => path === a) &&
          this.config.tests?.login?.submitPath !== path
        )
          throw Error("Mutating request requires allowedActions path");
        const delay = Math.max(0, this.nextRequest - Date.now());
        this.nextRequest =
          Math.max(Date.now(), this.nextRequest) +
          1000 / this.config.limits.requestsPerSecond;
        await new Promise((r) => setTimeout(r, delay));
        this.check();
        requestIds.set(req, s.transitionId || randomUUID());
        const headers = { ...req.headers() };
        delete headers["x-flowaudit-correlation"];
        delete headers["x-security-scan-correlation"];
        const bearer =
          profile.type === "bearer"
            ? credential.token
            : profile.type === "storageState"
              ? credential.bearer
              : undefined;
        if (bearer) headers.authorization = `Bearer ${bearer}`;
        const response = await route.fetch({
          headers,
          maxRedirects: 0,
          timeout: 12000,
        });
        const location = response.headers()["location"];
        if (location) {
          const redirect = new URL(location, req.url()).href;
          if (
            !inScope(this.config, redirect) ||
            (dangerous.test(decodeURIComponent(new URL(redirect).pathname)) &&
              !s.allowLogout)
          ) {
            this.blocker(
              "Redirect outside scope or action policy",
              role,
              redirect,
            );
            await route.fulfill({
              status: 403,
              contentType: "text/plain",
              body: "Redirect blocked by flowaudit scope policy",
            });
            return;
          }
        }
        await route.fulfill({ response });
      } catch (e) {
        this.blocker((e as Error).message, role, req.url());
        await route.abort().catch(() => {});
      }
    });
    context.on("response", (response) => {
      const p = (async () => {
        const req = response.request();
        const headers = await response.allHeaders();
        for (const [k, v] of Object.entries(headers))
          if (k === "set-cookie")
            for (const cookie of v.split("\n")) {
              const val = cookie.split(";")[0]?.split("=").slice(1).join("=");
              if (val) this.redactor.add(val);
            }
        const contentType = headers["content-type"] || "";
        let body = "";
        if (/json|text|javascript|xml/.test(contentType)) {
          try {
            body = (await response.text()).slice(0, 20000);
          } catch {}
        }
        const evidence = this.redactor.clean({
          id: randomUUID(),
          kind: "http" as const,
          role,
          transitionId: requestIds.get(req),
          url: this.redactor.url(req.url()),
          method: req.method(),
          status: response.status(),
          requestHeaders: await req.allHeaders(),
          responseHeaders: headers,
          requestBody: req.postData() || "",
          responseBody: body,
          at: now(),
        });
        if (
          this.config.mode === "active" &&
          inScope(this.config, req.url()) &&
          !s.authenticating &&
          ["GET", "POST"].includes(req.method()) &&
          (req.method() === "GET" ||
            this.config.allowedActions.includes(new URL(req.url()).pathname)) &&
          (req.postData()?.length || 0) < 1000000
        ) {
          const raw: Evidence = {
            id: evidence.id,
            kind: "http",
            role,
            method: req.method(),
            url: req.url(),
            requestHeaders: await req.allHeaders(),
            requestBody: req.postData() || "",
            responseHeaders: headers,
            status: response.status(),
            at: evidence.at,
          };
          const u = new URL(req.url());
          const shape = `${role} ${req.method()} ${u.pathname}?${[...u.searchParams.keys()].sort().join("&")} ${req.method() === "POST" ? [...new URLSearchParams(req.postData() || "").keys()].sort().join("&") : ""}`;
          if (
            this.liveRequests.size < this.config.limits.statesPerRole * 4 ||
            this.liveRequests.has(shape)
          )
            this.liveRequests.set(shape, raw);
        }
        this.data.evidence.push(evidence);
        this.save();
      })();
      s.pending.add(p);
      void p.catch(() => {}).finally(() => s.pending.delete(p));
    });
    try {
      if (profile.type === "cookie") {
        if (!Array.isArray(credential.cookies))
          throw Error("cookie credentials require cookies array");
        await context.addCookies(
          credential.cookies.map((c: any) =>
            c.domain ? c : { ...c, url: c.url || this.config.target },
          ),
        );
      }
      if (profile.type === "form") {
        const login = new URL(profile.loginPath || "/login", this.config.target)
          .href;
        assertScope(this.config, login);
        await page.goto(login);
        await page
          .locator(profile.usernameSelector || "[name=username]")
          .fill(credential.username);
        await page
          .locator(profile.passwordSelector || "[name=password]")
          .fill(credential.password);
        await page
          .locator(profile.submitSelector || "button[type=submit]")
          .click();
        await this.settle(s);
      } else await page.goto(this.config.target);
      s.authenticating = false;
      if (!(await this.probe(role)))
        throw Error(
          "Authentication probe failed (MFA/CAPTCHA or expired credentials)",
        );
      return await this.observe(role, "Open authenticated session");
    } catch (e) {
      s.authenticating = false;
      this.blocker((e as Error).message, role);
      await context.close().catch(() => {});
      this.sessions.delete(role);
      throw Error(this.redactor.text((e as Error).message));
    }
  }
  async settle(s: Session) {
    await s.page.waitForLoadState("domcontentloaded").catch(() => {});
    await s.page.waitForTimeout(180);
    await Promise.allSettled([...s.pending]);
  }
  session(role: string) {
    const s = this.sessions.get(role);
    if (!s) throw Error("Open role session first");
    return s;
  }
  async probe(role: string) {
    const s = this.session(role),
      p = this.config.roles[role];
    const url = new URL(p.probePath, this.config.target).href;
    assertScope(this.config, url);
    try {
      const result = await s.page.evaluate(
        async ({ url }) => {
          const r = await fetch(url, {
            redirect: "error",
            credentials: "include",
            signal: AbortSignal.timeout(6000),
          });
          return { status: r.status, text: await r.text() };
        },
        { url },
      );
      const ok = result.status === 200 && result.text.includes(p.probeContains);
      if (!ok)
        this.blocker(
          "Authentication lost; protected workflow stopped",
          role,
          url,
        );
      return ok;
    } catch {
      return false;
    }
  }
  async observe(role: string, action?: string, meta: Partial<Transition> = {}) {
    this.check();
    const s = this.session(role);
    await this.settle(s);
    for (const selector of this.config.sensitiveSelectors) {
      const values = await s.page
        .locator(selector)
        .evaluateAll((els) =>
          els.flatMap((el) => [
            (el.textContent || "").trim(),
            (el as HTMLInputElement).value || "",
          ]),
        );
      for (const value of values) this.redactor.add(value);
    }
    this.data.evidence = this.data.evidence.map((e) => this.redactor.clean(e));
    const observed = await s.page.evaluate(() => {
      for (const el of document.querySelectorAll("[data-scan-id]"))
        el.removeAttribute("data-scan-id");
      const dialogs = [
        ...document.querySelectorAll<HTMLElement>("dialog[open],[role=dialog]"),
      ].filter((el) => el.getClientRects().length > 0);
      const actionRoot = dialogs.at(-1) || document;
      const els = [
        ...actionRoot.querySelectorAll<HTMLElement>(
          "a[href],button,input:not([type=hidden]),select,textarea,[role=tab],[role=button]",
        ),
      ].filter((el) => el.getClientRects().length > 0);
      const actions = els.slice(0, 120).map((el, i) => {
        const id = `a${i}`;
        el.setAttribute("data-scan-id", id);
        const input = el as HTMLInputElement;
        const kind =
          el.tagName === "SELECT"
            ? "select"
            : el.matches(
                  "input:not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]),textarea",
                )
              ? "fill"
              : "click";
        return {
          id,
          kind,
          label:
            el.getAttribute("aria-label") ||
            el.textContent?.trim().slice(0, 100) ||
            input.placeholder ||
            input.name ||
            input.type,
          selector: `[data-scan-id="${id}"]`,
          href: (el as HTMLAnchorElement).href || undefined,
          inputType: input.type,
          required: input.required,
          options:
            el.tagName === "SELECT"
              ? [...(el as HTMLSelectElement).options].map((o) => o.value)
              : undefined,
        };
      });
      const structure = els.map((el) => [
        el.tagName,
        el.getAttribute("role"),
        el.getAttribute("name"),
        el.getAttribute("aria-selected"),
        el.getAttribute("aria-expanded"),
        el.textContent?.trim().slice(0, 100),
      ]);
      return {
        title: document.title,
        text: document.body.innerText.slice(0, 15000),
        actions,
        structure,
        dialogs: dialogs.map((el) => el.textContent?.slice(0, 300)),
      };
    });
    const url = this.redactor.url(s.page.url());
    const fingerprint = createHash("sha256")
      .update(
        JSON.stringify([
          role,
          new URL(s.page.url()).origin +
            new URL(s.page.url()).pathname +
            new URL(s.page.url()).search,
          observed.structure,
          observed.dialogs,
        ]),
      )
      .digest("hex");
    let screen = this.data.screens.find((x) => x.fingerprint === fingerprint);
    const actions: Action[] = observed.actions.map((a) => {
      let blocked: string | undefined;
      if (a.href && !inScope(this.config, a.href)) blocked = "Outside scope";
      if (
        dangerous.test(a.label + " " + (a.href || "")) &&
        !this.config.allowedActions.includes(a.label) &&
        !this.config.allowedActions.includes(
          a.href ? new URL(a.href).pathname : "",
        )
      )
        blocked = "Action policy";
      if (a.inputType === "password")
        blocked = "Credentials entered only by authentication profile";
      return this.redactor.clean({
        ...a,
        kind: a.kind as Action["kind"],
        blocked,
      });
    });
    if (!screen) {
      if (
        this.data.screens.filter(
          (x) => x.role === role && x.kind !== "browser-response",
        ).length >= this.config.limits.statesPerRole
      ) {
        this.blocker("State budget reached", role, url);
        throw Error("State budget reached");
      }
      const id = randomUUID();
      const screenshot = `screens/${id}.png`;
      await s.page.evaluate((values) => {
        for (const el of document.querySelectorAll("body *")) {
          if (
            el.children.length === 0 &&
            values.some((v) => (el.textContent || "").includes(v))
          )
            el.setAttribute("data-scan-sensitive", "true");
        }
      }, this.redactor.values);
      const masks = [
        s.page.locator("input,textarea,[data-scan-sensitive]"),
        ...this.config.sensitiveSelectors.map((x) => s.page.locator(x)),
      ];
      await s.page.screenshot({
        path: join(this.dir, screenshot),
        fullPage: false,
        mask: masks,
      });
      screen = {
        id,
        role,
        url,
        title: this.redactor.text(observed.title),
        text: this.redactor.text(observed.text),
        fingerprint,
        screenshot,
        actions,
        observedAt: now(),
      };
      this.data.screens.push(screen);
    } else screen.actions = actions;
    this.data.observations.push({ screenId: screen.id, at: now() });
    if (action) {
      const tid = s.transitionId || randomUUID();
      this.data.transitions.push(
        this.redactor.clean({
          id: tid,
          role,
          from: s.current?.id || null,
          to: screen.id,
          action,
          evidenceIds: this.data.evidence
            .filter((e) => e.transitionId === tid)
            .map((e) => e.id),
          at: now(),
          ...meta,
        }),
      );
    }
    s.current = screen;
    s.transitionId = undefined;
    this.save();
    return screen;
  }
  async act(role: string, actionId: string, value?: string) {
    this.check();
    if (typeof value !== "string") value = undefined;
    const s = this.session(role);
    if (!s.current) throw Error("Observe before action");
    const a = s.current.actions.find((x) => x.id === actionId);
    if (!a) throw Error("Unknown/stale action");
    if (a.blocked) {
      this.blocker(a.blocked, role, s.current.url, a.label);
      throw Error(a.blocked);
    }
    if (this.data.coverage.actions >= this.config.limits.actions) {
      this.blocker("Action budget reached", role);
      throw Error("Action budget reached");
    }
    if (!(await this.probe(role))) throw Error("Authentication expired");
    s.transitionId = randomUUID();
    this.data.coverage.actions++;
    this.save();
    try {
      if (a.kind === "fill") {
        if (value === undefined) {
          const defaults: Record<string, string> = {
            email: "scan@example.test",
            number: "1",
            tel: "0900000000",
            url: this.config.target,
            date: "2026-01-01",
            search: "invoice",
            text: "scan test",
          };
          value = defaults[a.inputType || "text"];
          if (!value) {
            this.blocker("Input value required", role, s.current.url, a.label);
            throw Error("Input value required");
          }
        }
        await s.page.locator(a.selector).fill(value);
      } else if (a.kind === "select") {
        const v = value || a.options?.find(Boolean);
        if (!v) throw Error("Selection value required");
        await s.page.locator(a.selector).selectOption(v);
      } else await s.page.locator(a.selector).click();
      return await this.observe(role, `${a.kind}: ${a.label}`, {
        actionId: a.id,
        selector: a.selector,
        value,
      });
    } catch (e) {
      this.blocker((e as Error).message, role, s.page.url(), a.label);
      throw Error(this.redactor.text((e as Error).message));
    }
  }
  async navigate(role: string, url: string, label = "Navigate") {
    this.check();
    const target = new URL(url, this.config.target).href;
    assertScope(this.config, target);
    if (dangerous.test(new URL(target).pathname))
      throw Error("Navigation blocked by action policy");
    if (this.data.coverage.actions >= this.config.limits.actions) {
      this.blocker("Action budget reached", role);
      throw Error("Action budget reached");
    }
    this.data.coverage.actions++;
    const s = this.session(role);
    s.transitionId = randomUUID();
    await s.page.goto(target);
    if (
      this.data.blockers.at(-1)?.url &&
      this.data.blockers.at(-1)?.reason ===
        "Redirect outside scope or action policy" &&
      (await s.page.locator("body").innerText()) ===
        "Redirect blocked by flowaudit scope policy"
    )
      throw Error("Redirect outside configured scope");
    return this.observe(role, label);
  }
  async replay(role: string, ids: string[]) {
    const steps = ids.map((id) => {
      const t = this.data.transitions.find((x) => x.id === id);
      if (!t) throw Error("Unknown transition");
      if (t.kind === "verification")
        throw Error(
          "Verification transitions require run_verifiers with fresh tokens; they cannot be replayed as UI clicks",
        );
      return { ...t };
    });
    await this.navigate(role, this.config.target, "Replay start");
    for (const t of steps) {
      if (t.from === null) continue;
      const screen = await this.observe(role);
      const [kind, ...label] = t.action.split(": ");
      const a = screen.actions.find(
        (a) => a.kind === kind && a.label === label.join(": "),
      );
      if (!a) {
        this.blocker(
          "Replay action no longer available; dynamic flow needs rediscovery",
          role,
          screen.url,
          t.action,
        );
        throw Error("Replay requires rediscovery");
      }
      await this.act(role, a.id, t.value);
    }
    return this.observe(role);
  }
  async close() {
    for (const s of this.sessions.values()) {
      await s.context.close().catch(() => {});
      await Promise.allSettled([...s.pending]);
    }
    this.sessions.clear();
    this.liveRequests.clear();
    await this.browser?.close();
    this.browser = undefined;
  }
}
