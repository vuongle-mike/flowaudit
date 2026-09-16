import { randomUUID } from "node:crypto";
import type { Finding } from "./types.js";
import { BrowserRecorder } from "./browser.js";
import { ASVS_IDS } from "./asvs.js";
import { assertScope } from "./config.js";
import { runPublicChecks } from "./public-checks.js";
export async function runVerifiers(
  r: BrowserRecorder,
  onlyRule?: string,
): Promise<Finding[]> {
  const out: Finding[] = [];
  const tests = r.config.tests;
  if (!tests) {
    r.blocker(
      "No business expectations configured; authorization/session tests need review",
    );
    return out;
  }
  if (r.config.mode !== "active")
    throw Error("Verification requires project mode active");
  if (tests.publicSurface && (!onlyRule || onlyRule === "public-surface"))
    out.push(...(await runPublicChecks(r)));
  const add = (
    f: Omit<Finding, "id" | "source" | "evidenceIds">,
    note: string,
    extraEvidenceIds: string[] = [],
  ) => {
    const eid = randomUUID();
    r.data.evidence.push({
      id: eid,
      kind: "verification",
      role: f.role,
      url: f.url,
      note: r.redactor.text(note),
      at: new Date().toISOString(),
    });
    const found = r.data.findings.find(
      (x) => x.ruleId === f.ruleId && x.role === f.role && x.url === f.url,
    );
    const value: Finding = r.redactor.clean({
      ...f,
      id: found?.id || randomUUID(),
      source: "verifier",
      evidenceIds: [
        ...new Set([
          eid,
          ...extraEvidenceIds,
          ...r.data.evidence
            .filter(
              (e) => e.role === f.role && e.url === f.url && e.kind === "http",
            )
            .slice(-4)
            .map((e) => e.id),
        ]),
      ],
    });
    if (found) Object.assign(found, value);
    else r.data.findings.push(value);
    out.push(value);
    for (const id of value.asvsIds) {
      const row = r.data.assessments.find((a) => a.id === id);
      if (!row) continue;
      row.evidenceIds = [
        ...new Set([...row.evidenceIds, ...value.evidenceIds]),
      ];
      row.status =
        value.status === "confirmed"
          ? "fail"
          : row.status === "fail"
            ? "fail"
            : "needs-review";
      row.scope = `${r.config.target}; configured ${value.ruleId} workflow for ${value.role}`;
      row.rationale =
        value.status === "confirmed"
          ? value.description
          : "Configured scenario did not reproduce the issue; full requirement still needs review.";
    }
    r.save();
  };
  if (tests.login && (!onlyRule || onlyRule === "login-inputs")) {
    const t = tests.login;
    if (!r.config.roles[t.role])
      throw Error("Login test role is not configured");
    const loginUrl = new URL(t.loginPath, r.config.target).href;
    const submitUrl = new URL(t.submitPath, r.config.target).href;
    assertScope(r.config, loginUrl);
    assertScope(r.config, submitUrl);
    await r.open(t.role);
    const session = r.session(t.role);
    const baseCookies = await session.context.cookies();
    const marker = randomUUID();
    const invalidEmail = `scan-${marker}@example.test`;
    const invalidPassword = `Invalid-${marker}`;
    r.redactor.add(invalidPassword);
    const cases = [
      {
        name: "invalid baseline",
        kind: "baseline",
        username: invalidEmail,
        password: invalidPassword,
      },
      {
        name: "SQL tautology in username",
        kind: "sql",
        username: `' OR '1'='1' -- `,
        password: invalidPassword,
      },
      {
        name: "SQL tautology in password",
        kind: "sql",
        username: invalidEmail,
        password: `' OR '1'='1' -- `,
      },
      {
        name: "HTML execution marker in username",
        kind: "xss",
        username: `\"><img src=x onerror="window.__securityScanLoginXss='${marker}'">`,
        password: invalidPassword,
      },
      {
        name: "template expression in username",
        kind: "template",
        username: `{{7*7}}-${marker}@example.test`,
        password: invalidPassword,
      },
    ].slice(0, t.maxAttempts);
    const results: Array<{
      name: string;
      kind: string;
      status?: number;
      location?: string;
      finalUrl: string;
      sqlError: boolean;
      reflected: boolean;
      executed: boolean;
      authenticated: boolean;
      failureSeen: boolean;
      evidenceIds: string[];
      screenId?: string;
    }> = [];
    for (const current of cases) {
      r.check();
      await session.context.clearCookies();
      if (baseCookies.length) await session.context.addCookies(baseCookies);
      await r.navigate(t.role, loginUrl, `Login input test: ${current.name}`);
      const fields = await session.page.evaluate(
        ({ usernameField, passwordField, csrfField, submitUrl }) => {
          const inputs = [
            ...document.querySelectorAll<HTMLInputElement>("input"),
          ];
          const username = inputs.find((input) => input.name === usernameField);
          const password = inputs.find((input) => input.name === passwordField);
          const csrf = csrfField
            ? inputs.find((input) => input.name === csrfField)
            : undefined;
          const form = username?.form;
          return {
            username: !!username,
            password: !!password,
            csrf: !csrfField || !!csrf?.value,
            action: form?.action,
            method: form?.method.toUpperCase(),
            expected: submitUrl,
          };
        },
        {
          usernameField: t.usernameField,
          passwordField: t.passwordField,
          csrfField: t.csrfField,
          submitUrl,
        },
      );
      if (!fields.username || !fields.password)
        throw Error("Configured login fields were not found");
      if (!fields.csrf) throw Error("Configured login CSRF field is missing");
      if (fields.method !== "POST" || fields.action !== submitUrl)
        throw Error(
          "Observed login form does not match configured POST endpoint",
        );
      await session.page.evaluate(
        ({ usernameField, passwordField, username, password }) => {
          const inputs = [
            ...document.querySelectorAll<HTMLInputElement>("input"),
          ];
          const user = inputs.find((input) => input.name === usernameField)!;
          const pass = inputs.find((input) => input.name === passwordField)!;
          user.type = "text";
          user.value = username;
          pass.value = password;
        },
        {
          usernameField: t.usernameField,
          passwordField: t.passwordField,
          username: current.username,
          password: current.password,
        },
      );
      r.redactor.add(current.password);
      if (r.data.coverage.actions >= r.config.limits.actions)
        throw Error("Action budget reached during login-input verification");
      const transitionId = randomUUID();
      session.transitionId = transitionId;
      r.data.coverage.actions++;
      r.save();
      await Promise.all([
        session.page
          .waitForNavigation({ waitUntil: "domcontentloaded", timeout: 15000 })
          .catch(() => undefined),
        session.page.evaluate((usernameField) => {
          const input = [
            ...document.querySelectorAll<HTMLInputElement>("input"),
          ].find((candidate) => candidate.name === usernameField);
          input?.form?.submit();
        }, t.usernameField),
      ]);
      const screen = await r.observe(
        t.role,
        `Login input test result: ${current.name}`,
      );
      const html = await session.page.content();
      const text = await session.page
        .locator("body")
        .innerText()
        .catch(() => "");
      const postEvidence = r.data.evidence.filter(
        (e) =>
          e.transitionId === transitionId &&
          e.method === "POST" &&
          e.url === r.redactor.url(submitUrl),
      );
      const response = postEvidence.at(-1);
      const sqlError =
        /SQLSTATE|PDOException|mysql_|PostgreSQL|ORA-\d{3,}|SQL syntax|unterminated quoted string|database query exception/i.test(
          `${response?.responseBody || ""}\n${html}`,
        );
      const reflected =
        current.kind === "xss" && html.includes(current.username);
      const executed =
        current.kind === "xss" &&
        (await session.page
          .evaluate(
            (value) => (window as any).__securityScanLoginXss === value,
            marker,
          )
          .catch(() => false));
      const finalUrl = session.page.url();
      const authenticated = Boolean(
        t.successContains &&
        text.includes(t.successContains) &&
        (!t.successPath ||
          new URL(finalUrl).pathname.startsWith(t.successPath)),
      );
      for (const evidence of postEvidence)
        evidence.note = r.redactor.text(
          `Login input case: ${current.name}; final path=${new URL(finalUrl).pathname}`,
        );
      r.save();
      results.push({
        name: current.name,
        kind: current.kind,
        status: response?.status,
        location: response?.responseHeaders?.location,
        finalUrl,
        sqlError,
        reflected,
        executed,
        authenticated,
        failureSeen: Boolean(
          t.failureContains && text.includes(t.failureContains),
        ),
        evidenceIds: postEvidence.map((e) => e.id),
        screenId: screen.id,
      });
    }
    await session.context.clearCookies();
    if (baseCookies.length) await session.context.addCookies(baseCookies);
    const baseline = results[0];
    const sql = results.filter((result) => result.kind === "sql");
    const sqlConfirmed =
      !baseline.authenticated && sql.some((result) => result.authenticated);
    const sqlAnomaly = sql.some(
      (result) =>
        result.sqlError ||
        result.status !== baseline.status ||
        result.location !== baseline.location ||
        new URL(result.finalUrl).pathname !==
          new URL(baseline.finalUrl).pathname ||
        (t.failureContains && baseline.failureSeen && !result.failureSeen),
    );
    const sqlEvidence = sql.flatMap((result) => result.evidenceIds);
    add(
      {
        title: "Login SQL injection or authentication bypass",
        severity: "high",
        status: sqlConfirmed
          ? "confirmed"
          : sqlAnomaly
            ? "needs-review"
            : "not-reproduced",
        ruleId: "login-sql-auth-bypass",
        role: t.role,
        url: submitUrl,
        screenId: sql.at(-1)?.screenId,
        asvsIds: [...ASVS_IDS.sqlInjection],
        steps: [
          `Open ${t.loginPath} and obtain a fresh anti-CSRF value for every attempt`,
          `Submit a unique invalid baseline to ${t.submitPath}`,
          "Submit bounded SQL tautology cases in the username and password fields",
          "Compare status, redirect, failure marker, database errors and configured authenticated-content evidence",
        ],
        description: sqlConfirmed
          ? "A SQL payload met the configured authenticated-content criterion while the invalid baseline did not."
          : sqlAnomaly
            ? "A SQL payload differed from the invalid baseline and needs manual confirmation."
            : "The bounded SQL login cases matched the invalid baseline and did not meet the configured authentication-success criterion.",
      },
      `Login attempts=${results.length}; SQL cases=${sql.length}; confirmed=${sqlConfirmed}; response anomaly=${sqlAnomaly}; HTTP evidence=${sqlEvidence.join(",")}`,
      [...baseline.evidenceIds, ...sqlEvidence],
    );
    const xss = results.find((result) => result.kind === "xss");
    if (xss)
      add(
        {
          title: "Reflected XSS through login input",
          severity: "high",
          status: xss.executed
            ? "confirmed"
            : xss.reflected
              ? "needs-review"
              : "not-reproduced",
          ruleId: "login-reflected-xss",
          role: t.role,
          url: submitUrl,
          screenId: xss.screenId,
          asvsIds: [...ASVS_IDS.xss],
          steps: [
            `Open ${t.loginPath} with a fresh anti-CSRF value`,
            `Submit an execution marker through ${t.usernameField}`,
            "Check the real response document for unsafe reflection and marker execution",
          ],
          description: xss.executed
            ? "The login input execution marker ran in the returned page."
            : xss.reflected
              ? "The marker was reflected verbatim but browser execution was not observed."
              : "The bounded login XSS marker was not reflected as executable markup.",
        },
        `Raw reflection=${xss.reflected}; browser execution=${xss.executed}; HTTP evidence=${xss.evidenceIds.join(",")}`,
        [...baseline.evidenceIds, ...xss.evidenceIds],
      );
  }
  if (tests.xss && (!onlyRule || onlyRule === "reflected-xss")) {
    const t = tests.xss;
    await r.open(t.role);
    if (!(await r.probe(t.role))) throw Error("Authentication expired");
    const marker = randomUUID(),
      url = new URL(t.path, r.config.target);
    url.searchParams.set(
      t.parameter,
      `<img src="/missing-scan-image" onerror="window.__securityScanXss='${marker}'">`,
    );
    await r.navigate(t.role, url.href, "Verify reflected XSS");
    const s = r.session(t.role);
    const executed = await s.page.evaluate(
      (m) => (window as any).__securityScanXss === m,
      marker,
    );
    add(
      {
        title: "Reflected XSS",
        severity: "high",
        status: executed ? "confirmed" : "not-reproduced",
        ruleId: "reflected-xss",
        role: t.role,
        url: r.redactor.url(url.href),
        screenId: s.current?.id,
        asvsIds: [...ASVS_IDS.xss],
        steps: [
          "Authenticate using configured role",
          `Open ${t.path} with a unique inert DOM execution marker in ${t.parameter}`,
          "Check marker execution in the browser",
        ],
        description: executed
          ? "Attacker-controlled input executed JavaScript in the authenticated page."
          : "Execution marker was not observed.",
      },
      `Unique marker ${marker}; browser execution observed=${executed}`,
    );
    await r.navigate(t.role, r.config.target, "Return after XSS verification");
  }
  for (const t of tests.authorization || []) {
    const ruleId = `authorization:${t.name}`;
    if (onlyRule && onlyRule !== ruleId) continue;
    await r.open(t.ownerRole);
    await r.open(t.attackerRole);
    if (!(await r.probe(t.ownerRole)) || !(await r.probe(t.attackerRole)))
      throw Error("Authentication expired");
    await r.navigate(
      t.ownerRole,
      t.discoveryPath,
      "Discover protected resource",
    );
    const owner = r.session(t.ownerRole);
    const href = await owner.page
      .locator(t.linkSelector)
      .first()
      .getAttribute("href");
    if (!href) {
      r.blocker("Protected resource not discovered", t.ownerRole);
      continue;
    }
    const url = new URL(href, r.config.target).href;
    assertScope(r.config, url);
    await r.navigate(t.ownerRole, url, "Verify owner access");
    const baseline = (await owner.page.locator("body").innerText()).includes(
      t.protectedMarker,
    );
    if (!baseline) {
      r.blocker(
        "Owner baseline missing protected marker; authorization result inconclusive",
        t.ownerRole,
        url,
      );
      continue;
    }
    await r.navigate(t.attackerRole, url, "Verify unauthorized access");
    const attacker = r.session(t.attackerRole);
    const exposed = (await attacker.page.locator("body").innerText()).includes(
      t.protectedMarker,
    );
    add(
      {
        title: t.name,
        severity: "high",
        status: exposed ? "confirmed" : "not-reproduced",
        ruleId,
        role: t.attackerRole,
        url,
        screenId: attacker.current?.id,
        asvsIds: t.asvsIds,
        steps: [
          `Authenticate as ${t.ownerRole}`,
          `Discover current resource through ${t.discoveryPath}`,
          `Confirm owner can see configured protected content`,
          `Open discovered resource as ${t.attackerRole} and check protected content`,
        ],
        description: exposed
          ? "A role explicitly configured as unauthorized received protected content."
          : "Protected content was not exposed in the configured scenario.",
      },
      `Owner baseline=${baseline}; attacker protected content=${exposed}; marker=${t.protectedMarker}`,
    );
  }
  if (tests.session && (!onlyRule || onlyRule === "session-logout")) {
    const t = tests.session;
    await r.open(t.role);
    const s = r.session(t.role);
    await r.navigate(t.role, t.protectedPath, "Session baseline");
    const baseline = (await s.page.locator("body").innerText()).includes(
      t.protectedMarker,
    );
    if (!baseline) {
      r.blocker("Protected baseline unavailable for logout test", t.role);
      return out;
    }
    const cookies = await s.context.cookies();
    for (const c of cookies) r.redactor.add(c.value);
    const credential = r.secrets[r.config.roles[t.role].secretRef];
    const token = credential.token;
    if (token) r.redactor.add(token);
    s.allowLogout = true;
    try {
      const logout = new URL(t.logoutPath, r.config.target).href;
      assertScope(r.config, logout);
      s.transitionId = randomUUID();
      await s.page.goto(logout);
      await r.observe(t.role, "Session test: logout");
    } finally {
      s.allowLogout = false;
    }
    await s.context.clearCookies();
    await s.context.addCookies(cookies);
    await r.navigate(t.role, t.protectedPath, "Replay pre-logout session");
    const exposed = (await s.page.locator("body").innerText()).includes(
      t.protectedMarker,
    );
    add(
      {
        title: "Session remains valid after logout",
        severity: "high",
        status: exposed ? "confirmed" : "not-reproduced",
        ruleId: "session-logout",
        role: t.role,
        url: new URL(t.protectedPath, r.config.target).href,
        screenId: s.current?.id,
        asvsIds: [...ASVS_IDS.session],
        steps: [
          "Authenticate and confirm protected baseline",
          "Preserve pre-logout session in memory",
          "Logout, restore previous credential, request protected content",
        ],
        description: exposed
          ? "The pre-logout session still returns protected content after logout."
          : "The previous session did not expose protected content after logout.",
      },
      `Protected baseline=true; old-session protected content=${exposed}`,
    );
    await s.context.close();
    r.sessions.delete(t.role);
  }
  return out;
}
