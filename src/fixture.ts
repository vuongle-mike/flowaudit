import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export interface FixtureOptions {
  mode: "vulnerable" | "fixed";
  port?: number;
  host?: string;
}
export interface Fixture {
  publicResponses: Array<{
    sha256: string;
    method: string;
    fetchMode: string;
    accept: string;
  }>;
  url: string;
  close: () => Promise<void>;
}
interface User {
  username: string;
  role: "user" | "admin";
  org: string;
  name: string;
}
interface Invoice {
  id: string;
  org: string;
  number: string;
  client: string;
  amount: number;
  status: string;
  note: string;
  marker: string;
}
const users: User[] = [
  { username: "userA", role: "user", org: "org-a", name: "Alex Morgan" },
  { username: "userB", role: "user", org: "org-b", name: "Bailey Chen" },
  { username: "admin", role: "admin", org: "staff", name: "Jamie Admin" },
];
const escape = (value: unknown) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const money = (value: number) =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(value);
const seed = (): Invoice[] => [
  {
    id: "inv_7e2a1042",
    org: "org-a",
    number: "INV-1042",
    client: "Northstar Studio",
    amount: 8400,
    status: "Pending",
    note: "Brand strategy and product design · September",
    marker: "ORG_A_PRIVATE_INVOICE",
  },
  {
    id: "inv_0bd31041",
    org: "org-a",
    number: "INV-1041",
    client: "Fieldwork Co.",
    amount: 5200,
    status: "Paid",
    note: "Research sprint · September",
    marker: "ORG_A_PRIVATE_INVOICE",
  },
  {
    id: "inv_fa8c2093",
    org: "org-b",
    number: "INV-2093",
    client: "Cedar Labs",
    amount: 12750,
    status: "Pending",
    note: "Engineering retainer · September",
    marker: "ORG_B_PRIVATE_INVOICE",
  },
];
const style = `:root{color-scheme:light;--ink:#182b38;--muted:#6e7d87;--green:#126b54;--line:#dfe6e6}*{box-sizing:border-box}body{margin:0;background:#f3f6f5;color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--green);text-decoration:none}button,input{font:inherit}button,a.button{cursor:pointer;border:0;border-radius:8px;background:var(--green);color:white;padding:10px 18px;display:inline-block;font-weight:600}button.secondary{background:#eaf1ee;color:var(--green)}button.ghost{background:transparent;color:var(--muted)}input{width:100%;padding:11px 13px;border:1px solid #cfdad6;border-radius:7px;color:var(--ink);background:white}label{display:block;font-size:13px;font-weight:600;margin:16px 0 6px}header{height:78px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 6%;gap:48px}.brand{font-size:22px;font-weight:800;letter-spacing:-1px;color:var(--ink)}.brand b{color:var(--green)}nav{display:flex;gap:26px;align-items:center}nav a{color:var(--muted);font-weight:600;font-size:14px}nav a.active{color:var(--green)}.identity{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:13px}.avatar{display:grid;place-items:center;width:36px;height:36px;border-radius:50%;background:#e6eee9;color:var(--green);font-weight:700}main{max-width:1170px;padding:44px 32px 72px;margin:auto}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:2px;font-weight:700;color:var(--green);margin:0 0 8px}h1{font-size:34px;line-height:1.2;letter-spacing:-1.2px;margin:0 0 12px}h2{font-size:18px;letter-spacing:-.3px;margin:0}p{margin:8px 0 16px}.muted{color:var(--muted)}.row{display:flex;align-items:center;justify-content:space-between;gap:20px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin:32px 0}.card{border:1px solid var(--line);border-radius:13px;background:#fff;overflow:hidden}.stat{padding:24px}.stat small{color:var(--muted);font-size:13px}.stat strong{display:block;font-size:29px;letter-spacing:-1px;margin:6px 0}.positive{font-size:12px;color:var(--green)}.card-heading{padding:22px 26px;border-bottom:1px solid var(--line)}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);background:#fafcfb}td,th{padding:18px 26px;border-bottom:1px solid #eef2f0}tbody tr:last-child td{border:0}.client{font-weight:600}.pill{display:inline-block;font-size:11px;font-weight:700;border-radius:20px;padding:4px 10px;background:#e7f1eb;color:var(--green)}.pill.pending{background:#fff2d7;color:#8b6321}.panel{padding:28px}.login{max-width:450px;margin:5vh auto;padding:36px}.login button{width:100%;margin-top:22px}.login .brand{margin-bottom:34px}.error{background:#fff0eb;border:1px solid #f5caba;color:#9a3e20;border-radius:8px;padding:12px}.tabs{display:flex;gap:20px;border-bottom:1px solid var(--line);margin:28px 0 0}.tabs button{border-radius:0;background:transparent;color:var(--muted);padding:14px 4px;border-bottom:3px solid transparent}.tabs button[aria-selected=true]{color:var(--green);border-bottom-color:var(--green)}.detail-grid{display:grid;grid-template-columns:2fr 1fr;gap:24px;margin-top:24px}.kv{padding:12px 0;border-bottom:1px solid #eef2f0;display:flex;justify-content:space-between}.marker{font:11px/1.6 ui-monospace,monospace;color:#819089;letter-spacing:.3px}.spaced{margin-top:26px}.search-form{display:flex;gap:12px;max-width:620px;margin:24px 0}.search-form label{margin:0;flex:1}.search-form button{align-self:stretch}.notice{font-size:12px;border-top:1px solid var(--line);padding:20px 6%;color:var(--muted)}dialog{width:min(480px,90vw);border:1px solid var(--line);border-radius:16px;padding:30px;color:var(--ink);box-shadow:0 25px 100px #15342933}dialog::backdrop{background:#102b3455}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}[hidden]{display:none!important}@media(max-width:700px){header{padding:15px 20px;height:auto;flex-wrap:wrap;gap:15px}nav{gap:18px}.identity{margin-left:0}.stats,.detail-grid{grid-template-columns:1fr}main{padding:28px 20px}.stats{gap:12px}td,th{padding:12px}.row{align-items:flex-start}}`;

export async function startFixture({
  mode,
  port = 0,
  host = "127.0.0.1",
}: FixtureOptions): Promise<Fixture> {
  if (mode !== "vulnerable" && mode !== "fixed")
    throw new Error("Fixture mode must be vulnerable or fixed");
  const sessions = new Map<string, User>();
  const publicCsrf = new Set<string>();
  const publicResponses: Array<{
    sha256: string;
    method: string;
    fetchMode: string;
    accept: string;
  }> = [];
  let invoices = seed();
  let metrics = {
    deleteRequests: 0,
    payRequests: 0,
    leakedCorrelationHeaders: 0,
    requests: 0,
  };
  const cookies = (req: IncomingMessage) =>
    Object.fromEntries(
      (req.headers.cookie ?? "")
        .split(";")
        .map((part) => part.trim().split(/=(.*)/s).slice(0, 2))
        .filter((pair) => pair.length === 2),
    );
  const token = (req: IncomingMessage) =>
    req.headers.authorization?.replace(/^Bearer\s+/i, "") ??
    cookies(req).fixture_session;
  const owner = (user: User, invoice: Invoice) =>
    user.role === "admin" || user.org === invoice.org;
  const html = (res: ServerResponse, content: string, status = 200) => {
    res.writeHead(status, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    res.end(content);
  };
  const json = (res: ServerResponse, data: unknown, status = 200) => {
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(JSON.stringify(data));
  };
  const redirect = (res: ServerResponse, location: string) => {
    res.writeHead(303, { location, "cache-control": "no-store" });
    res.end();
  };
  const shell = (title: string, body: string, user?: User, active = "") =>
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · Atlas Invoices</title><style>${style}</style></head><body>${
      user
        ? `<header data-authenticated="${escape(user.username)}"><a class="brand" href="/invoices">atlas<b>·</b></a><nav aria-label="Main navigation"><a class="${active === "invoices" ? "active" : ""}" href="/invoices">Invoices</a><a class="${active === "search" ? "active" : ""}" href="/search">Search</a><a class="${active === "admin" ? "active" : ""}" href="/admin" data-admin-link>Admin</a></nav><div class="identity"><span class="avatar">${escape(
            user.name
              .split(" ")
              .map((n) => n[0])
              .join(""),
          )}</span><span>${escape(user.name)}<br><span class="muted">${escape(user.org)}</span></span><a href="/logout" data-dangerous="logout">Log out</a></div></header>`
        : ""
    }<main>${body}</main><footer class="notice">Atlas invoice workspace · Local security training fixture · ${mode} mode · Use only with test data</footer></body></html>`;
  const loginPage = (csrf: string, error = "") =>
    shell(
      "Sign in",
      `<section class="card login"><div class="brand">atlas<b>·</b></div><p class="eyebrow">Your finance workspace</p><h1>Welcome back.</h1><p class="muted">Sign in to manage your invoices and keep work moving.</p>${error ? `<div role="alert" class="error">${escape(error)}</div>` : ""}<form method="post" action="/login"><input type="hidden" name="csrf" value="${escape(csrf)}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form><p class="muted spaced" style="font-size:12px">Demo accounts: userA, userB, admin<br>Use the password in the fixture documentation.</p></section>`,
    );
  const invoiceRows = (list: Invoice[]) =>
    list
      .map(
        (inv) =>
          `<tr><td><a href="/invoices/${encodeURIComponent(inv.id)}" data-invoice-link data-invoice-id="${escape(inv.id)}">${escape(inv.number)}</a></td><td class="client">${escape(inv.client)}</td><td>Sep 30, 2026</td><td><span class="pill ${inv.status === "Pending" ? "pending" : ""}">${escape(inv.status)}</span></td><td>${money(inv.amount)}</td></tr>`,
      )
      .join("");
  async function readBody(
    req: IncomingMessage,
  ): Promise<Record<string, unknown>> {
    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 64 * 1024) throw new Error("Request body too large");
    }
    if (req.headers["content-type"]?.includes("application/json"))
      return JSON.parse(body || "{}") as Record<string, unknown>;
    return Object.fromEntries(new URLSearchParams(body));
  }
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(
        req.url ?? "/",
        `http://${req.headers.host ?? "localhost"}`,
      );
      const method = req.method ?? "GET";
      if (url.pathname === "/.gitignore" && method === "GET") {
        res.writeHead(mode === "vulnerable" ? 200 : 404, {
          "content-type": "text/plain",
        });
        res.end(
          mode === "vulnerable"
            ? "/vendor\n/node_modules\n.env\n*.log\n"
            : "Not found",
        );
        return;
      }
      if (url.pathname === "/public-form" && method === "GET") {
        const csrf = randomBytes(18).toString("hex");
        publicCsrf.add(csrf);
        res.setHeader(
          "set-cookie",
          `public_csrf=${csrf}; Path=/; HttpOnly; SameSite=Strict`,
        );
        html(
          res,
          shell(
            "Public form",
            `<h1>Public test form</h1><form method="post" action="/public-submit"><input type="hidden" name="csrf" value="${csrf}"><label>Email<input name="email" type="email" required></label><button>Submit</button></form>`,
          ),
        );
        return;
      }
      if (url.pathname === "/public-submit" && method === "POST") {
        const body = await readBody(req);
        if (
          typeof body.csrf !== "string" ||
          !publicCsrf.delete(body.csrf) ||
          body.csrf !== cookies(req).public_csrf
        ) {
          html(res, "Expired CSRF", 419);
          return;
        }
        const malformed =
          req.headers["x-http-method-override"] ||
          Object.keys(body).some((k) => k.startsWith("email["));
        if (mode === "vulnerable" && malformed) {
          const responseBody = `<html><head><style>${"/* padding */".repeat(3000)}</style></head><body><h1>TypeError</h1><h2>Stack Trace</h2><pre>0 - app/Controllers/PublicController.php:42\n1 - public/index.php:51\n</pre><h2>Request Headers</h2><p>cookie: public_csrf=${body.csrf}</p></body></html>`;
          publicResponses.push({
            sha256: createHash("sha256").update(responseBody).digest("hex"),
            method,
            fetchMode: String(req.headers["sec-fetch-mode"] || ""),
            accept: String(req.headers.accept || ""),
          });
          html(res, responseBody, 500);
        } else
          html(
            res,
            malformed ? "Invalid input" : "Generic invalid test input",
            malformed ? 400 : 422,
          );
        return;
      }
      metrics.requests++;
      if (
        Object.keys(req.headers).some((name) =>
          /correlation|scan-action|flowaudit/i.test(name),
        )
      )
        metrics.leakedCorrelationHeaders++;
      if (url.pathname === "/api/reset" && method === "POST") {
        if (
          !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(
            req.socket.remoteAddress ?? "",
          )
        ) {
          json(res, { error: "Reset is restricted to loopback clients" }, 403);
          return;
        }
        invoices = seed();
        sessions.clear();
        metrics = {
          deleteRequests: 0,
          payRequests: 0,
          leakedCorrelationHeaders: 0,
          requests: 0,
        };
        json(res, { reset: true, mode });
        return;
      }
      if (url.pathname === "/api/metrics") {
        json(res, { ...metrics, mode });
        return;
      }
      if (url.pathname === "/health") {
        json(res, { ok: true, mode });
        return;
      }
      if (url.pathname === "/redirect-external") {
        redirect(res, "https://example.com/outside-fixture");
        return;
      }
      if (url.pathname === "/login" && method === "GET") {
        const csrf = randomBytes(18).toString("hex");
        res.setHeader(
          "set-cookie",
          `fixture_csrf=${csrf}; Path=/; HttpOnly; SameSite=Strict`,
        );
        html(res, loginPage(csrf));
        return;
      }
      if (url.pathname === "/login" && method === "POST") {
        const body = await readBody(req);
        const jsonRequest =
          req.headers["content-type"]?.includes("application/json");
        if (
          !jsonRequest &&
          (!body.csrf || body.csrf !== cookies(req).fixture_csrf)
        ) {
          html(
            res,
            loginPage(
              "",
              "Your sign-in form expired. Reload this page and try again.",
            ),
            403,
          );
          return;
        }
        const user = users.find((u) => u.username === body.username);
        if (!user || body.password !== "Demo-pass-123!") {
          if (jsonRequest || req.headers.accept?.includes("application/json"))
            json(res, { error: "Invalid username or password" }, 401);
          else
            html(
              res,
              loginPage(
                String(body.csrf ?? ""),
                "Invalid username or password",
              ),
              401,
            );
          return;
        }
        const session = randomBytes(24).toString("hex");
        sessions.set(session, user);
        res.setHeader(
          "set-cookie",
          `fixture_session=${session}; Path=/; HttpOnly; SameSite=Lax`,
        );
        if (jsonRequest || req.headers.accept?.includes("application/json"))
          json(res, { token: session, user });
        else redirect(res, "/invoices");
        return;
      }
      const user = sessions.get(token(req) ?? "");
      if (!user) {
        if (url.pathname.startsWith("/api/"))
          json(res, { error: "Authentication required" }, 401);
        else redirect(res, "/login");
        return;
      }
      if (url.pathname === "/api/me") {
        json(res, { ...user, marker: `AUTHENTICATED_${user.username}` });
        return;
      }
      if (url.pathname === "/logout") {
        if (mode === "fixed") sessions.delete(token(req) ?? "");
        res.setHeader(
          "set-cookie",
          "fixture_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        );
        redirect(res, "/login");
        return;
      }
      if (url.pathname === "/" || url.pathname === "/invoices") {
        const visible = invoices.filter((inv) => owner(user, inv));
        const total = visible.reduce((sum, inv) => sum + inv.amount, 0);
        html(
          res,
          shell(
            "Invoices",
            `<div class="row"><div><p class="eyebrow">Workspace / Overview</p><h1>Invoices</h1><p class="muted">A clear view of your work, your clients, and what’s next.</p></div><a class="button" href="/search">Find an invoice ↗</a></div><div class="stats"><section class="card stat"><small>Total invoiced</small><strong>${money(total)}</strong><span class="positive">September 2026</span></section><section class="card stat"><small>Awaiting payment</small><strong>${money(visible.filter((i) => i.status === "Pending").reduce((sum, i) => sum + i.amount, 0))}</strong><span class="muted">Due in the next 30 days</span></section><section class="card stat"><small>Active clients</small><strong>${visible.length.toString().padStart(2, "0")}</strong><span class="positive">Good work, strong relationships</span></section></div><section class="card"><div class="card-heading row"><h2>Recent invoices</h2><span class="muted">${visible.length} invoices</span></div><table><thead><tr><th>Invoice</th><th>Client</th><th>Due date</th><th>Status</th><th>Amount</th></tr></thead><tbody>${invoiceRows(visible)}</tbody></table></section>`,
            user,
            "invoices",
          ),
        );
        return;
      }
      if (url.pathname === "/api/invoices") {
        json(
          res,
          invoices.filter((inv) => owner(user, inv)),
        );
        return;
      }
      const match = url.pathname.match(
        /^\/(?:api\/)?invoices\/([^/]+)(?:\/(pay|delete))?$/,
      );
      if (match) {
        const inv = invoices.find(
          (invoice) => invoice.id === decodeURIComponent(match[1]),
        );
        if (!inv) {
          json(res, { error: "Invoice not found" }, 404);
          return;
        }
        if (mode === "fixed" && !owner(user, inv)) {
          if (url.pathname.startsWith("/api/"))
            json(res, { error: "Access denied" }, 403);
          else
            html(
              res,
              shell(
                "Access denied",
                '<section class="card panel"><p class="eyebrow">Workspace security</p><h1>Access denied</h1><p class="muted">This invoice belongs to another organization.</p><a href="/invoices">Return to your invoices</a></section>',
                user,
              ),
              403,
            );
          return;
        }
        if (match[2]) {
          if (method !== "POST") {
            json(res, { error: "Use POST" }, 405);
            return;
          }
          if (match[2] === "pay") metrics.payRequests++;
          else metrics.deleteRequests++;
          json(res, { accepted: true, operation: match[2] });
          return;
        }
        if (method === "POST") {
          const body = await readBody(req);
          if (typeof body.note === "string")
            inv.note = body.note.slice(0, 1000);
          if (typeof body.client === "string" && body.client.trim())
            inv.client = body.client.trim().slice(0, 100);
          if (url.pathname.startsWith("/api/")) json(res, inv);
          else redirect(res, url.pathname);
          return;
        }
        if (url.pathname.startsWith("/api/")) {
          json(res, inv);
          return;
        }
        html(
          res,
          shell(
            inv.number,
            `<a href="/invoices">← All invoices</a><div class="row spaced"><div><p class="eyebrow">Invoice details</p><h1>${escape(inv.number)}</h1><p class="muted">Prepared for ${escape(inv.client)}</p></div><button id="edit-invoice" type="button">Edit</button></div><div role="tablist" aria-label="Invoice sections" class="tabs"><button type="button" role="tab" aria-selected="true" data-tab="summary" aria-controls="summary">Summary</button><button type="button" role="tab" aria-selected="false" data-tab="history" aria-controls="history">History</button></div><section id="summary" role="tabpanel"><div class="detail-grid"><article class="card panel"><p class="eyebrow">Billed to</p><h2>${escape(inv.client)}</h2><p class="muted">${escape(inv.note)}</p><table class="spaced"><thead><tr><th>Description</th><th>Amount</th></tr></thead><tbody><tr><td>Professional services</td><td>${money(inv.amount)}</td></tr><tr><td><strong>Total due</strong></td><td><strong>${money(inv.amount)}</strong></td></tr></tbody></table><p class="marker spaced">${escape(inv.marker)}</p></article><aside class="card panel"><h2>Invoice information</h2><div class="kv"><span class="muted">Status</span><span class="pill ${inv.status === "Pending" ? "pending" : ""}">${escape(inv.status)}</span></div><div class="kv"><span class="muted">Issued</span><span>Sep 1, 2026</span></div><div class="kv"><span class="muted">Due</span><span>Sep 30, 2026</span></div><div class="kv"><span class="muted">Organization</span><span>${escape(inv.org)}</span></div><p class="muted spaced" style="font-size:12px">Payments and destructive actions are intentionally separate from normal invoice browsing.</p></aside></div></section><section id="history" role="tabpanel" hidden class="card panel spaced"><h2>Activity history</h2><p>September 2 · Invoice sent to ${escape(inv.client)}</p><p class="muted">September 1 · Invoice created by your team</p></section><dialog id="edit-dialog" aria-labelledby="edit-title"><form method="post" action="/invoices/${encodeURIComponent(inv.id)}"><div class="row"><h2 id="edit-title">Edit invoice</h2><button type="button" class="ghost" id="close-edit">Close</button></div><label for="client">Client name</label><input id="client" name="client" value="${escape(inv.client)}" required><label for="note">Invoice note</label><input id="note" name="note" value="${escape(inv.note)}"><div class="actions"><button type="submit">Save</button></div></form></dialog><script>document.getElementById('edit-invoice').addEventListener('click',()=>document.getElementById('edit-dialog').showModal());document.getElementById('close-edit').addEventListener('click',()=>document.getElementById('edit-dialog').close());document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('[data-tab]').forEach(tab=>tab.setAttribute('aria-selected',String(tab===button)));document.querySelectorAll('[role=tabpanel]').forEach(panel=>panel.hidden=panel.id!==button.dataset.tab)}));</script>`,
            user,
            "invoices",
          ),
        );
        return;
      }
      if (url.pathname === "/search") {
        const query = url.searchParams.get("q") ?? "";
        const visible = invoices.filter(
          (inv) =>
            owner(user, inv) &&
            `${inv.number} ${inv.client} ${inv.note}`
              .toLowerCase()
              .includes(query.toLowerCase()),
        );
        html(
          res,
          shell(
            "Search",
            `<p class="eyebrow">Workspace / Search</p><h1>Find your next detail.</h1><p class="muted">Search invoice numbers, client names, and notes.</p><form action="/search" method="get" class="search-form"><label for="q"><span hidden>Search invoices</span><input id="q" name="q" type="search" placeholder="Search invoices" value="${escape(query)}"></label><button type="submit">Search</button></form><section class="card"><div class="card-heading"><h2>${query ? `Results for <span id="search-term">${mode === "vulnerable" ? query : escape(query)}</span>` : "Your invoices"}</h2><p class="muted">${visible.length} matching invoices</p></div>${visible.length ? `<table><thead><tr><th>Invoice</th><th>Client</th><th>Due date</th><th>Status</th><th>Amount</th></tr></thead><tbody>${invoiceRows(visible)}</tbody></table>` : '<div class="panel muted">No matching invoices. Try another search.</div>'}</section>`,
            user,
            "search",
          ),
        );
        return;
      }
      if (url.pathname === "/admin") {
        if (mode === "fixed" && user.role !== "admin") {
          html(
            res,
            shell(
              "Access denied",
              '<section class="card panel"><p class="eyebrow">Workspace security</p><h1>Admin access required</h1><p class="muted">Your account does not have access to administration.</p><a href="/invoices">Return to invoices</a></section>',
              user,
              "admin",
            ),
            403,
          );
          return;
        }
        html(
          res,
          shell(
            "Administration",
            `<p class="eyebrow">Workspace / Administration</p><h1>Organization overview</h1><p class="muted">Manage access across your invoice workspace.</p><section class="card spaced"><div class="card-heading row"><h2>Workspace members</h2><span class="pill">Administrator area</span></div><table><thead><tr><th>Member</th><th>Username</th><th>Organization</th><th>Role</th></tr></thead><tbody>${users.map((u) => `<tr><td>${escape(u.name)}</td><td>${escape(u.username)}</td><td>${escape(u.org)}</td><td>${escape(u.role)}</td></tr>`).join("")}</tbody></table><div class="panel"><span class="marker">ADMIN_PRIVATE_DATA</span></div></section>`,
            user,
            "admin",
          ),
        );
        return;
      }
      html(
        res,
        shell(
          "Not found",
          '<h1>Page not found</h1><a href="/invoices">Back to invoices</a>',
          user,
        ),
        404,
      );
    } catch (error) {
      if (!res.headersSent)
        json(
          res,
          {
            error:
              error instanceof SyntaxError ? "Invalid JSON" : "Request failed",
          },
          400,
        );
      else res.end();
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Fixture did not bind a TCP port");
  return {
    publicResponses,
    url: `http://${host.includes(":") ? `[${host}]` : host}:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeIdleConnections();
      }),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const mode = process.env.FIXTURE_MODE ?? "vulnerable";
  if (mode !== "vulnerable" && mode !== "fixed")
    throw new Error("FIXTURE_MODE must be vulnerable or fixed");
  const fixture = await startFixture({
    mode,
    port: Number(process.env.PORT ?? 4173),
    host: process.env.HOST ?? "127.0.0.1",
  });
  console.log(`Atlas invoice fixture (${mode}): ${fixture.url}`);
  const stop = () => {
    void fixture.close().then(() => process.exit(0));
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
