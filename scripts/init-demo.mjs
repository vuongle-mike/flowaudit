import { mkdirSync, existsSync, writeFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
mkdirSync(".secrets", { recursive: true, mode: 0o700 });
mkdirSync("examples", { recursive: true });
mkdirSync("scan-data", { recursive: true, mode: 0o700 });
mkdirSync("projects/demo", { recursive: true, mode: 0o700 });
const write = (path, value, mode = 0o600) => {
  if (!existsSync(path)) writeFileSync(path, value, { mode });
};
write(
  ".env",
  `ZAP_API_KEY=${randomBytes(24).toString("hex")}\nFIXTURE_MODE=vulnerable\n`,
);
const credentials = JSON.stringify(
  Object.fromEntries(
    ["userA", "userB", "admin"].map((username) => [
      username,
      { username, password: "Demo-pass-123!" },
    ]),
  ),
  null,
  2,
);
write(".secrets/demo.json", credentials);
write("projects/demo/secrets.json", credentials);
const roles = Object.fromEntries(
  ["userA", "userB", "admin"].map((role) => [
    role,
    {
      secretRef: role,
      type: "form",
      loginPath: "/login",
      usernameSelector: "[name=username]",
      passwordSelector: "[name=password]",
      submitSelector: "button[type=submit]",
      probePath: "/api/me",
      probeContains: `AUTHENTICATED_${role}`,
    },
  ]),
);
const base = {
  name: "Atlas invoice demo",
  includePaths: ["/"],
  excludePaths: ["/api/reset", "/api/metrics", "/redirect-external"],
  roles,
  secretsFile: "../.secrets/demo.json",
  mode: "active",
  allowedActions: [],
  sensitiveSelectors: [],
  limits: {
    statesPerRole: 100,
    actions: 300,
    minutes: 30,
    requestsPerSecond: 5,
  },
  tests: {
    xss: { role: "userA", path: "/search", parameter: "q" },
    authorization: [
      {
        name: "Cross-tenant invoice access",
        ownerRole: "userA",
        attackerRole: "userB",
        discoveryPath: "/invoices",
        linkSelector: "a[data-invoice-link]",
        protectedMarker: "ORG_A_PRIVATE_INVOICE",
        asvsIds: ["v5.0.0-8.2.2"],
      },
      {
        name: "User accesses admin function",
        ownerRole: "admin",
        attackerRole: "userA",
        discoveryPath: "/invoices",
        linkSelector: "a[data-admin-link]",
        protectedMarker: "ADMIN_PRIVATE_DATA",
        asvsIds: ["v5.0.0-8.2.1"],
      },
    ],
    session: {
      role: "userA",
      logoutPath: "/logout",
      protectedPath: "/invoices",
      protectedMarker: "Recent invoices",
    },
  },
};
write(
  "examples/local.json",
  JSON.stringify({ ...base, target: "http://127.0.0.1:13000" }, null, 2),
  0o644,
);
const dockerConfig = {
  ...base,
  target: "http://fixture:3000",
  zap: {
    apiUrl: "http://zap:8080",
    proxyUrl: "http://zap:8080",
    apiKeyEnv: "ZAP_API_KEY",
  },
};
write("examples/docker.json", JSON.stringify(dockerConfig, null, 2), 0o644);
write(
  "projects/demo/project.json",
  JSON.stringify(
    {
      ...dockerConfig,
      secretsFile: "./secrets.json",
    },
    null,
    2,
  ),
  0o600,
);
console.log(
  "Ready: demo project, examples, local secrets and .env (existing files preserved).",
);
