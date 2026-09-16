import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { ProjectConfig } from "../src/types.js";
export function demoConfig(target: string, dir: string, zap = false) {
  mkdirSync(dir, { recursive: true });
  const secretsFile = join(dir, "secrets.json");
  writeFileSync(
    secretsFile,
    JSON.stringify(
      Object.fromEntries(
        ["userA", "userB", "admin"].map((username) => [
          username,
          { username, password: "Demo-pass-123!" },
        ]),
      ),
    ),
    { mode: 0o600 },
  );
  const config: ProjectConfig = {
    name: "Invoice security scan",
    target,
    includePaths: ["/"],
    excludePaths: ["/api/reset", "/api/metrics", "/redirect-external"],
    roles: Object.fromEntries(
      ["userA", "userB", "admin"].map((role) => [
        role,
        {
          secretRef: role,
          type: "form",
          loginPath: "/login",
          usernameSelector: "[name=username]",
          passwordSelector: "[name=password]",
          submitSelector: "button[type=submit]",
          loggedInSelector: "[data-authenticated]",
          probePath: "/api/me",
          probeContains: `AUTHENTICATED_${role}`,
        },
      ]),
    ) as ProjectConfig["roles"],
    secretsFile,
    mode: "active",
    allowedActions: ["Save"],
    sensitiveSelectors: [],
    limits: {
      statesPerRole: 100,
      actions: 300,
      minutes: 30,
      requestsPerSecond: 20,
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
  if (zap)
    config.zap = {
      apiUrl: process.env.ZAP_API_URL || "http://127.0.0.1:18090",
      proxyUrl: process.env.ZAP_PROXY_URL || "http://127.0.0.1:18090",
      apiKeyEnv: "ZAP_API_KEY",
    };
  const path = join(dir, "project.json");
  writeFileSync(path, JSON.stringify(config, null, 2));
  return path;
}
