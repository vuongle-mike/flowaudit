import { z } from "zod";
import { readFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import type { ProjectConfig } from "./types.js";
const auth = z.object({
  secretRef: z.string(),
  type: z.enum(["form", "cookie", "bearer", "storageState"]),
  loginPath: z.string().optional(),
  usernameSelector: z.string().optional(),
  passwordSelector: z.string().optional(),
  submitSelector: z.string().optional(),
  loggedInSelector: z.string().optional(),
  probePath: z.string(),
  probeContains: z.string().min(1),
});
export const configSchema = z.object({
  name: z.string().min(1),
  target: z.string().url(),
  includePaths: z.array(z.string()).default(["/"]),
  excludePaths: z.array(z.string()).default([]),
  roles: z.record(auth),
  secretsFile: z.string(),
  mode: z.enum(["passive", "active"]).default("passive"),
  allowedActions: z.array(z.string()).default([]),
  sensitiveSelectors: z.array(z.string()).default([]),
  limits: z
    .object({
      statesPerRole: z.number().int().positive().default(100),
      actions: z.number().int().positive().default(300),
      minutes: z.number().positive().default(30),
      requestsPerSecond: z.number().positive().max(20).default(5),
    })
    .default({}),
  zap: z
    .object({
      apiUrl: z.string().url(),
      proxyUrl: z.string().url(),
      apiKeyEnv: z.string(),
    })
    .optional(),
  tests: z
    .object({
      activeScan: z
        .object({
          role: z.string().min(1).optional(),
          profile: z.enum(["xss", "deep"]).default("xss"),
          attackStrength: z
            .enum(["LOW", "MEDIUM", "HIGH", "INSANE"])
            .default("LOW"),
          scannerIds: z.array(z.string().regex(/^\d+$/)).max(100).default([]),
          methods: z
            .array(z.enum(["GET", "POST"]))
            .min(1)
            .max(2)
            .default(["GET"]),
          includePathEndpoints: z.boolean().default(false),
          maxEndpoints: z.number().int().min(1).max(5000).default(250),
          discoveryPaths: z
            .array(z.string().startsWith("/"))
            .max(200)
            .default([]),
        })
        .optional(),
      publicSurface: z
        .object({
          role: z.string().min(1),
          files: z
            .array(z.enum(["/.gitignore"]))
            .max(1)
            .default(["/.gitignore"]),
          maxRequests: z.number().int().min(1).max(60).default(30),
          forms: z
            .array(
              z.object({
                pagePath: z.string().startsWith("/"),
                submitPath: z.string().startsWith("/"),
                fields: z
                  .array(z.string().regex(/^[\w.-]+$/))
                  .min(1)
                  .max(4),
                headerMutation: z.boolean().default(true),
              }),
            )
            .max(5)
            .default([]),
        })
        .optional(),
      login: z
        .object({
          role: z.string().min(1),
          loginPath: z.string().startsWith("/"),
          submitPath: z.string().startsWith("/"),
          usernameField: z.string().regex(/^[\w.\[\]-]+$/),
          passwordField: z.string().regex(/^[\w.\[\]-]+$/),
          csrfField: z
            .string()
            .regex(/^[\w.\[\]-]+$/)
            .optional(),
          maxAttempts: z.number().int().min(2).max(10).default(5),
          successPath: z.string().startsWith("/").optional(),
          successContains: z.string().min(1).optional(),
          failureContains: z.string().min(1).optional(),
        })
        .optional(),
      xss: z
        .object({ role: z.string(), path: z.string(), parameter: z.string() })
        .optional(),
      authorization: z
        .array(
          z.object({
            name: z.string(),
            ownerRole: z.string(),
            attackerRole: z.string(),
            discoveryPath: z.string(),
            linkSelector: z.string(),
            protectedMarker: z.string(),
            asvsIds: z.array(z.string()),
          }),
        )
        .optional(),
      session: z
        .object({
          role: z.string(),
          logoutPath: z.string(),
          protectedPath: z.string(),
          protectedMarker: z.string(),
        })
        .optional(),
    })
    .optional(),
});
export function loadConfig(path: string): ProjectConfig {
  const st = statSync(path);
  if (!st.isFile() || st.size > 1024 * 1024)
    throw Error("Config must be a regular JSON file up to 1 MiB");
  const c = configSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  c.secretsFile = resolve(dirname(path), c.secretsFile);
  const u = new URL(c.target);
  if (
    !["http:", "https:"].includes(u.protocol) ||
    u.username ||
    u.password ||
    [...u.searchParams.keys()].some((k) => /token|password|secret|key/i.test(k))
  )
    throw Error("HTTP(S) target without URL credentials required");
  return c;
}
export function readSecrets(c: ProjectConfig): Record<string, any> {
  const stat = statSync(c.secretsFile);
  if (!stat.isFile() || stat.size > 1024 * 1024)
    throw Error("Secrets must be a regular JSON file up to 1 MiB");
  try {
    return JSON.parse(readFileSync(c.secretsFile, "utf8"));
  } catch {
    throw Error("Cannot parse local secrets JSON");
  }
}
export const dangerous =
  /(?:logout|log.out|sign.out|delete|remove|destroy|pay(?:ment)?|checkout|refund|send.?email|reset)/i;
export function inScope(c: ProjectConfig, url: string): boolean {
  try {
    const u = new URL(url, c.target),
      t = new URL(c.target);
    const p = decodeURIComponent(u.pathname);
    return (
      ["http:", "https:"].includes(u.protocol) &&
      u.origin === t.origin &&
      !u.username &&
      !u.password &&
      c.includePaths.some((x) => p.startsWith(x)) &&
      !c.excludePaths.some((x) => p.startsWith(x))
    );
  } catch {
    return false;
  }
}
export function assertScope(c: ProjectConfig, url: string) {
  if (!inScope(c, url)) throw Error("URL outside configured scope");
}
