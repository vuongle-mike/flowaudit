import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  unlinkSync,
} from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { Scanner } from "./scanner.js";
const root = resolve(
  process.env.FLOWAUDIT_DATA || process.env.SECURITY_SCAN_DATA || ".runs",
);
const metaPath = join(root, "worker.json");
export class RemoteScanner {
  store = { list: () => this.call("list") };
  async call(method: string, args: any[] = []) {
    await ensureWorker();
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    const res = await fetch(`http://127.0.0.1:${meta.port}/rpc`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${meta.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ method, args }),
      signal: AbortSignal.timeout(120000),
    });
    const result = await res.json();
    if (!res.ok) throw Error(result.error || "Worker failed");
    return result.value;
  }
  create(p: string) {
    return this.call("create", [p]);
  }
  status(id: string) {
    return this.call("status", [id]);
  }
  data(id: string) {
    return this.call("data", [id]);
  }
  cancel(id: string) {
    return this.call("cancel", [id]);
  }
  finish(id: string) {
    return this.call("finish", [id]);
  }
  runZap(id: string, role: string, active: boolean) {
    return this.call("runZap", [id, role, active]);
  }
  verify(id: string, rule?: string) {
    return this.call("verify", [id, rule]);
  }
  attach(...args: any[]) {
    return this.call("attach", args);
  }
  assess(...args: any[]) {
    return this.call("assess", args);
  }
  report(id: string) {
    return this.call("report", [id]);
  }
  browser(id: string, method: string, ...args: any[]) {
    return this.call("browser", [id, method, ...args]);
  }
}
export async function ensureWorker() {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (existsSync(metaPath)) {
    try {
      const m = JSON.parse(readFileSync(metaPath, "utf8"));
      const res = await fetch(`http://127.0.0.1:${m.port}/health`, {
        headers: { authorization: `Bearer ${m.token}` },
        signal: AbortSignal.timeout(500),
      });
      if (res.ok) return;
    } catch {}
  }
  const workerFile = fileURLToPath(import.meta.url);
  if (workerFile.endsWith(".ts"))
    throw Error("Run npm run build before starting MCP worker");
  const child = spawn(process.execPath, [workerFile, "serve"], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, FLOWAUDIT_DATA: root, SECURITY_SCAN_DATA: root },
  });
  child.unref();
  for (let n = 0; n < 80; n++) {
    await new Promise((r) => setTimeout(r, 100));
    if (existsSync(metaPath)) {
      try {
        const m = JSON.parse(readFileSync(metaPath, "utf8"));
        const res = await fetch(`http://127.0.0.1:${m.port}/health`, {
          headers: { authorization: `Bearer ${m.token}` },
          signal: AbortSignal.timeout(200),
        });
        if (res.ok) return;
      } catch {}
    }
  }
  throw Error(
    "Worker did not start; inspect store lock / run node dist/src/worker.js serve",
  );
}
export async function serve() {
  const scanner = new Scanner(root);
  const token = randomBytes(32).toString("hex");
  const server = createServer(async (req, res) => {
    const reply = (status: number, value: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (req.headers.authorization !== `Bearer ${token}` || req.headers.origin)
      return reply(401, { error: "Unauthorized" });
    if (req.url === "/health") return reply(200, { ok: true });
    if (req.url !== "/rpc" || req.method !== "POST")
      return reply(404, { error: "Not found" });
    try {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 2 * 1024 * 1024) throw Error("Request too large");
      }
      const { method, args } = JSON.parse(body);
      let value: any;
      if (method === "list") value = scanner.store.list();
      else if (method === "browser") {
        const [id, op, ...params] = args;
        if (!["open", "observe", "act", "navigate", "replay"].includes(op))
          throw Error("Unknown browser operation");
        value = await scanner.exclusive(id, (r) => (r as any)[op](...params));
      } else if (method === "shutdown") {
        reply(200, { value: "stopped" });
        await scanner.close();
        server.close();
        try {
          unlinkSync(metaPath);
        } catch {}
        return;
      } else if (
        [
          "create",
          "status",
          "data",
          "cancel",
          "finish",
          "runZap",
          "verify",
          "attach",
          "assess",
          "report",
        ].includes(method)
      ) {
        value = await (scanner as any)[method](...args);
      } else throw Error("Unknown worker operation");
      reply(200, { value });
    } catch (e) {
      let message = (e as Error).message;
      for (const runtime of scanner.runtimes.values())
        message = runtime.recorder.redactor.text(message);
      reply(400, { error: message });
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as any;
  writeFileSync(
    metaPath,
    JSON.stringify({ pid: process.pid, port: address.port, token }),
    { mode: 0o600 },
  );
  const close = async () => {
    await scanner.close();
    server.close();
    try {
      unlinkSync(metaPath);
    } catch {}
    process.exit(0);
  };
  process.on("SIGINT", close);
  process.on("SIGTERM", close);
}
if (
  process.argv[2] === "serve" &&
  import.meta.url === new URL(process.argv[1] || "", "file:").href
)
  await serve();
