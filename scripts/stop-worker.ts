import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
const root = resolve(
  process.env.FLOWAUDIT_DATA || process.env.SECURITY_SCAN_DATA || ".runs",
);
try {
  const m = JSON.parse(readFileSync(join(root, "worker.json"), "utf8"));
  const response = await fetch(`http://127.0.0.1:${m.port}/rpc`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${m.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ method: "shutdown", args: [] }),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw Error("Worker did not stop");
  console.log("Scanner worker stopped; active scans retained as interrupted.");
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 1;
}
