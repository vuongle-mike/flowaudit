import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const client = new Client({
  name: "flowaudit-docker-acceptance",
  version: "1.0.0",
});
const transport = new StdioClientTransport({
  command: "docker",
  args: ["compose", "exec", "-T", "scanner", "node", "dist/src/mcp.js"],
  stderr: "inherit",
});
await client.connect(transport);
async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as any[])
    .filter((c) => c.type === "text")
    .map((c) => c.text)
    .join("");
  if (result.isError) throw Error(`${name}: ${text}`);
  return JSON.parse(text);
}
let id: string | undefined;
try {
  const created = await call("create_scan", {
    configPath: "/app/examples/docker.json",
  });
  id = created.id;
  for (const role of created.roles) {
    const s = await call("browser_open", { scanId: id, role });
    const a = s.actions.find((a: any) => a.label?.startsWith("INV-"));
    if (a) await call("browser_act", { scanId: id, role, actionId: a.id });
  }
  for (const tool of ["run_zap", "run_verifiers"]) {
    await call(tool, {
      scanId: id,
      ...(tool === "run_zap" ? { role: "userA", active: true } : {}),
    });
    for (let n = 0; n < 120; n++) {
      const status = await call("scan_status", { scanId: id });
      if (status.jobs.every((j: any) => j.status !== "running")) {
        if (status.jobs.some((j: any) => j.status === "failed"))
          throw Error(JSON.stringify(status.jobs));
        break;
      }
      if (n === 119) throw Error("Job timed out");
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  await call("finish_scan", { scanId: id });
  const findings = await call("list_findings", { scanId: id });
  const report = await call("generate_report", { scanId: id });
  console.log(
    JSON.stringify(
      {
        scanId: id,
        confirmed: findings.filter((f: any) => f.status === "confirmed").length,
        zapAlerts: findings.filter((f: any) => f.source === "zap").length,
        report,
      },
      null,
      2,
    ),
  );
} finally {
  if (id) {
    const s = await call("scan_status", { scanId: id }).catch(() => null);
    if (s?.status === "running") await call("cancel_scan", { scanId: id });
  }
  await client.close();
}
