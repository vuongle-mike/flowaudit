// Cold and warm standalone plugin launch, real fixture exploration and offline report.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { startFixture } from '../src/fixture.js';
const source = resolve(process.argv[2] || '.');
const home = mkdtempSync(join(tmpdir(), 'flowaudit-plugin-smoke-'));
const fixture = await startFixture({ mode: 'fixed' });
let client: Client | undefined;
async function connect() {
  client = new Client({ name: 'flowaudit-packaging-smoke', version: '1.0.0' });
  const env = Object.fromEntries(Object.entries(process.env).filter((pair): pair is [string,string] => typeof pair[1] === 'string'));
  await client.connect(new StdioClientTransport({ command: process.execPath,
    args: [join(source, 'scripts/plugin-bootstrap.mjs')], env: { ...env, FLOWAUDIT_HOME: home, FLOWAUDIT_DATA: join(home, 'scans') },
    cwd: tmpdir(), stderr: 'inherit' }), { timeout: 300000 });
}
async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await client!.callTool({ name, arguments: args });
  const text = (result.content as { type: string; text?: string }[]).filter(x => x.type === 'text').map(x => x.text).join('');
  assert.ok(!result.isError, text);
  return JSON.parse(text);
}
try {
  await connect();
  const tools = await client!.listTools();
  for (const name of ['start_login','finish_login','create_public_project','prepare_zap','setup_status','enable_project_zap'])
    assert.ok(tools.tools.some(tool => tool.name === name), name);
  const profile = await call('create_public_project', { target: fixture.url, name: 'fixture', probeContains: 'Sign in' });
  const scan = await call('create_scan', { configPath: profile.configPath });
  await call('browser_open', { scanId: scan.id, role: 'anonymous' });
  await call('finish_scan', { scanId: scan.id });
  const report = await call('generate_report', { scanId: scan.id });
  assert.ok(existsSync(report.html));
  assert.ok(readFileSync(report.html, 'utf8').includes('data:image/png;base64,'));
  const runtimes = readdirSync(join(home, 'runtimes'));
  await client!.close();
  await connect();
  assert.deepEqual(readdirSync(join(home, 'runtimes')), runtimes);
  assert.ok((await call('list_scans')).some((row: any) => row.id === scan.id));
  console.log('PASS: cold setup, real MCP tools, browser screenshot/report, warm reconnect and persisted scan');
} finally {
  await client?.close();
  const metadata = join(home, 'scans/worker.json');
  if (existsSync(metadata)) {
    const worker = JSON.parse(readFileSync(metadata, 'utf8'));
    await fetch(`http://127.0.0.1:${worker.port}/rpc`, { method: 'POST', headers: {
      authorization: `Bearer ${worker.token}`, 'content-type': 'application/json',
    }, body: JSON.stringify({ method: 'shutdown', args: [] }) }).catch(() => {});
  }
  await fixture.close();
  rmSync(home, { recursive: true, force: true });
}
