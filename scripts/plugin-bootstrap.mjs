#!/usr/bin/env node
// Keep stdout exclusively for MCP JSON-RPC.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, cpSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir } from 'node:os';
import { spawnSync, spawn } from 'node:child_process';
const source = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const home = resolve(process.env.FLOWAUDIT_HOME || join(homedir(), '.local', 'share', 'flowaudit'));
const major = Number(process.versions.node.split('.')[0]);
if (major < 20 || (major === 20 && Number(process.versions.node.split('.')[1]) < 19)) {
  console.error('FlowAudit requires Node.js 20.19+ (Node 22 LTS recommended).'); process.exit(1);
}
const inputs = ['package.json', 'package-lock.json', 'tsconfig.json', 'plugin-zap.yaml', 'src', 'report', 'scripts', 'data'];
const hash = createHash('sha256').update(process.versions.modules + process.platform + process.arch);
function fingerprint(path) {
  for (const entry of readdirSync(path, { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name))) {
    const child = join(path, entry.name);
    if (entry.isSymbolicLink()) throw Error('Plugin source must not contain symlinks');
    if (entry.isDirectory()) fingerprint(child);
    else hash.update(child.slice(source.length)).update(readFileSync(child));
  }
}
for (const name of inputs) {
  const path = join(source, name);
  if (name.includes('.')) hash.update(name).update(readFileSync(path)); else fingerprint(path);
}
const runtime = join(home, 'runtimes', hash.digest('hex').slice(0, 20));
mkdirSync(home, { recursive: true, mode: 0o700 });
mkdirSync(dirname(runtime), { recursive: true, mode: 0o700 });
const lock = runtime + '.lock';
let locked = false;
try {
  for (let attempt = 0; ; attempt++) {
    try { mkdirSync(lock); locked = true; writeFileSync(join(lock, 'pid'), String(process.pid)); break; }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        const pidPath = join(lock, 'pid');
        if (existsSync(pidPath)) {
          const ownerPid = Number(readFileSync(pidPath, 'utf8'));
          if (!Number.isInteger(ownerPid) || ownerPid < 1) throw Error('Invalid setup lock: ' + lock);
          try { process.kill(ownerPid, 0); } catch (error) {
            if (error.code === 'ESRCH') { rmSync(lock, { recursive: true, force: true }); continue; }
            if (error.code !== 'EPERM') throw error;
          }
        } else if (Date.now() - statSync(lock).mtimeMs > 5000) { rmSync(lock, { recursive: true, force: true }); continue; }
      } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      if (attempt >= 600) throw Error('Setup lock timed out. Ensure no setup is running, then remove ' + lock);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  function run(command, args) {
    const result = spawnSync(command, args, { cwd: runtime, stdio: ['ignore', 2, 2], timeout: 600000 });
    if (result.error || result.status !== 0) throw Error(`${command} failed: ${result.error?.message || result.status}`);
  }
  if (!existsSync(join(runtime, '.ready'))) {
    console.error('FlowAudit: preparing private runtime (npm dependencies, build, Chromium)…');
    mkdirSync(runtime, { recursive: true, mode: 0o700 });
    for (const name of inputs) cpSync(join(source, name), join(runtime, name), { recursive: true });
    run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['ci', '--no-audit', '--no-fund']);
    run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build']);
    run(process.execPath, ['node_modules/playwright/cli.js', 'install', 'chromium']);
    writeFileSync(join(runtime, '.ready'), 'ready\n');
  }
  const { chromium } = await import(pathToFileURL(join(runtime, 'node_modules/playwright/index.mjs')).href);
  if (!existsSync(process.env.CHROMIUM_PATH || chromium.executablePath()))
    run(process.execPath, ['node_modules/playwright/cli.js', 'install', 'chromium']);
} catch (e) { console.error('FlowAudit setup:', e.message); process.exitCode = 1; }
finally { if (locked) rmSync(lock, { recursive: true, force: true }); }
if (process.exitCode) process.exit(process.exitCode);
if (process.argv.includes('--setup-only')) { console.error('FlowAudit ready:', runtime); process.exit(0); }
const keyPath = join(home, 'zap-key');
if (!existsSync(keyPath)) writeFileSync(keyPath, randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
const zapKey = readFileSync(keyPath, 'utf8').trim();
const child = spawn(process.execPath, [join(runtime, 'dist/src/mcp.js')], {
  cwd: runtime, stdio: 'inherit', env: { ...process.env, FLOWAUDIT_HOME: home, FLOWAUDIT_ZAP_KEY: zapKey,
    FLOWAUDIT_DATA: process.env.FLOWAUDIT_DATA || join(home, 'scans') },
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('error', e => { console.error(e.message); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
