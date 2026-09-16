import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { randomUUID } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { slugify } from './project.js';
import { configSchema } from './config.js';
import type { ProjectConfig } from './types.js';

type Pending = { id: string; browser: Browser; context: BrowserContext; page: Page;
  target: string; name: string; role: string; replace: boolean; timer: ReturnType<typeof setTimeout> };
export class Onboarding {
  private pending?: Pending;
  private busy = false;
  constructor(readonly home = resolve(process.env.FLOWAUDIT_HOME || join(homedir(), '.local/share/flowaudit')),
    private headless = false) {}
  private target(value: string) {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
      throw Error('Use an HTTP(S) target without credentials in the URL');
    return url.href;
  }
  private async open(target: string, headless: boolean) {
    const browser = await chromium.launch({ headless, executablePath: process.env.CHROMIUM_PATH });
    try {
      const context = await browser.newContext({ serviceWorkers: 'block' });
      const origin = new URL(target).origin;
      await context.route('**/*', route => new URL(route.request().url()).origin === origin
        ? route.continue() : route.abort('blockedbyclient'));
      const page = await context.newPage();
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 20000 });
      return { browser, context, page };
    } catch (e) { await browser.close(); throw e; }
  }
  async start(target: string, name: string, role: string, replace = false) {
    if (this.pending || this.busy) throw Error('A login window is already open; finish or cancel it first');
    this.busy = true;
    try {
      target = this.target(target); name = slugify(name); role = slugify(role);
      this.checkDestination(target, name, role, replace);
      const opened = await this.open(target, this.headless);
      const id = randomUUID();
      const timer = setTimeout(() => { void this.cancel(id); }, 15 * 60 * 1000);
      timer.unref();
      this.pending = { ...opened, id, target, name, role, replace, timer };
      return { loginId: id, status: 'waiting-for-user', message: 'Complete login and OTP in the browser. Then provide a non-secret text label visible only after login to finish_login. Expires in 15 minutes.' };
    } finally { this.busy = false; }
  }
  async finish(id: string, probeContains: string) {
    const p = this.pending;
    if (!p || p.id !== id) throw Error('Login window expired or MCP reconnected; call start_login again');
    if (this.busy) throw Error('Login operation in progress');
    if (!probeContains.trim() || probeContains.length > 160) throw Error('Provide a non-secret protected-page label of 1-160 characters');
    this.busy = true;
    try {
      const current = new URL(p.page.url());
      if (current.origin !== new URL(p.target).origin) throw Error('Login must finish on the configured origin');
      // A real protected HTTP probe must work with captured state, not just a SPA label.
      const probe = await p.browser.newContext({ storageState: await p.context.storageState() });
      let state: Awaited<ReturnType<BrowserContext['storageState']>>;
      try {
        const response = await probe.request.get(current.href, { maxRedirects: 0, timeout: 15000 });
        if (response.status() !== 200 || !(await response.text()).includes(probeContains))
          throw Error('Protected probe did not return 200 with that label; navigate to a protected page or choose another label');
        state = await probe.storageState();
      } finally { await probe.close(); }
      const anonymous = await p.browser.newContext();
      try {
        const baseline = await anonymous.request.get(current.href, { maxRedirects: 0, timeout: 15000 });
        if (baseline.status() === 200 && (await baseline.text()).includes(probeContains))
          throw Error('That label is also visible without login; authentication is not established');
      } finally { await anonymous.close(); }
      const result = this.save(p.target, p.name, p.role, current.pathname + current.search, probeContains, state, p.replace);
      await this.cancel(id);
      return result;
    } finally { this.busy = false; }
  }
  async publicProject(target: string, name: string, probeContains?: string, replace = false) {
    target = this.target(target); name = slugify(name);
    this.checkDestination(target, name, 'anonymous', replace);
    const { browser, context, page } = await this.open(target, true);
    try {
      const marker = probeContains || (await page.locator('body').innerText()).split('\n').map(s => s.trim()).find(s => s.length >= 3 && s.length <= 80);
      if (!marker) throw Error('Supply a non-secret public-page probe label');
      const url = new URL(page.url());
      const response = await context.request.get(url.href, { maxRedirects: 0, timeout: 15000 });
      if (response.status() !== 200 || !(await response.text()).includes(marker)) throw Error('Public probe label does not match the server response');
      return this.save(target, name, 'anonymous', url.pathname + url.search, marker, { cookies: [], origins: [] }, replace);
    } finally { await browser.close(); }
  }
  private checkDestination(target: string, name: string, role: string, replace: boolean) {
    const path = join(this.home, 'projects', name, 'project.json');
    if (!existsSync(path)) return;
    const config = configSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
    if (config.target !== target) throw Error('Project already belongs to another target; use another name');
    if (config.roles[role] && !replace) throw Error('Role already exists; set replace=true only to recapture this role');
  }
  private save(target: string, name: string, role: string, probePath: string, probeContains: string,
    storageState: Awaited<ReturnType<BrowserContext['storageState']>>, replace: boolean) {
    this.checkDestination(target, name, role, replace);
    const directory = join(this.home, 'projects', name);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    const configPath = join(directory, 'project.json');
    const secretsPath = join(directory, 'secrets.json');
    const config: ProjectConfig = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')) : {
      name, target, roles: {}, secretsFile: './secrets.json', mode: 'passive', includePaths: ['/'],
      excludePaths: ['/logout','/delete','/payment','/checkout','/admin/reset'], allowedActions: [], sensitiveSelectors: [],
      limits: { statesPerRole: 100, actions: 300, minutes: 30, requestsPerSecond: 3 },
    };
    config.roles[role] = { type: 'storageState', secretRef: role, probePath, probeContains };
    // Always write only our adjacent private secret file; never follow a config-supplied path.
    if (config.secretsFile !== './secrets.json') throw Error('Existing project uses a custom secrets file; use a new project name');
    const secrets = existsSync(secretsPath) ? JSON.parse(readFileSync(secretsPath, 'utf8')) : {};
    secrets[role] = { storageState };
    configSchema.parse(config);
    writeFileSync(secretsPath, JSON.stringify(secrets, null, 2), { mode: 0o600 }); chmodSync(secretsPath, 0o600);
    writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 }); chmodSync(configPath, 0o600);
    return { configPath, role, status: 'ready', mode: config.mode, zapConfigured: !!config.zap,
      next: 'Call create_scan with configPath. For ZAP, prepare_zap then enable_project_zap before creating the scan.' };
  }
  async cancel(id?: string) {
    const p = this.pending;
    if (!p || (id && p.id !== id)) return { status: 'no-pending-login' };
    this.pending = undefined; clearTimeout(p.timer); await p.browser.close();
    return { status: 'cancelled' };
  }
}
