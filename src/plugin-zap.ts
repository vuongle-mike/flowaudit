import { get } from 'node:http';
import { execFile } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { findProjectRoot, slugify } from './project.js';
import { configSchema } from './config.js';
export class PluginZap {
  private state: 'not-started' | 'starting' | 'ready' | 'failed' = 'not-started';
  constructor(private home: string) {}
  private async healthy() {
    return new Promise<boolean>((resolve) => {
      const request = get('http://127.0.0.1:18091/JSON/core/view/version/', {
        headers: { 'X-ZAP-API-Key': process.env.FLOWAUDIT_ZAP_KEY || '', Host: 'zap' },
      }, response => {
        let body = '';
        response.on('data', chunk => { body += chunk; if (body.length > 10000) request.destroy(); });
        response.on('end', () => { try { resolve(response.statusCode === 200 && typeof JSON.parse(body).version === 'string'); } catch { resolve(false); } });
        response.on('error', () => resolve(false));
      });
      request.setTimeout(1500, () => { request.destroy(); resolve(false); });
      request.on('error', () => resolve(false));
    });
  }

  async status() {
    if (await this.healthy()) this.state = 'ready';
    else if (this.state === 'ready') this.state = 'failed';
    return { status: this.state, message: this.state === 'failed'
      ? 'ZAP unavailable. Check Docker is running, image download/network access, and whether localhost port 18091 is free; retry prepare_zap.'
      : 'Dedicated ZAP uses localhost:18091. Docker must be installed and running. Targets must also be reachable from Docker.' };
  }
  async prepare() {
    if (!process.env.FLOWAUDIT_ZAP_KEY) throw Error('Use the plugin bootstrap launcher to configure a private ZAP key');
    if (this.state === 'starting' || await this.healthy()) return this.status();
    this.state = 'starting';
    const project = 'flowaudit-' + createHash('sha256').update(this.home).digest('hex').slice(0, 10);
    execFile('docker', ['compose', '-p', project, '-f', join(findProjectRoot(), 'plugin-zap.yaml'),
      'up', '-d', '--wait', '--wait-timeout', '240'], { timeout: 300000, maxBuffer: 1024 * 1024 },
      (error) => { this.state = error ? 'failed' : 'ready'; });
    return { status: 'starting', next: 'Poll setup_status until ready; do not create the scan yet.' };
  }
  async enable(name: string) {
    if (!(await this.healthy())) throw Error('ZAP is not healthy; call prepare_zap and wait for setup_status ready');
    const path = join(this.home, 'projects', slugify(name), 'project.json');
    const config = configSchema.parse(JSON.parse(readFileSync(path, 'utf8')));
    config.zap = { apiUrl: 'http://127.0.0.1:18091', proxyUrl: 'http://127.0.0.1:18091', apiKeyEnv: 'FLOWAUDIT_ZAP_KEY' };
    writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
    return { configPath: path, zapConfigured: true, mode: config.mode };
  }
}
