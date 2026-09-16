import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Onboarding } from '../src/onboarding.js';
import { startFixture } from '../src/fixture.js';
import { Scanner } from '../src/scanner.js';

test('plugin onboarding captures real browser login, rejects anonymous markers, and writes private replayable profiles', async () => {
  const home = mkdtempSync(join(tmpdir(), 'flowaudit-onboarding-'));
  const fixture = await startFixture({ mode: 'fixed' });
  const onboarding = new Onboarding(home, true);
  const scanner = new Scanner(join(home, 'scans'));
  try {
    const started = await onboarding.start(fixture.url, 'Billing', 'user');
    await assert.rejects(onboarding.start(fixture.url, 'another', 'user'), /already open/);
    const page = (onboarding as any).pending.page;
    await assert.rejects(onboarding.finish(started.loginId, 'Sign in'), /also visible without login/);
    await page.locator('[name=username]').fill('userA');
    await page.locator('[name=password]').fill('Demo-pass-123!');
    await page.locator('button[type=submit]').click();
    await page.waitForURL('**/invoices');
    const ready = await onboarding.finish(started.loginId, 'Invoices');
    assert.equal(ready.mode, 'passive');
    assert.equal(ready.zapConfigured, false);
    const secretPath = join(home, 'projects/billing/secrets.json');
    assert.equal(statSync(secretPath).mode & 0o777, 0o600);
    assert.ok(JSON.parse(readFileSync(secretPath, 'utf8')).user.storageState.cookies.length);
    assert.ok(!JSON.stringify(ready).includes('Demo-pass-123!'));
    const { id } = scanner.create(ready.configPath);
    const observation = await scanner.runtime(id).recorder.open('user');
    assert.equal(observation.role, 'user');
    await assert.rejects(onboarding.start(fixture.url, 'billing', 'user'), /already exists/);
    const retry = await onboarding.start(fixture.url, 'billing', 'user', true);
    await onboarding.cancel(retry.loginId);
    await assert.rejects(onboarding.finish(retry.loginId, 'Invoices'), /expired/);
  } finally { await onboarding.cancel(); await scanner.close(); await fixture.close(); rmSync(home, { recursive: true, force: true }); }
});

test('plugin public project is passive and rejects credential URLs and external redirects', async () => {
  const home = mkdtempSync(join(tmpdir(), 'flowaudit-public-onboarding-'));
  const fixture = await startFixture({ mode: 'fixed' });
  const onboarding = new Onboarding(home, true);
  try {
    const ready = await onboarding.publicProject(fixture.url, 'public', 'Sign in');
    const config = JSON.parse(readFileSync(ready.configPath, 'utf8'));
    assert.equal(config.mode, 'passive');
    assert.deepEqual(config.allowedActions, []);
    await assert.rejects(onboarding.publicProject('http://user:secret@localhost/', 'bad'), /without credentials/);
    await assert.rejects(onboarding.publicProject(fixture.url + '/redirect-external', 'redirect'));
  } finally { await fixture.close(); rmSync(home, { recursive: true, force: true }); }
});
