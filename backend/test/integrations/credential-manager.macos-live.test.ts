import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PosixCredentialManager } from '../../src/integrations/agy/credential-manager.js';

// Talks to the real macOS `security` tool, so it only runs on macOS and only when explicitly enabled:
//   AGY_STUDIO_MACOS_LIVE_TEST=1 npm run test -w backend -- credential-manager.macos-live
// It never touches your login keychain: everything happens in a throwaway keychain that is made the
// default for the duration of the test and removed afterwards (the original default is restored).
const enabled = process.platform === 'darwin' && process.env.AGY_STUDIO_MACOS_LIVE_TEST === '1';

const SECURITY = '/usr/bin/security';
const PASSWORD = 'agy-studio-test';

function security(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(SECURITY, args, { encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe.skipIf(!enabled)('PosixCredentialManager against the real macOS Keychain', () => {
  let root: string;
  let keychain: string;
  let originalDefault = '';
  let originalList: string[] = [];
  let mgr: PosixCredentialManager;

  const unquote = (s: string) => s.trim().replace(/^"|"$/g, '');

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-macos-live-'));
    keychain = path.join(root, 'agy-test.keychain-db');
    originalDefault = unquote(security(['default-keychain', '-d', 'user']).stdout);
    originalList = security(['list-keychains', '-d', 'user'])
      .stdout.split('\n')
      .map(unquote)
      .filter(Boolean);

    expect(security(['create-keychain', '-p', PASSWORD, keychain]).status).toBe(0);
    expect(security(['set-keychain-settings', keychain]).status).toBe(0);
    expect(security(['unlock-keychain', '-p', PASSWORD, keychain]).status).toBe(0);
    expect(security(['list-keychains', '-d', 'user', '-s', keychain, ...originalList]).status).toBe(0);
    expect(security(['default-keychain', '-d', 'user', '-s', keychain]).status).toBe(0);

    mgr = new PosixCredentialManager({
      dataDir: path.join(root, 'data'),
      homeDir: path.join(root, 'home'),
      platform: 'darwin',
    });
  });

  afterAll(() => {
    if (originalDefault) security(['default-keychain', '-d', 'user', '-s', originalDefault]);
    if (originalList.length > 0) security(['list-keychains', '-d', 'user', '-s', ...originalList]);
    if (keychain) security(['delete-keychain', keychain]);
    if (root) fs.rmSync(root, { recursive: true, force: true });
  });

  it('writes, reads, overwrites and deletes a throwaway item using the real `security`', async () => {
    const target = `agy-studio-test:${randomBytes(6).toString('hex')}`;
    const [service, account] = target.split(':');
    const first = Buffer.from(JSON.stringify({ token: { refresh_token: randomBytes(24).toString('hex') } }));
    const second = Buffer.from(JSON.stringify({ token: { refresh_token: randomBytes(24).toString('hex') } }));

    expect(await mgr.read(target)).toEqual({ status: 'missing' });

    await mgr.write(target, 'whatever-user', first);
    const r1 = await mgr.read(target);
    expect(r1.status).toBe('ok');
    if (r1.status === 'ok') expect(r1.data.equals(first)).toBe(true);

    // the stored form must be the go-keyring payload agy itself uses
    const raw = security(['find-generic-password', '-s', service, '-a', account, '-w']);
    expect(raw.status).toBe(0);
    expect(raw.stdout.trim()).toBe(`go-keyring-base64:${first.toString('base64')}`);

    await mgr.write(target, 'whatever-user', second);
    const r2 = await mgr.read(target);
    expect(r2.status === 'ok' && r2.data.equals(second)).toBe(true);

    expect(await mgr.delete(target)).toBe(true);
    expect(await mgr.read(target)).toEqual({ status: 'missing' });
  }, 60_000);

  it('reads an item written the way agy (zalando/go-keyring) writes it', async () => {
    const target = `agy-studio-test:${randomBytes(6).toString('hex')}`;
    const [service, account] = target.split(':');
    const secret = Buffer.from('{"auth_method":"consumer"}');
    const add = security([
      'add-generic-password', '-U', '-s', service, '-a', account, '-w', `go-keyring-base64:${secret.toString('base64')}`,
    ]);
    expect(add.status).toBe(0);
    try {
      const r = await mgr.read(target);
      expect(r.status === 'ok' && r.data.equals(secret)).toBe(true);
    } finally {
      await mgr.delete(target);
    }
  }, 60_000);
});
