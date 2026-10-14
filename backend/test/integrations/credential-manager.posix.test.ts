import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PosixCredentialManager } from '../../src/integrations/agy/credential-manager.js';
import { createFakeKeychain, type FakeKeychain } from '../helpers/fake-keychain.js';

const TARGET = 'gemini:antigravity';
const OTHER_TARGET = 'other:snapshot';
const SECRET = '{"auth_method":"consumer","token":{"refresh_token":"1//super-secret-refresh"}}';
const SECRET_2 = '{"auth_method":"consumer","token":{"refresh_token":"1//second-account"}}';
const GO_PREFIX = 'go-keyring-base64:';
const goKeyring = (s: string) => GO_PREFIX + Buffer.from(s, 'utf8').toString('base64');

describe('PosixCredentialManager', () => {
  let root: string;
  let home: string;
  let dataDir: string;
  let kc: FakeKeychain;

  const agyTokenFile = () => path.join(home, '.gemini', 'antigravity-cli', 'antigravity-oauth-token');
  const legacyFile = () => path.join(home, '.gemini', 'oauth_creds.json');
  const fallbackFile = (target: string) =>
    path.join(dataDir, 'keyring', `${target.replace(/[^a-zA-Z0-9._-]+/g, '_')}.json`);

  const mac = () =>
    new PosixCredentialManager({ dataDir, homeDir: home, platform: 'darwin', securityBin: kc.securityBin });
  const headlessLinux = () => new PosixCredentialManager({ dataDir, homeDir: home, platform: 'linux' });
  const linuxDesktop = () =>
    new PosixCredentialManager({ dataDir, homeDir: home, platform: 'linux', secretToolBin: kc.secretToolBin });

  const readText = async (m: PosixCredentialManager, target = TARGET) => {
    const r = await m.read(target);
    return r.status === 'ok' ? r.data.toString('utf8') : r.status;
  };

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-posix-cred-'));
    home = path.join(root, 'home');
    dataDir = path.join(root, 'data');
    fs.mkdirSync(home, { recursive: true });
    kc = createFakeKeychain(path.join(root, 'bin'));
    vi.stubEnv('FAKE_KEYCHAIN_FILE', kc.stateFile);
    vi.stubEnv('DBUS_SESSION_BUS_ADDRESS', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    fs.rmSync(root, { recursive: true, force: true });
  });

  describe('macOS Keychain (simulated `security`)', () => {
    it('stores the credential in the keychain as a go-keyring payload and reads the same bytes back', async () => {
      const m = mac();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));

      expect(kc.items()).toEqual([{ service: 'gemini', account: 'antigravity', password: goKeyring(SECRET) }]);
      expect(await readText(m)).toBe(SECRET);
      // a working keychain means no second copy anywhere else
      expect(fs.existsSync(fallbackFile(TARGET))).toBe(false);
      expect(fs.existsSync(agyTokenFile())).toBe(false);
    });

    it('decodes a payload written by agy itself (go-keyring-base64)', async () => {
      fs.writeFileSync(
        kc.stateFile,
        JSON.stringify({ locked: false, items: [{ service: 'gemini', account: 'antigravity', password: goKeyring(SECRET) }] }),
      );
      expect(await readText(mac())).toBe(SECRET);
    });

    it('reads a plain (non go-keyring) password as-is', async () => {
      fs.writeFileSync(
        kc.stateFile,
        JSON.stringify({ locked: false, items: [{ service: 'gemini', account: 'antigravity', password: SECRET }] }),
      );
      expect(await readText(mac())).toBe(SECRET);
    });

    it('decodes a hex-encoded password, which `security -w` prints for non-printable data', async () => {
      const hex = Buffer.from(goKeyring(SECRET), 'utf8').toString('hex');
      fs.writeFileSync(
        kc.stateFile,
        JSON.stringify({ locked: false, items: [{ service: 'gemini', account: 'antigravity', password: hex }] }),
      );
      expect(await readText(mac())).toBe(SECRET);
    });

    it('overwrites an existing item instead of failing on a duplicate (-U)', async () => {
      const m = mac();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET_2, 'utf8'));

      expect(kc.items()).toHaveLength(1);
      expect(await readText(m)).toBe(SECRET_2);
    });

    it('reads back a credential whose user name differs from the target suffix', async () => {
      const m = mac();
      await m.write(OTHER_TARGET, 'some-other-user', Buffer.from(SECRET, 'utf8'));

      expect(kc.items().map((i) => [i.service, i.account])).toEqual([['other', 'snapshot']]);
      expect(await readText(m, OTHER_TARGET)).toBe(SECRET);
      expect(await m.delete(OTHER_TARGET)).toBe(true);
      expect(kc.items()).toEqual([]);
    });

    it('delete removes the keychain item', async () => {
      const m = mac();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));

      expect(await m.delete(TARGET)).toBe(true);
      expect(kc.items()).toEqual([]);
      expect(await m.read(TARGET)).toEqual({ status: 'missing' });
    });

    it('delete on an empty keychain reports nothing was deleted', async () => {
      expect(await mac().delete(TARGET)).toBe(false);
    });

    it('a keychain write also refreshes agy\'s token file when one exists, so it never keeps the old account', async () => {
      fs.mkdirSync(path.dirname(agyTokenFile()), { recursive: true });
      fs.writeFileSync(agyTokenFile(), SECRET);

      await mac().write(TARGET, 'antigravity', Buffer.from(SECRET_2, 'utf8'));

      expect(fs.readFileSync(agyTokenFile(), 'utf8')).toBe(SECRET_2);
    });

    it('a locked keychain falls back to agy\'s token file for the live slot', async () => {
      kc.setLocked(true);
      const m = mac();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));

      expect(fs.readFileSync(agyTokenFile(), 'utf8')).toBe(SECRET);
      expect(fs.existsSync(fallbackFile(TARGET))).toBe(false);
      expect(await readText(m)).toBe(SECRET);
    });

    it('a locked keychain falls back to the encrypted Studio copy for any other target', async () => {
      kc.setLocked(true);
      const m = mac();
      await m.write(OTHER_TARGET, 'u', Buffer.from(SECRET, 'utf8'));

      const onDisk = fs.readFileSync(fallbackFile(OTHER_TARGET), 'utf8');
      expect(onDisk).not.toContain(SECRET);
      expect(onDisk).not.toContain(Buffer.from(SECRET, 'utf8').toString('base64'));
      expect(await readText(m, OTHER_TARGET)).toBe(SECRET);
    });

    it('drops a stale Studio copy once the keychain holds the credential', async () => {
      kc.setLocked(true);
      await mac().write(OTHER_TARGET, 'u', Buffer.from(SECRET, 'utf8'));
      expect(fs.existsSync(fallbackFile(OTHER_TARGET))).toBe(true);

      kc.setLocked(false);
      await mac().write(OTHER_TARGET, 'u', Buffer.from(SECRET_2, 'utf8'));

      expect(fs.existsSync(fallbackFile(OTHER_TARGET))).toBe(false);
      expect(await readText(mac(), OTHER_TARGET)).toBe(SECRET_2);
    });

    it('a missing `security` binary is treated like an unavailable keychain, not an error', async () => {
      const m = new PosixCredentialManager({
        dataDir,
        homeDir: home,
        platform: 'darwin',
        securityBin: path.join(root, 'does-not-exist'),
      });
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      expect(await readText(m)).toBe(SECRET);
    });
  });

  describe('read priority', () => {
    it('keychain beats agy\'s token file, which beats Studio\'s copy, which beats the legacy file', async () => {
      const m = mac();
      fs.mkdirSync(path.dirname(legacyFile()), { recursive: true });
      fs.writeFileSync(legacyFile(), 'legacy');
      expect(await readText(m)).toBe('legacy');

      const studio = headlessLinux();
      // A Studio copy of the live target: write it through a manager that has no agy-file fallback
      const noFile = new PosixCredentialManager({
        dataDir,
        homeDir: home,
        platform: 'linux',
        disableGeminiFileFallback: true,
      });
      await noFile.write(TARGET, 'antigravity', Buffer.from('studio-copy', 'utf8'));
      expect(await readText(studio)).toBe('studio-copy');

      fs.mkdirSync(path.dirname(agyTokenFile()), { recursive: true });
      fs.writeFileSync(agyTokenFile(), 'agy-file');
      expect(await readText(studio)).toBe('agy-file');

      fs.writeFileSync(
        kc.stateFile,
        JSON.stringify({ locked: false, items: [{ service: 'gemini', account: 'antigravity', password: goKeyring('keychain') }] }),
      );
      expect(await readText(m)).toBe('keychain');
    });

    it('delete clears agy\'s token file so an account switch really removes the live credential', async () => {
      fs.mkdirSync(path.dirname(agyTokenFile()), { recursive: true });
      fs.writeFileSync(agyTokenFile(), SECRET);
      const m = headlessLinux();

      expect(await readText(m)).toBe(SECRET);
      expect(await m.delete(TARGET)).toBe(true);
      expect(fs.existsSync(agyTokenFile())).toBe(false);
      expect(await m.read(TARGET)).toEqual({ status: 'missing' });
    });
  });

  describe('headless Linux (no keyring daemon)', () => {
    it('writes agy\'s own token file with owner-only permissions', async () => {
      await headlessLinux().write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));

      expect(fs.readFileSync(agyTokenFile(), 'utf8')).toBe(SECRET);
      expect(fs.statSync(agyTokenFile()).mode & 0o777).toBe(0o600);
      expect(fs.statSync(path.dirname(agyTokenFile())).mode & 0o777).toBe(0o700);
    });

    it('replaces the previous account\'s token on switch', async () => {
      const m = headlessLinux();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET_2, 'utf8'));
      expect(await readText(m)).toBe(SECRET_2);
    });

    it('leaves no temp files behind after a write', async () => {
      await headlessLinux().write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      const left = fs.readdirSync(path.dirname(agyTokenFile())).filter((f) => f.endsWith('.tmp'));
      expect(left).toEqual([]);
    });

    it('keeps other targets only as an encrypted copy, with a 0600 master key', async () => {
      const m = headlessLinux();
      await m.write(OTHER_TARGET, 'u', Buffer.from(SECRET, 'utf8'));

      expect(fs.readFileSync(fallbackFile(OTHER_TARGET), 'utf8')).not.toContain('super-secret-refresh');
      expect(fs.statSync(path.join(dataDir, 'master.key')).mode & 0o777).toBe(0o600);
      expect(await readText(m, OTHER_TARGET)).toBe(SECRET);
      expect(await m.delete(OTHER_TARGET)).toBe(true);
      expect(await m.read(OTHER_TARGET)).toEqual({ status: 'missing' });
    });

    it('treats an encrypted copy that can no longer be decrypted (lost master key) as absent', async () => {
      const m = headlessLinux();
      await m.write(OTHER_TARGET, 'u', Buffer.from(SECRET, 'utf8'));
      fs.rmSync(path.join(dataDir, 'master.key'));

      // a new instance (i.e. after a restart) no longer has the key cached
      expect(await headlessLinux().read(OTHER_TARGET)).toEqual({ status: 'missing' });
    });

    it('still reads a legacy plaintext Studio copy written by earlier versions', async () => {
      fs.mkdirSync(path.dirname(fallbackFile(OTHER_TARGET)), { recursive: true });
      fs.writeFileSync(
        fallbackFile(OTHER_TARGET),
        JSON.stringify({ userName: 'u', dataB64: Buffer.from(SECRET, 'utf8').toString('base64') }),
      );
      expect(await readText(headlessLinux(), OTHER_TARGET)).toBe(SECRET);
    });

    it('reads the legacy ~/.gemini/oauth_creds.json only when nothing else holds the credential', async () => {
      fs.mkdirSync(path.dirname(legacyFile()), { recursive: true });
      fs.writeFileSync(legacyFile(), SECRET);
      expect(await readText(headlessLinux())).toBe(SECRET);
    });

    it('does not touch agy\'s files for an unrelated target', async () => {
      await headlessLinux().write(OTHER_TARGET, 'u', Buffer.from(SECRET, 'utf8'));
      expect(fs.existsSync(agyTokenFile())).toBe(false);
    });

    it('refuses to write an empty blob', async () => {
      await expect(headlessLinux().write(TARGET, 'antigravity', Buffer.alloc(0))).rejects.toThrow(/empty/i);
      expect(fs.existsSync(agyTokenFile())).toBe(false);
    });

    it('reports a failure writing agy\'s token file instead of silently succeeding', async () => {
      // ~/.gemini is a file, so the directory cannot be created
      fs.writeFileSync(path.join(home, '.gemini'), 'not a directory');
      await expect(headlessLinux().write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'))).rejects.toThrow(
        /agy token file/,
      );
    });

    it('disableGeminiFileFallback keeps ~/.gemini untouched', async () => {
      const m = new PosixCredentialManager({
        dataDir,
        homeDir: home,
        platform: 'linux',
        disableGeminiFileFallback: true,
      });
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      expect(fs.existsSync(path.join(home, '.gemini'))).toBe(false);
      expect(await readText(m)).toBe(SECRET);
    });
  });

  describe('Linux desktop (simulated `secret-tool`)', () => {
    beforeEach(() => {
      vi.stubEnv('DBUS_SESSION_BUS_ADDRESS', 'unix:path=/run/user/1000/bus');
    });

    it('stores in the Secret Service and reads the same bytes back', async () => {
      const m = linuxDesktop();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));

      expect(kc.items()).toEqual([
        { attrs: { service: 'gemini', username: 'antigravity' }, password: goKeyring(SECRET) },
      ]);
      expect(await readText(m)).toBe(SECRET);
      expect(fs.existsSync(agyTokenFile())).toBe(false);
    });

    it('delete clears the Secret Service entry', async () => {
      const m = linuxDesktop();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      expect(await m.delete(TARGET)).toBe(true);
      expect(kc.items()).toEqual([]);
      expect(await m.read(TARGET)).toEqual({ status: 'missing' });
    });

    it('a dead Secret Service falls back to agy\'s token file', async () => {
      kc.setLocked(true);
      const m = linuxDesktop();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      expect(fs.readFileSync(agyTokenFile(), 'utf8')).toBe(SECRET);
      expect(await readText(m)).toBe(SECRET);
    });

    it('ignores the Secret Service when there is no D-Bus session', async () => {
      vi.stubEnv('DBUS_SESSION_BUS_ADDRESS', '');
      const m = linuxDesktop();
      await m.write(TARGET, 'antigravity', Buffer.from(SECRET, 'utf8'));
      expect(kc.items()).toEqual([]);
      expect(fs.readFileSync(agyTokenFile(), 'utf8')).toBe(SECRET);
    });
  });
});
