import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  extractAuthUrl,
  PtyLoginHandle,
  PtyLoginTerminal,
  sanitizeAuthCode,
  shouldUsePtyLogin,
  stripAnsi,
} from '../../src/integrations/agy/login-pty.js';
import type { PtySpawner } from '../../src/integrations/agy/pty-spawn.js';
import { FakePty } from '../helpers/fake-pty.js';
import { AppError } from '../../src/utils/errors.js';
import type { AgyProfile } from '../../src/integrations/agy/profile/schema.js';

const AUTH_URL =
  'https://accounts.google.com/o/oauth2/v2/auth?client_id=abc.apps.googleusercontent.com&state=xyz&code_challenge=QWERTY';

const silentLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: () => silentLogger,
} as unknown as import('pino').Logger;

describe('stripAnsi', () => {
  it('removes colour, cursor and OSC sequences but keeps the text', () => {
    expect(stripAnsi('\x1b[1;32mSelect\x1b[0m login \x1b[2K\x1b[?25lmethod')).toBe('Select login method');
    expect(stripAnsi('\x1b]0;title\x07plain')).toBe('plain');
  });
});

describe('extractAuthUrl', () => {
  it('finds a plain URL terminated by whitespace', () => {
    expect(extractAuthUrl(`Open this link:\r\n${AUTH_URL}\r\nThen paste the code`)).toBe(AUTH_URL);
  });

  it('finds a URL wrapped in colour codes', () => {
    expect(extractAuthUrl(`\x1b[36m${AUTH_URL}\x1b[0m\r\n`)).toBe(AUTH_URL);
  });

  it('prefers the OSC 8 hyperlink target (full URL) over visible text', () => {
    const raw = `\x1b]8;;${AUTH_URL}\x1b\\Click here\x1b]8;;\x1b\\\r\n`;
    expect(extractAuthUrl(raw)).toBe(AUTH_URL);
    const bel = `\x1b]8;;${AUTH_URL}\x07Click here\x1b]8;;\x07`;
    expect(extractAuthUrl(bel)).toBe(AUTH_URL);
  });

  it('stops at a box-drawing border', () => {
    expect(extractAuthUrl(`│ ${AUTH_URL}│\r\n`)).toBe(AUTH_URL);
  });

  it('waits while the URL is still arriving (no terminator yet)', () => {
    expect(extractAuthUrl(`Open: ${AUTH_URL.slice(0, 60)}`)).toBeNull();
  });

  it('ignores other links and plain text', () => {
    expect(extractAuthUrl('see https://example.com/docs for help\r\n')).toBeNull();
    expect(extractAuthUrl('no link here')).toBeNull();
    expect(extractAuthUrl(`\x1b]8;;https://example.com/\x07x\x1b]8;;\x07`)).toBeNull();
  });
});

describe('sanitizeAuthCode', () => {
  it('trims and accepts the characters Google puts in an authorization code', () => {
    expect(sanitizeAuthCode('  4/0AbCd-EfG_h.iJk~l+m%2Fn=  ')).toBe('4/0AbCd-EfG_h.iJk~l+m%2Fn=');
  });

  it('rejects empty input', () => {
    expect(() => sanitizeAuthCode('   ')).toThrow(AppError);
  });

  it('rejects anything that could inject extra input into the terminal', () => {
    for (const bad of ['abc def', 'abc\nrm -rf', 'abc;ls', 'a$(b)', 'a`b`', 'abc\x1b[A', 'a"b', "a'b"]) {
      expect(() => sanitizeAuthCode(bad), JSON.stringify(bad)).toThrow(AppError);
    }
  });

  it('rejects an absurdly long value', () => {
    expect(() => sanitizeAuthCode('a'.repeat(2049))).toThrow(AppError);
  });
});

describe('shouldUsePtyLogin', () => {
  it('uses the in-browser flow on a Linux box without a display', () => {
    expect(shouldUsePtyLogin({}, 'linux')).toBe(true);
  });

  it('uses a terminal window when a display exists', () => {
    expect(shouldUsePtyLogin({ DISPLAY: ':0' }, 'linux')).toBe(false);
    expect(shouldUsePtyLogin({ WAYLAND_DISPLAY: 'wayland-0' }, 'linux')).toBe(false);
  });

  it('never switches other platforms automatically', () => {
    expect(shouldUsePtyLogin({}, 'darwin')).toBe(false);
    expect(shouldUsePtyLogin({}, 'win32')).toBe(false);
  });

  it('AGY_STUDIO_LOGIN_MODE overrides detection, ignoring case and spaces', () => {
    expect(shouldUsePtyLogin({ AGY_STUDIO_LOGIN_MODE: ' PTY ' }, 'darwin')).toBe(true);
    expect(shouldUsePtyLogin({ AGY_STUDIO_LOGIN_MODE: 'terminal' }, 'linux')).toBe(false);
  });
});

describe('PtyLoginHandle', () => {
  let pty: FakePty;
  let handle: PtyLoginHandle;

  beforeEach(() => {
    pty = new FakePty();
    handle = new PtyLoginHandle('login_1', pty, silentLogger);
  });

  it('starts waiting for the browser and asks for a code', () => {
    expect(handle.session).toEqual({
      loginId: 'login_1',
      status: 'awaiting_browser',
      authUrl: null,
      email: null,
      error: null,
      needsCode: true,
    });
  });

  it('presses Enter once on the first "Select login method" menu (Google is highlighted)', () => {
    pty.emit('\x1b[1mSelect login');
    expect(pty.written).toEqual([]);
    pty.emit(' method\x1b[0m\r\n> Google OAuth\r\n');
    pty.emit('Select login method again\r\n');
    expect(pty.written).toEqual(['\r']);
  });

  it('captures the authorization link across chunks and resolves waiters', async () => {
    const pending = handle.waitForAuthUrl();
    pty.emit(`Open this URL: ${AUTH_URL.slice(0, 50)}`);
    expect(handle.session.authUrl).toBeNull();
    pty.emit(`${AUTH_URL.slice(50)}\r\nPaste code: `);

    await expect(pending).resolves.toBe(AUTH_URL);
    expect(handle.session.authUrl).toBe(AUTH_URL);
    await expect(handle.waitForAuthUrl()).resolves.toBe(AUTH_URL);
  });

  it('keeps the first link it saw', () => {
    pty.emit(`${AUTH_URL}\r\n`);
    pty.emit('https://accounts.google.com/o/oauth2/v2/auth?other=1\r\n');
    expect(handle.session.authUrl).toBe(AUTH_URL);
  });

  it('refuses a code before the link is ready', async () => {
    await expect(handle.submitCode('4/abc')).rejects.toThrow(/not ready/);
    expect(pty.written).toEqual([]);
  });

  it('types the code, then Enter, and never logs the code', async () => {
    pty.emit(`${AUTH_URL}\r\n`);
    await handle.submitCode(' 4/0SecretCode ');

    expect(pty.written).toEqual(['4/0SecretCode', '\r']);
    const logged = JSON.stringify(
      ['info', 'warn', 'error', 'debug'].flatMap((m) => (silentLogger as never as Record<string, ReturnType<typeof vi.fn>>)[m].mock.calls),
    );
    expect(logged).not.toContain('SecretCode');
  });

  it('rejects an invalid code without touching the terminal', async () => {
    pty.emit(`${AUTH_URL}\r\n`);
    await expect(handle.submitCode('bad code; rm -rf /')).rejects.toThrow(AppError);
    expect(pty.written).toEqual([]);
  });

  it('refuses a code once the terminal has exited', async () => {
    pty.emit(`${AUTH_URL}\r\n`);
    pty.exit(0);
    await expect(handle.submitCode('4/abc')).rejects.toThrow(/already exited/);
  });

  it('an exit before completion is reported as a failure with the exit code', async () => {
    pty.exit(2);
    const done = await handle.waitForCompletion();
    expect(done.status).toBe('failed');
    expect(done.error).toContain('code 2');
  });

  it('cancel kills the terminal, marks the session cancelled and is idempotent', async () => {
    await handle.cancel();
    await handle.cancel();
    expect(pty.killed).toBe(1);
    expect(handle.session.status).toBe('cancelled');
    await expect(handle.waitForCompletion()).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('the exit that follows a cancel does not turn it into a failure', async () => {
    await handle.cancel();
    pty.exit(143);
    const done = await handle.waitForCompletion();
    expect(done.status).toBe('cancelled');
    expect(done.error).toBeNull();
  });

  it('session getter returns a copy', () => {
    const s = handle.session;
    s.status = 'completed';
    expect(handle.session.status).toBe('awaiting_browser');
  });
});

describe('PtyLoginTerminal', () => {
  it('launches the profile\'s login argv in a pty with the caller\'s env', async () => {
    const pty = new FakePty();
    const spawner = vi.fn<PtySpawner>().mockResolvedValue(pty);
    const profile = { login: { argv: ['--login-flag'] } } as unknown as AgyProfile;
    const terminal = new PtyLoginTerminal({
      profile,
      binaryPath: process.execPath,
      spawner,
      logger: silentLogger,
    });

    const handle = await terminal.startLogin({ accountName: 'acc', env: { AGY_TEST_VAR: '1' } });

    expect(spawner).toHaveBeenCalledTimes(1);
    const [bin, argv, opts] = spawner.mock.calls[0];
    expect(bin).toBe(process.execPath);
    expect(argv).toEqual(['--login-flag']);
    expect(opts?.env?.AGY_TEST_VAR).toBe('1');
    expect(handle.loginId).toMatch(/^login_/);
    expect(handle.session.status).toBe('awaiting_browser');
  });
});

/**
 * End to end through a real pseudo-terminal (`script` fallback, as used on Linux where node-pty is not
 * compiled) against a scripted stand-in for `agy`. It proves the plumbing - menu, link, code, exit - works
 * on a real tty; it cannot prove the real agy prints what the stand-in prints.
 */
const hasScript = process.platform !== 'win32' && spawnSync('script', ['--version']).status !== null;

describe.skipIf(!hasScript)('PtyLoginTerminal on a real pseudo-terminal (stand-in agy)', () => {
  let dir: string;
  let fakeAgy: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-pty-login-'));
    fakeAgy = path.join(dir, 'fake-agy-login.cjs');
    fs.writeFileSync(
      fakeAgy,
      `#!/usr/bin/env node
const readline = require('node:readline');
const out = (s) => process.stdout.write(s);
const rl = readline.createInterface({ input: process.stdin });
let step = 0;
out('Select login method\\r\\n> Google OAuth\\r\\n  Gemini API key\\r\\n');
rl.on('line', (line) => {
  if (step === 0) {
    step = 1;
    out('Open this URL in your browser:\\r\\n${AUTH_URL}\\r\\nPaste the authorization code: ');
  } else if (line.trim() === 'GOOD-CODE') {
    out('\\r\\nLogin successful\\r\\n');
    process.exit(0);
  } else {
    out('\\r\\nLogin failed\\r\\n');
    process.exit(3);
  }
});
`,
      { mode: 0o755 },
    );
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const profile = { login: { argv: [] } } as unknown as AgyProfile;

  async function start() {
    const terminal = new PtyLoginTerminal({ profile, binaryPath: fakeAgy, logger: silentLogger });
    return terminal.startLogin({ accountName: 'acc' });
  }

  it('answers the menu, surfaces the link, accepts the code and sees the process finish', async () => {
    const handle = await start();
    try {
      const url = await Promise.race([
        handle.waitForAuthUrl(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('no auth URL within 8s')), 8000)),
      ]);
      expect(url).toBe(AUTH_URL);

      await handle.submitCode('GOOD-CODE');
      const done = await Promise.race([
        handle.waitForCompletion(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('no exit within 8s')), 8000)),
      ]);
      // The handle only reports that the process ended; AccountService decides success from the credentials.
      expect(done.status).toBe('failed');
      expect(done.error).toContain('code 0');
    } finally {
      await handle.cancel();
    }
  }, 20_000);

  it('a wrong code makes the process exit non-zero and the exit code is reported', async () => {
    const handle = await start();
    try {
      await handle.waitForAuthUrl();
      await handle.submitCode('WRONG-CODE');
      const done = await Promise.race([
        handle.waitForCompletion(),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('no exit within 8s')), 8000)),
      ]);
      expect(done.status).toBe('failed');
      expect(done.error).toContain('code 3');
    } finally {
      await handle.cancel();
    }
  }, 20_000);

  it('cancel stops a login that is still waiting for the code', async () => {
    const handle = await start();
    await handle.waitForAuthUrl();
    await handle.cancel();
    const done = await handle.waitForCompletion();
    expect(done.status).toBe('cancelled');
  }, 20_000);
});
