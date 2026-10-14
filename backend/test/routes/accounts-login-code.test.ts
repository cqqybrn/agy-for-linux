import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import type Database from 'better-sqlite3';
import type { AccountLoginSession, ApiErrorResponse } from '@agy-studio/contracts';
import { createDatabase, AccountsRepository, EventsRepository } from '../../src/repositories/index.js';
import { CredentialStore } from '../../src/integrations/agy/credential-store.js';
import { MemoryWinCred } from '../../src/integrations/agy/credential-manager.js';
import { MemoryDpapi } from '../../src/integrations/agy/data-protection.js';
import { PtyLoginHandle } from '../../src/integrations/agy/login-pty.js';
import { AccountService } from '../../src/services/account/account.js';
import { AccountLeaseLock } from '../../src/services/account/lease-lock.js';
import { EventBus } from '../../src/services/event-bus.js';
import { accountsRoutes } from '../../src/routes/http/accounts.routes.js';
import type { LoginHandle, LoginPort } from '../../src/services/ports/login.port.js';
import { FakePty } from '../helpers/fake-pty.js';

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=xyz';
const TARGET = 'gemini:antigravity';

const silentLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: () => silentLogger,
} as unknown as import('pino').Logger;

function creds(sub: string, email: string): Buffer {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return Buffer.from(
    JSON.stringify({
      token: { access_token: `acc-${sub}`, refresh_token: `ref-${sub}`, token_type: 'Bearer' },
      auth_method: 'consumer',
      id_token: `${b64({ alg: 'RS256' })}.${b64({ sub, email })}.sig`,
    }),
  );
}

/** A login port backed by the real PtyLoginHandle driving a scripted pty. */
class PtyBackedLoginPort implements LoginPort {
  pty = new FakePty();
  async startLogin(): Promise<LoginHandle> {
    return new PtyLoginHandle('login_pty_1', this.pty, silentLogger);
  }
}

/** The login-in-a-terminal-window flow: a handle that cannot take a code. */
class WindowLoginPort implements LoginPort {
  async startLogin(): Promise<LoginHandle> {
    const session: AccountLoginSession = {
      loginId: 'login_window_1',
      status: 'awaiting_browser',
      authUrl: null,
      email: null,
      error: null,
    };
    return {
      loginId: session.loginId,
      get session() {
        return session;
      },
      waitForAuthUrl: async () => '',
      waitForCompletion: async () => session,
      cancel: async () => {},
    };
  }
}

describe('Login authorization-code flow', () => {
  let app: FastifyInstance;
  let db: Database.Database;
  let tempDir: string;
  let keyring: MemoryWinCred;
  let store: CredentialStore;
  let accountService: AccountService;
  let port: PtyBackedLoginPort | WindowLoginPort;

  async function setup(loginPort: PtyBackedLoginPort | WindowLoginPort) {
    port = loginPort;
    db = createDatabase(':memory:');
    tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'agy-login-code-'));
    keyring = new MemoryWinCred();
    store = new CredentialStore({
      dataDir: tempDir,
      wincred: keyring,
      dpapi: new MemoryDpapi(),
      profile: { credentials: { wincredTargetPatterns: [TARGET], credentialFiles: [] } },
    });
    accountService = new AccountService({
      accountsRepo: new AccountsRepository(db),
      credentialStore: store,
      leaseLock: new AccountLeaseLock(),
      loginPort,
      eventBus: new EventBus({ eventsRepo: new EventsRepository(db) }),
      loginPollIntervalMs: 20,
      loginSettleDelayMs: 30,
      loginTimeoutMs: 5000,
    });
    app = Fastify();
    await app.register(accountsRoutes, { accountService });
    await app.ready();
  }

  afterEach(async () => {
    await accountService?.close();
    await app?.close();
    db?.close();
    if (tempDir) await fs.promises.rm(tempDir, { recursive: true, force: true });
  });

  const start = async (saveAs = 'new-acc') => {
    const res = await app.inject({ method: 'POST', url: '/api/accounts/login', payload: { saveAs } });
    expect(res.statusCode).toBe(200);
    return res.json<AccountLoginSession>();
  };
  const poll = async (loginId: string) =>
    (await app.inject({ method: 'GET', url: `/api/accounts/login/${loginId}` })).json<AccountLoginSession>();
  const postCode = (loginId: string, payload: unknown) =>
    app.inject({ method: 'POST', url: `/api/accounts/login/${loginId}/code`, payload: payload as object });

  describe('with a pty-backed login', () => {
    let pty: FakePty;
    beforeEach(async () => {
      const p = new PtyBackedLoginPort();
      await setup(p);
      pty = p.pty;
    });

    it('polling shows the authorization link and needsCode as soon as the terminal prints them', async () => {
      const { loginId } = await start();
      expect(await poll(loginId)).toMatchObject({ status: 'awaiting_browser', authUrl: null });

      pty.emit(`Select login method\r\nOpen: ${AUTH_URL}\r\nPaste code: `);

      expect(await poll(loginId)).toMatchObject({
        status: 'awaiting_browser',
        authUrl: AUTH_URL,
        needsCode: true,
      });
    });

    it('POST …/code types the code into the terminal and returns the live session', async () => {
      const { loginId } = await start();
      pty.emit(`${AUTH_URL}\r\n`);

      const res = await postCode(loginId, { code: '4/0AbCdEf' });

      expect(res.statusCode).toBe(200);
      expect(res.json<AccountLoginSession>()).toMatchObject({ loginId, authUrl: AUTH_URL });
      expect(pty.written).toContain('4/0AbCdEf');
      expect(pty.written.at(-1)).toBe('\r');
    });

    it('rejects a missing, empty or oversized code with 400 and types nothing', async () => {
      const { loginId } = await start();
      pty.emit(`${AUTH_URL}\r\n`);
      pty.written.length = 0;

      for (const payload of [{}, { code: '' }, { code: 'a'.repeat(2049) }, { code: 42 }]) {
        const res = await postCode(loginId, payload);
        expect(res.statusCode, JSON.stringify(payload).slice(0, 40)).toBe(400);
        expect(res.json<ApiErrorResponse>().error.code).toBe('BAD_REQUEST');
      }
      expect(pty.written).toEqual([]);
    });

    it('rejects a code containing terminal control characters with 400', async () => {
      const { loginId } = await start();
      pty.emit(`${AUTH_URL}\r\n`);
      pty.written.length = 0;

      const res = await postCode(loginId, { code: 'abc\nrm -rf ~' });

      expect(res.statusCode).toBe(400);
      expect(pty.written).toEqual([]);
    });

    it('rejects a code sent before the authorization link exists', async () => {
      const { loginId } = await start();
      const res = await postCode(loginId, { code: '4/abc' });
      expect(res.statusCode).toBe(400);
      expect(res.json<ApiErrorResponse>().error.message).toMatch(/not ready/i);
    });

    it('404 for an unknown login id', async () => {
      await start();
      const res = await postCode('nope', { code: '4/abc' });
      expect(res.statusCode).toBe(404);
      expect(res.json<ApiErrorResponse>().error.code).toBe('NOT_FOUND');
    });

    it('a successful authorization completes the login even though agy exits afterwards', async () => {
      const { loginId } = await start('google-acc');
      pty.emit(`${AUTH_URL}\r\n`);
      await postCode(loginId, { code: '4/good' });

      // what the real agy does after accepting the code: write the credential, then exit
      keyring.set(TARGET, creds('sub-1', 'new@example.com'));
      pty.exit(0);

      const done = await accountService.waitForLoginCompletion(loginId);
      expect(done.status).toBe('completed');
      expect(done.email).toBe('new@example.com');
      expect((await poll(loginId)).status).toBe('completed');
    });

    it('agy exiting without a credential fails the login and reports the exit code', async () => {
      const { loginId } = await start();
      pty.emit(`${AUTH_URL}\r\n`);
      await postCode(loginId, { code: '4/bad' });
      pty.exit(3);

      const done = await accountService.waitForLoginCompletion(loginId);
      expect(done.status).toBe('failed');
      expect(done.error).toContain('code 3');
    });

    it('no more codes are accepted once the login has finished', async () => {
      const { loginId } = await start();
      pty.emit(`${AUTH_URL}\r\n`);
      pty.exit(3);
      await accountService.waitForLoginCompletion(loginId);

      const res = await postCode(loginId, { code: '4/late' });

      expect(res.statusCode).toBe(400);
      expect(res.json<ApiErrorResponse>().error.message).toMatch(/no longer waiting/i);
    });

    it('cancelling kills the terminal and puts the previous account\'s credential back', async () => {
      keyring.set(TARGET, creds('before', 'before@example.com'));
      const { loginId } = await start();
      // starting a login clears the live credential so a new one can be detected
      expect(await store.isPresent()).toBe(false);
      pty.emit(`${AUTH_URL}\r\n`);

      const del = await app.inject({ method: 'DELETE', url: `/api/accounts/login/${loginId}` });

      expect(del.statusCode).toBe(200);
      expect(del.json<AccountLoginSession>().status).toBe('cancelled');
      expect(pty.killed).toBeGreaterThanOrEqual(1);
      expect(await store.isPresent()).toBe(true);
      expect((await store.readLiveClaims())?.email).toBe('before@example.com');
    });

    it('a second login cannot start while one is waiting for its code', async () => {
      await start('first');
      const res = await app.inject({ method: 'POST', url: '/api/accounts/login', payload: { saveAs: 'second' } });
      expect(res.statusCode).toBe(423);
    });
  });

  describe('with a terminal-window login (no code relay)', () => {
    beforeEach(async () => {
      await setup(new WindowLoginPort());
    });

    it('POST …/code explains the login has to be finished in the terminal window', async () => {
      const { loginId } = await start();
      const res = await postCode(loginId, { code: '4/abc' });
      expect(res.statusCode).toBe(400);
      expect(res.json<ApiErrorResponse>().error.message).toMatch(/terminal window/i);
    });
  });
});
