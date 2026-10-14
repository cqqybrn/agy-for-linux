import type { AccountLoginSession } from '@agy-studio/contracts';
import type { Logger } from 'pino';
import type {
  LoginHandle,
  LoginPort,
  StartLoginOptions,
} from '../../services/ports/login.port.js';
import type { AgyProfile } from './profile/schema.js';
import { findAgyBinary } from './catalog.js';
import { resolveBinary } from './process.js';
import { spawnPty, type PtyProcess, type PtySpawner } from './pty-spawn.js';
import { AppError } from '../../utils/errors.js';
import { createId } from '../../utils/ids.js';
import { logger as defaultLogger } from '../../utils/logger.js';

const MAX_BUFFER_CHARS = 256 * 1024;
const MAX_CODE_LENGTH = 2048;
const AUTH_URL_PREFIX = 'https://accounts.google.com/o/oauth2/';

// eslint-disable-next-line no-control-regex
const OSC_HYPERLINK = /\x1b\]8;[^;\x07\x1b]*;(https?:\/\/[^\x07\x1b]+)(?:\x07|\x1b\\)/g;
// eslint-disable-next-line no-control-regex
const ANSI_SEQUENCE = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\x1b[=>78]/g;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_SEQUENCE, '');
}

/**
 * Pulls the Google authorization link out of the raw terminal stream. An OSC 8 hyperlink carries the
 * whole URL in one piece, so it wins over the visible text, which a narrow terminal may have wrapped.
 */
export function extractAuthUrl(raw: string): string | null {
  for (const match of raw.matchAll(OSC_HYPERLINK)) {
    if (match[1].startsWith(AUTH_URL_PREFIX)) return match[1].trim();
  }
  const visible = stripAnsi(raw).replace(/\r/g, '');
  const start = visible.indexOf(AUTH_URL_PREFIX);
  if (start < 0) return null;
  const rest = visible.slice(start);
  const end = rest.search(/[\s"'<>│]/);
  const url = end < 0 ? rest : rest.slice(0, end);
  // A URL cut off at the end of the buffer is still arriving: wait for the line to finish.
  if (end < 0) return null;
  return url;
}

export function sanitizeAuthCode(code: string): string {
  const trimmed = code.trim();
  if (!trimmed) {
    throw new AppError('BAD_REQUEST', 'Authorization code is required');
  }
  if (trimmed.length > MAX_CODE_LENGTH || !/^[\w\-./~+%=]+$/.test(trimmed)) {
    throw new AppError('BAD_REQUEST', 'Authorization code has an unexpected format');
  }
  return trimmed;
}

/**
 * A terminal window needs a display. Without one (SSH, WSL, containers) the login has to run in a
 * pseudo-terminal owned by the backend, with the link and the code relayed through the WebUI.
 */
export function shouldUsePtyLogin(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const mode = env.AGY_STUDIO_LOGIN_MODE?.trim().toLowerCase();
  if (mode === 'pty') return true;
  if (mode === 'terminal') return false;
  if (platform === 'linux') return !env.DISPLAY && !env.WAYLAND_DISPLAY;
  return false;
}

export class PtyLoginHandle implements LoginHandle {
  readonly loginId: string;
  private _session: AccountLoginSession;
  private buffer = '';
  private menuAnswered = false;
  private exited = false;
  private cancelled = false;
  private readonly authUrlWaiters: Array<(url: string) => void> = [];
  private readonly completion: Promise<AccountLoginSession>;
  private completionResolve!: (session: AccountLoginSession) => void;

  constructor(
    loginId: string,
    private readonly pty: PtyProcess,
    private readonly logger: Logger,
  ) {
    this.loginId = loginId;
    this._session = {
      loginId,
      status: 'awaiting_browser',
      authUrl: null,
      email: null,
      error: null,
      needsCode: true,
    };
    this.completion = new Promise((resolve) => {
      this.completionResolve = resolve;
    });

    pty.onData((chunk) => this.handleData(chunk));
    pty.onExit((code) => this.handleExit(code));
  }

  get session(): AccountLoginSession {
    return { ...this._session };
  }

  private handleData(chunk: string): void {
    this.buffer = (this.buffer + chunk).slice(-MAX_BUFFER_CHARS);

    // First run shows "Select login method"; the highlighted entry is Google OAuth.
    if (!this.menuAnswered && /Select login method/i.test(stripAnsi(this.buffer))) {
      this.menuAnswered = true;
      this.pty.write('\r');
    }

    if (!this._session.authUrl) {
      const url = extractAuthUrl(this.buffer);
      if (url) {
        this._session = { ...this._session, authUrl: url };
        this.logger.info({ loginId: this.loginId }, 'Login authorization URL captured');
        for (const resolve of this.authUrlWaiters.splice(0)) resolve(url);
      }
    }
  }

  private handleExit(code: number | null): void {
    this.exited = true;
    if (!this.cancelled && this._session.status === 'awaiting_browser') {
      this._session = {
        ...this._session,
        status: 'failed',
        error: `agy exited (code ${code ?? 'unknown'}) before the login completed`,
      };
    }
    this.completionResolve(this.session);
  }

  waitForAuthUrl(): Promise<string> {
    if (this._session.authUrl) return Promise.resolve(this._session.authUrl);
    return new Promise((resolve) => this.authUrlWaiters.push(resolve));
  }

  waitForCompletion(): Promise<AccountLoginSession> {
    return this.completion;
  }

  async submitCode(code: string): Promise<void> {
    const clean = sanitizeAuthCode(code);
    if (this.exited) {
      throw new AppError('BAD_REQUEST', 'The login terminal has already exited');
    }
    if (!this._session.authUrl) {
      throw new AppError('BAD_REQUEST', 'The authorization link is not ready yet');
    }
    // The code is a credential: never log it.
    this.pty.write(clean);
    await new Promise((resolve) => setTimeout(resolve, 120));
    this.pty.write('\r');
  }

  async cancel(): Promise<void> {
    if (this.cancelled) return;
    this.cancelled = true;
    this.pty.kill();
    if (this._session.status === 'awaiting_browser') {
      this._session = { ...this._session, status: 'cancelled' };
    }
    this.completionResolve(this.session);
  }
}

export interface PtyLoginOptions {
  profile: AgyProfile;
  binaryPath?: string;
  spawner?: PtySpawner;
  logger?: Logger;
}

export class PtyLoginTerminal implements LoginPort {
  private readonly profile: AgyProfile;
  private readonly binaryPath?: string;
  private readonly spawner: PtySpawner;
  private readonly logger: Logger;

  constructor(options: PtyLoginOptions) {
    this.profile = options.profile;
    this.binaryPath = options.binaryPath;
    this.spawner = options.spawner ?? spawnPty;
    this.logger = options.logger ?? defaultLogger;
  }

  async startLogin(options: StartLoginOptions): Promise<PtyLoginHandle> {
    const loginId = createId('login');
    const argv = this.profile.login?.argv ?? [];
    const bin =
      findAgyBinary(this.profile, this.binaryPath) ??
      resolveBinary(this.profile, this.binaryPath);

    this.logger.info(
      { loginId, bin, argv, accountName: options.accountName },
      'Launching login in a pseudo-terminal',
    );

    const pty = await this.spawner(bin, argv, {
      env: { ...process.env, ...options.env },
    });
    return new PtyLoginHandle(loginId, pty, this.logger);
  }
}
