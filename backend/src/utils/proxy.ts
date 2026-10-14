import { execFile } from 'node:child_process';
import net from 'node:net';
import type { FastifyBaseLogger } from 'fastify';

/**
 * Cross-platform System Proxy -> Environment Variable Bridge
 *
 * Background:
 *   The Antigravity CLI (`agy`) is a Go binary whose `net/http.DefaultTransport`
 *    uses `http.ProxyFromEnvironment` — it ONLY reads `HTTPS_PROXY` / `HTTP_PROXY`
 *   / `NO_PROXY` environment variables and does NOT query the OS system proxy.
 *   As a result, users behind local proxies (Clash / v2rayN / Surge / GNOME proxy)
 *   with "System Proxy" enabled can browse google.com in Chrome, yet `agy`
 *   hangs on `oauth2.googleapis.com` when no proxy env vars are exported.
 *
 * Design:
 *   1. Respect user intent: if `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` is
 *      already set in `process.env`, or `AGY_STUDIO_PROXY=off`, do nothing.
 *   2. Query the OS system proxy:
 *      - Windows (`win32`): `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
 *      - macOS (`darwin`): `scutil --proxy`
 *      - Linux (`linux`): `gsettings get org.gnome.system.proxy ...`
 *   3. TCP-probe the proxy endpoint before applying it so a stale system proxy
 *      left behind by a closed proxy client never breaks a working direct connection.
 *   4. Always keep `localhost,127.0.0.1,::1` in `NO_PROXY` so local WebUI / SSE
 *      traffic never loops through the proxy.
 */

const INTERNET_SETTINGS_KEY =
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

const LOOPBACK_BYPASS = ['localhost', '127.0.0.1', '::1'];

export interface SystemProxySettings {
  enabled: boolean;
  httpProxy?: string;
  httpsProxy?: string;
  pacUrl?: string;
  bypass: string[];
}

export type ProxyApplyResult =
  | { status: 'applied'; proxy: string }
  | {
      status: 'skipped';
      reason:
        | 'disabled'
        | 'unsupported-platform'
        | 'env-proxy-present'
        | 'system-proxy-off'
        | 'unusable'
        | 'unreachable'
        | 'read-failed';
    };

/**
 * Parse `reg query` output into a key -> value map.
 * Lines look like: `    ProxyEnable    REG_DWORD    0x1`
 */
export function parseRegQuery(stdout: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of stdout.split(/\r?\n/)) {
    const match = rawLine.match(/^\s+(\S+)\s+REG_[A-Z0-9_]+\s+(.*)$/);
    if (match && match[1] !== undefined && match[2] !== undefined) {
      out[match[1]] = match[2].trim();
    }
  }
  return out;
}

function normalizeHttpEndpoint(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  // Socks endpoints in ProxyServer cannot be used as HTTP_PROXY by Go's net/http
  // unless given a socks5:// scheme; skip rather than misconfigure.
  if (/^socks/i.test(trimmed)) return undefined;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const u = new URL(withScheme);
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.hostname || !u.port) {
      return undefined;
    }
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}

/**
 * Parse Windows `ProxyServer` value.
 * Supports both forms used by WinINET:
 *   - `"127.0.0.1:10809"`
 *   - `"http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808"`
 */
export function parseProxyServer(raw: string | undefined): {
  httpProxy?: string;
  httpsProxy?: string;
} {
  if (!raw) return {};
  const trimmed = raw.trim();
  if (!trimmed) return {};

  if (!trimmed.includes('=')) {
    const url = normalizeHttpEndpoint(trimmed);
    return url ? { httpProxy: url, httpsProxy: url } : {};
  }

  const byProto: Record<string, string> = {};
  for (const part of trimmed.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const proto = part.slice(0, eq).trim().toLowerCase();
    const target = normalizeHttpEndpoint(part.slice(eq + 1));
    if (target) byProto[proto] = target;
  }
  const httpProxy = byProto['http'];
  const httpsProxy = byProto['https'];
  return {
    ...(httpProxy ? { httpProxy } : {}),
    ...(httpsProxy ? { httpsProxy } : {}),
  };
}

/**
 * Convert Windows `ProxyOverride` (`;`-separated, `*.foo` wildcards, `<local>`)
 * into a list of entries suitable for `NO_PROXY` (`,`-separated, `.foo` suffix).
 */
export function parseProxyOverride(raw: string | undefined): string[] {
  if (!raw) return [];
  const entries: string[] = [];
  for (const item of raw.split(';')) {
    const token = item.trim();
    if (!token || token.toLowerCase() === '<local>') continue;
    // `127.*` / `10.*` style IP wildcards are not understood by Go's NO_PROXY
    if (token.includes('*') && !token.startsWith('*.')) continue;
    entries.push(token.startsWith('*.') ? token.slice(1) : token);
  }
  return entries;
}

export function settingsFromRegistry(values: Record<string, string>): SystemProxySettings {
  const enableRaw = values['ProxyEnable'] ?? '';
  const enabled = enableRaw === '0x1' || enableRaw === '1';
  const { httpProxy, httpsProxy } = parseProxyServer(values['ProxyServer']);
  const pacUrl = values['AutoConfigURL']?.trim() || undefined;
  const bypass = parseProxyOverride(values['ProxyOverride']);
  return { enabled, httpProxy, httpsProxy, pacUrl, bypass };
}

/**
 * Parse macOS `scutil --proxy` output into SystemProxySettings.
 */
export function parseScutilProxy(stdout: string): SystemProxySettings {
  const getVal = (key: string): string | undefined => {
    const re = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'm');
    return stdout.match(re)?.[1]?.trim();
  };

  const httpEnable = getVal('HTTPEnable') === '1';
  const httpHost = getVal('HTTPProxy');
  const httpPort = getVal('HTTPPort');

  const httpsEnable = getVal('HTTPSEnable') === '1';
  const httpsHost = getVal('HTTPSProxy');
  const httpsPort = getVal('HTTPSPort');

  const pacEnable = getVal('ProxyAutoConfigEnable') === '1';
  const pacUrl = getVal('ProxyAutoConfigURLString');

  const httpProxy =
    httpEnable && httpHost && httpPort ? normalizeHttpEndpoint(`${httpHost}:${httpPort}`) : undefined;
  const httpsProxy =
    httpsEnable && httpsHost && httpsPort
      ? normalizeHttpEndpoint(`${httpsHost}:${httpsPort}`)
      : httpProxy;

  const bypass: string[] = [];
  const exceptionsBlock = stdout.match(/ExceptionsList\s*:\s*<array>\s*\{([\s\S]*?)\}/);
  if (exceptionsBlock?.[1]) {
    for (const line of exceptionsBlock[1].split(/\r?\n/)) {
      const m = line.match(/^\s*\d+\s*:\s*(.+)$/);
      if (m?.[1]) {
        const token = m[1].trim();
        if (token && token !== '*.local' && !token.includes('/')) {
          bypass.push(token.startsWith('*.') ? token.slice(1) : token);
        }
      }
    }
  }

  return {
    enabled: Boolean(httpEnable || httpsEnable || pacEnable),
    ...(httpProxy ? { httpProxy } : {}),
    ...(httpsProxy ? { httpsProxy } : {}),
    ...(pacEnable && pacUrl ? { pacUrl } : {}),
    bypass,
  };
}

export function queryWindowsSystemProxy(): Promise<SystemProxySettings> {
  const systemRoot = process.env.SystemRoot || 'C:\\Windows';
  const regExe = `${systemRoot}\\System32\\reg.exe`;
  return new Promise((resolve, reject) => {
    execFile(
      regExe,
      ['query', INTERNET_SETTINGS_KEY],
      { windowsHide: true, timeout: 2500 },
      (err, stdout) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(settingsFromRegistry(parseRegQuery(String(stdout))));
      },
    );
  });
}

export function queryMacosSystemProxy(): Promise<SystemProxySettings> {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/sbin/scutil',
      ['--proxy'],
      { timeout: 2500 },
      (err, stdout) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(parseScutilProxy(String(stdout)));
      },
    );
  });
}

function execGsettings(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('gsettings', args, { timeout: 1500 }, (err, stdout) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(String(stdout).trim());
    });
  });
}

export async function queryLinuxSystemProxy(): Promise<SystemProxySettings> {
  const modeRaw = (await execGsettings(['get', 'org.gnome.system.proxy', 'mode'])).replace(/^'|'$/g, '');
  if (modeRaw !== 'manual' && modeRaw !== 'auto') {
    return { enabled: false, bypass: [] };
  }

  if (modeRaw === 'auto') {
    const autoconfigUrl = (await execGsettings(['get', 'org.gnome.system.proxy', 'autoconfig-url'])).replace(
      /^'|'$/g,
      '',
    );
    return {
      enabled: true,
      pacUrl: autoconfigUrl || undefined,
      bypass: [],
    };
  }

  const httpHost = (await execGsettings(['get', 'org.gnome.system.proxy.http', 'host'])).replace(/^'|'$/g, '');
  const httpPort = (await execGsettings(['get', 'org.gnome.system.proxy.http', 'port'])).replace(/\D+/g, '');
  const httpsHost = (await execGsettings(['get', 'org.gnome.system.proxy.https', 'host'])).replace(/^'|'$/g, '');
  const httpsPort = (await execGsettings(['get', 'org.gnome.system.proxy.https', 'port'])).replace(/\D+/g, '');

  const httpProxy =
    httpHost && Number(httpPort) > 0 ? normalizeHttpEndpoint(`${httpHost}:${httpPort}`) : undefined;
  const httpsProxy =
    httpsHost && Number(httpsPort) > 0
      ? normalizeHttpEndpoint(`${httpsHost}:${httpsPort}`)
      : httpProxy;

  return {
    enabled: Boolean(httpProxy || httpsProxy),
    ...(httpProxy ? { httpProxy } : {}),
    ...(httpsProxy ? { httpsProxy } : {}),
    bypass: [],
  };
}

export function querySystemProxy(platform: NodeJS.Platform = process.platform): Promise<SystemProxySettings> {
  if (platform === 'win32') return queryWindowsSystemProxy();
  if (platform === 'darwin') return queryMacosSystemProxy();
  if (platform === 'linux') return queryLinuxSystemProxy();
  return Promise.reject(new Error(`Unsupported platform: ${platform}`));
}

export function probeTcpPort(host: string, port: number, timeoutMs = 600): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

function hasExistingProxyEnv(env: NodeJS.ProcessEnv): string | undefined {
  for (const key of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy']) {
    const val = env[key]?.trim();
    if (val) return `${key}=${val}`;
  }
  return undefined;
}

export function mergeNoProxy(existing: string | undefined, extra: string[]): string {
  const seen = new Set<string>();
  const result: string[] = [];
  const push = (item: string) => {
    const trimmed = item.trim();
    if (!trimmed) return;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    result.push(trimmed);
  };
  if (existing) {
    for (const part of existing.split(',')) push(part);
  }
  for (const part of extra) push(part);
  return result.join(',');
}

export interface ApplySystemProxyOptions {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  logger?: FastifyBaseLogger;
  readSettings?: () => Promise<SystemProxySettings>;
  probe?: (host: string, port: number) => Promise<boolean>;
}

/**
 * Inspect the OS system proxy and, if an active reachable HTTP(S) proxy is
 * found, populate `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` on `env`
 * (defaults to `process.env`) so child `agy` processes inherit it.
 */
export async function applySystemProxyToEnv(
  options: ApplySystemProxyOptions = {},
): Promise<ProxyApplyResult> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const log = options.logger;

  const toggle = env.AGY_STUDIO_PROXY?.trim().toLowerCase();
  if (toggle === '0' || toggle === 'off' || toggle === 'false' || toggle === 'direct') {
    log?.debug('System proxy auto-detection disabled via AGY_STUDIO_PROXY');
    return { status: 'skipped', reason: 'disabled' };
  }

  if (platform !== 'win32' && platform !== 'darwin' && platform !== 'linux') {
    return { status: 'skipped', reason: 'unsupported-platform' };
  }

  const existing = hasExistingProxyEnv(env);
  if (existing) {
    log?.info(`Using proxy from environment (${existing})`);
    return { status: 'skipped', reason: 'env-proxy-present' };
  }

  let settings: SystemProxySettings;
  try {
    settings = await (options.readSettings ?? (() => querySystemProxy(platform)))();
  } catch (err) {
    log?.debug({ err }, 'Could not read system proxy settings; using direct connection');
    return { status: 'skipped', reason: 'read-failed' };
  }

  if (!settings.enabled) {
    return { status: 'skipped', reason: 'system-proxy-off' };
  }

  const primary = settings.httpsProxy ?? settings.httpProxy;
  if (!primary) {
    if (settings.pacUrl) {
      log?.warn(
        { pacUrl: settings.pacUrl },
        'System proxy uses a PAC script without a static HTTP proxy; set HTTPS_PROXY manually if agy cannot connect',
      );
    }
    return { status: 'skipped', reason: 'unusable' };
  }

  const parsed = new URL(primary);
  const probe = options.probe ?? probeTcpPort;
  const reachable = await probe(parsed.hostname, Number(parsed.port));
  if (!reachable) {
    log?.warn(
      { proxy: primary },
      'System proxy is enabled in OS settings but its port is not reachable; falling back to direct connection',
    );
    return { status: 'skipped', reason: 'unreachable' };
  }

  const httpsProxy = settings.httpsProxy ?? primary;
  const httpProxy = settings.httpProxy ?? primary;
  env.HTTPS_PROXY = httpsProxy;
  env.https_proxy = httpsProxy;
  env.HTTP_PROXY = httpProxy;
  env.http_proxy = httpProxy;

  const mergedNoProxy = mergeNoProxy(env.NO_PROXY ?? env.no_proxy, [
    ...LOOPBACK_BYPASS,
    ...settings.bypass,
  ]);
  env.NO_PROXY = mergedNoProxy;
  env.no_proxy = mergedNoProxy;

  const platformLabel =
    platform === 'win32' ? 'Windows' : platform === 'darwin' ? 'macOS' : 'Linux';
  log?.info(`Using the ${platformLabel} system proxy (${parsed.host}) for agy and quota requests`);
  return { status: 'applied', proxy: parsed.host };
}
