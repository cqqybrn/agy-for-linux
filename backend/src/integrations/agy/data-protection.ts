import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AppError } from '../../utils/errors.js';
import { killTree } from '../../utils/proc-tree.js';

export interface DpapiPort {
  protect(data: Buffer): Promise<Buffer>;
  unprotect(data: Buffer): Promise<Buffer>;
}

export interface WindowsDpapiOptions {
  powershellPath?: string;
  platform?: NodeJS.Platform;
  timeoutMs?: number;
}

const PROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Security
  $in = [Console]::In.ReadToEnd().Trim()
  if (-not $in) { exit 0 }
  $bytes = [Convert]::FromBase64String($in)
  $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  [Console]::Write([Convert]::ToBase64String($enc))
} catch {
  [Console]::Error.WriteLine($_)
  exit 1
}
`.trim();

const UNPROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Security
  $in = [Console]::In.ReadToEnd().Trim()
  if (-not $in) { exit 0 }
  $bytes = [Convert]::FromBase64String($in)
  $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  [Console]::Write([Convert]::ToBase64String($dec))
} catch {
  [Console]::Error.WriteLine($_)
  exit 1
}
`.trim();

export class WindowsDpapi implements DpapiPort {
  private readonly powershellPath: string;
  private readonly platform: NodeJS.Platform;
  private readonly timeoutMs: number;

  constructor(options?: WindowsDpapiOptions) {
    this.powershellPath = options?.powershellPath ?? 'powershell.exe';
    this.platform = options?.platform ?? process.platform;
    this.timeoutMs = options?.timeoutMs ?? 10_000;
  }

  async protect(data: Buffer): Promise<Buffer> {
    if (this.platform !== 'win32') {
      throw new AppError('INTERNAL', 'Windows DPAPI is only supported on Windows');
    }
    if (data.length === 0) {
      return Buffer.alloc(0);
    }
    return this.executeScript(PROTECT_SCRIPT, data, 'protect');
  }

  async unprotect(data: Buffer): Promise<Buffer> {
    if (this.platform !== 'win32') {
      throw new AppError('INTERNAL', 'Windows DPAPI is only supported on Windows');
    }
    if (data.length === 0) {
      return Buffer.alloc(0);
    }
    return this.executeScript(UNPROTECT_SCRIPT, data, 'unprotect');
  }

  private executeScript(script: string, inputData: Buffer, action: 'protect' | 'unprotect'): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.powershellPath, ['-NoProfile', '-NonInteractive', '-Command', script], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timer: NodeJS.Timeout | null = null;
      let timedOut = false;

      const cleanupTimer = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
      };

      if (this.timeoutMs > 0) {
        timer = setTimeout(() => {
          timedOut = true;
          cleanupTimer();
          if (child.pid) {
            void killTree(child.pid);
          } else {
            child.kill();
          }
          reject(
            new AppError('INTERNAL', `PowerShell DPAPI ${action} timed out after ${this.timeoutMs}ms`),
          );
        }, this.timeoutMs);
      }

      child.stdout.setEncoding('utf-8');
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
      });

      child.stderr.setEncoding('utf-8');
      child.stderr.on('data', (chunk) => {
        stderr += chunk;
      });

      child.on('error', (err) => {
        if (timedOut) return;
        cleanupTimer();
        reject(
          new AppError('INTERNAL', `Failed to execute PowerShell for DPAPI ${action}: ${err.message}`, {
            cause: err,
          }),
        );
      });

      child.on('close', (code) => {
        if (timedOut) return;
        cleanupTimer();

        if (code !== 0) {
          reject(
            new AppError('INTERNAL', `DPAPI ${action} failed with exit code ${code}: ${stderr.trim()}`),
          );
          return;
        }

        try {
          const trimmed = stdout.trim();
          if (!trimmed) {
            resolve(Buffer.alloc(0));
            return;
          }
          const buf = Buffer.from(trimmed, 'base64');
          resolve(buf);
        } catch (err) {
          reject(
            new AppError('INTERNAL', `Failed to decode DPAPI ${action} output: ${(err as Error).message}`, {
              cause: err,
            }),
          );
        }
      });

      child.stdin.end(inputData.toString('base64'), 'utf-8');
    });
  }
}

/**
 * Memory-based DPAPI mock for fast testing and cross-platform tests.
 */
export class MemoryDpapi implements DpapiPort {
  private static readonly PREFIX = Buffer.from('DPAPI_MOCK:');

  async protect(data: Buffer): Promise<Buffer> {
    if (data.length === 0) return Buffer.alloc(0);
    return Buffer.concat([MemoryDpapi.PREFIX, data]);
  }

  async unprotect(data: Buffer): Promise<Buffer> {
    if (data.length === 0) return Buffer.alloc(0);
    if (
      data.length >= MemoryDpapi.PREFIX.length &&
      data.subarray(0, MemoryDpapi.PREFIX.length).equals(MemoryDpapi.PREFIX)
    ) {
      return data.subarray(MemoryDpapi.PREFIX.length);
    }
    throw new AppError('INTERNAL', 'Failed to unprotect data: ciphertext is corrupted or invalid');
  }
}

const POSIX_GCM_PREFIX = Buffer.from('AGY_AESGCM_V1:', 'utf8');
const MOCK_PREFIX = Buffer.from('DPAPI_MOCK:', 'utf8');

export interface PosixCryptoDpapiOptions {
  dataDir?: string;
}

/**
 * Linux & macOS local encryption provider using AES-256-GCM with a per-user `0o600` master key.
 * Also transparently unprotects legacy `DPAPI_MOCK:` blobs if present.
 */
export class PosixCryptoDpapi implements DpapiPort {
  private readonly keyPath: string;
  private cachedKey: Buffer | null = null;

  constructor(options?: PosixCryptoDpapiOptions) {
    const baseDir = options?.dataDir ?? path.join(os.homedir(), '.agy-studio');
    this.keyPath = path.join(baseDir, 'master.key');
  }

  private getOrCreateKey(): Buffer {
    if (this.cachedKey) return this.cachedKey;
    try {
      if (fs.existsSync(this.keyPath)) {
        const raw = fs.readFileSync(this.keyPath);
        if (raw.length === 32) {
          this.cachedKey = raw;
          return raw;
        }
        const hex = raw.toString('utf8').trim();
        if (/^[0-9a-fA-F]{64}$/.test(hex)) {
          this.cachedKey = Buffer.from(hex, 'hex');
          return this.cachedKey;
        }
      }
      fs.mkdirSync(path.dirname(this.keyPath), { recursive: true, mode: 0o700 });
      const key = crypto.randomBytes(32);
      fs.writeFileSync(this.keyPath, key.toString('hex'), { encoding: 'utf8', mode: 0o600 });
      this.cachedKey = key;
      return key;
    } catch (err) {
      throw new AppError(
        'INTERNAL',
        `Failed to initialize POSIX master key at ${this.keyPath}: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }

  async protect(data: Buffer): Promise<Buffer> {
    if (data.length === 0) return Buffer.alloc(0);
    const key = this.getOrCreateKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([POSIX_GCM_PREFIX, iv, authTag, encrypted]);
  }

  async unprotect(data: Buffer): Promise<Buffer> {
    if (data.length === 0) return Buffer.alloc(0);
    if (data.length >= MOCK_PREFIX.length && data.subarray(0, MOCK_PREFIX.length).equals(MOCK_PREFIX)) {
      return data.subarray(MOCK_PREFIX.length);
    }
    if (
      data.length < POSIX_GCM_PREFIX.length + 12 + 16 ||
      !data.subarray(0, POSIX_GCM_PREFIX.length).equals(POSIX_GCM_PREFIX)
    ) {
      throw new AppError('INTERNAL', 'Failed to unprotect data: ciphertext is corrupted or invalid');
    }
    const key = this.getOrCreateKey();
    const offset = POSIX_GCM_PREFIX.length;
    const iv = data.subarray(offset, offset + 12);
    const authTag = data.subarray(offset + 12, offset + 28);
    const encrypted = data.subarray(offset + 28);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } catch (err) {
      throw new AppError('INTERNAL', 'Failed to unprotect data: authentication tag mismatch', {
        cause: err,
      });
    }
  }
}

export function createDefaultDpapi(dataDir?: string): DpapiPort {
  if (process.platform === 'win32') {
    return new WindowsDpapi();
  }
  return new PosixCryptoDpapi({ dataDir });
}

export const dpapi: DpapiPort = createDefaultDpapi();

export async function protect(data: Buffer): Promise<Buffer> {
  return dpapi.protect(data);
}

export async function unprotect(data: Buffer): Promise<Buffer> {
  return dpapi.unprotect(data);
}
