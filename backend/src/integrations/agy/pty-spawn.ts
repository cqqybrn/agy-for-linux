import { spawn, type ChildProcess } from 'node:child_process';
import { AppError } from '../../utils/errors.js';
import { killTree } from '../../utils/proc-tree.js';

export interface PtyProcess {
  readonly pid: number | undefined;
  onData(listener: (data: string) => void): void;
  onExit(listener: (exitCode: number | null) => void): void;
  write(data: string): void;
  kill(): void;
}

export interface PtySpawnOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  cols?: number;
  rows?: number;
}

export type PtySpawner = (
  command: string,
  args: string[],
  options?: PtySpawnOptions,
) => Promise<PtyProcess>;

const DEFAULT_COLS = 1000;
const DEFAULT_ROWS = 50;

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function cleanEnv(env: NodeJS.ProcessEnv | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries({ ...process.env, ...env })) {
    if (typeof value === 'string') out[key] = value;
  }
  out.TERM = out.TERM && out.TERM !== 'dumb' ? out.TERM : 'xterm-256color';
  return out;
}

type NodePtyModule = typeof import('node-pty');

function spawnWithNodePty(
  ptyModule: NodePtyModule,
  command: string,
  args: string[],
  options: PtySpawnOptions,
): PtyProcess {
  const spawnFn = ptyModule.spawn ?? (ptyModule as unknown as { default: typeof ptyModule }).default.spawn;
  const child = spawnFn(command, args, {
    name: 'xterm-256color',
    cols: options.cols ?? DEFAULT_COLS,
    rows: options.rows ?? DEFAULT_ROWS,
    cwd: options.cwd,
    env: cleanEnv(options.env),
  });
  let exited = false;
  child.onExit(() => {
    exited = true;
  });
  return {
    pid: child.pid,
    onData: (listener) => {
      child.onData(listener);
    },
    onExit: (listener) => {
      child.onExit(({ exitCode }) => listener(exitCode));
    },
    write: (data) => {
      if (!exited) child.write(data);
    },
    kill: () => {
      try {
        child.kill();
      } catch {
        // already gone
      }
    },
  };
}

/**
 * Fallback for POSIX hosts where node-pty has no compiled binary (Linux ships none): run the
 * command under `script(1)`, which allocates a pseudo-terminal and relays our pipes to it.
 */
function spawnWithScript(
  command: string,
  args: string[],
  options: PtySpawnOptions,
): Promise<PtyProcess> {
  const cols = options.cols ?? DEFAULT_COLS;
  const rows = options.rows ?? DEFAULT_ROWS;
  const inner = `stty cols ${cols} rows ${rows} 2>/dev/null; exec ${[command, ...args]
    .map(shellQuote)
    .join(' ')}`;
  // util-linux: script -qfec <cmd> /dev/null; BSD (macOS): script -q /dev/null <shell> -c <cmd>
  const scriptArgs =
    process.platform === 'darwin'
      ? ['-q', '/dev/null', '/bin/sh', '-c', inner]
      : ['-q', '-f', '-e', '-c', inner, '/dev/null'];

  return new Promise((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn('script', scriptArgs, {
        cwd: options.cwd,
        env: cleanEnv(options.env),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      reject(err);
      return;
    }

    const dataListeners: Array<(data: string) => void> = [];
    const exitListeners: Array<(code: number | null) => void> = [];
    let exited = false;

    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (chunk: string) => dataListeners.forEach((fn) => fn(chunk)));
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (chunk: string) => dataListeners.forEach((fn) => fn(chunk)));
    child.stdin!.on('error', () => {});

    child.once('error', (err) => {
      if (!exited) {
        exited = true;
        reject(err);
      }
    });
    child.once('spawn', () => {
      resolve({
        pid: child.pid,
        onData: (listener) => {
          dataListeners.push(listener);
        },
        onExit: (listener) => {
          exitListeners.push(listener);
        },
        write: (data) => {
          if (!exited && child.stdin?.writable) child.stdin.write(data);
        },
        kill: () => {
          if (child.pid) {
            void killTree(child.pid);
          } else {
            child.kill();
          }
        },
      });
    });
    child.once('close', (code) => {
      exited = true;
      exitListeners.forEach((fn) => fn(code));
    });
  });
}

/** Spawn `command` attached to a pseudo-terminal wide enough that long URLs never wrap. */
export const spawnPty: PtySpawner = async (command, args, options = {}) => {
  let ptyModule: NodePtyModule | null = null;
  let loadError: unknown = null;
  try {
    ptyModule = await import('node-pty');
  } catch (err) {
    loadError = err;
  }

  if (ptyModule) {
    // A failure here is about the command itself (e.g. a missing binary): do not mask it with the fallback.
    try {
      return spawnWithNodePty(ptyModule, command, args, options);
    } catch (err) {
      throw new AppError('AGY_SPAWN_ERROR', `无法在伪终端中启动 ${command}: ${(err as Error).message}`, {
        cause: err,
      });
    }
  }

  if (process.platform === 'win32') {
    throw new AppError('AGY_SPAWN_ERROR', '当前环境缺少伪终端组件（node-pty），无法启动登录终端', {
      cause: loadError,
    });
  }
  try {
    return await spawnWithScript(command, args, options);
  } catch (scriptErr) {
    throw new AppError(
      'AGY_SPAWN_ERROR',
      '无法创建伪终端：node-pty 未编译，且系统没有 script 命令。请安装 build-essential/python3 后重新运行 start.sh，或安装 util-linux。',
      { cause: scriptErr },
    );
  }
};
