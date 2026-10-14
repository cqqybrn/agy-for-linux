import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { getConfig } from '../utils/config.js';
import { runMigrations } from './migrations.js';

export interface DatabaseOptions {
  dbPath?: string;
  runMigrations?: boolean;
}

/**
 * The database holds chat history and account metadata: keep it (and its WAL/SHM sidecars)
 * readable by the owner only. No-op on Windows, where POSIX modes do not apply.
 */
export function hardenDbPermissions(dbPath: string): void {
  if (process.platform === 'win32' || dbPath === ':memory:') return;
  for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    try {
      if (fs.existsSync(file)) fs.chmodSync(file, 0o600);
    } catch {
      // best effort: a read-only or foreign-owned file must not stop the server from starting
    }
  }
}

export function createDatabase(options?: DatabaseOptions | string): Database.Database {
  const opts: DatabaseOptions =
    typeof options === 'string' ? { dbPath: options } : options ?? {};

  const dbPath = opts.dbPath ?? path.join(getConfig().dataDir, 'studio.db');

  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  const db = new Database(dbPath);
  hardenDbPermissions(dbPath);

  // WAL mode for concurrency, 5000ms busy timeout, and enforce foreign keys
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');

  if (opts.runMigrations !== false) {
    runMigrations(db);
  }

  // WAL/SHM sidecars only exist once the journal mode switch and migrations have run.
  hardenDbPermissions(dbPath);

  return db;
}
