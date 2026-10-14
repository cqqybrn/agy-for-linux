import fs from 'node:fs';
import path from 'node:path';

/**
 * Stand-ins for the OS keyring CLIs, so the macOS / Linux-desktop credential paths can be exercised on any
 * machine. They are a model of the real tools, not the real tools: the exit codes 44 (not found) and 45
 * (duplicate item) follow macOS `security`; every other failure is reported as exit 1. Whether the real
 * tools behave this way on a given OS release can only be confirmed on that OS.
 *
 * State lives in a JSON file so a test can inspect or seed it. Setting `locked: true` in that file makes
 * every call fail, like a locked Keychain / absent Secret Service daemon.
 */

const SECURITY_SCRIPT = `#!/usr/bin/env node
const fs = require('node:fs');
const file = process.env.FAKE_KEYCHAIN_FILE;
const db = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { locked: false, items: [] };
const [cmd, ...rest] = process.argv.slice(2);
const opt = (flag) => { const i = rest.indexOf(flag); return i >= 0 ? rest[i + 1] : undefined; };
const save = () => fs.writeFileSync(file, JSON.stringify(db));
if (db.locked) { process.stderr.write('User interaction is not allowed.\\n'); process.exit(1); }
const service = opt('-s'); const account = opt('-a');
const match = (it) => it.service === service && (account === undefined || it.account === account);
if (cmd === 'add-generic-password') {
  const pw = opt('-w');
  const existing = db.items.find((it) => it.service === service && it.account === account);
  if (existing && !rest.includes('-U')) { process.stderr.write('already exists\\n'); process.exit(45); }
  if (existing) existing.password = pw; else db.items.push({ service, account, password: pw });
  save(); process.exit(0);
} else if (cmd === 'find-generic-password') {
  const it = db.items.find(match);
  if (!it) { process.stderr.write('The specified item could not be found in the keychain.\\n'); process.exit(44); }
  if (rest.includes('-w')) process.stdout.write(it.password + '\\n');
  process.exit(0);
} else if (cmd === 'delete-generic-password') {
  const idx = db.items.findIndex(match);
  if (idx < 0) { process.stderr.write('The specified item could not be found in the keychain.\\n'); process.exit(44); }
  db.items.splice(idx, 1); save(); process.exit(0);
}
process.stderr.write('unsupported command ' + cmd + '\\n'); process.exit(1);
`;

const SECRET_TOOL_SCRIPT = `#!/usr/bin/env node
const fs = require('node:fs');
const file = process.env.FAKE_KEYCHAIN_FILE;
const db = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { locked: false, items: [] };
const [cmd, ...rest] = process.argv.slice(2);
const save = () => fs.writeFileSync(file, JSON.stringify(db));
if (db.locked) { process.stderr.write('Cannot autolaunch D-Bus\\n'); process.exit(1); }
const attrs = {};
const args = rest.filter((a) => !a.startsWith('--label'));
for (let i = 0; i + 1 < args.length; i += 2) attrs[args[i]] = args[i + 1];
const match = (it) => Object.entries(attrs).every(([k, v]) => it.attrs[k] === v);
if (cmd === 'store') {
  const pw = fs.readFileSync(0, 'utf8');
  const existing = db.items.find((it) => JSON.stringify(it.attrs) === JSON.stringify(attrs));
  if (existing) existing.password = pw; else db.items.push({ attrs, password: pw });
  save(); process.exit(0);
} else if (cmd === 'lookup') {
  const it = db.items.find(match);
  if (!it) process.exit(1);
  process.stdout.write(it.password); process.exit(0);
} else if (cmd === 'clear') {
  const before = db.items.length;
  db.items = db.items.filter((it) => !match(it));
  save(); process.exit(db.items.length < before ? 0 : 1);
}
process.exit(1);
`;

export interface FakeKeychainItem {
  service?: string;
  account?: string;
  attrs?: Record<string, string>;
  password: string;
}

export interface FakeKeychain {
  securityBin: string;
  secretToolBin: string;
  /** Path the scripts read via FAKE_KEYCHAIN_FILE; tests set it in process.env for the child processes. */
  stateFile: string;
  items(): FakeKeychainItem[];
  setLocked(locked: boolean): void;
}

export function createFakeKeychain(dir: string): FakeKeychain {
  fs.mkdirSync(dir, { recursive: true });
  const securityBin = path.join(dir, 'security');
  const secretToolBin = path.join(dir, 'secret-tool');
  const stateFile = path.join(dir, 'keychain.json');
  fs.writeFileSync(securityBin, SECURITY_SCRIPT, { mode: 0o755 });
  fs.writeFileSync(secretToolBin, SECRET_TOOL_SCRIPT, { mode: 0o755 });
  fs.writeFileSync(stateFile, JSON.stringify({ locked: false, items: [] }));

  const read = () => JSON.parse(fs.readFileSync(stateFile, 'utf8')) as { locked: boolean; items: FakeKeychainItem[] };
  return {
    securityBin,
    secretToolBin,
    stateFile,
    items: () => read().items,
    setLocked: (locked) => {
      const db = read();
      db.locked = locked;
      fs.writeFileSync(stateFile, JSON.stringify(db));
    },
  };
}
