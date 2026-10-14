/**
 * Shared utilities for agy-auto — eliminates duplicated helpers across modules.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const WINCRED_PS1 = path.join(ROOT, "scripts", "wincred.ps1");
const POSIXCRED_SH = path.join(ROOT, "scripts", "posixcred.sh");

// ─── JSON helpers ────────────────────────────────────────────────────────────

export function readJson(p, fallback = null) {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return fallback;
  }
}

export function writeJson(p, obj) {
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(obj, null, 2) + "\n", "utf8");
}

// ─── child process env ───────────────────────────────────────────────────────

/**
 * Copy `baseEnv` with `binDir` prepended to PATH.
 * Windows env keys are case-insensitive (`Path`), but a spread object is not —
 * collapse every PATH variant into one key so the child doesn't get two.
 */
export function envWithAgyPath(baseEnv, binDir) {
  const env = { ...baseEnv };
  const keys = Object.keys(env).filter((k) => k.toUpperCase() === "PATH");
  const current = keys.map((k) => env[k]).find((v) => v) || "";
  for (const k of keys) delete env[k];
  env[keys[0] || "PATH"] = current ? `${binDir}${path.delimiter}${current}` : binDir;
  return env;
}

// ─── Cross-platform credential store (Windows WinCred / macOS Keychain / Linux secret-tool + file) ───

export function runSystemCred(action, extra = {}) {
  const args = ["-Action", action];
  if (extra.blobB64) {
    args.push("-BlobBase64", extra.blobB64);
  }
  if (extra.username) {
    args.push("-UserName", extra.username);
  }

  let r;
  if (process.platform === "win32") {
    r = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", WINCRED_PS1, ...args],
      {
        encoding: "utf8",
        windowsHide: true,
        timeout: 8000,
        maxBuffer: 10 * 1024 * 1024,
      }
    );
  } else {
    r = spawnSync("bash", [POSIXCRED_SH, ...args], {
      encoding: "utf8",
      timeout: 8000,
      maxBuffer: 10 * 1024 * 1024,
    });
  }

  if (r.error) throw r.error;
  const out = (r.stdout || "").trim();
  const err = (r.stderr || "").trim();
  if (r.status !== 0) {
    throw new Error(`cred ${action} failed: ${err || out || `exit ${r.status}`}`);
  }
  if (!out) throw new Error(`cred ${action} returned empty output`);
  const lines = out.split(/\r?\n/).filter((l) => l.trim().startsWith("{"));
  const jsonLine = lines[lines.length - 1] || out;
  return JSON.parse(jsonLine);
}

// ─── agy binary resolution (single source of truth) ─────────────────────────

/**
 * Locate the agy CLI binary in priority order:
 * 1. AGY_BIN env var (explicit override)
 * 2. Platform-specific standard install paths (macOS / Linux / Windows)
 * 3. System PATH via which/where
 * 4. Bare name fallback (rely on system PATH)
 */
export function resolveAgyBinary() {
  if (process.env.AGY_BIN && existsSync(process.env.AGY_BIN)) {
    return process.env.AGY_BIN;
  }

  const home = os.homedir();
  const candidates =
    process.platform === "win32"
      ? [
          path.join(process.env.LOCALAPPDATA || "", "agy", "bin", "agy.exe"),
          path.join(
            process.env.LOCALAPPDATA || "",
            "Programs",
            "antigravity",
            "resources",
            "bin",
            "agy.exe"
          ),
        ]
      : [
          path.join(home, ".local", "bin", "agy"),
          path.join(home, ".antigravity", "bin", "agy"),
          "/opt/homebrew/bin/agy",
          "/usr/local/bin/agy",
          "/usr/bin/agy",
          "/Applications/Antigravity.app/Contents/Resources/app/bin/agy",
          "/Applications/Antigravity.app/Contents/Resources/bin/agy",
          path.join(home, "Applications", "Antigravity.app", "Contents", "Resources", "app", "bin", "agy"),
          "/opt/antigravity/resources/app/bin/agy",
          "/opt/antigravity/resources/bin/agy",
          "/usr/share/antigravity/resources/app/bin/agy",
          "/usr/share/antigravity/resources/bin/agy",
        ];

  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }

  // Last resort: check PATH via which/where
  const which = spawnSync(process.platform === "win32" ? "where.exe" : "which", ["agy"], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (which.status === 0) {
    const first = (which.stdout || "").split(/\r?\n/).map((l) => l.trim()).find(Boolean);
    if (first && existsSync(first)) return first;
  }

  return process.platform === "win32" ? "agy.exe" : "agy";
}

// ─── OAuth client extraction (single source of truth) ────────────────────────

const PREFERRED_CLIENT_ID_PREFIX = "1071006060591-";

/**
 * Extract OAuth client_id + client_secret by scanning the agy binary.
 * Both oauthLogin.js and usage.js use this — one copy, consistent filtering.
 */
export function extractOauthClientFromBinary(exePath) {
  try {
    const text = readFileSync(exePath).toString("latin1");
    const ids = [...text.matchAll(/[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/g)].map(
      (m) => m[0]
    );
    const secrets = [...text.matchAll(/GOCSPX-[A-Za-z0-9_-]{28}/g)].map((m) => m[0]);
    if (!ids.length || !secrets.length) return null;
    const clientId = ids.find((id) => id.startsWith(PREFERRED_CLIENT_ID_PREFIX)) || ids[0];
    // Filter: exact 35 chars, no URL fragments mixed in
    const unique = [...new Set(secrets)].filter((s) => s.length === 35 && !s.includes("http"));
    if (!unique.length) return null;
    return { client_id: clientId, client_secret: unique[0] };
  } catch {
    return null;
  }
}
