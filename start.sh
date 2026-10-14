#!/usr/bin/env bash
# Antigravity Gemini Armour Break / WebUI launcher for Linux and macOS.
# Counterpart of start.cmd: check Node and agy, install dependencies, build the frontend, start the backend.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

say()  { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

say "==================================================="
say "    Antigravity Gemini Armour Break / WebUI Launcher"
say "==================================================="

# 1. Node.js >= 20
command -v node >/dev/null 2>&1 || die "Node.js not found. Install Node.js v20 or newer from https://nodejs.org/ and run this script again."
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "${NODE_MAJOR}" -lt 20 ]; then
  die "Node.js v${NODE_MAJOR} is too old; v20 or newer is required."
fi
say "[OK] Node.js v$(node -v | sed 's/^v//')"

# 2. agy CLI (warn only: the WebUI starts without it, agent runs do not work)
AGY_FOUND=""
if [ -n "${AGY_BIN:-}" ] && [ -x "${AGY_BIN}" ]; then AGY_FOUND="${AGY_BIN}"; fi
if [ -z "${AGY_FOUND}" ] && command -v agy >/dev/null 2>&1; then AGY_FOUND="$(command -v agy)"; fi
if [ -z "${AGY_FOUND}" ]; then
  for candidate in "${HOME}/.local/bin/agy" "${HOME}/.antigravity/bin/agy" "/usr/local/bin/agy"; do
    if [ -x "${candidate}" ]; then AGY_FOUND="${candidate}"; break; fi
  done
fi
if [ -n "${AGY_FOUND}" ]; then
  say "[OK] agy CLI: ${AGY_FOUND}"
  export PATH="$(dirname "${AGY_FOUND}"):${PATH}"
else
  warn "agy CLI not found. Install it from https://antigravity.google/docs/getting-started"
  warn "(curl -fsSL https://antigravity.google/cli/install.sh | bash), or point AGY_BIN at the binary."
fi

# 3. Dependencies. .npmrc sets ignore-scripts=true, so native add-ons are handled explicitly below.
if [ ! -d node_modules ]; then
  say "[*] node_modules not found, running npm install ..."
  npm install || die "npm install failed. Check your network or npm registry settings."
fi

# 4. node-pty ships prebuilds for macOS and Windows only; on Linux it has to be compiled once.
#    It powers "edit and re-ask". The WebUI login falls back to `script(1)` when it is missing.
if [ "$(uname -s)" = "Linux" ] && [ -d node_modules/node-pty ]; then
  if ! compgen -G "node_modules/node-pty/build/Release/pty.node" >/dev/null \
     && ! compgen -G "node_modules/node-pty/prebuilds/linux-*/pty.node" >/dev/null; then
    say "[*] Building node-pty for Linux (needs make, g++ and python3) ..."
    if npm rebuild node-pty --ignore-scripts=false >/dev/null 2>&1; then
      say "[OK] node-pty built"
    else
      warn "node-pty could not be built (install build-essential and python3, then rerun)."
      warn "Edit-and-re-ask will be unavailable until then."
    fi
  fi
fi

# 5. Frontend build
if [ ! -f frontend/dist/index.html ]; then
  say "[*] frontend/dist not found, building the frontend ..."
  npm run build -w frontend || die "Frontend build failed. See the log above."
  say "[OK] Frontend build finished"
fi

# 6. Host / port
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8790}"
export HOST PORT
TARGET_URL="http://${HOST}:${PORT}"

say ""
say "==================================================="
say " Starting server: ${TARGET_URL}"
say " Press Ctrl+C to stop."
say "==================================================="

# 7. Open the default browser once the port answers (desktop sessions only)
OPENER=""
if [ "$(uname -s)" = "Darwin" ]; then
  OPENER="open"
elif [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
  OPENER="xdg-open"
fi
if [ -n "${OPENER}" ]; then
  (
    for _ in $(seq 1 50); do
      if (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        "${OPENER}" "${TARGET_URL}" >/dev/null 2>&1 || true
        break
      fi
      sleep 0.6
    done
  ) &
fi

# 8. Backend (tsx on the sources)
exec npx tsx backend/src/main.ts
