// Launcher: reads config from env vars (Railway/hosted) or a local .env file.
// Required: AGENT_GAMES_HMAC_SECRET (THIS agent's own secret from its
// registration — never the Proof Gatekeeper agent's secret),
// STEAL_VFY_PARAMS, STEAL_VFY_SALT. The secret is never printed.
// NOTE: no fallback to ../agent-registration.json — that file holds the FIRST
// agent's secret, and silently reusing it would fail every HMAC check.
import fs from 'fs';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Minimal .env loader (local dev only; Railway sets real env vars).
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
}

for (const k of ['AGENT_GAMES_HMAC_SECRET', 'STEAL_VFY_PARAMS', 'STEAL_VFY_SALT']) {
  if (!process.env[k]) {
    console.error(`FATAL: ${k} is not set (env var or .env)`);
    process.exit(1);
  }
}

const env = { ...process.env, PORT: process.env.PORT || '3100' };
const child = spawn('node', [path.join(__dirname, 'server.mjs')], { env, stdio: 'inherit' });
child.on('exit', (c) => process.exit(c ?? 0));
