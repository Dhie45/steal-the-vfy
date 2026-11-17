// Steal the VFY agent endpoint — zkVerify Agent Games
// Receives signed turn envelopes, plays the committed policy (HOLD / FORTIFY /
// EXTRACT) with a local Groth16 policy proof, and returns a signed response.
// Fail closed on any uncertainty. Structure mirrors the proven Proof Gatekeeper
// endpoint (endpoint/server.mjs): same HMAC handling, same idempotency cache.
// Secrets: AGENT_GAMES_HMAC_SECRET env var ONLY (this agent's own secret from
// its registration — NOT the Proof Gatekeeper agent's secret). Never logged.
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { handleStealVfy } from './src/stealVfy.mjs';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || '3100', 10);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
if (!SECRET) { console.error('FATAL: AGENT_GAMES_HMAC_SECRET not set'); process.exit(1); }

const VK_PATH = path.join(__dirname, 'circuits', 'verification_key.json');

const CACHE_FILE = path.join(__dirname, 'responses.json');
let respCache = {};
try { respCache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')); } catch {}
function persist() {
  try { fs.writeFileSync(CACHE_FILE, JSON.stringify(respCache)); } catch {}
}

// ---- HMAC (SHA-256, hex). Same dual-format logic as the gatekeeper endpoint:
// the secret is a 64-hex-char string; try UTF-8 bytes of the hex string first,
// then the raw 32 bytes decoded from hex. Record which matched.
let keyFormat = process.env.HMAC_KEY_FORMAT || 'utf8'; // 'utf8' | 'raw'
function hmacHex(bodyBuf, fmt) {
  const key = fmt === 'raw' ? Buffer.from(SECRET, 'hex') : Buffer.from(SECRET, 'utf8');
  return crypto.createHmac('sha256', key).update(bodyBuf).digest('hex');
}
function verifySig(bodyBuf, sigHeader) {
  if (!sigHeader) return false;
  const sig = String(sigHeader).trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  for (const fmt of ['utf8', 'raw']) {
    const d = hmacHex(bodyBuf, fmt);
    if (d.length === sig.length) {
      try {
        if (crypto.timingSafeEqual(Buffer.from(d, 'utf8'), Buffer.from(sig, 'utf8'))) {
          if (keyFormat !== fmt) { keyFormat = fmt; console.log(`[hmac] key format resolved: ${fmt}`); }
          return true;
        }
      } catch {}
    }
  }
  return false;
}
function signBody(bodyBuf) { return hmacHex(bodyBuf, keyFormat); }

function sendJson(res, obj, status = 200) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': signBody(body),
  });
  res.end(body);
}
function log(...a) { console.log(new Date().toISOString(), ...a); }

// Serialize proof generation (fullProve ~1-3s); the platform waits ~30s per push.
let proveQueue = Promise.resolve();
function serialized(fn) {
  const p = proveQueue.then(fn, fn);
  proveQueue = p.catch(() => {});
  return p;
}

const server = http.createServer(async (req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    try {
      if (req.method === 'GET') {
        return sendJson(res, { ok: true, protocolVersion: 'v1', service: 'steal-the-vfy' });
      }
      if (req.method !== 'POST') { res.writeHead(405); return res.end(); }

      // Verify HMAC over RAW body before parsing (if a signature is present).
      const sig = req.headers['x-agent-games-signature'];
      if (sig && !verifySig(raw, sig)) {
        log('[reject] bad HMAC', req.url);
        return sendJson(res, { error: 'bad signature' }, 401);
      }

      let body;
      try { body = raw.length ? JSON.parse(raw.toString('utf8')) : {}; }
      catch { return sendJson(res, { error: 'invalid json' }, 400); }

      // Preflight: empty body or explicit preflight type.
      const t = String(body.type || '');
      if (t === 'agent-games.preflight.v1' || Object.keys(body).length === 0) {
        log('[preflight] ok');
        return sendJson(res, { ok: true, protocolVersion: 'v1' });
      }

      // Steal the VFY turn envelope.
      const isVfy = body.eventId === 'steal-the-vfy'
        || t.includes('steal') || t.includes('vfy');
      if (!isVfy || body.matchId == null || body.turn == null) {
        log('[unknown-shape] keys=', Object.keys(body).join(','), 'type=', t);
        return sendJson(res, { ok: true, protocolVersion: 'v1' });
      }

      const cacheKey = `vfy:${body.matchId}:${body.turn}`;
      if (respCache[cacheKey]) {
        log('[idempotent] replay', cacheKey);
        return sendJson(res, respCache[cacheKey]);
      }

      const state = body.state || {};
      log(`[turn] match=${body.matchId} turn=${body.turn} self=${state.selfBalance} opp=${state.opponentBalance} mode=${body.mode || '?'}`);

      let out;
      try {
        out = await serialized(() => handleStealVfy(body));
        // Sanity: local verify before responding.
        const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
        const ok = await snarkjs.groth16.verify(vk, out.policyProof.public_signals, out.policyProof.proof);
        if (!ok) {
          log('[proof] LOCAL VERIFY FAILED', cacheKey);
          throw new Error('local proof verification failed');
        }
      } catch (e) {
        // Fail closed: HOLD with no proof (platform resolves as HOLD, -2).
        // Never fake a proof, never crash the match.
        log('[proof] failed', cacheKey, String(e && e.message || e).slice(0, 150));
        out = {
          matchId: body.matchId,
          turn: body.turn,
          action: { type: 'HOLD' },
          policyProof: null,
          agentTimestamp: new Date().toISOString(),
          idempotencyKey: crypto.randomUUID(),
        };
      }

      respCache[cacheKey] = out;
      persist();
      return sendJson(res, out);
    } catch (e) {
      log('[error]', String(e && e.stack || e).slice(0, 300));
      try { return sendJson(res, { error: 'internal error' }, 500); }
      catch { try { res.writeHead(500); res.end(); } catch {} }
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  log(`steal-the-vfy listening on 0.0.0.0:${PORT}`);
});
