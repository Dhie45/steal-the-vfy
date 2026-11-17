# Steal the VFY — zkVerify Agent Games agent

Head-to-head 20-turn match agent for the **Steal the VFY** track. Every move
carries a Groth16 policy proof that the move matches the Poseidon-committed
strategy for the live balances, bound to `matchId` + turn so proofs can't be
replayed. Platform: agentgames.zkverify.io. Account: getfreshtim29.

## Strategy (committed, private params)

- `selfBalance < 18` → **FORTIFY** (protect what's left)
- `opponentBalance < 8` → **HOLD** (nothing worth extracting)
- otherwise → **EXTRACT 8**

Params `8,18,8,0,0,0,0,0` + a random 19-digit salt, committed as
Poseidon(params, salt). Commitment (public):

- hex: `0x002f529b654578c641032f154e479eb73b6e3b1fb223448b4b406a1c24f3f6e6`
- dec: `83611944701874787233774473356282639112660375576131129188712103554309158630`

Params + salt live ONLY in env vars / Railway — never in this repo.

## Run locally

```bash
npm install
cp .env.example .env   # fill STEAL_VFY_SALT + AGENT_GAMES_HMAC_SECRET (this agent's own secret)
npm test               # 13 checks: HMAC, commitment, 5 turns + local proof verify, HTTP
npm start              # listens on $PORT (default 3100)
```

`GET /agent` → health. `POST /agent` accepts the signed preflight and
`steal-the-vfy` turn envelopes; responses are HMAC-signed.

## Publish (browser, GitHub @Dhie45)

New public repo **`steal-the-vfy`**, containing exactly:

```
server.mjs  start.mjs  package.json  package-lock.json  railway.json
.gitignore  README.md  src/stealVfy.mjs
circuits/vfy-policy.wasm  circuits/vfy-policy_final.zkey
circuits/verification_key.json
```

Do NOT commit: `node_modules/`, `.env`, `responses.json`, `*.log`.
(First commit a one-line README so the branch exists, then upload the rest
via the repo web UI — proven for the Proof Gatekeeper repos.)

## Deploy (browser, Railway)

Same pattern as `proof-gatekeeper-endpoint` (Railway project
empathetic-ambition, or a new project — free tier, no card):

1. New Project → Deploy from GitHub repo → `steal-the-vfy`.
2. Variables (exact values in the local `.env` — read them there, never paste
   into chat):
   - `AGENT_GAMES_HMAC_SECRET` = this agent's secret from the Agent Games
     dashboard (Rotate Secret) — NOT the Proof Gatekeeper agent's secret.
   - `STEAL_VFY_PARAMS=8,18,8,0,0,0,0,0`
   - `STEAL_VFY_SALT=<from .env>`
3. Deploy, copy the public URL, check `GET https://<name>.up.railway.app/agent`
   returns `{"ok":true,"protocolVersion":"v1",...}`.

## Wire it up (dashboard)

1. `/dashboard/agents` → agent **Steal the VFY** → set endpoint to the Railway URL.
2. Register the strategy commitment (hex above) in the agent's settings.
3. Test preflight, then dispatch a practice turn from `/dashboard/practice`
   and confirm the platform accepts the response with a verified proof.

## Files

- `server.mjs` — HTTP endpoint (HMAC verify, preflight, turns, idempotency)
- `src/stealVfy.mjs` — policy + proof generation
- `scripts/commitment.mjs` — prints the Poseidon commitment
- `test/test.mjs` — local suite (13 checks)
- `circuits/` — official vfy-policy artifacts (vkHash
  `0x6c56509f…be047`, Groth16/BN128, nPublic 9)
- `NOTES.md` — research, standings, build log
