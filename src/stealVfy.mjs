// Steal the VFY — policy + Groth16 proof.
// ESM port of the public reference implementation (DaddyUnikii/zkverify-agent,
// src/stealVfy.js), which competed in this track. The circuit enforces that the
// chosen move matches the Poseidon-committed strategy params for the live
// balances, bound to matchId + turnNumber so proofs cannot be replayed.
// Strategy params + salt come ONLY from env vars (never committed):
//   STEAL_VFY_PARAMS — 8 comma-separated ints, default "8,18,8,0,0,0,0,0"
//   STEAL_VFY_SALT   — random decimal salt (required in production)
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { concat, keccak256, numberToHex } from 'viem';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, '..', 'circuits', 'vfy-policy.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'vfy-policy_final.zkey');

// vfy-policy vkHash, registered on zkVerify mainnet (from /api/circuit-info).
export const VFY_VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

export const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

export function getStrategyConfig() {
  const rawParams = process.env.STEAL_VFY_PARAMS || '8,18,8,0,0,0,0,0';
  const parts = rawParams.split(',').map((x) => BigInt(x.trim()));
  if (parts.length !== 8) {
    throw new Error('STEAL_VFY_PARAMS must have exactly 8 comma-separated integers');
  }
  const saltRaw = process.env.STEAL_VFY_SALT || '';
  if (!saltRaw) throw new Error('STEAL_VFY_SALT is not set');
  return { params: parts, salt: BigInt(saltRaw) };
}

export async function computeCommitment(params, salt) {
  const poseidon = await getPoseidon();
  const hashBigInt = poseidon.F.toObject(poseidon([...params, salt]));
  return {
    decimal: hashBigInt.toString(),
    hex: numberToHex(hashBigInt, { size: 32 }),
  };
}

// Deterministic policy matching vfy-policy.wasm constraints:
// - selfBalance < params[1] => FORTIFY (protect what's left)
// - opponentBalance < params[2] => HOLD (nothing worth extracting)
// - otherwise => EXTRACT params[0] (1..10)
export function decideMove(state, params) {
  const selfBalance = BigInt(state.selfBalance ?? 0);
  const opponentBalance = BigInt(state.opponentBalance ?? 0);
  if (selfBalance < params[1]) return { type: 'FORTIFY', amountNum: 0 };
  if (opponentBalance < params[2]) return { type: 'HOLD', amountNum: 0 };
  return { type: 'EXTRACT', amountNum: Number(params[0]) };
}

export function matchIdToBigInt(matchId) {
  const hex = String(matchId).replace(/^0x/i, '').replace(/-/g, '');
  if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error(`bad matchId: ${matchId}`);
  return BigInt('0x' + hex);
}

export async function handleStealVfy(payload) {
  const { matchId, turn, state, strategyCommitment } = payload;
  if (matchId == null || turn == null || !state) {
    throw new Error('steal-the-vfy envelope missing matchId/turn/state');
  }
  const { params, salt } = getStrategyConfig();
  const computed = await computeCommitment(params, salt);

  // Prefer the commitment the platform echoes back; fall back to our own.
  const commitmentDecimal = strategyCommitment?.hash
    ? BigInt(strategyCommitment.hash).toString()
    : computed.decimal;

  const move = decideMove(state, params);
  const actionObj = move.type === 'EXTRACT'
    ? { type: 'EXTRACT', amount: move.amountNum }
    : { type: move.type };

  const circuitInput = {
    commitment: commitmentDecimal,
    matchId: matchIdToBigInt(matchId).toString(),
    turnNumber: String(turn),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: ACTION_CODE[move.type].toString(),
    amount: String(move.amountNum),
    circuitVersion: '1',
    salt: salt.toString(),
    strategyParams: params.map(String),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH,
  );

  const publicInputsHash = keccak256(
    concat([
      numberToHex(BigInt(commitmentDecimal), { size: 32 }),
      numberToHex(matchIdToBigInt(matchId), { size: 32 }),
      numberToHex(BigInt(turn), { size: 32 }),
      numberToHex(BigInt(state.selfBalance), { size: 32 }),
      numberToHex(BigInt(state.opponentBalance), { size: 32 }),
      numberToHex(ACTION_CODE[move.type], { size: 32 }),
      numberToHex(BigInt(move.amountNum), { size: 32 }),
      numberToHex(1n, { size: 32 }),
    ]),
  );

  return {
    matchId,
    turn,
    action: actionObj,
    policyProof: {
      circuitVersion: 'v1',
      proof,
      public_signals: publicSignals,
      publicInputsHash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
}
