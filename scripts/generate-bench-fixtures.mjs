#!/usr/bin/env node
/**
 * generate-bench-fixtures.mjs
 *
 * Generates the Groth16 proof fixture for pallet-zk-verifier benchmarks.
 *
 * Outputs to frame/zk-verifier/src/bench_fixtures/:
 *   proof_transfer.bin       — 128-byte arkworks compressed proof
 *
 * The verify_proof benchmark builds its own synthetic VK + inputs of arity n,
 * so only the proof fixture is embedded.
 *
 * Runs anywhere (incl. a fresh VPS) — all artifacts come from npm packages:
 *   @orbinum/circuits         circuit wasm + proving key
 *   @orbinum/groth16-proofs   snarkjs → arkworks proof compressor (wasm)
 *   snarkjs, circomlibjs      proof + witness helpers
 *
 * Usage:
 *   cd scripts && npm install && node generate-bench-fixtures.mjs
 */

import fs from "fs";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NODE_DIR = path.resolve(__dirname, "..");
const OUT_DIR = path.join(NODE_DIR, "frame/zk-verifier/src/bench_fixtures");

// ── Resolve artifacts from npm packages ──────────────────────────────────────

const { getCircuitPaths } = require("@orbinum/circuits");
const { wasm: WASM_PATH, zkey: ZKEY_PATH } = getCircuitPaths("transfer");

const { groth16 } = await import("snarkjs");
const { buildPoseidon, buildBabyjub } = await import("circomlibjs");

const gpModule = await import("@orbinum/groth16-proofs");
const gpWasm = require.resolve("@orbinum/groth16-proofs/groth16_proofs_bg.wasm");
await gpModule.default(fs.readFileSync(gpWasm));
const { compress_snarkjs_proof_wasm } = gpModule;

fs.mkdirSync(OUT_DIR, { recursive: true });

// ── Build valid circuit inputs ────────────────────────────────────────────────

const poseidon = await buildPoseidon();
const babyJub = await buildBabyjub();
const F = poseidon.F;

const TREE_DEPTH = 20;

function fe(v) { return F.toObject(v); }

function computeOwnerAx(sk) {
  const pt = babyJub.mulPointEscalar(babyJub.Base8, sk);
  return fe(pt[0]);
}

function poseidon4(a, b, c, d) {
  return fe(poseidon([a, b, c, d]));
}

function poseidon2(a, b) {
  return fe(poseidon([a, b]));
}

function buildMerkleProof(leaves, leafIndex) {
  const pathElements = [];
  const pathIndices = [];
  let level = new Map();
  for (let i = 0; i < leaves.length; i++) level.set(i, leaves[i]);

  for (let d = 0; d < TREE_DEPTH; d++) {
    const nodeIdx = leafIndex >> d;
    const isRight = nodeIdx % 2 === 1;
    pathIndices.push(isRight ? 1 : 0);
    pathElements.push(level.get(isRight ? nodeIdx - 1 : nodeIdx + 1) ?? 0n);

    const nextLevel = new Map();
    for (const [pos] of level) {
      const parent = pos >> 1;
      if (nextLevel.has(parent)) continue;
      const l = level.get(parent * 2) ?? 0n;
      const r = level.get(parent * 2 + 1) ?? 0n;
      nextLevel.set(parent, fe(poseidon([l, r])));
    }
    level = nextLevel;
  }
  return { root: level.get(0) ?? 0n, pathElements, pathIndices };
}

// Fixed deterministic values (same as transfer.test.ts defaults)
const SK0 = 0xdeadbeef0000001n;
const SK1 = 0xdeadbeef0000002n;
const BL0 = 0xaaaaaaaabbbbbbbbaaaaaaaabn;
const BL1 = 0xccccccccddddddddccccccccdn;
const OUTBL0 = 0x1111111100000001n;
const OUTBL1 = 0x2222222200000002n;
const ASSET = 0n;
const V0 = 100n;
const V1 = 200n;
const FEE = 0n;
const OUTV0 = 150n;
const OUTV1 = 150n;

const owner0 = computeOwnerAx(SK0);
const owner1 = computeOwnerAx(SK1);

const comm0 = poseidon4(V0, ASSET, owner0, BL0);
const comm1 = poseidon4(V1, ASSET, owner1, BL1);

const { root, pathElements: pe0, pathIndices: pi0 } = buildMerkleProof([comm0, comm1], 0);
const { pathElements: pe1, pathIndices: pi1 } = buildMerkleProof([comm0, comm1], 1);

const null0 = poseidon2(comm0, SK0);
const null1 = poseidon2(comm1, SK1);
const outC0 = poseidon4(OUTV0, ASSET, owner0, OUTBL0);
const outC1 = poseidon4(OUTV1, ASSET, owner1, OUTBL1);

const input = {
  merkle_root: root.toString(),
  nullifiers: [null0.toString(), null1.toString()],
  commitments: [outC0.toString(), outC1.toString()],
  asset_id: ASSET.toString(),
  fee: FEE.toString(),
  input_values: [V0.toString(), V1.toString()],
  input_asset_ids: [ASSET.toString(), ASSET.toString()],
  input_blindings: [BL0.toString(), BL1.toString()],
  spending_keys: [SK0.toString(), SK1.toString()],
  input_path_elements: [pe0.map(String), pe1.map(String)],
  input_path_indices: [pi0, pi1],
  output_values: [OUTV0.toString(), OUTV1.toString()],
  output_asset_ids: [ASSET.toString(), ASSET.toString()],
  output_owner_pubkeys: [owner0.toString(), owner1.toString()],
  output_blindings: [OUTBL0.toString(), OUTBL1.toString()],
};

// ── Generate + compress proof ─────────────────────────────────────────────────

console.log("[1/2] Generating Groth16 proof (transfer circuit)...");
const { proof, publicSignals } = await groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
console.log(`      Public signals (${publicSignals.length}): ${publicSignals.slice(0, 2).join(", ")}...`);

console.log("[2/2] Compressing proof to arkworks format...");
const proofHex = compress_snarkjs_proof_wasm(JSON.stringify(proof));
// compress_snarkjs_proof_wasm returns "0x..." — strip prefix before hex-decoding
const rawHex = proofHex.startsWith("0x") ? proofHex.slice(2) : proofHex;
const proofBytes = Buffer.from(rawHex, "hex");

const proofOut = path.join(OUT_DIR, "proof_transfer.bin");
fs.writeFileSync(proofOut, proofBytes);

console.log(`\n=== Fixture generated ===\n  ${path.relative(NODE_DIR, proofOut)}  (${proofBytes.length} bytes)`);
console.log("\nNow rebuild with: cargo build --release --features runtime-benchmarks,skip-proof-verification");
