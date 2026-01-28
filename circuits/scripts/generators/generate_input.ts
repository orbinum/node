#!/usr/bin/env ts-node
/**
 * Generate valid input.json for transfer circuit benchmarks
 *
 * This script generates cryptographically valid witness data including:
 * - EdDSA key pairs and signatures
 * - Merkle tree with valid paths
 * - Proper nullifiers and commitments
 *
 * Usage: npx ts-node scripts/generate_input.ts
 */

import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const MERKLE_TREE_DEPTH = 20;

interface InputNote {
    value: bigint;
    asset_id: bigint;
    owner_pubkey: any;
    blinding: bigint;
    spending_key: bigint;
}

interface OutputNote {
    value: bigint;
    asset_id: bigint;
    owner_pubkey: any;
    blinding: bigint;
}

interface CircuitInput {
    merkle_root: string;
    nullifiers: string[];
    commitments: string[];
    input_values: string[];
    input_asset_ids: string[];
    input_blindings: string[];
    spending_keys: string[];
    input_owner_Ax: string[];
    input_owner_Ay: string[];
    input_sig_R8x: string[];
    input_sig_R8y: string[];
    input_sig_S: string[];
    input_path_elements: string[][];
    input_path_indices: number[][];
    output_values: string[];
    output_asset_ids: string[];
    output_owner_pubkeys: string[];
    output_blindings: string[];
    [key: string]: any;
}

// Utility to convert Poseidon output to string
const poseidonToStr = (F: any, hash: any): string => F.toString(hash);

async function main(): Promise<void> {
    console.log("=== Transfer Circuit Input Generator ===\n");

    // Initialize crypto primitives
    console.log("1. Initializing crypto primitives...");
    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();
    const F = poseidon.F;

    // Generate EdDSA key pairs
    console.log("\n2. Generating EdDSA key pairs...");
    const privKey1 = crypto.randomBytes(32);
    const privKey2 = crypto.randomBytes(32);

    const pubKey1 = eddsa.prv2pub(privKey1);
    const pubKey2 = eddsa.prv2pub(privKey2);

    console.log("   Key 1 Ax:", F.toString(pubKey1[0]).slice(0, 20) + "...");
    console.log("   Key 2 Ax:", F.toString(pubKey2[0]).slice(0, 20) + "...");

    // Zero value for empty merkle leaves
    const ZERO = BigInt(0);

    // Compute zero hashes for merkle tree padding
    let zeroHashes: bigint[] = [ZERO];
    for (let i = 1; i <= MERKLE_TREE_DEPTH; i++) {
        const prevZero = zeroHashes[i - 1];
        zeroHashes.push(BigInt(poseidonToStr(F, poseidon([prevZero, prevZero]))));
    }

    // Input notes
    console.log("\n3. Creating input notes...");
    const input1: InputNote = {
        value: BigInt(100),
        asset_id: BigInt(0),
        owner_pubkey: pubKey1[0], // Ax is the owner pubkey
        blinding: BigInt("11111111111111111111"),
        spending_key: BigInt("99999999999999999999")
    };

    const input2: InputNote = {
        value: BigInt(50),
        asset_id: BigInt(0),
        owner_pubkey: pubKey2[0],
        blinding: BigInt("22222222222222222222"),
        spending_key: BigInt("99999999999999999999")
    };

    // Compute input commitments
    const inputCommitment1 = poseidon([
        input1.value,
        input1.asset_id,
        input1.owner_pubkey,
        input1.blinding
    ]);
    const inputCommitment2 = poseidon([
        input2.value,
        input2.asset_id,
        input2.owner_pubkey,
        input2.blinding
    ]);

    const c1 = BigInt(poseidonToStr(F, inputCommitment1));
    const c2 = BigInt(poseidonToStr(F, inputCommitment2));

    console.log("   Commitment 1:", c1.toString().slice(0, 20) + "...");
    console.log("   Commitment 2:", c2.toString().slice(0, 20) + "...");

    // Sign commitments with EdDSA
    console.log("\n4. Signing commitments with EdDSA...");
    const msg1 = F.e(c1);
    const msg2 = F.e(c2);

    const sig1 = eddsa.signPoseidon(privKey1, msg1);
    const sig2 = eddsa.signPoseidon(privKey2, msg2);

    console.log("   Signature 1 R8x:", F.toString(sig1.R8[0]).slice(0, 20) + "...");
    console.log("   Signature 2 R8x:", F.toString(sig2.R8[0]).slice(0, 20) + "...");

    // Verify signatures locally
    const valid1 = eddsa.verifyPoseidon(msg1, sig1, pubKey1);
    const valid2 = eddsa.verifyPoseidon(msg2, sig2, pubKey2);
    console.log("   Signature 1 valid:", valid1);
    console.log("   Signature 2 valid:", valid2);

    if (!valid1 || !valid2) {
        console.error("❌ EdDSA signature verification failed!");
        process.exit(1);
    }

    // Build Merkle tree
    console.log("\n5. Building Merkle tree...");

    // Level 0 hash: h01 = poseidon(c1, c2)
    const h01 = BigInt(poseidonToStr(F, poseidon([c1, c2])));

    // Build the rest of the tree upward
    let computedHashes: bigint[] = [h01];
    for (let i = 1; i < MERKLE_TREE_DEPTH; i++) {
        const prevHash = computedHashes[i - 1];
        const nextHash = BigInt(poseidonToStr(F, poseidon([prevHash, zeroHashes[i]])));
        computedHashes.push(nextHash);
    }
    const merkleRoot = computedHashes[MERKLE_TREE_DEPTH - 1];
    console.log("   Merkle Root:", merkleRoot.toString().slice(0, 20) + "...");

    // Build merkle paths
    // Circuit path_index semantics: 0 = right child, 1 = left child
    console.log("\n6. Building merkle paths...");

    // For c1 (index 0): left child at level 0
    const merkle_path_elements_1 = [c2.toString()];
    const merkle_path_indices_1 = [0]; // c1 is LEFT, so index = 0

    for (let i = 1; i < MERKLE_TREE_DEPTH; i++) {
        merkle_path_elements_1.push(zeroHashes[i].toString());
        merkle_path_indices_1.push(0); // always on LEFT
    }

    // For c2 (index 1): right child at level 0
    const merkle_path_elements_2 = [c1.toString()];
    const merkle_path_indices_2 = [1]; // c2 is RIGHT, so index = 1

    for (let i = 1; i < MERKLE_TREE_DEPTH; i++) {
        merkle_path_elements_2.push(zeroHashes[i].toString());
        merkle_path_indices_2.push(0); // always on LEFT
    }

    // Compute nullifiers
    console.log("\n7. Computing nullifiers...");
    const nullifier1 = poseidon([inputCommitment1, input1.spending_key]);
    const nullifier2 = poseidon([inputCommitment2, input2.spending_key]);

    console.log("   Nullifier 1:", poseidonToStr(F, nullifier1).slice(0, 20) + "...");
    console.log("   Nullifier 2:", poseidonToStr(F, nullifier2).slice(0, 20) + "...");

    // Output notes (must sum to same value: 100 + 50 = 80 + 70)
    console.log("\n8. Creating output notes...");
    const output1: OutputNote = {
        value: BigInt(80),
        asset_id: BigInt(0),
        owner_pubkey: BigInt("98765432109876543210"), // Bob
        blinding: BigInt("33333333333333333333")
    };

    const output2: OutputNote = {
        value: BigInt(70),
        asset_id: BigInt(0),
        owner_pubkey: F.toObject(pubKey1[0]), // Alice gets change
        blinding: BigInt("44444444444444444444")
    };

    const outputCommitment1 = poseidon([
        output1.value,
        output1.asset_id,
        output1.owner_pubkey,
        output1.blinding
    ]);
    const outputCommitment2 = poseidon([
        output2.value,
        output2.asset_id,
        output2.owner_pubkey,
        output2.blinding
    ]);

    // Prepare circuit input
    const input: CircuitInput = {
        // Public inputs
        merkle_root: merkleRoot.toString(),
        nullifiers: [
            poseidonToStr(F, nullifier1),
            poseidonToStr(F, nullifier2)
        ],
        commitments: [
            poseidonToStr(F, outputCommitment1),
            poseidonToStr(F, outputCommitment2)
        ],

        // Private inputs - input notes
        input_values: [input1.value.toString(), input2.value.toString()],
        input_asset_ids: [input1.asset_id.toString(), input2.asset_id.toString()],
        input_blindings: [input1.blinding.toString(), input2.blinding.toString()],
        spending_keys: [input1.spending_key.toString(), input2.spending_key.toString()],

        // EdDSA public keys (Ax, Ay)
        input_owner_Ax: [F.toString(pubKey1[0]), F.toString(pubKey2[0])],
        input_owner_Ay: [F.toString(pubKey1[1]), F.toString(pubKey2[1])],

        // EdDSA signatures (R8x, R8y, S)
        input_sig_R8x: [F.toString(sig1.R8[0]), F.toString(sig2.R8[0])],
        input_sig_R8y: [F.toString(sig1.R8[1]), F.toString(sig2.R8[1])],
        input_sig_S: [sig1.S.toString(), sig2.S.toString()],

        // Merkle paths
        input_path_elements: [merkle_path_elements_1, merkle_path_elements_2],
        input_path_indices: [merkle_path_indices_1, merkle_path_indices_2],

        // Output notes
        output_values: [output1.value.toString(), output2.value.toString()],
        output_asset_ids: [output1.asset_id.toString(), output2.asset_id.toString()],
        output_owner_pubkeys: [output1.owner_pubkey.toString(), output2.owner_pubkey.toString()],
        output_blindings: [output1.blinding.toString(), output2.blinding.toString()]
    };

    // Save input to circuits/build/ directory (not scripts/build/)
    const buildDir = path.join(__dirname, "..", "..", "build");
    if (!fs.existsSync(buildDir)) {
        fs.mkdirSync(buildDir, { recursive: true });
    }

    fs.writeFileSync(
        path.join(buildDir, "input.json"),
        JSON.stringify(input, null, 2)
    );

    console.log("\n✅ Saved input.json to build/input.json");
    console.log("\n=== DONE ===");
}

main().catch((err) => {
    console.error("❌ Error:", err.message);
    process.exit(1);
});
