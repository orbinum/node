/**
 * Poseidon Compatibility Test
 *
 * This test generates known Poseidon hash values that can be compared
 * against the Rust implementation in wallet-cli.
 *
 * Run: npm test -- --grep "Poseidon Compatibility"
 */

import { buildPoseidon } from 'circomlibjs';
import { assert } from 'chai';

describe("Poseidon Compatibility", function() {
    let poseidon: any;
    let F: any; // Field

    before(async function() {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    it("should compute hash_2([1, 2]) for Rust comparison", async function() {
        // Test vector: hash_2([1, 2])
        const inputs = [1n, 2n];
        const hash = poseidon(inputs);
        const hashBigInt: bigint = F.toObject(hash);

        console.log("\n=== POSEIDON HASH_2 TEST VECTOR ===");
        console.log("Inputs: [1, 2]");
        console.log("Hash (decimal):", hashBigInt.toString());
        console.log("Hash (hex):", "0x" + hashBigInt.toString(16).padStart(64, '0'));

        // Basic sanity check
        assert.notEqual(hashBigInt, 0n, "Hash should not be zero");
    });

    it("should compute hash_4([1, 2, 3, 4]) for Rust comparison", async function() {
        // Test vector: hash_4([1, 2, 3, 4])
        const inputs = [1n, 2n, 3n, 4n];
        const hash = poseidon(inputs);
        const hashBigInt: bigint = F.toObject(hash);

        console.log("\n=== POSEIDON HASH_4 TEST VECTOR ===");
        console.log("Inputs: [1, 2, 3, 4]");
        console.log("Hash (decimal):", hashBigInt.toString());
        console.log("Hash (hex):", "0x" + hashBigInt.toString(16).padStart(64, '0'));

        // Basic sanity check
        assert.notEqual(hashBigInt, 0n, "Hash should not be zero");
    });

    it("should compute note commitment for Rust comparison", async function() {
        // Note commitment: Poseidon(value, asset_id, owner_pk, blinding)
        // Using simple test values
        const value = 1000n;
        const assetId = 0n;
        const ownerPk = 0x0102030405060708091011121314151617181920212223242526272829303132n;
        const blinding = 0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899n;

        const inputs = [value, assetId, ownerPk, blinding];
        const hash = poseidon(inputs);
        const commitment: bigint = F.toObject(hash);

        console.log("\n=== NOTE COMMITMENT TEST VECTOR ===");
        console.log("value:", value.toString());
        console.log("asset_id:", assetId.toString());
        console.log("owner_pk (hex):", "0x" + ownerPk.toString(16));
        console.log("blinding (hex):", "0x" + blinding.toString(16));
        console.log("Commitment (decimal):", commitment.toString());
        console.log("Commitment (hex):", "0x" + commitment.toString(16).padStart(64, '0'));

        assert.notEqual(commitment, 0n, "Commitment should not be zero");
    });

    it("should compute nullifier for Rust comparison", async function() {
        // First compute a commitment
        const value = 1000n;
        const assetId = 0n;
        const ownerPk = 0x0102030405060708091011121314151617181920212223242526272829303132n;
        const blinding = 0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899n;

        const commitmentHash = poseidon([value, assetId, ownerPk, blinding]);
        const commitment: bigint = F.toObject(commitmentHash);

        // Nullifier: Poseidon(commitment, spending_key)
        const spendingKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

        const nullifierHash = poseidon([commitment, spendingKey]);
        const nullifier: bigint = F.toObject(nullifierHash);

        console.log("\n=== NULLIFIER TEST VECTOR ===");
        console.log("commitment (from above):", commitment.toString());
        console.log("spending_key (hex):", "0x" + spendingKey.toString(16));
        console.log("Nullifier (decimal):", nullifier.toString());
        console.log("Nullifier (hex):", "0x" + nullifier.toString(16).padStart(64, '0'));

        assert.notEqual(nullifier, 0n, "Nullifier should not be zero");
    });
});
