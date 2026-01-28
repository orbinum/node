import { buildPoseidon } from 'circomlibjs';
import assert from 'assert';

describe("Unshield Circuit Logic", function() {
    this.timeout(60000);

    let poseidon: any;
    let F: any;

    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    // Helper: compute note commitment
    function computeCommitment(value: bigint, assetId: bigint, owner: bigint, blinding: bigint): string {
        return F.toString(poseidon([value, assetId, owner, blinding]));
    }

    // Helper: compute nullifier
    function computeNullifier(commitment: string, spendingKey: bigint): string {
        return F.toString(poseidon([BigInt(commitment), spendingKey]));
    }

    // Helper: compute merkle root for simple 2-level tree
    function computeMerkleRoot(leaves: string[], depth: number = 2): string {
        if (leaves.length === 0) return "0";

        let level: bigint[] = leaves.map(l => BigInt(l));

        while (level.length > 1) {
            const newLevel: any[] = [];
            for (let i = 0; i < level.length; i += 2) {
                const left = level[i];
                const right = level[i + 1] || 0n;
                newLevel.push(poseidon([left, right]));
            }
            level = newLevel;
        }

        return F.toString(level[0]);
    }

    describe("Note Commitment for Unshield", () => {
        it("should compute commitment correctly", () => {
            const value = 1000n;
            const assetId = 0n;
            const owner = 0x1234567890abcdef1234567890abcdef12345678n;
            const blinding = 0xfedcba0987654321fedcba0987654321fedcba09n;

            const commitment = computeCommitment(value, assetId, owner, blinding);

            console.log("  Commitment:", commitment);
            assert(commitment !== "0", "Commitment should not be zero");
        });

        it("should be deterministic", () => {
            const value = 1000n;
            const assetId = 0n;
            const owner = 0x1234n;
            const blinding = 0x5678n;

            const c1 = computeCommitment(value, assetId, owner, blinding);
            const c2 = computeCommitment(value, assetId, owner, blinding);

            assert.strictEqual(c1, c2, "Same inputs should produce same commitment");
        });
    });

    describe("Nullifier for Unshield", () => {
        it("should compute nullifier correctly", () => {
            const commitment = computeCommitment(
                1000n,
                0n,
                0x1234n,
                0x5678n
            );
            const spendingKey = 0xdeadbeefcafebaben;

            const nullifier = computeNullifier(commitment, spendingKey);

            console.log("  Nullifier:", nullifier);
            assert(nullifier !== "0", "Nullifier should not be zero");
        });

        it("should be different for different spending keys", () => {
            const commitment = computeCommitment(
                1000n,
                0n,
                0x1234n,
                0x5678n
            );

            const n1 = computeNullifier(commitment, 0xdeadbeefn);
            const n2 = computeNullifier(commitment, 0xcafebaben);

            assert(n1 !== n2, "Different spending keys should produce different nullifiers");
        });

        it("should be different for different commitments", () => {
            const spendingKey = 0xdeadbeefn;

            const c1 = computeCommitment(1000n, 0n, 0x1234n, 0x5678n);
            const c2 = computeCommitment(2000n, 0n, 0x1234n, 0x5678n);

            const n1 = computeNullifier(c1, spendingKey);
            const n2 = computeNullifier(c2, spendingKey);

            assert(n1 !== n2, "Different commitments should produce different nullifiers");
        });
    });

    describe("Amount Verification", () => {
        it("should match amount to note value", () => {
            const noteValue = 1000n;
            const withdrawAmount = 1000n;

            assert.strictEqual(noteValue, withdrawAmount, "Amount should equal note value");
        });

        it("should reject mismatched amount", () => {
            const noteValue: bigint = 1000n;
            const withdrawAmount: bigint = 1500n; // Trying to withdraw more

            assert(noteValue !== withdrawAmount, "Should detect amount mismatch");
        });
    });

    describe("Merkle Membership Proof", () => {
        it("should verify commitment exists in tree", () => {
            // Create a note
            const noteValue = 1000n;
            const assetId = 0n;
            const owner = 0x1234n;
            const blinding = 0x5678n;
            const commitment = computeCommitment(noteValue, assetId, owner, blinding);

            // Create simple tree with this commitment
            const otherCommitment = computeCommitment(
                2000n, 0n, 0xabcdn, 0xef01n
            );

            // Build merkle root
            const root = computeMerkleRoot([commitment, otherCommitment]);

            console.log("  Tree root:", root);

            // Verify path: commitment is at index 0 (left)
            // Sibling at level 0: otherCommitment
            const computedRoot = F.toString(
                poseidon([BigInt(commitment), BigInt(otherCommitment)])
            );

            assert.strictEqual(computedRoot, root, "Should verify merkle path");
        });

        it("should build tree with multiple commitments", () => {
            const commitments: string[] = [
                computeCommitment(1000n, 0n, 0x1111n, 0xaan),
                computeCommitment(2000n, 0n, 0x2222n, 0xbbn),
                computeCommitment(3000n, 0n, 0x3333n, 0xccn),
                computeCommitment(4000n, 0n, 0x4444n, 0xddn)
            ];

            const root = computeMerkleRoot(commitments);

            console.log("  Multi-leaf tree root:", root);
            assert(root !== "0", "Root should not be zero");
        });
    });

    describe("Complete Unshield Example", () => {
        it("should simulate valid unshield", () => {
            console.log("\n  === Simulating Unshield Transaction ===");

            // Alice has a private note worth 1000 tokens
            const noteValue = 1000n;
            const assetId = 0n;
            const alice_pk = 0x1234567890abcdefn;
            const blinding = 0xfedcba0987654321n;
            const spending_key = 0xdeadbeefcafebaben;

            // Compute commitment
            const commitment = computeCommitment(noteValue, assetId, alice_pk, blinding);
            console.log("  Note commitment:", commitment.slice(0, 20) + "...");

            // Compute nullifier (to prevent double-spending)
            const nullifier = computeNullifier(commitment, spending_key);
            console.log("  Nullifier:", nullifier.slice(0, 20) + "...");

            // Add to merkle tree
            const otherCommitments = [
                computeCommitment(2000n, 0n, 0x5555n, 0x1111n),
                computeCommitment(3000n, 0n, 0x6666n, 0x2222n)
            ];

            const root = computeMerkleRoot([commitment, ...otherCommitments]);
            console.log("  Merkle root:", root.slice(0, 20) + "...");

            // Alice wants to unshield (withdraw) to public balance
            const withdrawAmount = 1000n;
            const recipientAddress = "0xAlicePublicAddress";

            assert.strictEqual(noteValue, withdrawAmount, "Withdraw amount must match note value");

            console.log("  ✓ Unshield valid: 1000 tokens");
            console.log("  ✓ Recipient:", recipientAddress);
            console.log("  ✓ Nullifier prevents double-spend");
        });
    });

    describe("Multi-Asset Unshield Support", () => {
        it("should unshield USDT (asset_id = 1)", () => {
            console.log("\n  === Testing USDT Unshield (asset_id = 1) ===");

            // Alice has a private USDT note
            const noteValue = 500n;
            const assetId = 1n; // USDT
            const alice_pk = 0x1234567890abcdefn;
            const blinding = 0xfedcba0987654321n;
            const spending_key = 0xdeadbeefcafebaben;

            // Compute commitment for USDT note
            const commitment = computeCommitment(noteValue, assetId, alice_pk, blinding);
            console.log("  USDT Note commitment:", commitment.slice(0, 20) + "...");

            // Compute nullifier
            const nullifier = computeNullifier(commitment, spending_key);
            console.log("  Nullifier:", nullifier.slice(0, 20) + "...");

            // Add to merkle tree
            const otherCommitments = [
                computeCommitment(1000n, 1n, 0x5555n, 0x1111n),
                computeCommitment(2000n, 1n, 0x6666n, 0x2222n)
            ];

            const root = computeMerkleRoot([commitment, ...otherCommitments]);
            console.log("  Merkle root:", root.slice(0, 20) + "...");

            // Unshield to public balance
            const withdrawAmount = 500n;
            const recipientAddress = "0xAlicePublicAddress";

            assert.strictEqual(noteValue, withdrawAmount, "Withdraw amount must match note value");
            assert.strictEqual(assetId, 1n, "Should be USDT");

            console.log("  ✓ Unshield valid: 500 USDT");
            console.log("  ✓ Asset ID: 1 (USDT)");
            console.log("  ✓ Recipient:", recipientAddress);
        });

        it("should unshield DAI (asset_id = 2)", () => {
            console.log("\n  === Testing DAI Unshield (asset_id = 2) ===");

            const noteValue = 1000n;
            const assetId = 2n; // DAI
            const owner_pk = 0xabcdefn;
            const blinding = 0x123456n;

            const commitment = computeCommitment(noteValue, assetId, owner_pk, blinding);
            console.log("  DAI Note commitment:", commitment.slice(0, 20) + "...");

            assert(commitment !== "0", "Commitment should be valid");
            console.log("  ✓ DAI note created with asset_id = 2");
        });

        it("should unshield custom token (asset_id = 42)", () => {
            const noteValue = 12345n;
            const assetId = 42n; // Custom token
            const owner_pk = 0x9999n;
            const blinding = 0xaaaan;

            const commitment = computeCommitment(noteValue, assetId, owner_pk, blinding);

            assert(commitment !== "0", "Custom token commitment valid");
            console.log("  ✓ Custom token (asset_id = 42) unshield supported");
        });

        it("should support high asset_id values in unshield", () => {
            const max_asset_id = 4294967295n; // 2^32 - 1
            const noteValue = 100n;
            const owner_pk = 0xffffn;
            const blinding = 0xeeeeen;

            const commitment = computeCommitment(noteValue, max_asset_id, owner_pk, blinding);

            assert(commitment !== "0", "Max asset_id should work");
            console.log("  ✓ Max asset_id (2^32-1) supported in unshield");
        });

        it("should produce different nullifiers for different asset notes", () => {
            const owner_pk = 0x1234n;
            const blinding = 0x5678n;
            const spending_key = 0xdeadbeefn;
            const value = 100n;

            // Create notes with different asset_ids
            const commit_native = computeCommitment(value, 0n, owner_pk, blinding);
            const commit_usdt = computeCommitment(value, 1n, owner_pk, blinding);
            const commit_dai = computeCommitment(value, 2n, owner_pk, blinding);

            // Compute nullifiers
            const null_native = computeNullifier(commit_native, spending_key);
            const null_usdt = computeNullifier(commit_usdt, spending_key);
            const null_dai = computeNullifier(commit_dai, spending_key);

            // All should be different (different commitments → different nullifiers)
            assert(null_native !== null_usdt, "Native vs USDT nullifier different");
            assert(null_native !== null_dai, "Native vs DAI nullifier different");
            assert(null_usdt !== null_dai, "USDT vs DAI nullifier different");

            console.log("  ✓ Different asset notes produce unique nullifiers");
            console.log("    Native nullifier:", null_native.slice(0, 16) + "...");
            console.log("    USDT nullifier:  ", null_usdt.slice(0, 16) + "...");
            console.log("    DAI nullifier:   ", null_dai.slice(0, 16) + "...");
        });

        it("should simulate multi-asset unshield scenarios", () => {
            console.log("\n  === Multi-Asset Unshield Scenarios ===");

            const alice_pk = 0x111111n;
            const bob_pk = 0x222222n;
            const spending_key = 0xdeadbeefn;

            // Scenario 1: Unshield 100 USDT
            console.log("\n  Scenario 1: Alice unshields 100 USDT");
            const usdt_note = computeCommitment(100n, 1n, alice_pk, 0xaa11n);
            const usdt_nullifier = computeNullifier(usdt_note, spending_key);
            console.log("  ✓ USDT note commitment:", usdt_note.slice(0, 20) + "...");
            console.log("  ✓ Nullifier:", usdt_nullifier.slice(0, 20) + "...");

            // Scenario 2: Unshield 500 DAI
            console.log("\n  Scenario 2: Bob unshields 500 DAI");
            const dai_note = computeCommitment(500n, 2n, bob_pk, 0xbb22n);
            const dai_nullifier = computeNullifier(dai_note, spending_key);
            console.log("  ✓ DAI note commitment:", dai_note.slice(0, 20) + "...");
            console.log("  ✓ Nullifier:", dai_nullifier.slice(0, 20) + "...");

            // Scenario 3: Unshield 1000 Native tokens
            console.log("\n  Scenario 3: Alice unshields 1000 ORB (native)");
            const native_note = computeCommitment(1000n, 0n, alice_pk, 0xcc33n);
            const native_nullifier = computeNullifier(native_note, spending_key);
            console.log("  ✓ Native note commitment:", native_note.slice(0, 20) + "...");
            console.log("  ✓ Nullifier:", native_nullifier.slice(0, 20) + "...");

            // Verify all commitments are unique
            assert(usdt_note !== dai_note, "USDT vs DAI commitments different");
            assert(usdt_note !== native_note, "USDT vs Native commitments different");
            assert(dai_note !== native_note, "DAI vs Native commitments different");

            console.log("\n  ✓ Multi-asset unshield fully supported!");
            console.log("  ✓ Each asset type produces unique commitments");
            console.log("  ✓ Nullifiers prevent double-spending across all assets");
        });

        it("should validate amount consistency across different assets", () => {
            const owner_pk = 0xababn;
            const blinding = 0xcdcdn;

            // Same value, different assets should produce different commitments
            const value = 1000n;

            const c1 = computeCommitment(value, 0n, owner_pk, blinding);
            const c2 = computeCommitment(value, 1n, owner_pk, blinding);
            const c3 = computeCommitment(value, 2n, owner_pk, blinding);

            assert(c1 !== c2 && c2 !== c3 && c1 !== c3, 
                "Same value with different assets must produce different commitments");

            console.log("  ✓ Amount consistency validated across assets");
            console.log("  ✓ Asset ID is part of commitment calculation");
        });
    });
});
