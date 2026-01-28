import path from 'path';
import { expect } from 'chai';
import { wasm as wasm_tester } from 'circom_tester';
import { buildPoseidon } from 'circomlibjs';
import type { WasmTester } from 'circom_tester';

interface CircuitInput extends Record<string, string> {
    commitment: string;
    revealed_value: string;
    revealed_asset_id: string;
    revealed_owner_hash: string;
    value: string;
    asset_id: string;
    owner_pubkey: string;
    blinding: string;
    viewing_key: string;
    disclose_value: string;
    disclose_asset_id: string;
    disclose_owner: string;
}

describe("Selective Disclosure Circuit - Phase 2", function() {
    this.timeout(120000); // Compilation may take time
    
    const circuitPath = path.join(__dirname, "..", "circuits", "disclosure.circom");
    
    let circuit: WasmTester;
    let poseidon: any;
    let F: any;
    
    before(async function() {
        circuit = await wasm_tester(circuitPath, { 
            output: path.join(__dirname, "..", "build"),
            recompile: false // Use precompiled circuit
        });
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });
    
    // Helper: Compute commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
    function computeCommitment(value: bigint, assetId: bigint, ownerPubkey: bigint, blinding: bigint): string {
        const hash = poseidon([value, assetId, ownerPubkey, blinding]);
        return F.toString(hash);
    }
    
    // Helper: Compute viewing_key = Poseidon(owner_pubkey)
    function computeViewingKey(ownerPubkey: bigint): string {
        const hash = poseidon([ownerPubkey]);
        return F.toString(hash);
    }
    
    // Helper: Compute owner_hash = Poseidon(owner_pubkey)
    function computeOwnerHash(ownerPubkey: bigint): string {
        return computeViewingKey(ownerPubkey); // Same function
    }
    
    describe("Checklist 2.2 - Commitment Verification", () => {
        it("should verify valid commitment matches recomputed hash", async () => {
            // Test data (use asset_id=0 per MVP constraint)
            const value = 1000n;
            const assetId = 0n; // MVP: native token only
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            // Inputs (revealing nothing)
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: "0",
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "0",
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        });
        
        it("should reject invalid commitment", async () => {
            const value = 1000n;
            const assetId = 0n;
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            // Invalid commitment (change expected value)
            const input: CircuitInput = {
                commitment: (BigInt(commitment) + 1n).toString(), // ❌ Wrong commitment
                revealed_value: "0",
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "0",
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            try {
                await circuit.calculateWitness(input);
                expect.fail("Should have thrown error for invalid commitment");
            } catch (error: any) {
                expect(error.message).to.include("Assert Failed");
            }
        });
        
        it("should validate all 4 fields contribute to commitment", () => {
            // Test 1: Changing value should change commitment
            const value1 = 1000n;
            const value2 = 2000n;
            const assetId = 0n;
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment1 = computeCommitment(value1, assetId, ownerPubkey, blinding);
            const commitment2 = computeCommitment(value2, assetId, ownerPubkey, blinding);
            
            expect(commitment1).to.not.equal(commitment2);
            
            // Test 2: Changing asset_id should change commitment
            const commitment3 = computeCommitment(value1, 2n, ownerPubkey, blinding);
            expect(commitment1).to.not.equal(commitment3);
            
            // Test 3: Changing owner_pubkey should change commitment
            const commitment4 = computeCommitment(value1, assetId, 99999999999999999999n, blinding);
            expect(commitment1).to.not.equal(commitment4);
            
            // Test 4: Changing blinding should change commitment
            const commitment5 = computeCommitment(value1, assetId, ownerPubkey, 11111111111111111111n);
            expect(commitment1).to.not.equal(commitment5);
        });
    });
    
    describe("Checklist 2.3 - Viewing Key Verification", () => {
        it("should accept valid viewing key", async () => {
            const value = 5000n;
            const assetId = 0n;
            const ownerPubkey = 777777777777777777n;
            const blinding = 123456789012345678n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: "0",
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "0",
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        });
        
        it("should reject invalid viewing key", async () => {
            const value = 5000n;
            const assetId = 0n;
            const ownerPubkey = 777777777777777777n;
            const blinding = 123456789012345678n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            // Wrong viewing key
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: "0",
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: (BigInt(viewingKey) + 1n).toString(), // ❌ Wrong viewing key
                disclose_value: "0",
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            try {
                await circuit.calculateWitness(input);
                expect.fail("Should have thrown error for invalid viewing key");
            } catch (error: any) {
                expect(error.message).to.include("Assert Failed");
            }
        });
    });
    
    describe("Checklist 2.4 - Selective Disclosure", () => {
        it("should reveal value when disclose_value=1", async () => {
            const value = 1000n;
            const assetId = 0n;
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: value.toString(), // ✅ Revealed
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "1", // ✅ Reveal value
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        });
        
        it("should hide value when disclose_value=0", async () => {
            const value = 1000n;
            const assetId = 0n;
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: "0", // ✅ Hidden
                revealed_asset_id: "0",
                revealed_owner_hash: "0",
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "0", // ✅ Hide value
                disclose_asset_id: "0",
                disclose_owner: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        });
        
        it("should reveal all fields when all masks are 1", async () => {
            const value = 1000n;
            const assetId = 0n;
            const ownerPubkey = 12345678901234567890n;
            const blinding = 98765432109876543210n;
            
            const commitment = computeCommitment(value, assetId, ownerPubkey, blinding);
            const viewingKey = computeViewingKey(ownerPubkey);
            const ownerHash = computeOwnerHash(ownerPubkey);
            
            const input: CircuitInput = {
                commitment: commitment,
                revealed_value: value.toString(),
                revealed_asset_id: assetId.toString(),
                revealed_owner_hash: ownerHash,
                value: value.toString(),
                asset_id: assetId.toString(),
                owner_pubkey: ownerPubkey.toString(),
                blinding: blinding.toString(),
                viewing_key: viewingKey,
                disclose_value: "1",
                disclose_asset_id: "1",
                disclose_owner: "1"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        });
    });
});
