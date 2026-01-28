import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { buildPoseidon } from 'circomlibjs';
import { expect } from 'chai';
import type { WasmTester } from 'circom_tester';

describe("Note Circuit Components", function() {
    this.timeout(120000);
    
    let poseidon: any;
    let F: any;
    
    before(async function() {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });
    
    describe("NoteCommitment Template", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const noteCommitmentCircuit = `
                pragma circom 2.0.0;
                include "../circuits/note.circom";
                component main = NoteCommitment();
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_note_commitment.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, noteCommitmentCircuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should compute commitment correctly", async () => {
            const value = 1000n;
            const asset_id = 0n;
            const owner_pubkey = 12345678901234567890n;
            const blinding = 99999999999999999999n;
            
            const expectedCommitment = F.toString(
                poseidon([value, asset_id, owner_pubkey, blinding])
            );
            
            const input = {
                value: value.toString(),
                asset_id: asset_id.toString(),
                owner_pubkey: owner_pubkey.toString(),
                blinding: blinding.toString()
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const commitment = witness[1];
            expect(commitment.toString()).to.equal(expectedCommitment);
        });
        
        it("should be deterministic", async () => {
            const input = {
                value: "5000",
                asset_id: "0",
                owner_pubkey: "777777777777777777",
                blinding: "888888888888888888"
            };
            
            const witness1 = await circuit.calculateWitness(input);
            const witness2 = await circuit.calculateWitness(input);
            
            expect(witness1[1].toString()).to.equal(witness2[1].toString());
        });
        
        it("should produce different commitments for different values", async () => {
            const base = {
                asset_id: "0",
                owner_pubkey: "12345",
                blinding: "67890"
            };
            
            const input1 = { ...base, value: "100" };
            const input2 = { ...base, value: "200" };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should produce different commitments for different asset_ids", async () => {
            const base = {
                value: "1000",
                owner_pubkey: "12345",
                blinding: "67890"
            };
            
            const input1 = { ...base, asset_id: "0" };
            const input2 = { ...base, asset_id: "1" };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should produce different commitments for different owner_pubkeys", async () => {
            const base = {
                value: "1000",
                asset_id: "0",
                blinding: "67890"
            };
            
            const input1 = { ...base, owner_pubkey: "11111" };
            const input2 = { ...base, owner_pubkey: "22222" };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should produce different commitments for different blindings", async () => {
            const base = {
                value: "1000",
                asset_id: "0",
                owner_pubkey: "12345"
            };
            
            const input1 = { ...base, blinding: "11111" };
            const input2 = { ...base, blinding: "22222" };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should handle zero values", async () => {
            const input = {
                value: "0",
                asset_id: "0",
                owner_pubkey: "0",
                blinding: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            // Should compute hash of all zeros
            const expectedCommitment = F.toString(poseidon([0n, 0n, 0n, 0n]));
            expect(witness[1].toString()).to.equal(expectedCommitment);
        });
        
        it("should handle maximum field values", async () => {
            const maxValue = "21888242871839275222246405745257275088548364400416034343698204186575808495616"; // Close to field modulus
            
            const input = {
                value: "1000000000000000000000",
                asset_id: "999999",
                owner_pubkey: maxValue,
                blinding: maxValue
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            // Should not overflow
            expect(witness[1]).to.not.equal(0n);
        });
    });
    
    describe("Nullifier Template", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const nullifierCircuit = `
                pragma circom 2.0.0;
                include "../circuits/note.circom";
                component main = Nullifier();
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_nullifier.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, nullifierCircuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should compute nullifier correctly", async () => {
            const commitment = 123456789012345678901234567890n;
            const spending_key = 987654321098765432109876543210n;
            
            const expectedNullifier = F.toString(
                poseidon([commitment, spending_key])
            );
            
            const input = {
                commitment: commitment.toString(),
                spending_key: spending_key.toString()
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const nullifier = witness[1];
            expect(nullifier.toString()).to.equal(expectedNullifier);
        });
        
        it("should be deterministic", async () => {
            const input = {
                commitment: "111111111111111111",
                spending_key: "222222222222222222"
            };
            
            const witness1 = await circuit.calculateWitness(input);
            const witness2 = await circuit.calculateWitness(input);
            
            expect(witness1[1].toString()).to.equal(witness2[1].toString());
        });
        
        it("should produce different nullifiers for different commitments", async () => {
            const spending_key = "999999999999999999";
            
            const input1 = {
                commitment: "111111",
                spending_key: spending_key
            };
            
            const input2 = {
                commitment: "222222",
                spending_key: spending_key
            };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should produce different nullifiers for different spending_keys", async () => {
            const commitment = "555555555555555555";
            
            const input1 = {
                commitment: commitment,
                spending_key: "111111"
            };
            
            const input2 = {
                commitment: commitment,
                spending_key: "222222"
            };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should handle zero commitment", async () => {
            const input = {
                commitment: "0",
                spending_key: "123456"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const expectedNullifier = F.toString(poseidon([0n, 123456n]));
            expect(witness[1].toString()).to.equal(expectedNullifier);
        });
        
        it("should handle zero spending_key", async () => {
            const input = {
                commitment: "123456",
                spending_key: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const expectedNullifier = F.toString(poseidon([123456n, 0n]));
            expect(witness[1].toString()).to.equal(expectedNullifier);
        });
        
        it("should provide unlinkability (same commitment, different keys)", async () => {
            // This is the privacy property: observers can't link nullifiers
            // to the same commitment if spending keys are different
            const commitment = "777777777777777777";
            
            const input1 = {
                commitment: commitment,
                spending_key: "111111111111111111"
            };
            
            const input2 = {
                commitment: commitment,
                spending_key: "222222222222222222"
            };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            // Nullifiers should be completely different
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
            
            // And there should be no obvious relationship
            const nullifier1 = BigInt(witness1[1].toString());
            const nullifier2 = BigInt(witness2[1].toString());
            const diff = nullifier1 > nullifier2 ? nullifier1 - nullifier2 : nullifier2 - nullifier1;
            
            // Difference should not be a simple increment
            expect(diff).to.not.equal(1n);
            expect(diff).to.not.equal(111111111111111111n); // Not just key difference
        });
    });
    
    describe("Integration: NoteCommitment -> Nullifier", () => {
        let commitmentCircuit: WasmTester;
        let nullifierCircuit: WasmTester;
        
        before(async function() {
            const noteCommitmentCircuit = `
                pragma circom 2.0.0;
                include "../circuits/note.circom";
                component main = NoteCommitment();
            `;
            
            const nullifierTestCircuit = `
                pragma circom 2.0.0;
                include "../circuits/note.circom";
                component main = Nullifier();
            `;
            
            const fs = require('fs');
            const commitmentPath = path.join(__dirname, "..", "build", "test_note_commitment.circom");
            const nullifierPath = path.join(__dirname, "..", "build", "test_nullifier.circom");
            
            fs.writeFileSync(commitmentPath, noteCommitmentCircuit);
            fs.writeFileSync(nullifierPath, nullifierTestCircuit);
            
            commitmentCircuit = await wasm_tester(commitmentPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
            
            nullifierCircuit = await wasm_tester(nullifierPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should create commitment and then nullifier", async () => {
            // Step 1: Create note commitment
            const noteInput = {
                value: "1000",
                asset_id: "0",
                owner_pubkey: "12345678901234567890",
                blinding: "99999999999999999999"
            };
            
            const commitmentWitness = await commitmentCircuit.calculateWitness(noteInput);
            const commitment = commitmentWitness[1].toString();
            
            console.log("   Created commitment:", commitment.slice(0, 20) + "...");
            
            // Step 2: Create nullifier from commitment
            const spending_key = "88888888888888888888";
            const nullifierInput = {
                commitment: commitment,
                spending_key: spending_key
            };
            
            const nullifierWitness = await nullifierCircuit.calculateWitness(nullifierInput);
            const nullifier = nullifierWitness[1].toString();
            
            console.log("   Created nullifier:", nullifier.slice(0, 20) + "...");
            
            // Verify nullifier is different from commitment
            expect(nullifier).to.not.equal(commitment);
            
            // Verify nullifier matches expected hash
            const expectedNullifier = F.toString(
                poseidon([BigInt(commitment), BigInt(spending_key)])
            );
            expect(nullifier).to.equal(expectedNullifier);
        });
    });
});
