import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { buildPoseidon } from 'circomlibjs';
import { expect } from 'chai';
import type { WasmTester } from 'circom_tester';

describe("Poseidon Wrapper Circuit Components", function() {
    this.timeout(120000);
    
    let poseidon: any;
    let F: any;
    
    before(async function() {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });
    
    describe("Poseidon2 Template", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const poseidon2Circuit = `
                pragma circom 2.0.0;
                include "../circuits/poseidon_wrapper.circom";
                component main = Poseidon2();
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_poseidon2.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, poseidon2Circuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should compute Poseidon hash with 2 inputs", async () => {
            const input1 = 100n;
            const input2 = 200n;
            
            const expectedHash = F.toString(poseidon([input1, input2]));
            
            const input = {
                inputs: [input1.toString(), input2.toString()]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const output = witness[1];
            expect(output.toString()).to.equal(expectedHash);
        });
        
        it("should be deterministic", async () => {
            const input = {
                inputs: ["123", "456"]
            };
            
            const witness1 = await circuit.calculateWitness(input);
            const witness2 = await circuit.calculateWitness(input);
            
            expect(witness1[1].toString()).to.equal(witness2[1].toString());
        });
        
        it("should produce different hashes for different inputs", async () => {
            const input1 = {
                inputs: ["100", "200"]
            };
            
            const input2 = {
                inputs: ["100", "300"]
            };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should handle zero inputs", async () => {
            const input = {
                inputs: ["0", "0"]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const expectedHash = F.toString(poseidon([0n, 0n]));
            expect(witness[1].toString()).to.equal(expectedHash);
        });
        
        it("should handle large field elements", async () => {
            const input = {
                inputs: [
                    "123456789012345678901234567890",
                    "987654321098765432109876543210"
                ]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            expect(witness[1]).to.not.equal(0n);
        });
        
        it("should match circomlibjs implementation", async () => {
            const testCases = [
                [1n, 2n],
                [100n, 200n],
                [0n, 1n],
                [999n, 888n],
                [12345678901234567890n, 98765432109876543210n]
            ];
            
            for (const [a, b] of testCases) {
                const input = {
                    inputs: [a.toString(), b.toString()]
                };
                
                const witness = await circuit.calculateWitness(input);
                const circuitHash = witness[1].toString();
                
                const expectedHash = F.toString(poseidon([a, b]));
                
                expect(circuitHash).to.equal(expectedHash, 
                    `Mismatch for inputs [${a}, ${b}]`);
            }
        });
        
        it("should be collision resistant (different inputs, different outputs)", async () => {
            const hashes = new Set<string>();
            
            for (let i = 0; i < 10; i++) {
                const input = {
                    inputs: [i.toString(), (i * 2).toString()]
                };
                
                const witness = await circuit.calculateWitness(input);
                const hash = witness[1].toString();
                
                expect(hashes.has(hash)).to.be.false;
                hashes.add(hash);
            }
            
            expect(hashes.size).to.equal(10);
        });
    });
    
    describe("Poseidon4 Template", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const poseidon4Circuit = `
                pragma circom 2.0.0;
                include "../circuits/poseidon_wrapper.circom";
                component main = Poseidon4();
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_poseidon4.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, poseidon4Circuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should compute Poseidon hash with 4 inputs", async () => {
            const input1 = 100n;
            const input2 = 200n;
            const input3 = 300n;
            const input4 = 400n;
            
            const expectedHash = F.toString(
                poseidon([input1, input2, input3, input4])
            );
            
            const input = {
                inputs: [
                    input1.toString(),
                    input2.toString(),
                    input3.toString(),
                    input4.toString()
                ]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const output = witness[1];
            expect(output.toString()).to.equal(expectedHash);
        });
        
        it("should be deterministic", async () => {
            const input = {
                inputs: ["1", "2", "3", "4"]
            };
            
            const witness1 = await circuit.calculateWitness(input);
            const witness2 = await circuit.calculateWitness(input);
            
            expect(witness1[1].toString()).to.equal(witness2[1].toString());
        });
        
        it("should produce different hashes for different inputs", async () => {
            const input1 = {
                inputs: ["1", "2", "3", "4"]
            };
            
            const input2 = {
                inputs: ["1", "2", "3", "5"]
            };
            
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            
            expect(witness1[1].toString()).to.not.equal(witness2[1].toString());
        });
        
        it("should handle zero inputs", async () => {
            const input = {
                inputs: ["0", "0", "0", "0"]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const expectedHash = F.toString(poseidon([0n, 0n, 0n, 0n]));
            expect(witness[1].toString()).to.equal(expectedHash);
        });
        
        it("should handle mixed zero and non-zero inputs", async () => {
            const testCases = [
                [1n, 0n, 0n, 0n],
                [0n, 1n, 0n, 0n],
                [0n, 0n, 1n, 0n],
                [0n, 0n, 0n, 1n],
                [1n, 2n, 0n, 0n],
                [0n, 0n, 3n, 4n]
            ];
            
            for (const [a, b, c, d] of testCases) {
                const input = {
                    inputs: [a.toString(), b.toString(), c.toString(), d.toString()]
                };
                
                const witness = await circuit.calculateWitness(input);
                const circuitHash = witness[1].toString();
                
                const expectedHash = F.toString(poseidon([a, b, c, d]));
                
                expect(circuitHash).to.equal(expectedHash,
                    `Mismatch for inputs [${a}, ${b}, ${c}, ${d}]`);
            }
        });
        
        it("should match circomlibjs implementation for note commitments", async () => {
            // Simulate note commitment structure: (value, asset_id, owner_pubkey, blinding)
            const testCases = [
                [1000n, 0n, 12345678901234567890n, 99999999999999999999n],
                [5000n, 0n, 777777777777777777n, 888888888888888888n],
                [0n, 0n, 0n, 0n],
                [1n, 1n, 1n, 1n]
            ];
            
            for (const [value, asset_id, owner_pubkey, blinding] of testCases) {
                const input = {
                    inputs: [
                        value.toString(),
                        asset_id.toString(),
                        owner_pubkey.toString(),
                        blinding.toString()
                    ]
                };
                
                const witness = await circuit.calculateWitness(input);
                const circuitHash = witness[1].toString();
                
                const expectedHash = F.toString(
                    poseidon([value, asset_id, owner_pubkey, blinding])
                );
                
                expect(circuitHash).to.equal(expectedHash,
                    `Mismatch for note commitment [${value}, ${asset_id}, ${owner_pubkey}, ${blinding}]`);
            }
        });
        
        it("should be collision resistant", async () => {
            const hashes = new Set<string>();
            
            for (let i = 0; i < 10; i++) {
                const input = {
                    inputs: [
                        i.toString(),
                        (i * 2).toString(),
                        (i * 3).toString(),
                        (i * 4).toString()
                    ]
                };
                
                const witness = await circuit.calculateWitness(input);
                const hash = witness[1].toString();
                
                expect(hashes.has(hash)).to.be.false;
                hashes.add(hash);
            }
            
            expect(hashes.size).to.equal(10);
        });
        
        it("should produce different hashes when inputs are permuted", async () => {
            const baseInputs = ["1", "2", "3", "4"];
            
            const permutations = [
                ["1", "2", "3", "4"],
                ["4", "3", "2", "1"],
                ["2", "1", "4", "3"],
                ["3", "4", "1", "2"]
            ];
            
            const hashes = new Set<string>();
            
            for (const perm of permutations) {
                const input = { inputs: perm };
                const witness = await circuit.calculateWitness(input);
                hashes.add(witness[1].toString());
            }
            
            // All permutations should produce different hashes
            expect(hashes.size).to.equal(permutations.length);
        });
    });
    
    describe("Poseidon2 vs Poseidon4 Comparison", () => {
        let circuit2: WasmTester;
        let circuit4: WasmTester;
        
        before(async function() {
            const poseidon2Circuit = `
                pragma circom 2.0.0;
                include "../circuits/poseidon_wrapper.circom";
                component main = Poseidon2();
            `;
            
            const poseidon4Circuit = `
                pragma circom 2.0.0;
                include "../circuits/poseidon_wrapper.circom";
                component main = Poseidon4();
            `;
            
            const fs = require('fs');
            const path2 = path.join(__dirname, "..", "build", "test_poseidon2.circom");
            const path4 = path.join(__dirname, "..", "build", "test_poseidon4.circom");
            
            fs.writeFileSync(path2, poseidon2Circuit);
            fs.writeFileSync(path4, poseidon4Circuit);
            
            circuit2 = await wasm_tester(path2, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
            
            circuit4 = await wasm_tester(path4, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should produce different hashes for same prefix values", async () => {
            // Hash2([1, 2]) should differ from Hash4([1, 2, 0, 0])
            const input2 = {
                inputs: ["1", "2"]
            };
            
            const input4 = {
                inputs: ["1", "2", "0", "0"]
            };
            
            const witness2 = await circuit2.calculateWitness(input2);
            const witness4 = await circuit4.calculateWitness(input4);
            
            expect(witness2[1].toString()).to.not.equal(witness4[1].toString());
        });
    });
});
