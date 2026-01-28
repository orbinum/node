import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { buildPoseidon } from 'circomlibjs';
import { expect } from 'chai';
import type { WasmTester } from 'circom_tester';

describe("Merkle Tree Circuit Components", function() {
    this.timeout(120000);
    
    let poseidon: any;
    let F: any;
    
    before(async function() {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });
    
    describe("Selector Template", () => {
        let circuit: WasmTester;
        
        before(async function() {
            // Create a simple test circuit for Selector
            const selectorCircuit = `
                pragma circom 2.0.0;
                
                template Selector() {
                    signal input in[2];
                    signal input s;
                    signal output out;
                    
                    out <== (in[1] - in[0]) * s + in[0];
                }
                
                component main = Selector();
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_selector.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, selectorCircuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should select first input when s=0", async () => {
            const input = {
                in: ["100", "200"],
                s: "0"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const output = witness[1]; // Index 1 is the output signal
            expect(output.toString()).to.equal("100");
        });
        
        it("should select second input when s=1", async () => {
            const input = {
                in: ["100", "200"],
                s: "1"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const output = witness[1];
            expect(output.toString()).to.equal("200");
        });
        
        it("should work with large field elements", async () => {
            const input = {
                in: [
                    "123456789012345678901234567890",
                    "987654321098765432109876543210"
                ],
                s: "1"
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const output = witness[1];
            expect(output.toString()).to.equal("987654321098765432109876543210");
        });
    });
    
    describe("MerkleTreeVerifier - Depth 2", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const merkleCircuit = `
                pragma circom 2.0.0;
                include "../circuits/merkle_tree.circom";
                component main = MerkleTreeVerifier(2);
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_merkle_2.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, merkleCircuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should verify leaf at index 0 (left-left)", async () => {
            // Tree structure (depth 2):
            //         root
            //        /    \
            //      h01    h23
            //     /  \   /  \
            //    l0  l1 l2  l3
            
            const l0 = 1111n;
            const l1 = 2222n;
            const l2 = 3333n;
            const l3 = 4444n;
            
            const h01 = F.toString(poseidon([l0, l1]));
            const h23 = F.toString(poseidon([l2, l3]));
            const root = F.toString(poseidon([BigInt(h01), BigInt(h23)]));
            
            // Path for l0: sibling l1, then sibling h23
            // l0 is LEFT at level 0 (index=0)
            // h01 is LEFT at level 1 (index=0)
            const input = {
                leaf: l0.toString(),
                path_elements: [l1.toString(), h23],
                path_index: [0, 0]  // 0 = left child
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(root);
        });
        
        it("should verify leaf at index 1 (left-right)", async () => {
            const l0 = 1111n;
            const l1 = 2222n;
            const l2 = 3333n;
            const l3 = 4444n;
            
            const h01 = F.toString(poseidon([l0, l1]));
            const h23 = F.toString(poseidon([l2, l3]));
            const root = F.toString(poseidon([BigInt(h01), BigInt(h23)]));
            
            // Path for l1: sibling l0, then sibling h23
            // l1 is RIGHT at level 0 (index=1)
            // h01 is LEFT at level 1 (index=0)
            const input = {
                leaf: l1.toString(),
                path_elements: [l0.toString(), h23],
                path_index: [1, 0]  // 1 = right child
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(root);
        });
        
        it("should verify leaf at index 2 (right-left)", async () => {
            const l0 = 1111n;
            const l1 = 2222n;
            const l2 = 3333n;
            const l3 = 4444n;
            
            const h01 = F.toString(poseidon([l0, l1]));
            const h23 = F.toString(poseidon([l2, l3]));
            const root = F.toString(poseidon([BigInt(h01), BigInt(h23)]));
            
            // Path for l2: sibling l3, then sibling h01
            // l2 is LEFT at level 0 (index=0)
            // h23 is RIGHT at level 1 (index=1)
            const input = {
                leaf: l2.toString(),
                path_elements: [l3.toString(), h01],
                path_index: [0, 1]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(root);
        });
        
        it("should verify leaf at index 3 (right-right)", async () => {
            const l0 = 1111n;
            const l1 = 2222n;
            const l2 = 3333n;
            const l3 = 4444n;
            
            const h01 = F.toString(poseidon([l0, l1]));
            const h23 = F.toString(poseidon([l2, l3]));
            const root = F.toString(poseidon([BigInt(h01), BigInt(h23)]));
            
            // Path for l3: sibling l2, then sibling h01
            // l3 is RIGHT at level 0 (index=1)
            // h23 is RIGHT at level 1 (index=1)
            const input = {
                leaf: l3.toString(),
                path_elements: [l2.toString(), h01],
                path_index: [1, 1]
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(root);
        });
    });
    
    describe("MerkleTreeVerifier - Depth 4", () => {
        let circuit: WasmTester;
        
        before(async function() {
            const merkleCircuit = `
                pragma circom 2.0.0;
                include "../circuits/merkle_tree.circom";
                component main = MerkleTreeVerifier(4);
            `;
            
            const tempCircuitPath = path.join(__dirname, "..", "build", "test_merkle_4.circom");
            const fs = require('fs');
            fs.writeFileSync(tempCircuitPath, merkleCircuit);
            
            circuit = await wasm_tester(tempCircuitPath, { 
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });
        });
        
        it("should verify deep merkle path", async () => {
            // Build a simple tree with depth 4
            const leaf = 12345n;
            
            // Path with zero siblings
            const zero = 0n;
            const pathElements: string[] = [];
            const pathIndices: number[] = [];
            
            let currentHash = leaf;
            for (let i = 0; i < 4; i++) {
                pathElements.push(zero.toString());
                pathIndices.push(0); // Always left
                currentHash = BigInt(F.toString(poseidon([currentHash, zero])));
            }
            
            const expectedRoot = currentHash.toString();
            
            const input = {
                leaf: leaf.toString(),
                path_elements: pathElements,
                path_index: pathIndices
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(expectedRoot);
        });
        
        it("should verify alternating left-right path", async () => {
            const leaf = 99999n;
            const sibling1 = 11111n;
            const sibling2 = 22222n;
            const sibling3 = 33333n;
            const sibling4 = 44444n;
            
            // Alternate between left (0) and right (1)
            const pathIndices = [0, 1, 0, 1];
            
            let currentHash = leaf;
            const siblings = [sibling1, sibling2, sibling3, sibling4];
            
            for (let i = 0; i < 4; i++) {
                if (pathIndices[i] === 0) {
                    // Current is left
                    currentHash = BigInt(F.toString(poseidon([currentHash, siblings[i]])));
                } else {
                    // Current is right
                    currentHash = BigInt(F.toString(poseidon([siblings[i], currentHash])));
                }
            }
            
            const expectedRoot = currentHash.toString();
            
            const input = {
                leaf: leaf.toString(),
                path_elements: siblings.map(s => s.toString()),
                path_index: pathIndices
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const computedRoot = witness[1];
            expect(computedRoot.toString()).to.equal(expectedRoot);
        });
    });
});
