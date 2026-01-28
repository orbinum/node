#!/usr/bin/env ts-node

/**
 * Proof Generation Wrapper
 *
 * Generates Groth16 proofs for Orbinum circuits
 * Called from Rust via child_process
 *
 * Input: JSON stdin with { witness, circuitName }
 * Output: JSON stdout with { proof: [hex bytes], publicSignals, error? }
 */

import * as fs from 'fs';
import * as path from 'path';
import * as snarkjs from 'snarkjs';

interface ProofRequest {
    witness: Record<string, string>;
    circuitName: string;
}

interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
}

interface ErrorResponse {
    error: string;
    code: string;
    stack?: string;
}

interface SuccessResponse {
    success: boolean;
    proof: string;
    publicSignals: string[];
    circuitName: string;
}

async function main(): Promise<void> {
    try {
        // Read input from stdin
        let input = '';
        process.stdin.setEncoding('utf8');

        for await (const chunk of process.stdin) {
            input += chunk;
        }

        if (!input) {
            const errorResponse: ErrorResponse = {
                error: 'No input provided on stdin',
                code: 'EMPTY_INPUT'
            };
            console.error(JSON.stringify(errorResponse));
            process.exit(1);
        }

        let request: ProofRequest;
        try {
            request = JSON.parse(input);
        } catch (e) {
            const error = e as Error;
            const errorResponse: ErrorResponse = {
                error: 'Invalid JSON input: ' + error.message,
                code: 'INVALID_JSON'
            };
            console.error(JSON.stringify(errorResponse));
            process.exit(1);
        }

        const { witness, circuitName } = request;

        if (!witness) {
            const errorResponse: ErrorResponse = {
                error: 'Missing "witness" in input',
                code: 'MISSING_WITNESS'
            };
            console.error(JSON.stringify(errorResponse));
            process.exit(1);
        }

        if (!circuitName) {
            const errorResponse: ErrorResponse = {
                error: 'Missing "circuitName" in input',
                code: 'MISSING_CIRCUIT'
            };
            console.error(JSON.stringify(errorResponse));
            process.exit(1);
        }

        // Paths to circuit files
        const wasmPath = path.join(__dirname, `../build/${circuitName}_js/${circuitName}.wasm`);
        const zkeyPath = path.join(__dirname, `../build/${circuitName}_final.zkey`);

        // Verify files exist
        if (!fs.existsSync(wasmPath)) {
            throw new Error(`WASM file not found: ${wasmPath}`);
        }
        if (!fs.existsSync(zkeyPath)) {
            throw new Error(`zkey file not found: ${zkeyPath}`);
        }

        // Generate proof
        console.error(`[DEBUG] Generating proof for circuit: ${circuitName}`);
        console.error(`[DEBUG] Using WASM: ${wasmPath}`);
        console.error(`[DEBUG] Using zkey: ${zkeyPath}`);

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            witness,
            wasmPath,
            zkeyPath
        );

        // Convert proof to hex format (Groth16 proof structure)
        const proofHex = convertProofToHex(proof as Groth16Proof);

        // Return success response
        const response: SuccessResponse = {
            success: true,
            proof: proofHex,
            publicSignals: publicSignals as string[],
            circuitName: circuitName
        };

        console.log(JSON.stringify(response));
        process.exit(0);

    } catch (error) {
        const err = error as Error;
        const errorResponse: ErrorResponse = {
            error: err.message,
            code: 'PROOF_GENERATION_FAILED',
            stack: err.stack
        };
        console.error(JSON.stringify(errorResponse));
        process.exit(1);
    }
}

/**
 * Convert snarkjs proof object to hex string
 * Groth16 proof format: 2 group elements (A, B) + 1 field element (C)
 * Total: 48 + 96 + 32 = 176 bytes → 352 hex chars
 * But for compatibility, pad to 256 bytes (512 hex chars)
 */
function convertProofToHex(proof: Groth16Proof): string {
    // Groth16 proof contains:
    // - A (G1 point): 2 field elements = 64 bytes
    // - B (G2 point): 4 field elements = 128 bytes
    // - C (G1 point): 2 field elements = 64 bytes
    // Total: 256 bytes

    try {
        // Convert proof point coordinates to hex
        let proofHex = '';

        // A point (2 coordinates)
        proofHex += BigInt(proof.pi_a[0]).toString(16).padStart(64, '0');
        proofHex += BigInt(proof.pi_a[1]).toString(16).padStart(64, '0');

        // B point (4 coordinates for G2)
        proofHex += BigInt(proof.pi_b[0][1]).toString(16).padStart(64, '0');
        proofHex += BigInt(proof.pi_b[0][0]).toString(16).padStart(64, '0');
        proofHex += BigInt(proof.pi_b[1][1]).toString(16).padStart(64, '0');
        proofHex += BigInt(proof.pi_b[1][0]).toString(16).padStart(64, '0');

        // C point (2 coordinates)
        proofHex += BigInt(proof.pi_c[0]).toString(16).padStart(64, '0');
        proofHex += BigInt(proof.pi_c[1]).toString(16).padStart(64, '0');

        return proofHex;
    } catch (error) {
        const err = error as Error;
        console.error(`[ERROR] Failed to convert proof to hex: ${err.message}`);
        throw new Error('Proof conversion failed: ' + err.message);
    }
}

main();
