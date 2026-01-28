#!/usr/bin/env ts-node
/**
 * EdDSA Signature Generator Helper
 *
 * Called from Rust to generate EdDSA signatures for circuit inputs.
 * This avoids reimplementing EdDSA in Rust and reuses circomlibjs.
 *
 * Input (stdin): JSON with { privateKey: "hex", messages: ["bigint", ...] }
 * Output (stdout): JSON with { signatures: [{ R8x, R8y, S, Ax, Ay }, ...] }
 */

import { buildEddsa, buildBabyjub } from 'circomlibjs';

interface SignatureRequest {
  privateKey: string;
  messages: string[];
}

interface Signature {
  R8x: string;
  R8y: string;
  S: string;
  Ax: string;
  Ay: string;
}

interface SignatureResponse {
  success: boolean;
  publicKey: { Ax: string; Ay: string };
  signatures: Signature[];
}

async function main(): Promise<void> {
  try {
    // Read input from stdin
    let input = '';
    for await (const chunk of process.stdin) {
      input += chunk;
    }

    if (!input) {
      throw new Error('No input provided on stdin');
    }

    const request: SignatureRequest = JSON.parse(input);
    const { privateKey, messages } = request;

    if (!privateKey) {
      throw new Error('Missing "privateKey" in input');
    }
    if (!messages || !Array.isArray(messages)) {
      throw new Error('Missing or invalid "messages" array in input');
    }

    // Initialize EdDSA
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();
    const F = babyJub.F;

    // Convert privateKey hex to buffer
    const prvKey = Buffer.from(privateKey, 'hex');
    if (prvKey.length !== 32) {
      throw new Error('Private key must be exactly 32 bytes');
    }

    // Derive public key
    const pubKey = eddsa.prv2pub(prvKey);
    const Ax = F.toString(pubKey[0]);
    const Ay = F.toString(pubKey[1]);

    // Generate signatures for each message
    const signatures: Signature[] = [];

    for (const msgStr of messages) {
      // Convert message string to field element
      const msg = F.e(BigInt(msgStr));

      // Sign with EdDSA Poseidon
      const sig = eddsa.signPoseidon(prvKey, msg);

      signatures.push({
        R8x: F.toString(sig.R8[0]),
        R8y: F.toString(sig.R8[1]),
        S: sig.S.toString(),
        Ax: Ax,  // Include public key for convenience
        Ay: Ay
      });
    }

    // Return success response
    const response: SignatureResponse = {
      success: true,
      publicKey: { Ax, Ay },
      signatures
    };

    console.log(JSON.stringify(response));
    process.exit(0);

  } catch (error) {
    // Return error response
    const errorResponse = {
      success: false,
      error: error instanceof Error ? error.message : String(error)
    };
    console.error(JSON.stringify(errorResponse));
    process.exit(1);
  }
}

main();
