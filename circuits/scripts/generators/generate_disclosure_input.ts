#!/usr/bin/env ts-node
/**
 * Generate valid input.json for disclosure circuit testing
 * 
 * The disclosure circuit proves selective revelation of memo fields
 * without revealing the complete memo data.
 */

import { buildPoseidon } from 'circomlibjs';
import * as fs from 'fs';
import * as path from 'path';

interface Memo {
    value: bigint;
    asset_id: bigint;
    owner_pubkey: bigint;
    blinding: bigint;
}

interface Scenario {
    disclose_value: bigint;
    disclose_asset_id: bigint;
    disclose_owner: bigint;
    revealed_value: bigint;
    revealed_asset_id: bigint;
    revealed_owner_hash: bigint;
}

interface CircuitInput {
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

async function main(): Promise<void> {
    console.log("=== Disclosure Circuit Input Generator ===\n");

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    console.log("1. Creating memo data...");

    // Private memo data (known only to owner)
    const memo: Memo = {
        value: 1000n,              // 1000 tokens
        asset_id: 0n,              // Native asset (enforced by circuit)
        owner_pubkey: 12345678901234567890n,  // Owner's public key
        blinding: 99999999999999999999n       // Random blinding factor
    };

    console.log("   Value:", memo.value);
    console.log("   Asset ID:", memo.asset_id);
    console.log("   Owner Pubkey:", memo.owner_pubkey.toString().slice(0, 20) + "...");

    // Compute commitment
    console.log("\n2. Computing commitment...");
    const commitment_hash = poseidon([
        memo.value,
        memo.asset_id,
        memo.owner_pubkey,
        memo.blinding
    ]);
    const commitment = BigInt(F.toString(commitment_hash));
    console.log("   Commitment:", commitment.toString().slice(0, 20) + "...");

    // Compute viewing key (proves ownership)
    const viewing_key_hash = poseidon([memo.owner_pubkey]);
    const viewing_key = BigInt(F.toString(viewing_key_hash));
    console.log("   Viewing Key:", viewing_key.toString().slice(0, 20) + "...");

    // Disclosure scenarios
    const scenarios: Record<string, Scenario> = {
        // Scenario 1: Reveal nothing (full privacy)
        reveal_nothing: {
            disclose_value: 0n,
            disclose_asset_id: 0n,
            disclose_owner: 0n,
            revealed_value: 0n,
            revealed_asset_id: 0n,
            revealed_owner_hash: 0n
        },
        
        // Scenario 2: Reveal only value
        reveal_value_only: {
            disclose_value: 1n,
            disclose_asset_id: 0n,
            disclose_owner: 0n,
            revealed_value: memo.value,
            revealed_asset_id: 0n,
            revealed_owner_hash: 0n
        },
        
        // Scenario 3: Reveal value and asset
        reveal_value_and_asset: {
            disclose_value: 1n,
            disclose_asset_id: 1n,
            disclose_owner: 0n,
            revealed_value: memo.value,
            revealed_asset_id: memo.asset_id,
            revealed_owner_hash: 0n
        },
        
        // Scenario 4: Reveal everything
        reveal_all: {
            disclose_value: 1n,
            disclose_asset_id: 1n,
            disclose_owner: 1n,
            revealed_value: memo.value,
            revealed_asset_id: memo.asset_id,
            revealed_owner_hash: viewing_key  // Hash of owner
        }
    };

    // Generate input files for each scenario
    console.log("\n3. Generating input files...");
    
    const buildDir = path.join(__dirname, "..", "..", "build");
    if (!fs.existsSync(buildDir)) {
        fs.mkdirSync(buildDir, { recursive: true });
    }

    for (const [name, scenario] of Object.entries(scenarios)) {
        const input: CircuitInput = {
            // Public inputs
            commitment: commitment.toString(),
            revealed_value: scenario.revealed_value.toString(),
            revealed_asset_id: scenario.revealed_asset_id.toString(),
            revealed_owner_hash: scenario.revealed_owner_hash.toString(),
            
            // Private inputs
            value: memo.value.toString(),
            asset_id: memo.asset_id.toString(),
            owner_pubkey: memo.owner_pubkey.toString(),
            blinding: memo.blinding.toString(),
            viewing_key: viewing_key.toString(),
            
            // Disclosure mask
            disclose_value: scenario.disclose_value.toString(),
            disclose_asset_id: scenario.disclose_asset_id.toString(),
            disclose_owner: scenario.disclose_owner.toString()
        };

        const filename = `disclosure_input_${name}.json`;
        const filepath = path.join(buildDir, filename);
        fs.writeFileSync(filepath, JSON.stringify(input, null, 2));
        console.log(`   ✓ Generated: ${filename}`);
    }

    console.log("\n✅ Input generation complete!");
    console.log("\nGenerated scenarios:");
    console.log("  • reveal_nothing: Full privacy (no fields revealed)");
    console.log("  • reveal_value_only: Show amount only");
    console.log("  • reveal_value_and_asset: Show amount + asset type");
    console.log("  • reveal_all: Full disclosure");
    console.log("\nUsage:");
    console.log("  snarkjs wtns calculate \\");
    console.log("    build/disclosure_js/disclosure.wasm \\");
    console.log("    build/disclosure_input_reveal_value_only.json \\");
    console.log("    build/witness.wtns");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error:", error);
        process.exit(1);
    });
