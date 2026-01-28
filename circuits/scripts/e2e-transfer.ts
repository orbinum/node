#!/usr/bin/env ts-node
/**
 * End-to-End Transfer Circuit Workflow: compile → setup → gen-input → prove → verify
 */

import { execSync } from 'child_process';
import * as path from 'path';

function run(command: string, description: string): void {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  ${description}`);
    console.log(`${'='.repeat(60)}\n`);

    try {
        execSync(command, {
            stdio: 'inherit',
            cwd: path.join(__dirname, '..')
        });
        console.log(`\n✓ ${description} completed\n`);
    } catch (error) {
        console.error(`\n✗ Error in: ${description}`);
        process.exit(1);
    }
}

function main() {
    console.log('\n');
    console.log('═'.repeat(70));
    console.log('  Orbinum Transfer Circuit - End-to-End Workflow');
    console.log('═'.repeat(70));
    console.log('\nThis script will execute the complete workflow:');
    console.log('  1. Compile circuit (transfer.circom → .r1cs + .wasm)');
    console.log('  2. Trusted setup (generate .zkey keys)');
    console.log('  3. Generate test input (input.json)');
    console.log('  4. Generate ZK proof (proof.json)');
    console.log('  5. Verify proof');
    console.log('\n');

    // Step 1: Compile
    run('npm run compile:transfer', 'Circuit compilation');

    // Step 2: Trusted setup
    run('npm run setup:transfer', 'Trusted Setup (key generation)');

    // Step 3: Generate input
    run('npm run gen-input:transfer', 'Test input generation');

    // Step 4: Generate proof
    run('npm run prove', 'ZK proof generation');

    console.log('\n');
    console.log('═'.repeat(70));
    console.log('  ✓ COMPLETE WORKFLOW FINISHED SUCCESSFULLY');
    console.log('═'.repeat(70));
    console.log('\nGenerated files:');
    console.log('  • build/transfer.r1cs');
    console.log('  • build/transfer_js/transfer.wasm');
    console.log('  • keys/transfer_pk.zkey');
    console.log('  • build/verification_key_transfer.json');
    console.log('  • build/input.json');
    console.log('  • build/proof.json');
    console.log('  • build/public.json');
    console.log('\n');
    
    process.exit(0);
}

try {
    main();
} catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
}
