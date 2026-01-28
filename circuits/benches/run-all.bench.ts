#!/usr/bin/env ts-node
/**
 * Run All Circuit Benchmarks
 *
 * Orchestrates running all circuit benchmarks and aggregates results
 */

import * as fs from 'fs';
import * as path from 'path';
import { AggregatedResults } from './types';
import { getSystemInfo } from './utils';

const BUILD_DIR = path.join(__dirname, '../build');
const TIMEOUT_MS = 120000; // 2 minutes per circuit

/**
 * Run all circuit benchmarks and aggregate results
 */
async function runAllBenchmarks(): Promise<void> {
    console.log('🚀 Running Complete Circuit Benchmark Suite\n');
    console.log('='.repeat(70));

    const aggregatedResults: AggregatedResults = {
        timestamp: new Date().toISOString(),
        system: getSystemInfo(),
        circuits: {}
    };

    // System info
    console.log('\n💻 System Information:');
    console.log(`  Platform:    ${aggregatedResults.system.platform}`);
    console.log(`  Architecture:  ${aggregatedResults.system.arch}`);
    console.log(`  Node Version: ${aggregatedResults.system.nodeVersion}`);
    console.log(`  CPU:          ${aggregatedResults.system.cpuModel}`);
    console.log(`  CPU Cores:    ${aggregatedResults.system.cpuCount}`);
    console.log(`  Total Memory: ${aggregatedResults.system.totalMemory}`);

    // Run Transfer benchmarks
    try {
        console.log('\n\n📦 TRANSFER CIRCUIT');
        console.log('='.repeat(70));
        
        const transferBench = await import('./transfer.bench');
        const transferResults = await Promise.race([
            transferBench.runAllBenchmarks(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Transfer benchmark timeout')), TIMEOUT_MS)
            )
        ]) as any;

        aggregatedResults.circuits.transfer = {
            constraints: transferResults.circuitInfo?.constraints || 'N/A',
            witnessGen: transferResults.benchmarks?.witnessGeneration || null,
            proofGen: transferResults.benchmarks?.proofGeneration || null,
            verification: transferResults.benchmarks?.proofVerification || null
        };
    } catch (error) {
        console.error(`❌ Transfer benchmark failed: ${(error as Error).message}`);
        aggregatedResults.circuits.transfer = {
            constraints: 'N/A',
            witnessGen: null,
            proofGen: null,
            verification: null,
            error: (error as Error).message
        };
    }

    // Run Disclosure benchmarks
    try {
        console.log('\n\n📦 DISCLOSURE CIRCUIT');
        console.log('='.repeat(70));
        
        const disclosureBench = await import('./disclosure.bench');
        const disclosureResults = await Promise.race([
            disclosureBench.runAllBenchmarks(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Disclosure benchmark timeout')), TIMEOUT_MS)
            )
        ]) as any;

        aggregatedResults.circuits.disclosure = {
            constraints: disclosureResults.circuitInfo?.constraints || 'N/A',
            witnessGen: disclosureResults.benchmarks?.witnessGeneration || null,
            proofGen: disclosureResults.benchmarks?.proofGeneration || null,
            verification: disclosureResults.benchmarks?.proofVerification || null
        };
    } catch (error) {
        console.error(`❌ Disclosure benchmark failed: ${(error as Error).message}`);
        aggregatedResults.circuits.disclosure = {
            constraints: 'N/A',
            witnessGen: null,
            proofGen: null,
            verification: null,
            error: (error as Error).message
        };
    }

    // Save aggregated results
    const aggregatedPath = path.join(BUILD_DIR, 'benchmark_results_all.json');
    fs.writeFileSync(aggregatedPath, JSON.stringify(aggregatedResults, null, 2));

    // Print summary
    console.log('\n\n' + '='.repeat(70));
    console.log('📊 BENCHMARK SUMMARY');
    console.log('='.repeat(70));

    for (const [name, results] of Object.entries(aggregatedResults.circuits)) {
        console.log(`\n${name.toUpperCase()} Circuit:`);
        console.log(`  Constraints: ${typeof results.constraints === 'number' ? results.constraints.toLocaleString() : results.constraints}`);
        
        if (results.error) {
            console.log(`  ❌ Error: ${results.error}`);
            continue;
        }

        if (results.witnessGen) {
            console.log(`  Witness Gen:   ${results.witnessGen.avgTime.toFixed(2)} ms (avg)`);
        }
        if (results.proofGen) {
            console.log(`  Proof Gen:     ${results.proofGen.avgTime.toFixed(2)} ms (avg)`);
        }
        if (results.verification) {
            console.log(`  Verification:  ${results.verification.avgTime.toFixed(2)} ms (avg)`);
        }
    }

    console.log('\n' + '='.repeat(70));
    console.log(`✅ All benchmarks complete! Results saved to:`);
    console.log(`   ${aggregatedPath}`);
    console.log('='.repeat(70) + '\n');
}

// Run if called directly
if (require.main === module) {
    runAllBenchmarks()
        .then(() => process.exit(0))
        .catch(error => {
            console.error('❌ Benchmark suite failed:', error);
            process.exit(1);
        });
}

export { runAllBenchmarks };
