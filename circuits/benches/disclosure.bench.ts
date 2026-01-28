#!/usr/bin/env ts-node
/**
 * Disclosure Circuit Benchmarks
 *
 * Measures performance of disclosure proof generation and verification
 */

import { performance } from 'perf_hooks';
import * as fs from 'fs';
import * as path from 'path';
import * as snarkjs from 'snarkjs';
import { CircuitBenchmarkResults, CircuitInfo, BenchmarkResult } from './types';
import { calculateStats, getSystemInfo, printResults, warmUp } from './utils';

const CIRCUIT_NAME = 'disclosure';
const BENCHMARK_ITERATIONS = 10;
const WARMUP_ITERATIONS = 3;

// Paths
const BUILD_DIR = path.join(__dirname, '../build');
const KEYS_DIR = path.join(__dirname, '../keys');
const WASM_PATH = path.join(BUILD_DIR, `${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm`);
const ZKEY_PATH = path.join(KEYS_DIR, `${CIRCUIT_NAME}_pk.zkey`);
const VK_PATH = path.join(BUILD_DIR, `verification_key_${CIRCUIT_NAME}.json`);

/**
 * Load pre-generated test witness data
 */
function loadTestWitness(): any {
    // Try different input files in order of preference
    const inputFiles = [
        'disclosure_input_reveal_all.json',
        'disclosure_input_reveal_value_and_asset.json',
        'disclosure_input_reveal_value_only.json',
        'disclosure_input_reveal_nothing.json',
        'disclosure_input.json' // legacy fallback
    ];

    for (const filename of inputFiles) {
        const inputPath = path.join(BUILD_DIR, filename);
        if (fs.existsSync(inputPath)) {
            return JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
        }
    }

    throw new Error(
        'Missing disclosure input files - Run circuit setup first to generate valid witness data.\n' +
        'Execute: npm run gen-input:disclosure'
    );
}

/**
 * Benchmark witness generation
 */
async function benchmarkWitnessGeneration(iterations: number = BENCHMARK_ITERATIONS): Promise<BenchmarkResult> {
    console.log(`\n📊 Benchmarking Witness Generation (${iterations} iterations)...`);

    // Warm-up
    await warmUp(() => Promise.resolve(loadTestWitness()), WARMUP_ITERATIONS);

    const times: number[] = [];
    const memUsages: number[] = [];

    for (let i = 0; i < iterations; i++) {
        const memBefore = process.memoryUsage();
        const start = performance.now();

        loadTestWitness();

        const end = performance.now();
        const memAfter = process.memoryUsage();

        times.push(end - start);
        memUsages.push((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024);
    }

    const results = calculateStats(times, memUsages);
    printResults(results, 'Witness Generation');
    return results;
}

/**
 * Benchmark proof generation
 */
async function benchmarkProofGeneration(iterations: number = BENCHMARK_ITERATIONS): Promise<BenchmarkResult | null> {
    console.log(`\n📊 Benchmarking Proof Generation (${iterations} iterations)...`);

    if (!fs.existsSync(WASM_PATH)) {
        console.error(`❌ WASM file not found: ${WASM_PATH}`);
        return null;
    }
    if (!fs.existsSync(ZKEY_PATH)) {
        console.error(`❌ ZKey file not found: ${ZKEY_PATH}`);
        return null;
    }

    const witness = loadTestWitness();
    
    // Warm-up
    await warmUp(async () => {
        await snarkjs.groth16.fullProve(witness, WASM_PATH, ZKEY_PATH);
    }, WARMUP_ITERATIONS);

    const times: number[] = [];
    const memUsages: number[] = [];

    for (let i = 0; i < iterations; i++) {
        const memBefore = process.memoryUsage();
        const start = performance.now();

        try {
            await snarkjs.groth16.fullProve(witness, WASM_PATH, ZKEY_PATH);

            const end = performance.now();
            const memAfter = process.memoryUsage();

            times.push(end - start);
            memUsages.push((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024);
        } catch (error) {
            console.error(`❌ Proof generation failed: ${(error as Error).message}`);
            return null;
        }
    }

    const results = calculateStats(times, memUsages);
    printResults(results, 'Proof Generation');
    return results;
}

/**
 * Benchmark proof verification
 */
async function benchmarkProofVerification(iterations: number = BENCHMARK_ITERATIONS * 10): Promise<BenchmarkResult | null> {
    console.log(`\n📊 Benchmarking Proof Verification (${iterations} iterations)...`);

    if (!fs.existsSync(VK_PATH)) {
        console.error(`❌ Verification key not found: ${VK_PATH}`);
        return null;
    }

    // Generate one proof for verification
    const witness = loadTestWitness();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(witness, WASM_PATH, ZKEY_PATH);
    const vKey = JSON.parse(fs.readFileSync(VK_PATH, 'utf-8'));

    // Warm-up
    await warmUp(async () => {
        await snarkjs.groth16.verify(vKey, publicSignals, proof);
    }, WARMUP_ITERATIONS);

    const times: number[] = [];

    for (let i = 0; i < iterations; i++) {
        const start = performance.now();

        const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);

        const end = performance.now();
        times.push(end - start);

        if (!isValid) {
            console.error('❌ Proof verification failed!');
            return null;
        }
    }

    const results = calculateStats(times);
    printResults(results, 'Proof Verification');
    return results;
}

/**
 * Get circuit constraint count
 */
async function getCircuitInfo(): Promise<CircuitInfo | null> {
    const r1csPath = path.join(BUILD_DIR, `${CIRCUIT_NAME}.r1cs`);
    if (!fs.existsSync(r1csPath)) {
        console.warn('⚠️  R1CS file not found');
        return null;
    }

    try {
        const r1cs: any = await snarkjs.r1cs.info(r1csPath);
        return {
            constraints: r1cs.nConstraints,
            privateInputs: r1cs.nPrvInputs,
            publicInputs: r1cs.nPubInputs,
            labels: r1cs.nLabels,
            outputs: r1cs.nOutputs
        };
    } catch (error) {
        console.error(`❌ Failed to read R1CS info: ${(error as Error).message}`);
        return null;
    }
}

/**
 * Run all benchmarks
 */
export async function runAllBenchmarks(): Promise<CircuitBenchmarkResults> {
    console.log('🚀 Starting Disclosure Circuit Benchmarks\n');
    console.log('='.repeat(60));

    // Circuit info
    console.log('\n📋 Circuit Information:');
    const info = await getCircuitInfo();
    if (info) {
        console.log(`  Constraints:     ${info.constraints.toLocaleString()}`);
        console.log(`  Private Inputs:  ${info.privateInputs}`);
        console.log(`  Public Inputs:   ${info.publicInputs}`);
        console.log(`  Labels:          ${info.labels.toLocaleString()}`);
    }

    // Run benchmarks
    const results: CircuitBenchmarkResults = {
        circuit: CIRCUIT_NAME,
        timestamp: new Date().toISOString(),
        system: getSystemInfo(),
        circuitInfo: info,
        benchmarks: {
            witnessGeneration: null,
            proofGeneration: null,
            proofVerification: null
        }
    };

    results.benchmarks.witnessGeneration = await benchmarkWitnessGeneration();
    results.benchmarks.proofGeneration = await benchmarkProofGeneration();
    results.benchmarks.proofVerification = await benchmarkProofVerification();

    // Save results
    const resultsPath = path.join(BUILD_DIR, 'benchmark_results_disclosure.json');
    fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));

    console.log('\n' + '='.repeat(60));
    console.log(`✅ Benchmarks complete! Results saved to:`);
    console.log(`   ${resultsPath}\n`);

    return results;
}

// Run if called directly
if (require.main === module) {
    runAllBenchmarks()
        .then(() => process.exit(0))
        .catch(error => {
            console.error('❌ Benchmark failed:', error);
            process.exit(1);
        });
}
