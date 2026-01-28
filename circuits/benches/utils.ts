/**
 * Benchmark utilities for circuit performance testing
 */

import * as os from 'os';
import { SystemInfo, BenchmarkResult } from './types';

/**
 * Calculate statistics from timing measurements
 */
export function calculateStats(times: number[], memUsages?: number[]): BenchmarkResult {
    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);

    // Calculate standard deviation
    const variance = times.reduce((sum, time) => sum + Math.pow(time - avgTime, 2), 0) / times.length;
    const stdDev = Math.sqrt(variance);

    const result: BenchmarkResult = {
        avgTime,
        minTime,
        maxTime,
        stdDev,
        throughput: 1000 / avgTime // operations per second
    };

    if (memUsages && memUsages.length > 0) {
        result.avgMem = memUsages.reduce((a, b) => a + b, 0) / memUsages.length;
    }

    return result;
}

/**
 * Get system information
 */
export function getSystemInfo(): SystemInfo {
    const cpus = os.cpus();
    return {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        cpuModel: cpus[0].model,
        cpuCount: cpus.length,
        totalMemory: `${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB`
    };
}

/**
 * Format time in human-readable format
 */
export function formatTime(ms: number): string {
    if (ms < 1) return `${(ms * 1000).toFixed(2)} μs`;
    if (ms < 1000) return `${ms.toFixed(2)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}

/**
 * Format memory in human-readable format
 */
export function formatMemory(mb: number): string {
    if (mb < 1) return `${(mb * 1024).toFixed(2)} KB`;
    if (mb < 1024) return `${mb.toFixed(2)} MB`;
    return `${(mb / 1024).toFixed(2)} GB`;
}

/**
 * Print benchmark results in a formatted table
 */
export function printResults(results: BenchmarkResult, label: string): void {
    console.log(`  ${label}:`);
    console.log(`    Average:    ${formatTime(results.avgTime)}`);
    console.log(`    Min:        ${formatTime(results.minTime)}`);
    console.log(`    Max:        ${formatTime(results.maxTime)}`);
    console.log(`    Std Dev:    ${formatTime(results.stdDev)}`);
    console.log(`    Throughput: ${results.throughput?.toFixed(2)} ops/sec`);
    if (results.avgMem !== undefined) {
        console.log(`    Memory:     ${formatMemory(results.avgMem)}`);
    }
}

/**
 * Warm-up function to stabilize JIT compilation
 */
export async function warmUp<T>(fn: () => Promise<T>, iterations: number = 3): Promise<void> {
    console.log(`  Warming up (${iterations} iterations)...`);
    for (let i = 0; i < iterations; i++) {
        await fn();
    }
}
