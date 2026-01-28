/**
 * TypeScript types for circuit benchmarks
 */

export interface BenchmarkResult {
    avgTime: number;
    minTime: number;
    maxTime: number;
    stdDev: number;
    avgMem?: number;
    throughput?: number;
}

export interface CircuitInfo {
    constraints: number;
    privateInputs: number;
    publicInputs: number;
    labels: number;
    outputs: number;
}

export interface SystemInfo {
    platform: string;
    arch: string;
    nodeVersion: string;
    cpuModel: string;
    cpuCount: number;
    totalMemory: string;
}

export interface CircuitBenchmarkResults {
    circuit: string;
    timestamp: string;
    system: SystemInfo;
    circuitInfo: CircuitInfo | null;
    benchmarks: {
        witnessGeneration: BenchmarkResult | null;
        proofGeneration: BenchmarkResult | null;
        proofVerification: BenchmarkResult | null;
    };
}

export interface AggregatedResults {
    timestamp: string;
    system: SystemInfo;
    circuits: {
        [key: string]: {
            constraints: number | string;
            witnessGen: BenchmarkResult | null;
            proofGen: BenchmarkResult | null;
            verification: BenchmarkResult | null;
            error?: string;
        };
    };
}
