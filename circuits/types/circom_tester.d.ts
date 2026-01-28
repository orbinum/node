declare module 'circom_tester' {
    export interface WasmTester {
        calculateWitness(input: Record<string, string | string[] | number[]>, sanityCheck?: boolean): Promise<bigint[]>;
        checkConstraints(witness: bigint[]): Promise<void>;
        loadSymbols(): Promise<void>;
        getDecoratedOutput(witness: bigint[]): Promise<Record<string, string>>;
    }

    export interface WasmTesterFunction {
        (circuitPath: string, options?: {
            output?: string;
            recompile?: boolean;
            verbose?: boolean;
            O?: number;
        }): Promise<WasmTester>;
    }

    export const wasm: WasmTesterFunction;
}
