## Approach to fuzzing
This harness is "structure-aware": [arbitrary](https://github.com/rust-fuzz/arbitrary) turns the fuzzer's bytes into one EVM transaction (`src/grammar.rs`), sent from Alith on the runtime's development genesis:

- a call to a contract whose code is generated opcode by opcode;
- a contract creation from generated init code;
- a call to one of the precompiles (Ethereum's 0x01–0x09 and Orbinum's) with raw input.

After the transaction the harness checks:

1. The gas used never exceeds the gas limit.
2. The proof size used never exceeds the proof-size limit (halved on some inputs, so the limit is hit more often).
3. No account has consumers without providers.
4. Each account's frozen balance equals its largest lock or freeze, and its holds never exceed its reserved balance.
5. Total issuance equals the sum of all balances and never grows.

The genesis storage is built once and cloned for every input.

Important notes:
1. Since the fuzzing happens in `debug` mode, the EVM execution will be notably slower. Set a reasonably high timeout, five or six seconds is a good starter.
2. You will need to use `SKIP_WASM_BUILD=1` to fuzz due to some polkadot-sdk wasm conflicts.

## Orchestrating the campaign
Fuzzing is orchestrated by [ziggy](https://github.com/srlabs/ziggy/).

It uses [AFL++](https://github.com/AFLplusplus/AFLplusplus/) and [honggfuzz](https://github.com/google/honggfuzz) under the hood.

Please refer to its documentation for details.

Quickstart command to fuzz, from this directory:

```bash
SKIP_WASM_BUILD=1 cargo ziggy fuzz -j$(nproc) -t5
```

To replay inputs (e.g. a crash) without AFL, pass the files to the plain binary:

```bash
SKIP_WASM_BUILD=1 cargo run -p fuzz -- <input files>
```

`cargo test -p fuzz` runs the harness on a few hundred deterministic inputs.
