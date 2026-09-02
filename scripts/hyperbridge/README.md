# Hyperbridge relayer

Configuration and procedure for connecting Orbinum to Hyperbridge, so the two chains can
exchange ISMP messages.

Nothing here is compiled or used by the node — these are operator inputs for
**Tesseract**, Hyperbridge's relayer, which runs as a Docker image.

| File | Purpose |
|---|---|
| `relayer.local.toml` | Validate the flow against a node on your own machine |
| `relayer.paseo.toml` | Production template, pointing at the deployed testnet node |

## How the connection works

Verification is **bidirectional** — each side has to learn how to verify the other:

| Side | Needs to know | Who does it |
|---|---|---|
| **Orbinum** | How to verify Hyperbridge's proofs | Us, via `create_consensus_client` |
| **Hyperbridge** | How to verify Orbinum's proofs | Them, via an onboarding issue |

The relayer holds no authority. It carries proofs; if it delivers a forged one,
verification rejects it. Postman, not notary.

## Prerequisites

- **The node runs a runtime with ISMP.** Check with the `state_call` below; if the
  method is missing, the deployed runtime predates the integration and needs a
  `spec_version` bump and a redeploy.
- **Built for the right network.** `--features hyperbridge-testnet` targets
  `Kusama(4009)`; the default targets Polkadot mainnet. With the wrong build, proofs
  **fail to verify silently**.
- **Unsafe RPC methods are exposed** (`--rpc-methods Unsafe`). Tesseract calls methods
  outside Substrate's Safe set; without them it fails at runtime, not at startup.

```bash
# Should return 0x036f726269 — SCALE for Substrate("orbi")
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"state_call","params":["IsmpRuntimeApi_host_state_machine","0x"]}' \
  <RPC_URL>

# Should return 0x0102a90f0000 — Some(Kusama(4009)), i.e. the Paseo build
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"state_call","params":["OrbinumIsmpApi_coprocessor","0x"]}' \
  <RPC_URL>
```

The first call is exactly what Tesseract issues
(`tesseract/messaging/substrate/src/registry.rs`) to derive our state machine. If it
fails, the relayer will not start.

## Procedure

### 1. Initialise Hyperbridge's consensus client on Orbinum

```bash
docker run --network=host \
  -v $PWD/scripts/hyperbridge/relayer.paseo.toml:/root/relayer.toml \
  polytopelabs/tesseract:latest \
  --config=/root/relayer.toml --db=/root/relayer.db \
  log-consensus-state KUSAMA-4009
```

Prints a hex blob: the relay chain's current validator set plus its latest finalised
block. Submit it through `Ismp::create_consensus_client` via sudo:

| Field | Value |
|---|---|
| `consensus_state` | the hex from the command |
| `consensus_client_id` | `GRNP` — always, for GRANDPA |
| `consensus_state_id` | `PAS0` on Paseo |
| `unbonding_period` | the relay chain's |
| `challenge_periods` | map per state machine; 0 for Hyperbridge |
| `state_machine_commitments` | usually empty |

⚠️ `challenge_periods` is a **map**, not a scalar, and `state_machine_commitments` is not
mentioned in the published docs.

`scripts/setup-paseo-local.mjs` does all of this against a local node, and refuses to run
against a mainnet build.

### 2. Export Orbinum's consensus state

```bash
docker run --network=host \
  -v $PWD/scripts/hyperbridge/relayer.paseo.toml:/root/relayer.toml \
  polytopelabs/tesseract:latest \
  --config=/root/relayer.toml --db=/root/relayer.db \
  log-consensus-state SUBSTRATE-orbi
```

### 3. File the onboarding issue

At `https://github.com/polytope-labs/hyperbridge/issues/new`, with:

| Field | Value |
|---|---|
| State machine id | `SUBSTRATE-orbi` |
| Consensus state id | `ORBI` |
| Consensus client | GRANDPA (`GRNP`) |
| Slot duration | 6000 ms |
| Hashing | Blake2 |
| Public RPC | the node's WS endpoint |
| Consensus state | the hex from step 2 |

Until they install it, the relayer reports `Error fetching Consensus state (9876)` for the
Orbinum → Hyperbridge direction. That is the half of the handshake only they can do; the
other direction works as soon as step 1 is done.

⚠️ The 4-byte id **cannot change** once messages are in flight — it is baked into every
commitment emitted.

### 4. Run the relayer

With both sides initialised, run with no subcommand:

```bash
docker run --network=host \
  -v $PWD/scripts/hyperbridge/relayer.paseo.toml:/root/relayer.toml \
  polytopelabs/tesseract:latest \
  --config=/root/relayer.toml --db=/root/relayer.db
```

The daemon needs `signer` filled in on any chain it should submit to. Steps 1 and 2 are
read-only and work without one.

## Validating locally first

`relayer.local.toml` points at a node on the host instead of the deployed one, so the
whole flow can be exercised against real Paseo before touching production:

```bash
cargo build --release -p orbinum-node --features hyperbridge-testnet
./target/release/orbinum-node --dev --tmp --rpc-port 9944 --rpc-methods Unsafe

mkdir -p /tmp/tess && cp scripts/hyperbridge/relayer.local.toml /tmp/tess/local.toml
HEX=$(docker run --rm --platform linux/amd64 -v /tmp/tess:/data \
  polytopelabs/tesseract:latest --config=/data/local.toml --db=/data/relayer.db \
  log-consensus-state KUSAMA-4009 2>/dev/null | grep -oE '0x[0-9a-f]+' | tail -1)

node scripts/setup-paseo-local.mjs "$HEX"
```

Its `signer` is a dev key derived from Substrate's public development mnemonic, funded
from `//Alice` on the dev chain. It has no value and exists only so the daemon can be
exercised end to end.

## Notes that are not in the upstream docs

**The `tesseract-consensus` binary no longer exists.** `developers/polkadot/solochains`
still shows it, along with `[chain.grandpa]` sections. On `main` there is only
`tesseract` (consolidated) and `tesseract-prover`, and the config format is the one
`relayer/src/config.rs` parses — which is what these files use.

**`signer = ""` breaks.** An empty string is hex-decoded and fails with `Invalid seed
length`. Omit the field entirely: absent generates a throwaway key and leaves the chain
inbound-only.

**`ismp_queryConsensusState` takes `(height, consensus_state_id)`** — height first.
Reversed, it yields a confusing type error rather than a clear one.

**The Docker image is amd64.** On Apple Silicon, pass `--platform linux/amd64`.

**Relay RPC endpoints go stale.** `relayer.*.toml` names a public Paseo relay endpoint;
if the relayer cannot connect, verify that host still resolves before debugging further.

## Related

- `frame/ismp-messaging/README.md` — sending and receiving messages
- `scripts/setup-paseo-local.mjs` — automates step 1 against a local node
