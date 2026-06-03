# Validator Keys

Scripts to generate and insert session keys for an Orbinum validator node.
These scripts work for both **testnet** and **mainnet** — they are network-agnostic.

Each validator needs two cryptographic keys derived from a single mnemonic:

| Key         | Scheme  | Key type | Role                                                |
| ----------- | ------- | -------- | --------------------------------------------------- |
| **Aura**    | Sr25519 | `aura`   | Block production — your on-chain validator identity |
| **GRANDPA** | Ed25519 | `gran`   | Block finalization                                  |

> **EVM relay address:** The node derives it automatically from the Aura key at startup.
> You do not generate or insert a separate EVM key.

---

## Scripts

| Script                       | Purpose                                                  |
| ---------------------------- | -------------------------------------------------------- |
| `generate-validator-keys.sh` | Generate the two session keys from a single mnemonic     |
| `insert-session-keys.sh`     | Insert the generated keys into a running node's keystore |

The `keys/` directory produced by these scripts is in `.gitignore`. **Never commit it.**

---

## Prerequisites

```bash
# 1. Build the node binary
cargo build --release --package orbinum-node

# 2. jq (JSON parser)
brew install jq   # macOS
apt install jq    # Ubuntu/Debian
```

---

## Step 1 — Generate keys

```bash
cd scripts/validator-keys
chmod +x generate-validator-keys.sh insert-session-keys.sh

./generate-validator-keys.sh
```

Output written to `keys/validator-1/`:

```
keys/validator-1/
├── aura.json      ← Sr25519 key (Aura)
├── grandpa.json   ← Ed25519 key (GRANDPA)
└── summary.txt    ← All values + ready-to-run insert commands
```

> **Security:** Save `summary.txt` to a password manager (Bitwarden, 1Password) before proceeding. Delete it from disk afterwards.

### What to record

| Value                    | File           | Field          |
| ------------------------ | -------------- | -------------- |
| Mnemonic (secret phrase) | `aura.json`    | `secretPhrase` |
| Aura public key          | `aura.json`    | `publicKey`    |
| GRANDPA public key       | `grandpa.json` | `publicKey`    |

---

## Step 2 — Start the node

Start the node and wait until it is synced (you will see `Idle` in the logs) before inserting keys.

---

## Step 3 — Insert keys into the node

```bash
./insert-session-keys.sh --validator 1 --rpc http://localhost:9944
```

This calls `author_insertKey` for each key type (`aura`, `gran`) via local JSON-RPC. No balance or on-chain transaction is required — these are local keystore writes.

The script also calls `author_rotateKeys` and prints the **combined session key**. Save it to register on-chain.

---

## Step 4 — Restart the node — EVM address is derived automatically

After inserting keys, restart the node:

```bash
docker compose restart validator-1
```

At block #1 the node reads the Aura key from the keystore, derives the EVM relay address, and prints a log box if not yet registered:

```
╔══════════════════════════════════════════════════╗
║   EVM relay key detected — register via sudo     ║
╠══════════════════════════════════════════════════╣
║  Substrate : 5GrwvaEF5...
║  EVM addr  : 0xd43593c7...
╠══════════════════════════════════════════════════╣
║  relayer.registerRelayer(who, evmAddress)        ║
╚══════════════════════════════════════════════════╝
```

**Copy the `Substrate` and `EVM addr` values** — you will need them in Step 6.

---

## Step 5 — Register session key on-chain

With the combined session key obtained in Step 3:

**Polkadot.js Apps** → Developer → Extrinsics → `session.setKeys(keys, proof)`
- `keys`: the combined session key from Step 3
- `proof`: `0x`

Submit from your validator account.

---

## Step 6 — Request validator approval

Orbinum uses a permissioned validator set. Send the Orbinum team:

- **Substrate AccountId** (from the log box in Step 4)
- **EVM relay address** (from the log box in Step 4, `0x...` 40 hex chars)
- **Server public IP** and **Peer ID** (`12D3KooW...`)
- Confirmation that `validatorSet.registerValidator()` was called on-chain

The team will execute in order:
1. `relayer.registerRelayer(who, evmAddress)` — links your EVM relay address
2. `validatorSet.approveValidator(who)` — moves you to the active validator set

