# Validator Keys

Scripts to generate and insert session keys for an Orbinum validator node.
These scripts work for both **testnet** and **mainnet** — they are network-agnostic.

Each validator needs two session keys derived from a single mnemonic, plus an
EVM relay key it chooses freely:

| Key          | Scheme  | Key type | Role                                                |
| ------------ | ------- | -------- | --------------------------------------------------- |
| **Aura**     | Sr25519 | `aura`   | Block production — your on-chain validator identity |
| **GRANDPA**  | Ed25519 | `gran`   | Block finalization                                  |
| **EVM relay**| ECDSA   | `evmr`   | Signs relay transactions — your EVM identity        |

> **EVM relay key:** you pick it. It is independent of the Aura key, so your
> consensus identity does not dictate your EVM identity. Insert it with
> `author_insertKey("evmr", …)`. Without it the node still authors blocks, but
> cannot relay.

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

## Step 4 — Insert an EVM relay key and restart

> **Upgrading an existing validator?** Until `spec_version` 9 the node derived
> this key from your Aura mnemonic automatically. To keep the EVM address you
> already registered on-chain, recover that exact key with
> `node scripts/vk/derive-legacy-evm-key.cjs "<your aura mnemonic>"` and insert
> what it prints. To switch addresses instead, generate a fresh ECDSA key here,
> then call `unregisterRelayer` followed by `registerRelayer` with the new one.

Pick any ECDSA key you control and insert it into the keystore:

```bash
curl -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"author_insertKey",
  "params":["evmr","<your mnemonic>","<your ECDSA public key>"]
}' http://localhost:9944
```

Then restart the node so it loads every key from the keystore:

```bash
docker compose restart validator-1
```

At startup the node logs the relay address it will sign with:

```
EVM relay address: 0xd43593c7… — register it with relayer.registerRelayer(evmAddress)
```

**Copy that address** — you register it yourself in Step 6.

If the key is missing you get a warning instead, and relaying stays disabled:

```
no EVM relay key in keystore (type "evmr"); relaying is disabled.
```

---

## Step 5 — Register session key on-chain

With the combined session key obtained in Step 3:

**Polkadot.js Apps** → Developer → Extrinsics → `session.setKeys(keys, proof)`
- `keys`: the combined session key from Step 3
- `proof`: `0x`

Submit from your validator account.

---

## Step 6 — Ask to be added, then register your relay address

Orbinum uses a permissioned validator set. Candidate selection happens off-chain:
send the Orbinum team

- **Substrate AccountId** (SS58) — the only thing they need for the extrinsic
- **Server public IP** and **Peer ID** (`12D3KooW...`) — for peering

They run `validatorSet.addValidator(who)` under sudo. It fails with
`NoSessionKeys` if Step 5 is missing, so complete that first. Your node joins the
active set at the next session rotation.

**Once you are in the approved set**, register the EVM relay address yourself.
The call needs a signature proving you hold the EVM key, which the node produces
for you:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"relayer_getRelayInfo","params":[]}' \
  http://localhost:9944
```

It returns your account, your EVM address, and the `signature` to pass along:

```json
{"substrate_account":"0x…","evm_address":"0x…","signature":"0x…"}
```

**Polkadot.js Apps** → Developer → Extrinsics →
`relayer.registerRelayer(evmAddress, signature)`

Sign from your validator account. The call fails with `NotValidator` if you are
not yet in the set, `BadEvmSignature` if the proof does not match the address,
and `InvalidEvmAddress` for the zero address or the reserved precompile range.

The signature is what stops another validator from claiming your address: it is
public (every relay transaction reveals it), so without proof of key ownership
anyone approved could register it and collect your fees.

> Until you register, relay fees you earn are credited to the block author
> instead of to you. Nothing breaks; the attribution is just wrong.

To leave the set, call `validatorSet.deregisterValidator()`. Leaving also clears
your EVM relay binding, so re-register it if you rejoin.
