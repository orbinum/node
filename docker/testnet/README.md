# Running a Validator on Orbinum Testnet

This guide walks through everything needed to join the Orbinum testnet as a validator: server setup, key generation, node startup, and requesting approval to produce blocks.

**Flow at a glance:**

```
1.  Prepare server and install Docker
2.  Generate your two session keys (one mnemonic)
3.  Start the node — sync with the network
4.  Insert the session keys into the running node's keystore (local RPC)
5.  Restart the node — it will derive and log your EVM relay address automatically
6.  Share the logged EVM address with the Orbinum team — they register it via sudo
7.  Register session keys on-chain  →  session.setKeys
8.  Submit validator registration (locks 1 000 ORB bond)  →  validatorSet.registerValidator
9.  Contact the Orbinum team — governance approves your registration
10. Wait for the next session (~1 h) — you are now an active validator
```

> **Steps 7–8 must be completed in order.** `registerValidator` will be rejected
> on-chain if session keys or the EVM relay address are not already registered.
> The EVM relay address is registered by the Orbinum team (sudo) — you do not call any extrinsic for it.

---

## 1. Hardware Requirements

| Resource  | Minimum                       |
| --------- | ----------------------------- |
| CPU       | 2 vCPU dedicated              |
| RAM       | 8 GB                          |
| Disk      | 80 GB SSD                     |
| Bandwidth | 10 TB / month                 |
| OS        | Ubuntu 22.04 LTS or 24.04 LTS |

> Recommended provider: **Hetzner CCX13** (~$18/mo). Shared-CPU VPS instances are not recommended — validators run ZK proof verification which is CPU-intensive.

---

## 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker                     # apply group without logging out

sudo apt-get install -y docker-compose-plugin
docker compose version            # should print v2.x
```

---

## 3. Open Firewall Ports

```bash
sudo ufw allow 30333/tcp   # P2P — must be publicly reachable
sudo ufw allow 9615/tcp    # Prometheus metrics (optional)
sudo ufw enable
```

Do **not** open port `9944` (RPC) on a validator. The RPC port is only used locally during key insertion.

---

## 4. Get the Node

```bash
git clone https://github.com/orbinum/node.git
cd node/docker/testnet
docker compose build         # compiles the node from source (~10-20 min first time)
```

---

## 5. Generate Your Session Keys

Each validator has **two session keys**, both derived from a single mnemonic:

| Key         | Scheme  | Key type | Role                                       |
| ----------- | ------- | -------- | ------------------------------------------ |
| **Aura**    | Sr25519 | `aura`   | Block production (your validator identity) |
| **GRANDPA** | Ed25519 | `gran`   | Block finalization                         |

> **EVM relay key:** The node derives your EVM relay address automatically from the Aura key at startup — you do not need to generate or insert a separate EVM key.

### Option A — Automated (recommended)

```bash
cd scripts/validator-keys
./generate-validator-keys.sh
```

Output is saved to `keys/validator-1/`:
- `aura.json` — Sr25519 key
- `grandpa.json` — Ed25519 key
- `summary.txt` — human-readable summary of all values

### Option B — Manual

```bash
# Step 1: generate Aura key — this produces your mnemonic
docker run --rm orbinum-node:latest key generate --scheme Sr25519
```

Save the **Secret phrase**. You will use it for both keys.

```bash
# Step 2: derive GRANDPA from the same mnemonic
docker run --rm orbinum-node:latest key inspect --scheme Ed25519 "<SECRET PHRASE>"
```

### What to record

| Value                  | Where to find it           | Example                |
| ---------------------- | -------------------------- | ---------------------- |
| **Mnemonic**           | `key generate` output      | `abandon ... about`    |
| **Aura public key**    | `aura.json → publicKey`    | `0x72d4f4...` (64 hex) |
| **GRANDPA public key** | `grandpa.json → publicKey` | `0x96749e...` (64 hex) |

> **Security:** Store the mnemonic in a password manager (Bitwarden, 1Password). Never commit it to the repository. The `keys/` directory is in `.gitignore`.

---

## 6. Start the Node

```bash
cd docker/testnet
docker compose up -d
docker compose logs -f validator-1
```

The node will start syncing. Wait until you see `Idle` in the logs before proceeding:

```
2026-06-02 12:00:00 Idle (3 peers), best: #1234 ...
```

Get your **Peer ID** — you will need it when requesting approval:

```bash
docker compose logs validator-1 | grep "Local node identity"
# -> Local node identity is: 12D3KooWxxxxx...
```

---

## 7. Insert Session Keys into Keystore

This writes the keys into the **node's local keystore** via RPC. These are local calls — not blockchain transactions — and require no balance.

```bash
# Replace <MNEMONIC>, <AURA_PUBKEY>, <GRANDPA_PUBKEY>
# with the values recorded in Step 5.

# Aura (Sr25519)
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["aura","<MNEMONIC>","<AURA_PUBKEY>"]}' \
  http://localhost:9944

# GRANDPA (Ed25519)
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["gran","<MNEMONIC>","<GRANDPA_PUBKEY>"]}' \
  http://localhost:9944
```

Or use the script:

```bash
cd scripts/validator-keys
./insert-session-keys.sh --validator 1 --rpc http://localhost:9944
```

Each call returns `{"result":null}` on success.

---

## 8. Restart the Node — EVM Address Is Derived Automatically

After inserting the Aura key, restart the node:

```bash
docker compose restart validator-1
```

At block #1 the node reads the Aura key from the keystore, derives the corresponding EVM relay address, and prints a log box if not yet registered:

```
╔══════════════════════════════════════════════════╗
║   EVM relay key detected — register via sudo     ║
╠══════════════════════════════════════════════════╣
║  Substrate : 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNe...
║  EVM addr  : 0xd43593c715fdd31c61141abd04a99fd...
╠══════════════════════════════════════════════════╣
║  relayer.registerRelayer(who, evmAddress)        ║
╚══════════════════════════════════════════════════╝
```

**Copy both values from the log** and include them in your approval request (Step 9). The Orbinum team will register the EVM address on your behalf via sudo — you do not call any extrinsic for this step.

> After this step, continue with the **on-chain** steps (9 → 10 → 11) in order.

---

## 9. Register Session Keys On-Chain

This is an on-chain transaction — **not** the same as inserting keys into the keystore in Step 7.

First, get the combined session key from the node:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_rotateKeys","params":[]}' \
  http://localhost:9944
# Returns: {"result":"0x<combined_hex_session_key>"}
```

Or if you used the script, it was saved automatically to `keys/validator-1/session_key.txt`.

Now submit the on-chain transaction via [Polkadot.js Apps](https://polkadot.js.org/apps/):

```
Developer → Extrinsics
  Pallet:  session
  Method:  setKeys(keys, proof)
  keys:    <combined hex from above>
  proof:   0x
  Sign with: your validator account
```

This links your node's session keys to your account on-chain.

---

## 10. Submit Validator Registration

This locks **1 000 ORB** as a bond and places your account in the **pending** queue. Your account must have > 1 001 ORB free balance (1 000 for the bond + fees buffer).

> **Prerequisites enforced on-chain:** If session keys (Step 8) or EVM relay address (Step 9) are not registered, this call will fail with `NoSessionKeys` or `NoRelayer`.

Via [Polkadot.js Apps](https://polkadot.js.org/apps/):

```
Developer → Extrinsics
  Pallet:  validatorSet
  Method:  registerValidator()
  Sign with: your validator account
```

On success, a `ValidatorRegistrationRequested` event is emitted and your bond is locked. You are now in the **pending** queue — not yet an active validator.

---

## 11. Request Approval

Validators are permissioned on Orbinum Testnet. Governance (sudo) must:
1. Register your EVM relay address (`relayer → registerRelayer`)
2. Approve your validator registration (`validatorSet → approveValidator`)

Contact the Orbinum team on **Discord** with:

- Your **Substrate AccountId** (from the log box in Step 8)
- Your **EVM relay address** (from the log box in Step 8, `0x...` 40 hex chars)
- Your **server's public IP** and **Peer ID** (`12D3KooW...`)
- Confirmation that `registerValidator()` was called and `ValidatorRegistrationRequested` was emitted

The team will execute on-chain:
```
1. relayer → registerRelayer(who, evmAddress)    ← links your EVM address
2. validatorSet → approveValidator(who)           ← moves you to the active set
```

This emits `ValidatorApproved`. Your bond remains locked as long as you are an active validator.

You can verify your status at any time:

```
Developer → Chain state → validatorSet → approvedValidators()
Developer → Chain state → validatorSet → pendingValidators()
```

---

## 12. Wait for the Next Session

Validator set changes take effect at the **next session boundary**. Sessions on Orbinum Testnet are **600 blocks** — approximately 1 hour at 6 seconds per block.

Once the session boundary is crossed, your node will begin authoring and finalizing blocks:

```
Prepared block for proposing at #1801 ...
Idle (5 peers), best: #1802 ...
```

---

## Bond and Deregistration

Your **1 000 ORB bond** remains locked while you are in the pending queue or active validator set.

To leave voluntarily:

```
Developer → Extrinsics
  Pallet:  validatorSet
  Method:  deregisterValidator()
  Sign with: your validator account
```

The bond is returned immediately. Removal from the active set takes effect at the next session rotation.

If you are still in the **pending** queue (not yet approved), you can also call `deregisterValidator()` to cancel and reclaim your bond.

---

## Useful Commands

```bash
# View logs
docker compose logs -f validator-1

# Stop the node
docker compose down

# Restart
docker compose restart validator-1

# Full reset — deletes all chain data (use only for a fresh start)
docker compose down -v

# Resource usage
docker stats orbinum-validator-1
```

---

## Troubleshooting

**Node has 0 peers after several minutes**
- Confirm port `30333` is open and publicly reachable: `nc -zv <YOUR_PUBLIC_IP> 30333`
- Check that `testnet-spec.json` has bootnodes listed

**`author_insertKey` returns an error**
- Make sure the node is running before calling the RPC
- Port `9944` is not exposed publicly; call from the same machine: `http://localhost:9944`

**Node is not producing blocks after approval**
- Verify all three keys are inserted: restart and check logs for `Loaded session key`
- The validator set update takes effect at the next session boundary (~30 min after approval)
- Confirm your AccountId is in `validatorSet → approvedValidators()`

**`registerValidator` fails with `NoRelayer`**
- Your EVM relay address has not been registered yet by the Orbinum team
- Share the values from the log box (Step 8) with the team and wait for confirmation

**`registerValidator` fails with `NoSessionKeys`**
- Verify that `session.setKeys` was called on-chain (Step 9)
- Confirm the combined key returned by `author_rotateKeys` was used correctly

---

## File Reference

| File                     | Purpose                                        |
| ------------------------ | ---------------------------------------------- |
| `Dockerfile`             | Multi-stage build — shared by all node types   |
| `docker-compose.yml`     | Validator node configuration                   |
| `docker-compose.rpc.yml` | Public RPC node configuration                  |
| `testnet-spec.json`      | Raw chain spec used by all nodes               |
| `rpc-node.md`            | Guide for running a public RPC node with Nginx |
