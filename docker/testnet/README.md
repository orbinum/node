# Running a Validator on Orbinum Testnet

This guide covers everything needed to join the Orbinum testnet as a validator: server setup, key generation, node startup, on-chain registration, and keeping your node up to date.

---

## Table of Contents

- [Running a Validator on Orbinum Testnet](#running-a-validator-on-orbinum-testnet)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Part 1 — Server Setup](#part-1--server-setup)
    - [1. Hardware Requirements](#1-hardware-requirements)
    - [2. Firewall Ports](#2-firewall-ports)
  - [Part 2 — Run the Node](#part-2--run-the-node)
      - [A.1 Install Docker](#a1-install-docker)
      - [A.2 Authenticate with GHCR](#a2-authenticate-with-ghcr)
      - [A.3 Configure the `.env` file](#a3-configure-the-env-file)
      - [A.4 Start the node](#a4-start-the-node)
      - [A.5 Automatic updates (Watchtower)](#a5-automatic-updates-watchtower)
  - [Part 3 — Key Setup](#part-3--key-setup)
    - [3. Generate Session Keys](#3-generate-session-keys)
      - [Option A — Automated (recommended)](#option-a--automated-recommended)
      - [Option B — Manual](#option-b--manual)
      - [What to record](#what-to-record)
    - [4. Insert Keys into Keystore](#4-insert-keys-into-keystore)
    - [5. Get Your EVM Relay Address](#5-get-your-evm-relay-address)
  - [Part 4 — On-Chain Registration](#part-4--on-chain-registration)
    - [6. Register Session Keys On-Chain](#6-register-session-keys-on-chain)
    - [7. Submit Validator Registration](#7-submit-validator-registration)
    - [8. Request Approval](#8-request-approval)
    - [9. Wait for the Next Session](#9-wait-for-the-next-session)
  - [Part 5 — Operations](#part-5--operations)
    - [Keeping the Node Updated](#keeping-the-node-updated)
      - [Docker — automatic (Watchtower)](#docker--automatic-watchtower)
    - [Bond and Deregistration](#bond-and-deregistration)
    - [Useful Commands](#useful-commands)
    - [Troubleshooting](#troubleshooting)

---

## Overview

This guide is for **validators joining the Orbinum testnet**. Your node connects
to the network by dialing the public RPC bootnodes listed in `testnet-spec.json`,
so it needs a publicly reachable P2P port. You do **not** appear in `bootNodes`
yourself.

> **Running a public RPC node** (no consensus, serves wallets/dApps)? See
> [rpc-node.md](rpc-node.md) instead.

**Registration flow at a glance:**

```
1.  Prepare server
2.  Run the node and sync with the network
3.  Generate session keys (Aura + GRANDPA)
4.  Insert session keys into the local keystore
5.  Restart node → EVM relay address is derived and logged automatically
6.  Share EVM address with Orbinum team → they register it via sudo
7.  Register session keys on-chain  →  session.setKeys
8.  Submit validator registration (locks 1 000 ORB bond)  →  validatorSet.registerValidator
9.  Contact the Orbinum team → governance approves your registration
10. Wait for the next session (~1 h) → you are now an active validator
```

> **Steps 7–8 must be completed in order.** `registerValidator` will be rejected
> on-chain if session keys or the EVM relay address are not already registered.
> The EVM relay address is registered by the Orbinum team (sudo) — you do not call any extrinsic for it.

---

## Part 1 — Server Setup

### 1. Hardware Requirements

| Resource  | Minimum                       |
| --------- | ----------------------------- |
| CPU       | 2 vCPU dedicated              |
| RAM       | 8 GB                          |
| Disk      | 80 GB SSD                     |
| Bandwidth | 10 TB / month                 |
| OS        | Ubuntu 22.04 LTS or 24.04 LTS |

> Recommended provider: **Hetzner CCX13** (~$18/mo). Shared-CPU VPS instances are not recommended — validators run ZK proof verification which is CPU-intensive.

### 2. Firewall Ports

```bash
sudo ufw allow 30333/tcp   # P2P — must be publicly reachable
sudo ufw allow 22/tcp      # SSH — remote admin
sudo ufw enable
```

> Do **not** open port `9944` (RPC) on a validator. It is never exposed to the host or network — it only listens inside the container and is reached via `docker compose exec` during key insertion.

---

## Part 2 — Run the Node

The `docker-compose.yml` includes the node and **Watchtower**, which automatically updates your container whenever a new testnet release is published.

#### A.1 Install Docker

Install Docker Engine following the official guide for your distribution: https://docs.docker.com/engine/install/

Make sure the Compose plugin is available:

```bash
docker compose version   # should print v2.x
```

#### A.2 Authenticate with GHCR

The Orbinum node image is hosted on GitHub Container Registry (private). You need to authenticate once:

```bash
# Create a GitHub Personal Access Token with read:packages scope at:
# https://github.com/settings/tokens/new?scopes=read:packages

docker login ghcr.io -u <your_github_username>
```

After entering your username, Docker prompts for a password — paste the
generated token (not your GitHub account password). The token is hidden
as you type/paste it. On success you see `Login Succeeded`.

> Credentials are saved to `~/.docker/config.json`. Watchtower uses them automatically for future pulls.

#### A.3 Configure the `.env` file

Clone the repository and create your `.env` from the template:

```bash
git clone https://github.com/orbinum/node.git
cd node/docker/testnet
cp .env.example .env
```

Edit `.env` and set the validator block:

| Variable             | What to set                                                        |
| -------------------- | ------------------------------------------------------------------ |
| `VALIDATOR_NAME`     | Any identifiable name shown in telemetry (e.g. `Alice-Validator`). |
| `VALIDATOR_NODE_KEY` | Your node key — generate with `openssl rand -hex 32` (see below).  |
| `P2P_PUBLIC_ADDR`    | **Leave empty** when joining the public testnet.                   |
| `RESERVED_NODES`     | **Leave empty** when joining the public testnet.                   |
| `P2P_BIND`           | Leave as `0.0.0.0` when joining the public testnet.                |

**The node key** is a 32-byte key that fixes your node's Peer ID on the libp2p network. Without a stable key the Peer ID changes on every restart and peers cannot reliably locate you.

```bash
openssl rand -hex 32
# Example: 847eff06b1f1b8a10b1a8b3b03a0dc90fe4e4a7c86f5e6063a88382f545f7704
```

Paste the output into `VALIDATOR_NODE_KEY=` in your `.env`.

> **Security:** `.env` is in `.gitignore` — never commit it. Back up the node key in a password manager. Whoever holds this key can impersonate your node on the network.

> **Joining the public testnet?** Leave `P2P_PUBLIC_ADDR`, `RESERVED_NODES` empty and `P2P_BIND=0.0.0.0`. The node auto-detects its public address, binds P2P on all interfaces, and finds the network through the public bootnodes in `testnet-spec.json` — you do **not** set any private IP. Just make sure TCP port `30333` is publicly reachable (see [Firewall Ports](#2-firewall-ports)). The `P2P_PUBLIC_ADDR` / `RESERVED_NODES` / private-IP settings exist only for Orbinum-operated sentry validators on a private network; external validators never touch them.

Your **Peer ID** is derived from the node key and printed in the logs on startup:

```
Local node identity is: 12D3KooWxxxxx...
```

#### A.4 Start the node

With your `.env` file in place (see A.3), start the node from `node/docker/testnet`:

```bash
docker compose pull       # download pre-built image (~1-2 min)
docker compose up -d      # start validator + watchtower
docker compose logs -f orbinum-validator
```

Wait until you see `Idle` in the logs before proceeding:

```
2026-06-02 12:00:00 Idle (3 peers), best: #1234 ...
```

Get your **Peer ID** — you will need it when requesting approval:

```bash
docker compose logs orbinum-validator | grep "Local node identity"
# -> Local node identity is: 12D3KooWxxxxx...
```

#### A.5 Automatic updates (Watchtower)

Watchtower monitors GHCR and restarts your container automatically when a new `testnet-latest` image is published — no manual action required.

```
Orbinum team publishes v0.1.1-rc.1
         ↓
ghcr.io/orbinum/node:testnet-latest is updated
         ↓
Watchtower detects change (checks every 5 min)
         ↓
docker pull + restart validator  (~5s downtime)
```

Watchtower starts automatically with `docker compose up -d`. To check update history:

```bash
docker compose logs watchtower
```

---

## Part 3 — Key Setup

### 3. Generate Session Keys

Each validator needs **two session keys**, both derived from a single mnemonic:

| Key         | Scheme  | Key type | Role               |
| ----------- | ------- | -------- | ------------------ |
| **Aura**    | Sr25519 | `aura`   | Block production   |
| **GRANDPA** | Ed25519 | `gran`   | Block finalization |

> **EVM relay key:** The node derives your EVM relay address automatically from the Aura key — you do not generate or insert a separate EVM key.

#### Option A — Automated (recommended)

```bash
cd scripts/validator-keys
./generate-validator-keys.sh
```

Output is saved to `keys/validator-1/`:
- `aura.json` — Sr25519 key
- `grandpa.json` — Ed25519 key
- `summary.txt` — human-readable summary

#### Option B — Manual

```bash
# Generate Aura key — save the Secret phrase shown in the output
docker run --rm ghcr.io/orbinum/node:testnet-latest key generate --scheme Sr25519

# Derive GRANDPA from the same mnemonic
docker run --rm ghcr.io/orbinum/node:testnet-latest key inspect --scheme Ed25519 "<SECRET PHRASE>"
```

#### What to record

| Value                  | Where to find it           |
| ---------------------- | -------------------------- |
| **Mnemonic**           | `key generate` output      |
| **Aura public key**    | `aura.json → publicKey`    |
| **GRANDPA public key** | `grandpa.json → publicKey` |

> **Security:** Store the mnemonic in a password manager (Bitwarden, 1Password). Never commit it to the repository. The `keys/` directory is in `.gitignore`.

---

### 4. Insert Keys into Keystore

This writes the keys into the **node's local keystore** via RPC. These are local calls — not blockchain transactions — and require no balance.

The validator's RPC port (`9944`) is **not** published to the host or the
network — it only listens on `127.0.0.1` *inside* the container. Run the calls
with `docker exec orbinum-validator`, which executes them from inside the container
where `localhost:9944` is reachable (the image ships `curl` for this purpose).

The node must be running before you proceed.

```bash
# Replace <MNEMONIC>, <AURA_PUBKEY>, <GRANDPA_PUBKEY> with your values

# Aura (Sr25519)
docker exec orbinum-validator curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["aura","<MNEMONIC>","<AURA_PUBKEY>"]}' \
  http://localhost:9944

# GRANDPA (Ed25519)
docker exec orbinum-validator curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["gran","<MNEMONIC>","<GRANDPA_PUBKEY>"]}' \
  http://localhost:9944
```

Each call returns `{"result":null}` on success.

**Verify the keys were inserted.** Two files must exist in the keystore — one for
aura, one for grandpa:

```bash
docker exec orbinum-validator ls /data/chains/orbinum_testnet/keystore/
# expect 2 files (the 8-hex prefix is the key type: 61757261=aura, 6772616e=gran)
```

You can also ask the node directly whether it holds each public key:

```bash
# Aura — replace <AURA_PUBKEY>
docker exec orbinum-validator curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_hasKey","params":["<AURA_PUBKEY>","aura"]}' \
  http://localhost:9944

# GRANDPA — replace <GRANDPA_PUBKEY>
docker exec orbinum-validator curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_hasKey","params":["<GRANDPA_PUBKEY>","gran"]}' \
  http://localhost:9944
```

Both must return `{"result":true}`. If either is `false`, the seed and the public
key don't match — re-check them before continuing (GRANDPA finalization needs ≥2 of
3 validators holding their `gran` key, or the chain produces blocks but never
finalizes).

---

### 5. Get Your EVM Relay Address

After inserting the Aura key, restart the node:

```bash
docker compose restart orbinum-validator
```

The node reads the Aura key from the keystore, derives the EVM relay address, and prints it in the logs:

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

**Copy both values** — you will need them for the approval request in Step 8.

The Orbinum team registers the EVM address on your behalf via sudo — you do not call any extrinsic for this step.

---

## Part 4 — On-Chain Registration

### 6. Register Session Keys On-Chain

First, get the combined session key from the node (same `docker compose exec`
pattern as Step 4 — the RPC is only reachable inside the container):

```bash
docker exec orbinum-validator curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_rotateKeys","params":[]}' \
  http://localhost:9944
# Returns: {"result":"0x<combined_hex_session_key>"}
```

Then submit the on-chain transaction via [Polkadot.js Apps](https://polkadot.js.org/apps/):

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

### 7. Submit Validator Registration

This locks **1 000 ORB** as a bond and places your account in the **pending** queue. Your account must have > 1 001 ORB free balance.

> **Prerequisites enforced on-chain:** If session keys (Step 6) or EVM relay address (Step 5) are not registered, this call will fail with `NoSessionKeys` or `NoRelayer`.

Via [Polkadot.js Apps](https://polkadot.js.org/apps/):

```
Developer → Extrinsics
  Pallet:  validatorSet
  Method:  registerValidator()
  Sign with: your validator account
```

On success, a `ValidatorRegistrationRequested` event is emitted and your bond is locked. You are now in the **pending** queue — not yet an active validator.

---

### 8. Request Approval

Validators are permissioned on Orbinum Testnet. Contact the Orbinum team on **Discord** with:

- Your **Substrate AccountId** (from the log box in Step 5)
- Your **EVM relay address** (from the log box in Step 5, `0x...` 40 hex chars)
- Your **server's public IP** and **Peer ID** (`12D3KooW...`)
- Confirmation that `registerValidator()` was called and `ValidatorRegistrationRequested` was emitted

The team will execute on-chain:
```
1. relayer → registerRelayer(who, evmAddress)    ← links your EVM address
2. validatorSet → approveValidator(who)           ← moves you to the active set
```

You can verify your status at any time via Polkadot.js Apps:

```
Developer → Chain state → validatorSet → approvedValidators()
Developer → Chain state → validatorSet → pendingValidators()
```

---

### 9. Wait for the Next Session

Validator set changes take effect at the **next session boundary**. Sessions on Orbinum Testnet are **600 blocks** — approximately 1 hour at 6 seconds per block.

Once the session boundary is crossed, your node will begin authoring and finalizing blocks:

```
Prepared block for proposing at #1801 ...
Idle (5 peers), best: #1802 ...
```

---

## Part 5 — Operations

### Keeping the Node Updated

The Orbinum team publishes new testnet releases periodically. Your node needs to stay on the latest version.

#### Docker — automatic (Watchtower)

If you are running with Docker, **no action is required**. Watchtower checks GHCR every 5 minutes and restarts the container automatically when `testnet-latest` is updated.

To force an immediate update without waiting:

```bash
docker compose pull && docker compose up -d
```

---

### Bond and Deregistration

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

### Useful Commands

```bash
# View validator logs
docker compose logs -f orbinum-validator

# View Watchtower logs (check when updates were applied)
docker compose logs -f watchtower

# Stop everything
docker compose down

# Restart validator only
docker compose restart orbinum-validator

# Force update now (without waiting for Watchtower)
docker compose pull && docker compose up -d

# Full reset — deletes all chain data
docker compose down -v

# Resource usage
docker stats orbinum-validator
```

---

### Troubleshooting

**Node has 0 peers after several minutes**
- Confirm port `30333` is open and publicly reachable: `nc -zv <YOUR_PUBLIC_IP> 30333`
- Check that `testnet-spec.json` has bootnodes listed

**`author_insertKey` returns an error**
- Make sure the node is running before calling the RPC
- Port `9944` is not exposed to the host or network — it only listens on
  `127.0.0.1` inside the container. Always call it via `docker exec
  orbinum-validator curl ... http://localhost:9944` (see Step 4), not from the host directly.

**Node is not producing blocks after approval**
- Verify all keys are inserted: restart and check logs for `Loaded session key`
- The validator set update takes effect at the next session boundary (~1 h after approval)
- Confirm your AccountId is in `validatorSet → approvedValidators()`

**`registerValidator` fails with `NoRelayer`**
- Your EVM relay address has not been registered yet by the Orbinum team
- Share the values from the log box (Step 5) with the team and wait for confirmation

**`registerValidator` fails with `NoSessionKeys`**
- Verify that `session.setKeys` was called on-chain (Step 6)
- Confirm the combined key returned by `author_rotateKeys` was used correctly

**Watchtower is not updating the container**
- Confirm GHCR login is still valid: `docker login ghcr.io`
- Check Watchtower logs: `docker compose logs watchtower`
