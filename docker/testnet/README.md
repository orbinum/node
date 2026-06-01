# Orbinum Testnet — Node Setup

This directory contains Docker configuration for running Orbinum testnet nodes.

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build — shared by all node types |
| `docker-compose.yml` | Validator node |
| `docker-compose.rpc.yml` | RPC node |
| `testnet-spec.json` | Raw chain spec — used by all nodes |

---

# Validator Node

This section covers everything needed to run a validator node on the Orbinum public testnet.

---

## Hardware Requirements

| Resource | Minimum |
|----------|---------|
| CPU | 2 vCPU dedicated (AMD EPYC recommended) |
| RAM | 8 GB |
| Disk | 80 GB SSD |
| Bandwidth | 10 TB/month |
| OS | Ubuntu 22.04 LTS or 24.04 LTS |

Recommended: **Hetzner CCX13** (~$18.49/mo). Shared CPU instances are not recommended for validators due to CPU contention during ZK proof verification.

---

## Prerequisites

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect.

### 2. Install Docker Compose

```bash
sudo apt-get install -y docker-compose-plugin
docker compose version
```

### 3. Open firewall ports

```bash
# P2P port (required — must be publicly reachable)
sudo ufw allow 30333/tcp

# Prometheus (optional — for internal monitoring only)
sudo ufw allow 9615/tcp

sudo ufw enable
```

Do **not** open port `9944` on validator nodes. RPC is only exposed on the dedicated RPC node.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/orbinum/node.git
cd node
```

### 2. Get the chain spec

The `testnet-spec.json` is distributed via the repository. Verify it has the correct genesis hash before using it:

```bash
cat docker/testnet/testnet-spec.json | jq '.genesis.raw.top."0x3a636f6465"' | head -c 66
# Expected: 0x52bc537646db8e0528b52ffd0088ac18...
```

### 3. Build the Docker image

```bash
cd docker/testnet
docker compose build
```

This compiles the node binary from source inside Docker (~10–20 min on first run).

---

## Generate Session Keys

Session keys are required for block production and finalization. Each validator needs a unique set.

The keys must be generated using the same binary that will run the node. The easiest approach is to start the node once without `--validator`, call `author_rotateKeys`, then restart with `--validator`.

Alternatively, use pre-generated keys from `scripts/testnet-keys/` (contact the core team for access).

---

## Start the Node

```bash
cd docker/testnet
docker compose up -d
```

View logs:

```bash
docker compose logs -f validator-1
```

### Confirm the node is running

```bash
# Should show "Idle" or "Preparing" with peer count > 0
docker compose logs validator-1 | grep -E "Idle|Preparing|peers"

# Get your Peer ID (needed for bootnode registration)
docker compose logs validator-1 | grep "Local node identity"
# → Local node identity is: 12D3KooW...
```

---

## Insert Session Keys

Once the node is running, insert the Aura and GRANDPA keys into the keystore:

```bash
# Aura (Sr25519)
curl -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["aura","<MNEMONIC>","<AURA_PUBKEY_HEX>"]}' \
  http://localhost:9944

# GRANDPA (Ed25519)
curl -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"author_insertKey","params":["gran","<MNEMONIC>","<GRANDPA_PUBKEY_HEX>"]}' \
  http://localhost:9944
```

Keys are stored in the node's keystore and persist across restarts. **Never share your mnemonics.**

---

## Useful Commands

```bash
# Stop the node
docker compose down

# Restart
docker compose restart validator-1

# Full reset (deletes all chain data)
docker compose down -v

# Check resource usage
docker stats orbinum-validator-1
```
