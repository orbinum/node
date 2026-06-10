
# RPC Node

The RPC node exposes a public HTTP/WebSocket endpoint for wallets, dApps, and the explorer. It does **not** participate in consensus.

## Firewall ports

```bash
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP (Let's Encrypt challenge)
sudo ufw allow 443/tcp     # HTTPS / WSS
sudo ufw allow 30333/tcp   # P2P
sudo ufw enable
```

Do **not** open port `9944` — Caddy proxies it over HTTPS/WSS on 443.

## DNS

Point your domain to the server's public IP **before** starting the node —
Caddy needs a resolvable A record to obtain a Let's Encrypt certificate:

```
rpc-1.testnet.orbinum.io  A  <PUBLIC_IP>
```

## Configure the `.env` file

```bash
cd docker/testnet
cp .env.rpc.example .env
```

Edit `.env` and set:

| Variable       | What to set                                                         |
| -------------- | ------------------------------------------------------------------- |
| `RPC_NAME`     | Identifiable name shown in telemetry (e.g. `Orbinum-RPC-1`).        |
| `RPC_NODE_KEY` | This node's libp2p key — generate with `openssl rand -hex 32`.      |
| `RPC_DOMAIN`   | Public domain with a DNS A record pointing to this VPS's public IP. |

> **Keep `RPC_NODE_KEY` stable** — this node's PeerId goes public in `bootNodes`.
> If the key changes, the PeerId changes and the chain spec's bootnode entry breaks.

## Start the RPC node

The `docker-compose.rpc.yml` stack runs the node **and Caddy**. Caddy reverse-proxies
HTTPS/WSS on port 443 to the node's local RPC (`localhost:9944`) and obtains/renews
a Let's Encrypt certificate for `RPC_DOMAIN` automatically — no Nginx or Certbot needed.

```bash
docker compose -f docker-compose.rpc.yml up -d
docker compose -f docker-compose.rpc.yml logs -f rpc-node
```

Wait until you see `Idle` or `Syncing` in the logs. On first start, check that Caddy
issued the certificate (needs ports 80 + 443 open and DNS resolving):

```bash
docker compose -f docker-compose.rpc.yml logs caddy | grep -i "certificate obtained"
```

## Verify

Use the domain you set in `RPC_DOMAIN` (replace below):

```bash
curl -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_health","params":[]}' \
  https://rpc-1.testnet.orbinum.io

# Expected: {"jsonrpc":"2.0","result":{"isSyncing":false,"peers":3,...},"id":1}
```

The endpoint is ready to use as:
- `https://rpc-1.testnet.orbinum.io` — HTTP RPC
- `wss://rpc-1.testnet.orbinum.io` — WebSocket (Polkadot.js, Talisman)

## Useful Commands

```bash
# Stop the node
docker compose -f docker-compose.rpc.yml down

# Full reset
docker compose -f docker-compose.rpc.yml down -v

# Check sync status
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_syncState","params":[]}' \
  https://rpc-1.testnet.orbinum.io | jq
```
