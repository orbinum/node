
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

Do **not** open port `9944` — Nginx will proxy it.

## DNS

Point your domain to the server's public IP before requesting a certificate:

```
testnet-rpc.orbinum.io  A  <PUBLIC_IP>
```

## Install Nginx and Certbot

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

## Start the RPC node

```bash
cd docker/testnet
docker compose -f docker-compose.rpc.yml up -d
docker compose -f docker-compose.rpc.yml logs -f rpc-node
```

Wait until you see `Idle` or `Syncing` in the logs before configuring Nginx.

## Configure Nginx

```bash
sudo nano /etc/nginx/sites-available/orbinum-rpc
```

```nginx
server {
    server_name testnet-rpc.orbinum.io;

    proxy_read_timeout 300s;
    proxy_send_timeout 300s;

    location / {
        proxy_pass http://127.0.0.1:9944;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    listen 80;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/orbinum-rpc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Enable TLS

```bash
sudo certbot --nginx -d testnet-rpc.orbinum.io
```

Certbot modifies the Nginx config automatically and sets up auto-renewal.

## Verify

```bash
# HTTP
curl -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_health","params":[]}' \
  https://testnet-rpc.orbinum.io

# Expected: {"jsonrpc":"2.0","result":{"isSyncing":false,"peers":3,...},"id":1}
```

The endpoint is ready to use as:
- `https://testnet-rpc.orbinum.io` — HTTP RPC
- `wss://testnet-rpc.orbinum.io` — WebSocket (Polkadot.js, Talisman)

## Useful Commands

```bash
# Stop the node
docker compose -f docker-compose.rpc.yml down

# Full reset
docker compose -f docker-compose.rpc.yml down -v

# Check sync status
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_syncState","params":[]}' \
  https://testnet-rpc.orbinum.io | jq
```
