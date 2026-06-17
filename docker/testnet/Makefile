# Orbinum Testnet — node operations
#
# Auto-detects the node role from which compose file exists on this server:
#   - docker-compose.rpc.yml present  → RPC / bootnode
#   - docker-compose.yml present      → validator
# Same Makefile on every server; each one operates on its own node.
#
# Usage:  make <target>     (run from this directory)
#         make help         lists all targets

# ── Role auto-detection ───────────────────────────────────────────────────────
# Prefer the RPC compose if it exists, else fall back to the validator compose.
COMPOSE := $(firstword $(wildcard docker-compose.rpc.yml docker-compose.yml))
# The volume name is "<project>_<volume>"; project defaults to this dir's name.
PROJECT := $(notdir $(CURDIR))
ifeq ($(COMPOSE),docker-compose.rpc.yml)
  CONTAINER := orbinum-rpc-node
  ROLE      := RPC
  VOLUME    := $(PROJECT)_rpc-node-data
else
  CONTAINER := orbinum-validator
  ROLE      := validator
  VOLUME    := $(PROJECT)_validator-data
endif

DC      := docker compose -f $(COMPOSE)
RPC_URL := http://127.0.0.1:9944

.DEFAULT_GOAL := help

# ── Basics ────────────────────────────────────────────────────────────────────
.PHONY: up
up: ## Start the node (and sidecars) in the background
	$(DC) up -d

.PHONY: down
down: ## Stop and remove containers (KEEPS volumes — chain data + keystore safe)
	$(DC) down

.PHONY: restart
restart: ## Restart the node container (keeps data + keystore)
	$(DC) restart

.PHONY: logs
logs: ## Follow the node logs (Ctrl+C to exit)
	$(DC) logs -f $(CONTAINER)

.PHONY: tail
tail: ## Last 50 log lines (no follow)
	$(DC) logs --tail 50 $(CONTAINER)

.PHONY: ps
ps: ## Show container status
	$(DC) ps

# ── Update ────────────────────────────────────────────────────────────────────
.PHONY: update
update: ## git pull, then recreate the node with the new compose/spec (keeps data)
	git pull
	$(DC) up -d --force-recreate

# ── Diagnostics ───────────────────────────────────────────────────────────────
.PHONY: peers
peers: ## Current peer count + best/finalized (last log line)
	@$(DC) logs --tail 20 $(CONTAINER) 2>&1 | grep -i 'Idle\|Syncing' | tail -1 || echo "no status line yet"

.PHONY: sync
sync: ## Chain sync state: best vs finalized (via local RPC)
	@docker run --rm --network container:$(CONTAINER) alpine/curl:latest -s \
	  -H "Content-Type: application/json" \
	  -d '{"id":1,"jsonrpc":"2.0","method":"system_syncState"}' $(RPC_URL) ; echo

.PHONY: keys
keys: ## List the keystore (validator only — expects aura + gran files)
	@docker run --rm -v $(VOLUME):/data alpine \
	  ls -la /data/chains/orbinum_testnet/keystore/ 2>/dev/null \
	  || echo "no keystore (this is an RPC node, or data volume missing)"

.PHONY: health
health: ## system_health via local RPC (peers, isSyncing)
	@docker run --rm --network container:$(CONTAINER) alpine/curl:latest -s \
	  -H "Content-Type: application/json" \
	  -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' $(RPC_URL) ; echo

# ── Re-genesis (DESTRUCTIVE — keeps keystore) ─────────────────────────────────
.PHONY: reset-chain
reset-chain: ## Wipe chain DB + network cache for a re-genesis. KEEPS keystore. Asks first.
	@echo "⚠️  This deletes the chain database and peer cache for $(ROLE) ($(CONTAINER))."
	@echo "    The keystore (session keys) is PRESERVED."
	@echo "    Use this only for a re-genesis (new chain-spec / genesis hash)."
	@printf "    Type 'yes' to continue: " && read ans && [ "$$ans" = "yes" ] || (echo "aborted" && exit 1)
	$(DC) down
	docker run --rm -v $(VOLUME):/data alpine \
	  rm -rf /data/chains/orbinum_testnet/db /data/chains/orbinum_testnet/network
	@echo "✅ Chain data wiped. Run 'make up' to start from the new genesis."

# ── Full cleanup (DESTRUCTIVE — wipes EVERYTHING) ─────────────────────────────
.PHONY: clean
clean: ## Wipe ALL: containers, volumes (chain DB + keystore), networks, images. Asks first.
	@echo "⚠️  This permanently DESTROYS everything for $(ROLE) ($(CONTAINER)):"
	@echo "    - containers (stopped + removed)"
	@echo "    - volumes    → chain database AND keystore (session keys LOST)"
	@echo "    - networks   (project networks removed)"
	@echo "    - images     (compose images removed)"
	@echo "    This is NOT recoverable. Back up the keystore first if you need it."
	@printf "    Type 'yes' to continue: " && read ans && [ "$$ans" = "yes" ] || (echo "aborted" && exit 1)
	$(DC) down --volumes --remove-orphans --rmi all
	@echo "✅ Full cleanup done. Run 'make up' to start fresh."

# ── Help ──────────────────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help
	@echo "Orbinum Testnet — role: $(ROLE)  (compose: $(COMPOSE))"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
