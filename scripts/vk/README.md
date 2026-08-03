# VK Scripts Architecture

This folder centralizes all Verification Key (VK) operations for development and local workflows.

## Structure

- `lib/registry.sh`
  - Atomic on-chain operations by circuit/version:
    - `register`
    - `set-active`
    - `remove`
- `workflows/setup-dev.sh`
  - DEV bootstrap for fixed circuits `1,2,6`.
- `workflows/rotate-dev.sh`
  - Version rotation `old -> new` with RPC validation and optional `--remove-old`.
- `policy/verify-window-dev.sh`
  - Version-window policy validation (`active` + `supported_versions`).

## Conventions

- Do not use legacy scripts outside this namespace.
- `lib/` does not depend on `workflows/`.
- `workflows/` uses `policy/` to gate destructive actions.
- Artifact source: `node/artifacts/verification_key_*.json`.

## Core commands

- Setup:
  - `bash scripts/vk/workflows/setup-dev.sh ws://127.0.0.1:9944 "//Alice" 1`
- Rotate:
  - `bash scripts/vk/workflows/rotate-dev.sh 2 ws://127.0.0.1:9944 "//Alice" 1`
- Rotate + remove old:
  - `bash scripts/vk/workflows/rotate-dev.sh 2 ws://127.0.0.1:9944 "//Alice" 1 --remove-old`
- Verify window:
  - `bash scripts/vk/policy/verify-window-dev.sh 2 http://127.0.0.1:9944 "1,2" true`
- Purge a retired circuit:
  - `bash scripts/vk/lib/registry.sh purge 5 ws://127.0.0.1:9944 "//Alice"`

## Retiring a whole circuit

`remove` and `retire` both refuse to touch a circuit's active version — the guard
that stops a live circuit from ending up with no key to verify against. A circuit
with a single registered version is therefore unreachable by either call, so
retiring one as a whole needs `purge`.

`purge_circuit` clears all five maps (`VerificationKeys`, `VkHashes`,
`VerificationStats`, `RetiredVersions`, `ActiveCircuitVersion`) and accepts a
circuit **only** when the runtime no longer implements it, i.e. when
`expected_public_inputs` returns `None`. Transfer (1), unshield (2) and
value_proof (6) are rejected with `CircuitStillInUse` for as long as they remain
compiled in — storage contents cannot override that.

Order matters: deploy the runtime that drops the circuit **first**, then purge.
Purging against a runtime that still knows the id just fails.

For the `private_link` circuit (id 5) no manual call is needed —
`pallet_zk_verifier::migrations::v1::MigrateToV1` clears it during the runtime
upgrade.

## Security

### Who can modify VKs?

Only the account holding the **sudo key** of the chain. All management extrinsics
(`register_verification_key`, `set_active_version`, `remove_verification_key`,
`batch_register_verification_keys`) enforce `ensure_root(origin)` at the runtime
level — any other origin is rejected with `BadOrigin` before the call is executed.
Regular nodes, validators, and signed accounts have no access.

`verify_proof` is the only extrinsic that accepts a signed (non-root) origin, and
it is read-only from a state perspective.

### Passing the sudo seed safely in production

Never pass the mnemonic inline on the CLI — it ends up in shell history:

```bash
# BAD — mnemonic visible in `history`
bash scripts/vk/workflows/setup-dev.sh ws://... "word1 word2 ..." 1

# GOOD — load from environment variable
export SUDO_SEED="word1 word2 ..."
bash scripts/vk/workflows/setup-dev.sh ws://... "$SUDO_SEED" 1
unset SUDO_SEED
```

After the session, clear the history entry:

```bash
history -d $(history 1 | awk '{print $1}')
```
