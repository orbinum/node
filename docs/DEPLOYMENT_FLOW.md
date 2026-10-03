# Deployment Flow — Testnet & Mainnet

How to ship changes to a running Orbinum network. The central question is
**runtime, image, or both** — get that right first, then follow the matching
runbook.

---

## Two independent update axes

An Orbinum node is two separable pieces. They version and deploy independently.

| Axis | What it is | How it changes on-chain | Consensus-critical? |
|------|-----------|--------------------------|---------------------|
| **Runtime** | The WASM blob (`spec_version`) — pallet logic, extrinsic validation, weights | `sudo.setCode(wasm)` — a transaction, no restart | **Yes.** Every node runs the same runtime by consensus. |
| **Image / binary** | The node executable — client, networking, RPC, host functions | Pull new Docker image + restart the node | No. Nodes can run different client versions. |

The runtime is stored *on-chain* and swapped by an extrinsic. The binary is the
*process* running the chain and swapped by restarting the container. Changing one
does not change the other.

---

## Decide: runtime, image, or both

Look at what your diff actually touches.

### Runtime upgrade required when the change is consensus-critical

Any change to on-chain behavior. If two nodes could disagree on whether a block
is valid, it is a runtime change. **Requires bumping `spec_version`** in
`template/runtime/src/lib.rs`.

- Pallet extrinsic logic (validation, storage reads/writes, dispatch)
- Runtime constants that gate extrinsics (`MaxProofSize`, `MaxPublicInputs`, …)
- New/removed pallets or calls
- Weight changes (they gate block inclusion)
- Anything under `frame/*/src`, `primitives/*`, or `template/runtime/src` that a
  node executes while validating a block

> `transaction_version` also bumps **only** if an extrinsic's SCALE signature or
> call index changes (breaks offline signing). Renaming a field, changing arg
> types, reordering calls. A pure logic change inside an extrinsic does not.

### Image update required when the change is client-side

Anything the *process* does, outside block execution.

- `client/`, `node/src` — RPC, networking, service wiring
- Host functions the runtime calls (e.g. native Poseidon) — the binary must
  provide them, so a runtime relying on a new host function needs the new binary too
- Chain-spec / bootnode / telemetry config baked into the image
- Dependency or base-image security patches

### Both — the common case for a feature release

Most feature work touches runtime logic *and* client/host code, or bumps weights
*and* ships a new binary. When in doubt, do both: runtime first, then image (see
ordering below).

### Quick reference

| Change | Runtime | Image |
|--------|:-------:|:-----:|
| Pallet extrinsic logic / storage | ✅ | — |
| Runtime constant (MaxProofSize, …) | ✅ | — |
| Weights regenerated | ✅ | — |
| New host function used by runtime | ✅ | ✅ |
| RPC / networking / service.rs | — | ✅ |
| Chain-spec / bootnodes / telemetry | — | ✅ |
| Base-image / client security patch | — | ✅ |
| Typical feature (logic + client) | ✅ | ✅ |

---

## How the pipeline maps to the axes

Two workflows. `release.yml` builds and publishes; `runtime-upgrade.yml` touches the
chain. Know what each does.

### `release.yml` — tag push (`vX.Y.Z`): **builds the testnet flavour, deploys nothing**

```
metadata → build → docker-publish → github-release
```

- Refuses the tag unless it is GPG-signed and equals `version` in
  `template/node/Cargo.toml`. The binary reports `<crate version>-<sha>` to telemetry
  and `--version`, so this is what makes "which release runs on that node" readable.
- Builds the binary and the runtime WASM with the `hyperbridge-testnet` feature.
- Publishes the Docker image as `X.Y.Z-testnet` and `testnet-latest`.
- Creates the GitHub Release (pre-release) with the WASM + binary attached.
- **Does NOT touch the chain.** No setCode. Pushing a tag is safe — it only produces
  artifacts (and Watchtower picks up the new image).

There is no `-rc` tag. Every release is a plain version; testnet gets all of them
and mainnet gets the ones promoted to it (below). Version = code, network = build
flavour.

### `release.yml` — manual dispatch: **mainnet promotion**

| Input | Effect |
|-------|--------|
| `environment` | Build flavour. `mainnet` = promotion; `testnet` = rebuild the testnet flavour of an existing tag |
| `version` | The release, e.g. `0.2.0` (git tag `v0.2.0`). Must be `X.Y.Z` |

A mainnet dispatch builds `v<version>` without the testnet feature, publishes `X.Y.Z` +
`latest`, attaches the mainnet assets to the existing GitHub Release and clears its
pre-release flag. It fails unless the tag is GPG-signed, matches the crate version,
and `X.Y.Z-testnet` was published. `docker-publish` waits for the `mainnet`
environment reviewer, since pushing `latest` is the fleet rollout. The build, the
image's final stage and the release notes all come from the tag, not from `main`.

### `runtime-upgrade.yml` — manual dispatch: **testnet setCode**

Actions → "Runtime Upgrade (testnet)" → Run workflow, input `image_tag`: a release
image (`0.1.0-rc.28`, `0.3.0-testnet`) or `testnet-latest`.

- `sudo.setCode` with the WASM extracted from that published image. **Does not
  compile.**
- **Testnet only.** The job is pinned to the `testnet` environment (reviewer
  required); there is no mainnet option, and a mainnet-flavour image is refused
  (`verify-coprocessor.sh testnet` on the image's binary). Mainnet runtime upgrades
  go through a multisig, never a sudo key held by CI.
- Four preflight guards run before any chain state is touched: the image resolves,
  it was built from the commit its git tag names (image tag minus `-testnet`, with a
  `v` prefix), `spec_version` strictly rises, and the RPC node already runs that
  release's binary. A floating `testnet-latest` names no git tag, so it skips the
  provenance and binary checks — prefer the release tag.
- One run at a time (`concurrency: runtime-upgrade-testnet`).

The **binary update is not a workflow job** — nodes run Watchtower, which pulls the
new `testnet-latest` (or `latest` on mainnet) image and restarts them automatically
once `docker-publish` publishes it.

> Ordering note: because Watchtower is autonomous, the binary may swap *before* the
> setCode. Harmless — a new binary is backward-compatible with the old runtime, and
> the setCode then bumps the runtime under it. Preflight guard 4 asserts the node
> got there first rather than trusting the timing.

> Recovery note: Watchtower now also revives a node that a bad image left `created`
> or `restarting`, and keeps the previous image on disk. Before that, a node killed
> by a broken image was invisible to Watchtower (it scans running containers only)
> and needed a human on every host — which is exactly what `v0.1.0-rc.23` cost.

---

## Runbooks

> **The binary always updates via Watchtower.** In every runbook below, pushing the
> tag publishes `testnet-latest` and Watchtower restarts the nodes onto it — no
> manual step. `runtime-upgrade.yml` is only ever for the runtime setCode.

### A. Image-only update (no runtime change)

`spec_version` unchanged. Example: an RPC fix, a base-image patch.

1. Merge to `main`, CI green.
2. Bump `version` in `template/node/Cargo.toml` (+ `Cargo.lock`), merge, tag
   `vX.Y.Z` → builds + publishes `testnet-latest`. Watchtower restarts the nodes
   onto the new image. **No workflow dispatch needed.**
3. Verify the client version bumped (allow a few minutes for Watchtower):
   ```bash
   bash scripts/check-deployment.sh --expect-impl <version> \
     https://rpc-1.testnet.orbinum.io https://rpc-2.testnet.orbinum.io
   ```

### B. Runtime-only upgrade

`spec_version` bumped; no client-side change worth chasing (the binary Watchtower
ships with the tag is fine).

1. **Bump `spec_version`** in `template/runtime/src/lib.rs`. Without it, setCode is
   rejected.
2. Regenerate weights if any extrinsic logic/storage changed (see
   [BENCHMARKING_STEPS.md](./BENCHMARKING_STEPS.md)).
3. Merge to `main`, CI green. Confirm:
   ```bash
   git show main:template/runtime/src/lib.rs | grep spec_version
   ```
4. Tag `vX.Y.Z` (crate version bumped to match) → builds the WASM (and image;
   Watchtower will pull it).
5. **Wait for the release run to finish `success`** (WASM built, image published).
6. Actions → "Runtime Upgrade (testnet)" → Run workflow: `image_tag: <release image>`.
7. Verify:
   ```bash
   bash scripts/check-deployment.sh --expect-spec <N> \
     https://rpc-1.testnet.orbinum.io https://rpc-2.testnet.orbinum.io
   ```

### C. Both — runtime + image (typical feature release)

1. **Bump `spec_version`** (+ `transaction_version` if a call signature changed).
2. Regenerate weights if needed.
3. Merge to `main`, CI green. Confirm `spec_version` on `main`.
4. **Baseline the current state** before deploying:
   ```bash
   bash scripts/check-deployment.sh \
     https://rpc-1.testnet.orbinum.io https://rpc-2.testnet.orbinum.io
   # note the current spec_version and client — this is your rollback reference
   ```
5. Tag `vX.Y.Z` (crate version bumped to match) → builds WASM + image. Watchtower
   restarts nodes onto the new binary. **Wait for the release run to finish `success`.**
6. Actions → "Runtime Upgrade (testnet)" → Run workflow: `image_tag: <release image>`. (Binary already updated via
   Watchtower — only the runtime setCode is left.)
7. Verify both axes moved:
   ```bash
   bash scripts/check-deployment.sh --expect-spec <N> \
     https://rpc-1.testnet.orbinum.io https://rpc-2.testnet.orbinum.io
   # spec_version == N and client shows the new commit hash
   ```

### D. spec 16 — memo-bound circuits (v1 → v2)

No migration rotates the keys: Root does it right after `setCode`, inside a
maintenance window with every service stopped, since a live v1 lets a pending
spend be resubmitted with swapped memos or an aliased recipient. Every client
able to prove v2 must be published **before** the window. Order:

| # | Step | Why first |
|---|---|---|
| 1 | `@orbinum/circuits` 0.15.0, with v1 **and** v2 in the manifest (`ROTATE_CIRCUIT=transfer,unshield`) | clients fetch v2 artifacts from it |
| 2 | `@orbinum/proof-generator` 8.0.0 | 8 public signals for v2; proves the version the provider serves |
| 3 | `@orbinum/protocol` 0.6.0, then `@orbinum/wallet-sdk` 0.5.0 (`CIRCUITS_PACKAGE_VERSION` 0.15.0, `proof-generator ^8.0.0`) | proves v2; keeps proving v1 until the chain moves |
| 4 | app, indexer, explorer on those versions | the old app's fee claim is gone in spec 16 |
| 5 | relay operators: `register_relayer` | the new relay RPC refuses unregistered addresses |
| 6 | node image (runbook C, step 5) | binary before runtime |
| 7 | stop every service (app, relays, indexer) | nothing may submit a v1 spend during the rotation |
| 8 | `setCode` (runbook C, step 6) | v1 is still the active version |
| 9 | sudo `zkVerifier.batchRegisterVerificationKeys` — both v2 keys, `version: 2`, `set_active: true` | v2 becomes the active version |
| 10 | sudo `zkVerifier.retireVersion(1, 1)` and `retireVersion(2, 1)` | closes the v1 window |
| 11 | resume the services | |

Before step 11, check `zkVerifier_getCircuitVersionInfo(1|2)`: `active_version = 2`,
`supported_versions = [2]`, and the v2 `vk_hash` equal to the manifest's.

---

## Creating and pushing tags

### When to cut a tag

Cut a tag when you have a **merged, CI-green `main`** that you want to release —
never before the merge lands. A tag is the release trigger; tagging an unmerged
branch ships a release off a commit that is not on `main`.

- **Any release → testnet:** `vX.Y.Z`. Patch bump for client-only changes, minor
  bump when the runtime changes (`spec_version` moved).
- **Promoting a vetted release → mainnet:** no new tag. Dispatch the workflow on the
  same version with `environment: mainnet`. This only ships
  the binary; the mainnet runtime upgrade goes through a multisig, never this workflow.
- Don't tag for every commit. Tag when you intend to deploy. Between deploys,
  work merges to `main` without tags.

### Version format

The trigger matches `v[0-9]+.[0-9]+.[0-9]+` only. A suffixed tag (`-rc.N`) does not
release anything. The tag must equal `version` in `template/node/Cargo.toml` or the
`metadata` job fails.

| Version | Runtime changed? | Example |
|---------|:----------------:|---------|
| Patch `X.Y.Z+1` | no | RPC fix, base-image patch, telemetry |
| Minor `X.Y+1.0` | yes (`spec_version` bumped) | Pallet logic, weights, new host function |

| Run | Flavour | Docker tags | GitHub Release |
|-----|---------|-------------|----------------|
| Tag push `v0.2.0` | testnet | `0.2.0-testnet`, `testnet-latest` | `Orbinum 0.2.0`, pre-release, testnet assets |
| Dispatch `mainnet` on `0.2.0` | mainnet | `0.2.0`, `latest` | same release, pre-release cleared, mainnet assets added |

Three versions live in the repo; only two matter:

- `template/node/Cargo.toml` `version` — **the release**. Shown by telemetry and
  `--version` as `0.2.0-<sha>`. Bump every release.
- `spec_version` in `template/runtime/src/lib.rs` — the on-chain runtime. Bump only
  when the WASM changes; setCode rejects an equal or lower value.
- `template/runtime/Cargo.toml` `version` — cosmetic. Nothing reads it; keep it in
  step with the node crate if you like.

Historic testnet tags (`v0.1.0-rc.1` … `v0.1.0-rc.27`) stay as they are; the first
tag under this scheme is `v0.2.0`.

### Prerequisite: GPG-signed tags

**Tags must be GPG-signed.** The release CI runs `git verify-tag` against
`RELEASE_GPG_PUBLIC_KEY` and **fails the whole release if the signature is missing
or unknown**. One-time setup:

```bash
git config user.signingkey <your-key-id>     # gpg --list-secret-keys --keyid-format=long
gpg --list-secret-keys                        # confirm the key exists
```
The public key must be in the repo's `RELEASE_GPG_PUBLIC_KEY` secret. Signed tags
are cut locally (GPG is interactive) — never in CI.

### Cutting the tag

```bash
# 1. Be on the merged main
git checkout main && git pull origin main

# 2. Sanity-check what you're about to release
git log -1 --oneline                                   # the merge commit
grep -m1 '^version' template/node/Cargo.toml           # == the tag you are about to cut
git show main:template/runtime/src/lib.rs | grep spec_version   # bumped if runtime change

# 3. Confirm the tag is free — never reuse one
git fetch origin --tags
git tag -l "v*" | sort -V | tail -3

# 4. Create the signed tag and push it
git tag -s vX.Y.Z -m "<what this release contains>"
git push origin vX.Y.Z
```

Pushing the tag triggers `release.yml` (build + publish). It does **not** deploy —
that's `runtime-upgrade.yml` (see runbooks above).

### Tag hygiene

- Tags are immutable release points. **Never reuse a tag** — each `vX.Y.Z` cuts one
  release from one commit.
- If a release fails mid-run, fix the cause, bump the crate version, merge to
  `main`, and cut the **next** version. Do not delete and re-push the same tag.
- A version that never reached mainnet is still a version. Gaps in mainnet's
  sequence are expected; gaps in the tag sequence are not.

---

## Testnet vs Mainnet

The pipeline is the same; the caution level is not.

| | Testnet | Mainnet |
|-|---------|---------|
| Release | Tag push `vX.Y.Z` → `X.Y.Z-testnet`, `testnet-latest` | Dispatch `release.yml` with `mainnet` on a testnet-proven version → `X.Y.Z`, `latest` |
| Runtime upgrade | Deploy directly via workflow | Multisig, not a raw sudo setCode — separate flow, not `runtime-upgrade.yml` |
| Weights hardware | CCX33 reference (see BENCHMARKING_STEPS.md); shared-vCPU tolerated for RC | Dedicated CCX only — shared-vCPU noise is not acceptable |
| Rollout | Both nodes at once is fine | Canary one node, watch finality, then the rest |
| Pre-deploy | Baseline check | Baseline check + a tested rollback runtime staged |

**Mainnet rule:** never `sudo.setCode` a runtime that has not run on testnet first.
Every version ships to testnet before it can be promoted; that run is the dress
rehearsal for the mainnet release.

---

## Scripts

- [`scripts/deploy-runtime.sh`](../scripts/deploy-runtime.sh) — `sudo.setCode`, checks
  `spec_version` rose. Run by `runtime-upgrade.yml`.
- [`scripts/check-deployment.sh`](../scripts/check-deployment.sh) — reads
  `spec_version` / client version per RPC; `--expect-spec` / `--expect-impl` fail
  the command if a node is off-version.
- [`scripts/healthcheck.sh`](../scripts/healthcheck.sh) — node liveness / runtime check.
