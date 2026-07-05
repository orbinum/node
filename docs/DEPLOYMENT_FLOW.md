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

`release.yml` has two triggers. Know what each does.

### Tag push (`v*.*.*` / `v*.*.*-rc.N`) — **builds artifacts, deploys nothing**

```
build → docker-publish → github-release
```

- Builds the binary and the runtime WASM.
- Publishes the Docker image. A prerelease tag (`-rc.N`) tags it `testnet-latest`;
  a stable tag (`vX.Y.Z`) tags it `latest`.
- Creates the GitHub Release with the WASM + binary attached.
- **Does NOT touch the chain.** No setCode, no node restart. Pushing a tag is safe
  — it only produces artifacts.

### Manual dispatch (Actions → "Release & Deploy" → Run workflow) — **deploys**

The input gates the deploy job:

| Input | Job | Effect |
|-------|-----|--------|
| `deploy_runtime: true` | `deploy-runtime` | `sudo.setCode(wasm)` — **runtime upgrade** on-chain |

The **binary update is not a workflow job** — nodes run Watchtower, which pulls the
new `testnet-latest` image and restarts them automatically once the tag's
`docker-publish` job publishes it. So the manual dispatch only ever does the
runtime upgrade; the binary follows on its own.

> Ordering note: because Watchtower is autonomous, the binary may swap *before* the
> setCode. Harmless — a new binary is backward-compatible with the old runtime, and
> the setCode then bumps the runtime under it.

---

## Runbooks

> **The binary always updates via Watchtower.** In every runbook below, pushing the
> tag publishes `testnet-latest` and Watchtower restarts the nodes onto it — no
> manual step. The manual dispatch is only ever for the runtime setCode.

### A. Image-only update (no runtime change)

`spec_version` unchanged. Example: an RPC fix, a base-image patch.

1. Merge to `main`, CI green.
2. Tag `vX.Y.Z-rc.N` → builds + publishes `testnet-latest`. Watchtower restarts the
   nodes onto the new image. **No workflow dispatch needed.**
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
4. Tag `vX.Y.Z-rc.N` → builds the WASM (and image; Watchtower will pull it).
5. **Wait for the release run to finish `success`** (WASM built, image published).
6. Actions → Run workflow: `deploy_runtime: true`.
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
5. Tag `vX.Y.Z-rc.N` → builds WASM + image. Watchtower restarts nodes onto the new
   binary. **Wait for the release run to finish `success`.**
6. Actions → Run workflow: `deploy_runtime: true`. (Binary already updated via
   Watchtower — only the runtime setCode is left.)
7. Verify both axes moved:
   ```bash
   bash scripts/check-deployment.sh --expect-spec <N> \
     https://rpc-1.testnet.orbinum.io https://rpc-2.testnet.orbinum.io
   # spec_version == N and client shows the new commit hash
   ```

---

## Creating and pushing tags

### When to cut a tag

Cut a tag when you have a **merged, CI-green `main`** that you want to release —
never before the merge lands. A tag is the release trigger; tagging an unmerged
branch ships a release off a commit that is not on `main`.

- **Image-only or runtime change → testnet:** `vX.Y.Z-rc.N` (prerelease).
- **Promoting a vetted RC → stable/mainnet:** `vX.Y.Z` (no suffix).
- Don't tag for every commit. Tag when you intend to deploy. Between deploys,
  work merges to `main` without tags.

### Version format

The trigger matches `v[0-9]+.[0-9]+.[0-9]+` and `v[0-9]+.[0-9]+.[0-9]+-*`.

| Tag | `is_prerelease` | Docker tag | Meaning |
|-----|:---------------:|-----------|---------|
| `v0.1.0-rc.5` | true | `testnet-latest` | Testnet release candidate |
| `v0.1.0-alpha.1` / `-beta.1` / `-pre.1` | true | `testnet-latest` | Also prerelease → testnet |
| `v0.1.0` | false | `latest` | Stable release |

The `-rc` / `-alpha` / `-beta` / `-pre` suffix is what classifies a tag as a
prerelease (`release.yml` metadata step). Increment `N` per RC (`rc.1`, `rc.2`, …).

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
git show main:template/runtime/src/lib.rs | grep spec_version   # bumped if runtime change

# 3. Pick the next free tag — never reuse one
git fetch origin --tags
git tag -l "v0.1.0-rc.*" | sort -V                     # last used → pick next N

# 4. Create the signed tag and push it
git tag -s v0.1.0-rc.N -m "<what this release contains>"
git push origin v0.1.0-rc.N
```

Pushing the tag triggers `release.yml` (build + publish). It does **not** deploy —
that's the separate manual dispatch (see runbooks above).

### Tag hygiene

- Tags are immutable release points. **Never reuse a tag** — each `-rc.N` cuts one
  release from one commit. If a tag already exists, bump to the next `N`.
- If a release fails mid-run, fix the cause, merge to `main`, and cut the **next**
  `N`. Do not delete and re-push the same tag.

---

## Testnet vs Mainnet

The pipeline is the same; the caution level is not.

| | Testnet | Mainnet |
|-|---------|---------|
| Tag | `vX.Y.Z-rc.N` (prerelease → `testnet-latest`) | `vX.Y.Z` (stable → `latest`) |
| Runtime upgrade | Deploy directly via workflow | Behind on-chain governance / multisig, not a raw sudo setCode |
| Weights hardware | CCX33 reference (see BENCHMARKING_STEPS.md); shared-vCPU tolerated for RC | Dedicated CCX only — shared-vCPU noise is not acceptable |
| Rollout | Both nodes at once is fine | Canary one node, watch finality, then the rest |
| Pre-deploy | Baseline check | Baseline check + a tested rollback runtime staged |

**Mainnet rule:** never `sudo.setCode` a runtime that has not run on testnet first.
The testnet RC is the dress rehearsal for the mainnet release.

---

## Scripts

- [`scripts/deploy-runtime.sh`](../scripts/deploy-runtime.sh) — `sudo.setCode`, checks
  `spec_version` rose. Run by the `deploy-runtime` job.
- [`scripts/check-deployment.sh`](../scripts/check-deployment.sh) — reads
  `spec_version` / client version per RPC; `--expect-spec` / `--expect-impl` fail
  the command if a node is off-version.
- [`scripts/healthcheck.sh`](../scripts/healthcheck.sh) — node liveness / runtime check.
