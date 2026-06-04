# Release Signing & Tag Protection

All Orbinum Node releases are signed with GPG using an Ed25519 key. This guarantees that any published binary, Docker image, or release artifact was produced from a tag created by a trusted maintainer — not an arbitrary commit or unsigned push.

---

## How it works

```
Maintainer signs tag locally (GPG Ed25519)
         ↓
git push origin vX.Y.Z[-rc.N]
         ↓
GitHub Actions: Verify GPG signature
         ↓  (fails → pipeline blocked)
Build binary + WASM
         ↓
Publish Docker image (ghcr.io/orbinum/node)
GitHub Release (binary + WASM + checksums)
         ↓
Runtime upgrade on-chain  ← manual via workflow_dispatch
```

The CI pipeline **refuses to build or publish anything** if the tag signature is missing or invalid.

---

## Signing key

| Field       | Value                                                                |
| ----------- | -------------------------------------------------------------------- |
| Algorithm   | Ed25519 (ECC)                                                        |
| Key ID      | `B82CFAF08B9338D5`                                                   |
| Fingerprint | `9925 5706 A9BC A11B 6B25 6B38 B82C FAF0 8B93 38D5`                  |
| UID         | Orbinum Release (Orbinum Node Releases) `<nome.ahumada@outlook.com>` |
| Expires     | Never                                                                |

The **public key** is stored as a GitHub Actions secret (`RELEASE_GPG_PUBLIC_KEY`) and imported in CI to verify each tag. The **private key** never leaves the maintainer's machine.

---

## Tag naming convention

| Pattern          | Type        | Docker tag published              |
| ---------------- | ----------- | --------------------------------- |
| `v1.0.0`         | Stable      | `1.0.0`, `1.0`, `latest`          |
| `v1.0.0-rc.1`    | Pre-release | `1.0.0-rc.1`, `testnet-latest`    |
| `v1.0.0-alpha.1` | Pre-release | `1.0.0-alpha.1`, `testnet-latest` |
| `v1.0.0-beta.1`  | Pre-release | `1.0.0-beta.1`, `testnet-latest`  |

Stable releases update `latest`. Pre-releases (suffix `-rc`, `-alpha`, `-beta`, `-pre`) only update `testnet-latest`.

> **Current strategy**: Orbinum is in testnet phase. All releases use pre-release tags (`-rc.N`). Stable tags (`v1.0.0`) are reserved for mainnet launch.

---

## Creating a release (maintainers)

### Prerequisites (one-time setup)

```bash
# 1. Verify your GPG config
gpg --list-secret-keys --keyid-format LONG

# 2. Configure git to sign all tags automatically
git config --global user.signingkey B82CFAF08B9338D5
git config --global tag.gpgsign true

# 3. Ensure GPG can prompt for passphrase in terminal
echo 'export GPG_TTY=$(tty)' >> ~/.zshrc
echo "pinentry-mode loopback" >> ~/.gnupg/gpg.conf
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
```

### Publishing a testnet release (pre-release)

```bash
# 1. Ensure main is clean and up to date
git checkout main && git pull

# 2. Create signed pre-release tag
git tag -s v1.0.0-rc.1 -m "Testnet release candidate 1"

# 3. Verify the signature locally before pushing
git verify-tag v1.0.0-rc.1

# 4. Push — triggers CI: build + Docker testnet-latest + GitHub Release
git push origin v1.0.0-rc.1
```

### Publishing a mainnet release (stable — reserved for mainnet launch)

```bash
git tag -s v1.0.0 -m "Mainnet launch"
git verify-tag v1.0.0
git push origin v1.0.0
# → publishes ghcr.io/orbinum/node:latest
```

### Triggering a runtime upgrade on-chain (manual)

After a release is published, the on-chain runtime upgrade must be triggered manually:

```
GitHub → Actions → Release → Run workflow
  deploy_runtime: true
```

This requires `TESTNET_RPC_WS` and `TESTNET_SUDO_SEED` secrets to be configured.

### Recreating a tag (if needed)

```bash
git tag -d v1.0.0                    # delete local
git push origin --delete v1.0.0      # delete remote
git tag -s v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

---

## Verifying a release (validators / users)

Anyone can verify that a tag was signed by the Orbinum release key:

```bash
# 1. Import the Orbinum release public key from the keyserver
gpg --keyserver keys.openpgp.org --recv-keys B82CFAF08B9338D5

# 2. Verify the tag
git fetch --tags
git verify-tag v1.0.0
```

Expected output:
```
gpg: Signature made ...
gpg:                using EDDSA key 99255706A9BCA11B6B256B38B82CFAF08B9338D5
gpg: Good signature from "Orbinum Release (Orbinum Node Releases) <nome.ahumada@outlook.com>"
```

---

## Key rotation

If the signing key needs to be rotated (lost passphrase, compromised machine, maintainer change):

1. Generate a new Ed25519 GPG key
2. Update the `RELEASE_GPG_PUBLIC_KEY` secret in GitHub (`Settings → Secrets → Actions`)
3. Update `git config --global user.signingkey <NEW_KEY_ID>` on the maintainer's machine
4. Update the key information in this document
5. Announce the key rotation to validators

---

## Security model

- Tags pushed without a valid GPG signature are **silently ignored** by the pipeline — no build, no Docker image, no release
- The private key is protected by a passphrase and never stored in GitHub
- The public key in CI is only used for verification — it cannot sign anything
- Docker images are built deterministically from the exact commit the signed tag points to
