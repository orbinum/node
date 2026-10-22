# Overview

Orbinum is a Substrate-based network that pairs a zero-knowledge shielded pool
with a full Ethereum compatibility layer. The transparent side behaves like any
EVM chain; the private side holds value as cryptographic commitments that reveal
neither amounts nor participants.

## The two domains

Value moves between a public domain and a private one:

- **Public.** An `AccountId` with a visible balance, usable from Solidity
  contracts and standard Ethereum tooling.
- **Private.** A note, represented on-chain only by a Poseidon commitment
  `Poseidon4(value, asset_id, owner_pubkey, blinding)` inserted as a leaf in a
  Merkle tree. Nothing about the note is visible beyond the commitment itself.

Three operations connect them:

| Operation | Direction | What it reveals |
|---|---|---|
| `shield` | public to private | depositor and amount |
| `private_transfer` | private to private | the asset and the relay fee |
| `unshield` | private to public | recipient and amount |

Spending a note publishes its nullifier, `Poseidon2(commitment, spending_key)`.
The chain records nullifiers in a set and rejects repeats, which prevents
double-spending without linking the nullifier back to the commitment it came
from.

## Proofs

Every private operation carries a Groth16 proof over BN254, verified in the
runtime by `pallet-zk-verifier`. The circuits are written in Circom and live in
[orbinum/circuits](https://github.com/orbinum/circuits); the runtime stores only
their verification keys, versioned per circuit and rotatable by governance.

A transfer proof establishes, without revealing the notes involved, that:

- each input commitment is a member of a known Merkle root
- the spender owns each input note, via an EdDSA signature over the commitment
- each published nullifier matches its input note
- each output commitment is correctly formed
- value is conserved: `sum(inputs) == sum(outputs) + fee`
- every note in the transaction uses the same asset

## Gasless submission

`private_transfer` and `unshield` are unsigned extrinsics. A signature would
identify the sender, so instead the proof itself authorises the operation and
the fee is deducted from the note value inside the circuit. A relayer submits
the transaction, pays gas, and accrues the fee as a credit it can later claim as
a shielded note of its own.

Relayers can be reached through the shielded-pool EVM precompile, which takes
the caller's address as the fee recipient, or through a node running the
built-in relay RPC.

## Note recovery

Because a commitment hides its own contents, a wallet cannot tell which notes
belong to it by looking at the chain. Each commitment therefore carries an
encrypted memo holding the note's preimage, encrypted with ChaCha20-Poly1305
under a key derived by BabyJubJub ECDH between the sender's ephemeral key and
the recipient's incoming viewing key. A wallet scans memos and keeps the ones it
can decrypt.

## Components

| Crate | Role |
|---|---|
| `pallet-shielded-pool` | Commitments, nullifiers, the Merkle forest, and the three operations |
| `pallet-zk-verifier` | Versioned verification keys and Groth16 verification |
| `pallet-relayer` | Relay configuration, the EVM-to-Substrate relayer registry, and fee accounting |
| `pallet-validator-set` | Two-phase validator registration behind governance approval |
| `orbinum-zk-core` | Poseidon hashing and field-element handling, shared by runtime and clients |
| `orbinum-encrypted-memo` | Memo layout, key derivation, and memo encryption |

## Relationship to Frontier

The EVM pallets, the Ethereum RPC layer, and much of the client infrastructure
are derived from [Frontier](https://github.com/polkadot-evm/frontier). Orbinum
adds the privacy stack above and a precompile that bridges Solidity calls into
the shielded pool. See the [attribution note](https://github.com/orbinum/node#attribution)
in the repository README.
