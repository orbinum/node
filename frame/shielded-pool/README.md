# pallet-shielded-pool

Shielded Pool pallet for private transactions in Orbinum.

## Overview

This pallet implements a privacy pool based on the UTXO model with commitments and nullifiers. It allows users to:

- **Shield**: Deposit public tokens into the private pool
- **Private Transfer**: Transfer tokens privately within the pool using ZK proofs
- **Unshield**: Withdraw tokens from the private pool to a public account

## Architecture

The shielded pool uses a **UTXO (Unspent Transaction Output)** model where:

1. Funds enter the pool via `shield()` - converting to private "notes"
2. Transfers are private - only commitments visible on-chain
3. Funds exit via `unshield()` - revealed when user chooses

### Key Components

- **Merkle Tree**: Stores commitments of all notes (depth 32)
- **Nullifier Set**: Prevents double-spending
- **ZK Proofs**: Verify transaction validity without revealing details

## Usage

### Shield (Deposit)

```rust
// Deposit 100 tokens into the pool
ShieldedPool::shield(origin, 100, commitment)?;
```

### Private Transfer

```rust
// Transfer privately using a ZK proof
ShieldedPool::private_transfer(origin, proof)?;
```

### Unshield (Withdraw)

```rust
// Withdraw to a public account
ShieldedPool::unshield(origin, proof, nullifier, 100, recipient)?;
```

## Security Considerations

- **Double-spend prevention**: Nullifiers are checked before processing transfers
- **Merkle root validation**: Only known roots are accepted
- **ZK verification**: All operations require valid ZK proofs

## License

GPL-3.0-or-later
