# Orbinum Network

Orbinum is a privacy-focused blockchain network built on Substrate that enables confidential transactions with selective disclosure capabilities.

## Overview

Orbinum combines the transparency benefits of blockchain technology with advanced cryptographic privacy features, allowing users to control what information they reveal while maintaining verifiable trust.

## Key Features

### Privacy by Design
- **Shielded Pool**: Confidential transaction layer using zero-knowledge proofs (Groth16 on BN254 curve)
- **Private Transfers**: Send and receive assets without revealing amounts, sender, or recipient
- **Shield/Unshield**: Move assets between transparent and private domains seamlessly

### Selective Disclosure
- **Proof Generation**: Create cryptographic proofs that reveal specific transaction properties without exposing underlying data
- **Compliance Tools**: Selectively disclose transaction details to authorized parties
- **Audit Trail**: Maintain verifiable records while preserving user privacy

### EVM Compatibility
- **Frontier Integration**: Full Ethereum Virtual Machine compatibility layer
- **Ethereum RPC APIs**: Standard Ethereum tooling and infrastructure support
- **Cross-Layer Interaction**: Bridge between private and public execution environments

### Advanced Cryptography
- **Zero-Knowledge Proofs**: Groth16 SNARKs for efficient proof verification
- **Poseidon Hash**: ZK-friendly hash function optimized for circuit constraints
- **Merkle Trees**: Commitment trees for efficient membership proofs
- **Encrypted Memos**: Optional encrypted messages attached to private transactions

## Architecture

Orbinum is built using Substrate's FRAME framework and implements Clean Architecture principles across all components:

- **Pallets**: Modular runtime components (`pallet-shielded-pool`, `pallet-zk-verifier`)
- **Primitives**: Core cryptographic libraries (`zk-core`, `zk-verifier`, `zk-circuits`)
- **Client**: RPC layer and blockchain infrastructure
- **Circuits**: TypeScript/Circom zero-knowledge circuits

## License

Orbinum is dual-licensed under:

- **Apache License 2.0** ([LICENSE-APACHE2](LICENSE-APACHE2) or http://www.apache.org/licenses/LICENSE-2.0)
- **GNU General Public License v3.0** ([LICENSE-GPL3](LICENSE-GPL3) or https://www.gnu.org/licenses/gpl-3.0.html)

You may choose either license to govern your use of this software.

## Attribution

Orbinum is built upon and extends [Frontier](https://github.com/polkadot-evm/frontier), the Ethereum compatibility layer for Substrate. The EVM integration, Ethereum RPC, and related client infrastructure are derived from Frontier's work by Parity Technologies and contributors.

We are grateful to the Frontier and Substrate communities for their foundational work.
