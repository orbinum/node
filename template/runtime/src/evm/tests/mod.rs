//! The EVM through the runtime.
//!
//! - `address_mapping`: one account for an EVM address and its secp256k1 key.
//! - `precompiles`: the address list against what the set executes, and vectors.
//! - `self_contained`: Ethereum transactions as self-signed extrinsics.

mod address_mapping;
mod precompiles;
mod self_contained;
