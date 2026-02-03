//! Cryptographic Adapters
//!
//! Concrete implementations of cryptographic domain ports.
//! These adapters use external libraries (light-poseidon, ark-bn254)
//! while implementing domain interfaces.

mod poseidon_hasher;

pub use poseidon_hasher::LightPoseidonHasher;
