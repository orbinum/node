//! Domain Aggregates
//!
//! Complex domain objects that encapsulate entities and maintain business invariants.
//!
//! ## Aggregates
//!
//! - [`disclosure`] - Selective disclosure proof structures (mask, signals, proof, partial)
//! - [`keyset`]     - Wallet key management (spending, viewing, nullifier, EdDSA)

pub mod disclosure;
pub mod keyset;
