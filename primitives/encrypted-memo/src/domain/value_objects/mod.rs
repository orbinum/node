//! Value Objects
//!
//! Immutable, identity-less domain objects defined by their attributes.
//!
//! ## Modules
//!
//! - [`constants`]    - Size limits and domain separators
//! - [`viewing_key`]  - Read-only auditable key
//! - [`nullifier_key`] - Key for nullifier derivation
//! - [`eddsa_key`]    - Circuit signing key (BabyJubJub)

pub mod constants;
pub mod eddsa_key;
pub mod nullifier_key;
pub mod viewing_key;

pub use eddsa_key::EdDSAKey;
pub use nullifier_key::NullifierKey;
pub use viewing_key::ViewingKey;
