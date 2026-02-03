//! # Domain Value Objects
//!
//! Value Objects following Domain-Driven Design principles.
//!

//! - **Immutable**: Once created, cannot be modified
//! - **Equality by value**: Two VOs are equal if their values are equal
//! - **Self-validating**: Maintain their own invariants
//! - **Side-effect free**: Methods don't modify state
//!

//! - `field_element`: Base wrapper for BN254 field elements
//! - `commitment`: Cryptographic commitment to a note
//! - `nullifier`: Unique identifier marking a note as spent
//! - `spending_key`: Private key for spending notes
//! - `blinding`: Random factor for unlinkability
//! - `owner_pubkey`: Public key identifying note owner

pub mod blinding;
pub mod commitment;
pub mod field_element;
pub mod nullifier;
pub mod owner_pubkey;
pub mod spending_key;

// Re-export for convenience
pub use blinding::Blinding;
pub use commitment::Commitment;
pub use field_element::FieldElement;
pub use nullifier::Nullifier;
pub use owner_pubkey::OwnerPubkey;
pub use spending_key::SpendingKey;
