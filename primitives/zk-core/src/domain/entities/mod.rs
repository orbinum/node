//! # Domain Entities
//!
//! Entities and Aggregates following Domain-Driven Design.
//!

//! Objects with identity that have a lifecycle:
//! - **Identity**: Identified by a unique ID (not by attributes)
//! - **Mutability**: Can change state while maintaining identity
//! - **Lifecycle**: Creation, state changes, deletion
//!

//! Entities that control access to a cluster of related objects:
//! - **Consistency boundary**: Enforces invariants
//! - **Transaction boundary**: Changes happen atomically
//! - **Access point**: Only way to access aggregate internals
//!

//! - `note`: Note entity (Aggregate Root) - represents a private UTXO

pub mod note;

pub use note::Note;
