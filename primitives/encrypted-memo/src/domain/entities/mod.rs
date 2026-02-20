//! Domain Entities
//!
//! Core business entities that form the foundation of the domain model.
//!
//! ## Modules
//!
//! - [`memo_data`] - Plaintext memo entity with serialization and format validation
//! - [`error`]     - Error types for domain operations

pub mod error;
pub mod memo_data;

pub use memo_data::{is_valid_encrypted_memo, MemoData};
