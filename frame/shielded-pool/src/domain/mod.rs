//! Domain layer - Business logic and entities
//!
//! Este módulo contiene la lógica de negocio pura sin dependencias
//! de Substrate o detalles de infraestructura.

pub mod entities;
pub mod errors;
pub mod value_objects;

// Re-exports para facilitar el uso
pub use entities::{Commitment, Note, Nullifier};
pub use errors::{DomainError, DomainResult};
pub use value_objects::AssetId;
// Note: EncryptedMemo requires a MaxSize parameter, use types::EncryptedMemo for the default
