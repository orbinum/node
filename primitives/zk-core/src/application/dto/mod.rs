//! Data Transfer Objects (DTOs)
//!
//! DTOs for the application layer that act as data contracts
//! between domain and external systems.
//!
//! ## Responsibilities
//!
//! - Serialization/deserialization (JSON, protobuf, etc.)
//! - Translation between domain entities and external representations
//! - Isolation of domain from external concerns
//!
//! ## Conversions
//!
//! - `from_domain()`: Converts from domain entity
//! - `to_domain()`: Converts to domain entity
//!
//! ## Available types
//!
//! - [`NoteDto`]: Represents a note for external APIs
//! - [`MerkleProofDto`]: Represents a Merkle proof for verification

pub mod merkle_proof_dto;
pub mod note_dto;

pub use merkle_proof_dto::MerkleProofDto;
pub use note_dto::NoteDto;
