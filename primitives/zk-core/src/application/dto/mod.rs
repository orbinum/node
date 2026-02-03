//! Data Transfer Objects (DTOs)
//!
//! This module contains DTOs for the application layer, serving as the
//! data contracts between the application and external systems.
//!

//! DTOs are part of the **Application Layer** and:

//! - Handle serialization/deserialization
//! - Translate between domain entities and external representations
//! - Isolate domain from external concerns
//!

//! - **Stability**: Provide stable API contracts independent of domain changes
//! - **Serialization**: Easy to serialize to JSON, protobuf, etc.
//! - **Validation**: Can add API-level validation separate from domain rules
//! - **Versioning**: Support multiple API versions
//!

//! Each DTO provides:
//! - `from_domain()`: Convert from domain entity
//! - `to_domain()`: Convert to domain entity
//! - Serialization support (when `std` feature enabled)
//!

//! - `NoteDto`: Represents a note for external APIs
//! - `MerkleProofDto`: Represents a Merkle proof for verification

mod merkle_proof_dto;
mod note_dto;

pub use merkle_proof_dto::MerkleProofDto;
pub use note_dto::NoteDto;
