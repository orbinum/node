//! Repository Implementations
//!
//! Concrete implementations of repository domain ports.
//! These provide data storage and retrieval mechanisms.

mod in_memory_merkle_repository;

pub use in_memory_merkle_repository::InMemoryMerkleRepository;
