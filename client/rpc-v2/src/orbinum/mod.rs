//! Orbinum Privacy RPC Module
//!
//! Arquitectura Clean Architecture + DDD:
//! - Domain: Reglas de negocio puras (ports, entities, value objects)
//! - Application: Casos de uso y servicios (sin dependencias de FRAME)
//! - Infrastructure: Adaptadores para Substrate/FRAME (storage, mappers)
//! - Presentation: API RPC y handlers (jsonrpsee)
//!
//! # Architecture Layers
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │              Presentation Layer                         │
//! │  (API trait, Server, Handlers, Validation)              │
//! │  - PrivacyApiServer                                     │
//! │  - PrivacyRpcServer                                     │
//! │  - Handlers (MerkleProofHandler, etc.)                  │
//! └───────────────────┬─────────────────────────────────────┘
//!                     │
//!                     ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │             Application Layer                           │
//! │  (Services, DTOs, Use Cases)                            │
//! │  - MerkleProofService                                   │
//! │  - PoolQueryService                                     │
//! │  - NullifierService                                     │
//! └───────────────────┬─────────────────────────────────────┘
//!                     │
//!                     ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                Domain Layer                             │
//! │  (Ports, Entities, Value Objects)                       │
//! │  - Ports: BlockchainQuery, MerkleTreeQuery, etc.        │
//! │  - Entities: MerkleProofPath, PoolStatistics            │
//! │  - Value Objects: BlockHash, TreeDepth, TreeSize        │
//! └───────────────────┬─────────────────────────────────────┘
//!                     │
//!                     ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │           Infrastructure Layer                          │
//! │  (Adapters, Mappers, Storage)                           │
//! │  - SubstrateStorageAdapter (implementa ports)           │
//! │  - Mappers (Commitment, Domain)                         │
//! │  - Storage keys (construcción de claves de storage)     │
//! └─────────────────────────────────────────────────────────┘
//! ```

// ============================================================================
// Módulos de las 4 capas
// ============================================================================

/// Domain layer - Reglas de negocio puras
pub mod domain;

/// Application layer - Casos de uso y servicios
pub mod application;

/// Infrastructure layer - Adaptadores y detalles técnicos
pub mod infrastructure;

/// Presentation layer - API RPC
pub mod presentation;

// ============================================================================
// Tests
// ============================================================================

// #[cfg(test)]
// mod tests;

// ============================================================================
// Re-exports públicos (Clean Architecture)
// ============================================================================

// Domain layer
pub use domain::{
	AssetId, BlockHash, BlockchainQuery, Commitment, DomainError, DomainResult,
	MerkleProofPath as DomainMerkleProofPath, MerkleTreeQuery, Nullifier, NullifierQuery,
	PoolQuery, PoolStatistics, TreeDepth, TreeSize,
};

// Application layer
pub use application::{
	ApplicationError, ApplicationResult, MerkleProofResponse, MerkleProofService, NullifierService,
	NullifierStatusResponse, PoolQueryService, PoolStatsResponse,
};

// Infrastructure layer
pub use infrastructure::{CommitmentMapper, DomainMapper, SubstrateStorageAdapter};

// Presentation layer
pub use presentation::{PrivacyApiServer, PrivacyRpcServer};
