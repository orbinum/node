//! Presentation layer - RPC interface
//!
//! This layer exposes the RPC API and handles:
//! - RPC trait definition (`jsonrpsee`)
//! - RPC server implementation
//! - Endpoint-specific handlers
//! - Input validation
//!
//! This layer delegates business logic to the application layer.

pub mod api;
pub mod handlers;
pub mod server;
pub mod validation;

// Re-exports
pub use api::PrivacyApiServer;
pub use server::PrivacyRpcServer;
