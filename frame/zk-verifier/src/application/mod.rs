//! Application layer - Use cases and business logic orchestration
//!
//! This layer contains:
//! - Use Cases: Orchestrate domain logic for specific operations
//! - Commands: Input DTOs for use cases
//! - Application Services: Cross-cutting concerns
//! - Application Errors: Use case specific errors
//!
//! The application layer depends on the domain layer but is independent
//! of infrastructure and presentation layers.

pub mod commands;
pub mod errors;
pub mod use_cases;
