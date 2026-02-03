//! Application Layer
//!
//! This module contains the application business logic following Clean Architecture.
//!

//! The application layer is the **middle circle** and:
//! - Orchestrates domain objects to fulfill user intentions
//! - Depends on domain layer (inner circle)
//! - Independent of infrastructure and frameworks
//! - Defines use cases (application-specific business rules)
//!

//! - `use_cases/`: Application use cases (orchestration logic)
//! - `dto/`: Data Transfer Objects for external APIs
//!

//! ```text
//! Application (this layer)
//!   ↓ depends on
//!   Domain Layer
//! ```

pub mod dto;
pub mod use_cases;
