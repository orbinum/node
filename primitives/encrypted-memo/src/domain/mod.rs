//! Domain Layer
//!
//! Pure business logic without external dependencies.
//!
//! ## Structure
//!
//! - [`entities`] - Core entities and value objects
//! - [`services`] - Domain services (business logic)
//! - [`aggregates`] - Complex aggregates with behavior

pub mod aggregates;
pub mod entities;
pub mod services;
