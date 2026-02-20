//! Domain Layer
//!
//! Pure business logic with no external framework dependencies.
//!
//! ## Structure
//!
//! - [`value_objects`] - Immutable domain objects (keys, constants)
//! - [`entities`]      - Core business entities (MemoData, MemoError)
//! - [`ports`]         - Abstract interfaces (traits) for inversion of control
//! - [`aggregates`]    - Complex domain objects with business invariants
//! - [`services`]      - Domain service implementations

pub mod aggregates;
pub mod entities;
pub mod ports;
pub mod services;
pub mod value_objects;
