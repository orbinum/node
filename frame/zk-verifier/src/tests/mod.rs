//! Tests organized by Clean Architecture layers
//!
//! - unit/         - Domain layer tests (no FRAME)
//! - integration/  - Application layer tests (mocked repositories)
//! - e2e/          - Presentation layer tests (full runtime)
//! - mocks/        - Mock implementations

pub mod e2e;
pub mod integration;
pub mod mocks;
pub mod unit;
