//! Infrastructure Layer
//!
//! External adapters and resource access.
//!
//! ## Structure
//!
//! - [`adapters`] - Format conversions and protocol adapters
//! - [`repositories`] - External resource access (filesystem, WASM runtime)

pub mod adapters;
pub mod repositories;
