//! Presentation layer - User interface (extrinsics, error mapping)
//!
//! This layer contains:
//! - Extrinsics: Pallet calls that delegate to use cases
//! - Error mapping: Maps application errors to pallet errors
//!
//! This layer depends on all other layers and translates between
//! domain/application types and FRAME types.

pub mod extrinsics;
