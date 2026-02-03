//! # Infrastructure Layer
//!
//! This layer contains technical implementations and adapters:
//! - **crypto**: Poseidon hasher adapter (light-poseidon)
//! - **repositories**: Repository implementations (in-memory, substrate)
//! - **host_interface**: Native runtime interface for Poseidon (OPT-2)
//!
//! Infrastructure depends on Domain (crypto primitives) but not on Application or Presentation.

pub mod crypto;
pub mod repositories;

#[cfg(feature = "sp-runtime-interface")]
pub mod host_interface;
