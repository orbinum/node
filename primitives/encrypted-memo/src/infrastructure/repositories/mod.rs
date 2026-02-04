//! Infrastructure Repositories
//!
//! External resource access for filesystem, WASM runtime, and other external systems.

#[cfg(feature = "disclosure")]
pub mod key_loader;

#[cfg(feature = "wasm-witness")]
pub mod wasm_witness;
