//! The runtime's primitives.
//!
//! - `types`: primitive types and the extrinsic format.
//! - `constants`: time, token and block-size constants.
//! - `version`: the runtime version.
//! - `opaque`: extrinsic-agnostic types and the session keys; declared at the crate
//!   root as `crate::opaque`, since `SessionKeys`' path is part of the metadata.

pub(crate) mod constants;
pub(crate) mod types;
pub(crate) mod version;

#[cfg(test)]
mod tests;
