//! The pallet's types: admission ([`admission`]) and the declared node version
//! ([`NodeVersion`], defined with the rest of the author-version rules).

pub mod admission;

pub use crate::author_version::NodeVersion;
pub use admission::{AdmissionMode, BanTerm, Inadmissible};
