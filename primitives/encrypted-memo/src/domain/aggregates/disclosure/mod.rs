//! Selective Disclosure
//!
//! Structures for selectively revealing encrypted note fields while maintaining
//! cryptographic privacy for undisclosed fields.
//!
//! ## Components
//!
//! - [`mask`]    - [`DisclosureMask`] controls which fields are revealed
//! - [`signals`] - [`DisclosurePublicSignals`] verified outputs of the circuit
//! - [`proof`]   - [`DisclosureProof`] bundles proof bytes + signals + mask
//! - [`partial`] - [`PartialMemoData`] holds `Option` values for revealed fields

pub mod mask;
pub mod partial;
pub mod proof;
pub mod signals;

pub use mask::DisclosureMask;
pub use partial::PartialMemoData;
pub use proof::DisclosureProof;
pub use signals::DisclosurePublicSignals;
