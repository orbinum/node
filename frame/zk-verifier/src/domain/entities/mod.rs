//! Domain entities - Objects with identity and behavior

mod circuit;
mod proof;
mod verification_key;

pub use circuit::Circuit;
pub use proof::Proof;
pub use verification_key::VerificationKey;
