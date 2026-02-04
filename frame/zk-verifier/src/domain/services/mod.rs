//! Domain services - Business logic that doesn't belong to a single entity

mod proof_validator;
mod vk_validator;
mod zk_verifier_port;

pub use proof_validator::ProofValidator;
pub use vk_validator::{DefaultVkValidator, VkValidator};
pub use zk_verifier_port::ZkVerifierPort;
