//! `OrbinumSignature` through the runtime. The signed texts are tested in `text`.
//!
//! - `sr25519_ecdsa`: the Substrate signature variants; raw ECDSA never verifies.
//! - `hardening`: keys and encodings that would verify forged signatures.

mod hardening;
mod sr25519_ecdsa;
