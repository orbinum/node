//! The chain state the pallet starts from and must keep: genesis
//! ([`genesis`]) and the invariants `try_state` checks (`invariants`).

pub mod genesis;
#[cfg(feature = "try-runtime")]
mod invariants;
