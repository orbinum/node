//! The pallet's types: the snapshot it takes from staking ([`snapshot`]) and
//! the election's progress and outcome ([`phase`]).

pub mod phase;
pub mod snapshot;

pub use phase::{ElectionError, ElectionMeta, FailReason, Phase};
pub use snapshot::{Candidate, PageInfo, SnapshotVoter, TargetIndex};
