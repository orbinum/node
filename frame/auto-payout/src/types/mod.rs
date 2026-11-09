//! The pallet's types: the interface to staking ([`staking`]), the era being
//! paid ([`era`]) and the spending limits ([`limits`]).

pub mod era;
pub mod limits;
pub mod staking;

pub use era::EraState;
pub use limits::{LimitsError, MAX_CATCH_UP, MAX_FLOOR, MAX_IDLE, PayoutLimits};
pub use staking::{EraIndex, EraPayouts, Page, PayoutOutcome, ValidatorPages};
