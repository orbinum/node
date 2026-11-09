//! Who votes and with what weight: the voter list's bags ([`bags`]), its walk kept
//! to accounts that vote ([`live`]), stake to vote weight ([`vote`]) and
//! nomination pools, each one voter ([`pools`]).

pub(crate) mod bags;
pub(crate) mod live;
pub(crate) mod pools;
pub(crate) mod vote;
