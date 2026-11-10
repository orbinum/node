//! Tests by concern: the allowlist, admission (mode, bans) and the minimum author
//! version.

pub(crate) use crate::{ApprovedValidators, Error, Event, mock::*};
pub(crate) use frame_support::{assert_noop, assert_ok};

mod admission;
mod allowlist;
mod author_version;
