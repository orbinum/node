// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Balance transfers: recipient and amount.

use super::{labels::yes_no, Line};
use crate::{
	signature::text::format::{account, orb},
	BalancesCall, Runtime,
};
use alloc::{vec, vec::Vec};

pub(super) fn lines(call: &BalancesCall<Runtime>) -> Option<Vec<Line>> {
	Some(match call {
		BalancesCall::transfer_allow_death { dest, value }
		| BalancesCall::transfer_keep_alive { dest, value } => {
			vec![(b"to", account(dest)), (b"amount", orb(*value))]
		}
		BalancesCall::transfer_all { dest, keep_alive } => vec![
			(b"to", account(dest)),
			(b"amount", b"all".to_vec()),
			(b"keep alive", yes_no(*keep_alive)),
		],
		_ => return None,
	})
}
