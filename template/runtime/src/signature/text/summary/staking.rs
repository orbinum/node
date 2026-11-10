//! Staking calls: what they bond, where rewards go, whom they nominate and what a
//! validator charges.

use super::{
	labels::{account_lines, rewards_to},
	Line,
};
use crate::{
	signature::text::format::{account, decimal, orb, percent},
	Runtime,
};
use alloc::{vec, vec::Vec};
use pallet_staking_async::{Call, ValidatorPrefs};

pub(super) fn lines(call: &Call<Runtime>) -> Option<Vec<Line>> {
	Some(match call {
		Call::bond { value, payee } => {
			vec![(b"amount", orb(*value)), (b"rewards to", rewards_to(payee))]
		}
		Call::bond_extra {
			max_additional: value,
		}
		| Call::unbond { value }
		| Call::rebond { value } => vec![(b"amount", orb(*value))],
		Call::set_payee { payee } => vec![(b"rewards to", rewards_to(payee))],
		Call::nominate { targets } => account_lines(b"validator", targets)?,
		Call::kick { who } => account_lines(b"nominator", who)?,
		Call::validate {
			prefs: ValidatorPrefs {
				commission,
				blocked,
			},
		} => {
			let mut lines = vec![(b"commission".as_slice(), percent(commission.deconstruct()))];
			if *blocked {
				lines.push((b"blocked", b"yes".to_vec()));
			}
			lines
		}
		Call::payout_stakers {
			validator_stash,
			era,
		} => vec![
			(b"validator", account(validator_stash)),
			(b"era", decimal(u128::from(*era))),
		],
		Call::payout_stakers_by_page {
			validator_stash,
			era,
			page,
		} => vec![
			(b"validator", account(validator_stash)),
			(b"era", decimal(u128::from(*era))),
			(b"page", decimal(u128::from(*page))),
		],
		// Nothing to show: they only stop staking or free funds to the stash itself.
		Call::chill {}
		| Call::withdraw_unbonded {
			num_slashing_spans: _,
		} => Vec::new(),
		_ => return None,
	})
}
