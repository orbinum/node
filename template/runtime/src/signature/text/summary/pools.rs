// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Nomination pool calls: the member calls (join, bond more, claim, leave) and the pool
//! operator's calls that bond, nominate, set the pool's state, hand its roles over or
//! manage its commission or name it. A name is shown as written: the runtime takes only
//! ASCII letters and digits for it, and a plain `https` link (`staking::pools`).

use super::{
	labels::{
		account_lines, blocks, bond_extra, claim_permission, commission_claim_permission,
		member_line, pool_line, pool_state, role_op,
	},
	Line,
};
use crate::{
	signature::text::format::{account, orb, percent, units},
	Runtime,
};
use alloc::{vec, vec::Vec};
use pallet_nomination_pools::{Call, CommissionChangeRate};

pub(super) fn lines(call: &Call<Runtime>) -> Option<Vec<Line>> {
	Some(match call {
		Call::join { amount, pool_id } => vec![pool_line(pool_id), (b"amount", orb(*amount))],
		Call::bond_extra { extra } => vec![(b"amount", bond_extra(extra))],
		Call::bond_extra_other { member: who, extra } => {
			vec![member_line(who), (b"amount", bond_extra(extra))]
		}
		// Pays the signer's own rewards to the signer.
		Call::claim_payout {} => Vec::new(),
		Call::claim_payout_other { other } => vec![member_line(other)],
		// Points, not ORB: a pool's points track its balance 1:1 until a slash.
		Call::unbond {
			member_account,
			unbonding_points,
		} => vec![
			member_line(member_account),
			(b"points", units(*unbonding_points)),
		],
		Call::withdraw_unbonded {
			member_account,
			num_slashing_spans: _,
		} => vec![member_line(member_account)],
		Call::pool_withdraw_unbonded {
			pool_id,
			num_slashing_spans: _,
		}
		| Call::chill { pool_id } => {
			vec![pool_line(pool_id)]
		}
		Call::create {
			amount,
			root,
			nominator,
			bouncer,
		} => vec![
			(b"amount", orb(*amount)),
			(b"root", account(root)),
			(b"nominator", account(nominator)),
			(b"bouncer", account(bouncer)),
		],
		// A dissolved pool's id taken again: the same as `create`, and the id.
		Call::create_with_pool_id {
			amount,
			root,
			nominator,
			bouncer,
			pool_id,
		} => vec![
			pool_line(pool_id),
			(b"amount", orb(*amount)),
			(b"root", account(root)),
			(b"nominator", account(nominator)),
			(b"bouncer", account(bouncer)),
		],
		Call::nominate {
			pool_id,
			validators,
		} => {
			let mut lines = vec![pool_line(pool_id)];
			lines.extend(account_lines(b"validator", validators)?);
			lines
		}
		Call::set_state { pool_id, state } => {
			vec![pool_line(pool_id), (b"state", pool_state(state))]
		}
		// Hands the pool's authority over: each role kept, removed or set, in full.
		Call::update_roles {
			pool_id,
			new_root,
			new_nominator,
			new_bouncer,
		} => vec![
			pool_line(pool_id),
			(b"root", role_op(new_root)),
			(b"nominator", role_op(new_nominator)),
			(b"bouncer", role_op(new_bouncer)),
		],
		// The pool's name and link, shown as written; any other metadata is filtered.
		Call::set_metadata { pool_id, metadata } => {
			let profile = crate::staking::pools::pool_profile(metadata)?;
			let name = if profile.name.is_empty() {
				b"none".to_vec()
			} else {
				profile.name.as_bytes().to_vec()
			};
			let mut lines = vec![pool_line(pool_id), (b"name", name)];
			if let Some(url) = profile.url {
				lines.push((b"link", url.as_bytes().to_vec()));
			}
			lines
		}
		// Tops the pool's reward account up to the deposit, or returns the excess.
		Call::adjust_pool_deposit { pool_id } => vec![pool_line(pool_id)],
		// Applies a member's pending slash; it earns the caller nothing here.
		Call::apply_slash { member_account } => vec![member_line(member_account)],
		Call::set_claim_permission { permission } => {
			vec![(b"permission", claim_permission(permission))]
		}
		// The payee receives every later claim: it is authority over the commission.
		Call::set_commission {
			pool_id,
			new_commission,
		} => match new_commission {
			Some((commission, payee)) => vec![
				pool_line(pool_id),
				(b"commission", percent(commission.deconstruct())),
				(b"payee", account(payee)),
			],
			None => vec![pool_line(pool_id), (b"commission", b"none".to_vec())],
		},
		Call::set_commission_max {
			pool_id,
			max_commission,
		} => vec![
			pool_line(pool_id),
			(b"max commission", percent(max_commission.deconstruct())),
		],
		Call::set_commission_change_rate {
			pool_id,
			change_rate: CommissionChangeRate {
				max_increase,
				min_delay,
			},
		} => vec![
			pool_line(pool_id),
			(b"max increase", percent(max_increase.deconstruct())),
			(b"min delay", blocks(*min_delay)),
		],
		// Pays the payee the pool's root set, whoever claims.
		Call::claim_commission { pool_id } => vec![pool_line(pool_id)],
		Call::set_commission_claim_permission {
			pool_id,
			permission,
		} => vec![
			pool_line(pool_id),
			(
				b"permission",
				commission_claim_permission(permission.as_ref()),
			),
		],
		_ => return None,
	})
}

/// A pool root's private staking call: opening or closing its pool to private
/// members. Setting the entry minimum is governance's, not text-signable.
pub(super) fn private_lines(call: &crate::staking::private::Call<Runtime>) -> Option<Vec<Line>> {
	use crate::staking::private::Call;
	match call {
		Call::set_private { pool_id, enabled } => Some(vec![
			pool_line(pool_id),
			(
				b"private members",
				if *enabled {
					b"on".to_vec()
				} else {
					b"off".to_vec()
				},
			),
		]),
		_ => None,
	}
}
