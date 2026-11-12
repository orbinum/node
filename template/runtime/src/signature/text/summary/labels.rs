// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Values the call families write alike: pools, members, account lists, reward
//! destinations, flags and sizes.

use super::{Line, MAX_LISTED_ACCOUNTS};
use crate::{
	signature::text::format::{account, decimal, orb},
	AccountId, Balance,
};
use alloc::vec::Vec;
use pallet_nomination_pools::{
	BondExtra, ClaimPermission, CommissionClaimPermission, ConfigOp, PoolState,
};
use pallet_staking_async::RewardDestination;

/// A pool role change: `keep`, `remove`, or the account the role is handed to.
pub(super) fn role_op(op: &ConfigOp<AccountId>) -> Vec<u8> {
	match op {
		ConfigOp::Noop => b"keep".to_vec(),
		ConfigOp::Remove => b"remove".to_vec(),
		ConfigOp::Set(who) => account(who),
	}
}

/// `pool: {id}`.
pub(super) fn pool_line(id: &u32) -> Line {
	(b"pool".as_slice(), decimal(u128::from(*id)))
}

/// `member: {account}`.
pub(super) fn member_line(who: &AccountId) -> Line {
	(b"member".as_slice(), account(who))
}

/// One `{key}: {account}` line per account, or `None` past [`MAX_LISTED_ACCOUNTS`].
pub(super) fn account_lines(key: &'static [u8], list: &[AccountId]) -> Option<Vec<Line>> {
	(list.len() <= MAX_LISTED_ACCOUNTS)
		.then(|| list.iter().map(|who| (key, account(who))).collect())
}

/// Where a staker's rewards go: `staked`, `stash`, `none`, or the paid account.
pub(super) fn rewards_to(payee: &RewardDestination<AccountId>) -> Vec<u8> {
	match payee {
		RewardDestination::Staked => b"staked".to_vec(),
		RewardDestination::Stash => b"stash".to_vec(),
		RewardDestination::Account(who) => account(who),
		RewardDestination::None => b"none".to_vec(),
		// Deprecated: `set_payee` refuses it and the call filter refuses a `bond`
		// with it, so the summary only names it.
		#[allow(deprecated)]
		RewardDestination::Controller => b"controller".to_vec(),
	}
}

/// What a pool bond adds: an amount from the free balance, or `rewards`.
pub(super) fn bond_extra(extra: &BondExtra<Balance>) -> Vec<u8> {
	match extra {
		BondExtra::FreeBalance(amount) => orb(*amount),
		BondExtra::Rewards => b"rewards".to_vec(),
	}
}

pub(super) fn pool_state(state: &PoolState) -> Vec<u8> {
	match state {
		PoolState::Open => b"open".to_vec(),
		PoolState::Blocked => b"blocked".to_vec(),
		PoolState::Destroying => b"destroying".to_vec(),
	}
}

/// Who besides the member may claim (`withdraw`) or restake (`compound`) its rewards.
pub(super) fn claim_permission(permission: &ClaimPermission) -> Vec<u8> {
	match permission {
		ClaimPermission::Permissioned => b"permissioned".to_vec(),
		ClaimPermission::PermissionlessCompound => b"permissionless compound".to_vec(),
		ClaimPermission::PermissionlessWithdraw => b"permissionless withdraw".to_vec(),
		ClaimPermission::PermissionlessAll => b"permissionless all".to_vec(),
	}
}

/// Who may claim a pool's commission besides its root: `permissionless`, the account,
/// or `root only`.
pub(super) fn commission_claim_permission(
	permission: Option<&CommissionClaimPermission<AccountId>>,
) -> Vec<u8> {
	match permission {
		Some(CommissionClaimPermission::Permissionless) => b"permissionless".to_vec(),
		Some(CommissionClaimPermission::Account(who)) => account(who),
		None => b"root only".to_vec(),
	}
}

/// `{n} blocks`, whatever `n`.
pub(super) fn blocks(n: u32) -> Vec<u8> {
	let mut out = decimal(u128::from(n));
	out.extend_from_slice(b" blocks");
	out
}

pub(super) fn yes_no(flag: bool) -> Vec<u8> {
	if flag {
		b"yes".to_vec()
	} else {
		b"no".to_vec()
	}
}

/// `{n} bytes`, whatever `n`.
pub(super) fn bytes(len: usize) -> Vec<u8> {
	let mut out = decimal(len as u128);
	out.extend_from_slice(b" bytes");
	out
}
