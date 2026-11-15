// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Nomination pools: holders below `MinNominatorBond` stake together. Each pool
//! is one nominator to staking; its members never appear in an election.
//!
//! | What | How |
//! |---|---|
//! | Funds | Stay in each member's account, held for the pool (`pallet-delegated-staking`). The pool's bonded account is a virtual staker: staking bonds it without moving funds. |
//! | Rewards | `pallet-auto-payout` pays the pool like any nominator, into its reward account. Each member claims its share with `claim_payout`; anyone may claim it for the member (`claim_payout_other`) or restake it (`bond_extra_other`) if the member allows it (`set_claim_permission`). Nothing iterates members. |
//! | Slashes | Staking slashes the pool's bond when the slash applies. Each member's share comes out of its held funds when it withdraws, or when anyone calls `apply_slash` for it; until then the member owes it and what it unbonds is already reduced. |
//! | Validating | Never: a pool's accounts are keyless, so they cannot sign `staking.validate`. A pool only nominates. |
//!
//! | Name | A pool's metadata is its public name and at most one link: `name` or `name\nurl`. The name is ASCII letters and digits in words one space apart; the link an `https` URL of plain ASCII. The call filter refuses any other (`PoolMetadataRules`), so a name never hides, reorders or imitates text. |
//!
//! Pool configs are in `configs/staking/pools.rs`, their genesis values in `params`.

use crate::{Balance, RuntimeCall};
use frame_support::traits::Contains;
use sp_core::U256;
use sp_runtime::traits::Convert;

/// Widens a balance for the pools' reward arithmetic.
pub struct BalanceToU256;

impl Convert<Balance, U256> for BalanceToU256 {
	fn convert(balance: Balance) -> U256 {
		U256::from(balance)
	}
}

/// Narrows the pools' reward arithmetic back to a balance, saturating.
pub struct U256ToBalance;

impl Convert<U256, Balance> for U256ToBalance {
	fn convert(n: U256) -> Balance {
		n.try_into().unwrap_or(Balance::MAX)
	}
}

/// The most bytes of a pool's name.
pub const POOL_NAME_MAX_BYTES: usize = 64;

/// A pool's name and its link, read from its metadata.
#[derive(Debug, PartialEq, Eq)]
pub struct PoolProfile<'a> {
	pub name: &'a str,
	pub url: Option<&'a str>,
}

/// ASCII letters and digits, in words one space apart: nothing that can hide, reorder or
/// imitate text, nor pass for another name (no look-alike letters).
fn valid_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= POOL_NAME_MAX_BYTES
		&& name
			.split(' ')
			.all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// An `https` URL of plain ASCII: a lowercase dotted host (letters, digits, `-`, no
/// port, no credentials), then an optional path, query or fragment of URL characters.
fn valid_url(url: &str) -> bool {
	let Some(rest) = url.strip_prefix("https://") else {
		return false;
	};
	let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
	let (host, tail) = rest.split_at(end);
	let host_ok = host.contains('.')
		&& !host.starts_with(['.', '-'])
		&& !host.ends_with(['.', '-'])
		&& host
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
	let tail_ok = tail
		.bytes()
		.all(|b| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b));
	host_ok && tail_ok
}

/// The profile in `metadata`, or `None` when it breaks the rules. Empty metadata (no
/// name) is `Some` with an empty name: it clears the pool's name.
pub fn pool_profile(metadata: &[u8]) -> Option<PoolProfile<'_>> {
	let text = core::str::from_utf8(metadata).ok()?;
	if text.is_empty() {
		return Some(PoolProfile {
			name: "",
			url: None,
		});
	}
	let (name, url) = match text.split_once('\n') {
		Some((name, url)) => (name, Some(url)),
		None => (text, None),
	};
	(valid_name(name) && url.is_none_or(valid_url)).then_some(PoolProfile { name, url })
}

/// Refuses `nominationPools.setMetadata` whose metadata is not a valid pool profile
/// ([`pool_profile`]).
pub struct PoolMetadataRules;

impl Contains<RuntimeCall> for PoolMetadataRules {
	fn contains(call: &RuntimeCall) -> bool {
		match call {
			RuntimeCall::NominationPools(pallet_nomination_pools::Call::set_metadata {
				metadata,
				..
			}) => pool_profile(metadata).is_some(),
			_ => true,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_name_is_ascii_letters_and_digits_in_words_one_space_apart() {
		for ok in [
			"Orbinum",
			"Orbinum Pool 7",
			"A",
			&"a".repeat(POOL_NAME_MAX_BYTES),
		] {
			assert!(pool_profile(ok.as_bytes()).is_some(), "{ok}");
		}
		for bad in [
			"Orbinum 🌊",
			"Señor Pool",
			"Pool-7",
			"Pool_7",
			" Pool",
			"Pool ",
			"Pool  7",
			"Pool\t7",
			"P\u{202E}loop",
			"Pаypal", // Cyrillic a
			&"a".repeat(POOL_NAME_MAX_BYTES + 1),
		] {
			assert!(pool_profile(bad.as_bytes()).is_none(), "{bad:?}");
		}
		assert!(pool_profile(&[0xff, 0xfe]).is_none(), "not UTF-8");
	}

	#[test]
	fn the_link_is_one_plain_https_url_after_the_name() {
		let ok = pool_profile(b"Orbinum\nhttps://x.com/orbinum?ref=1#top").unwrap();
		assert_eq!(ok.name, "Orbinum");
		assert_eq!(ok.url, Some("https://x.com/orbinum?ref=1#top"));
		assert!(pool_profile(b"Orbinum\nhttps://xn--bcher-kva.example/").is_some());
		for bad in [
			"Orbinum\nhttp://x.com",
			"Orbinum\njavascript:alert(1)",
			"Orbinum\nhttps://user:pw@x.com",
			"Orbinum\nhttps://X.com",
			"Orbinum\nhttps://x.com:8443/",
			"Orbinum\nhttps://localhost/",
			"Orbinum\nhttps://x.com/a b",
			"Orbinum\nhttps://x.com/\"><script>",
			"Orbinum\nhttps://x.com/\nhttps://y.com",
			"\nhttps://x.com",
		] {
			assert!(pool_profile(bad.as_bytes()).is_none(), "{bad:?}");
		}
	}

	#[test]
	fn empty_metadata_clears_the_name() {
		assert_eq!(
			pool_profile(b""),
			Some(PoolProfile {
				name: "",
				url: None
			})
		);
	}
}
