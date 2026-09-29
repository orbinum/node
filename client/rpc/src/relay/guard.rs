// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bookkeeping that keeps the relay from paying for a spend twice, or for one
//! another relayer is paid for.
//!
//! - [`InFlight`] — one relay per spend. The dry-run reads the best block, which
//!   does not see the pool: until a spend is included, every copy of it passes.
//!   [`ClaimGuard`] holds a request's claim and releases it unless submitted.
//! - [`rival_wins`] — the chain's rule for which relay commit takes the fee.
//! - [`NonceTracker`] — nonces for several submissions within one block, and
//!   recovery when a submitted transaction never lands.

use std::{
	collections::HashMap,
	time::{Duration, Instant},
};

use ethereum_types::U256;
use pallet_evm_precompile_shielded_pool::MAX_SPEND_INPUTS;

use super::{
	config::IN_FLIGHT_TTL,
	operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD},
};

/// The nullifiers a relayable spend consumes, read from its calldata; `None`
/// when the calldata is not a well-formed spend. Zero nullifiers (dummy inputs)
/// are left out: they identify nothing.
///
/// `unshield` holds its nullifier in head slot 2; `privateTransfer` holds the
/// offset of its `bytes32[]` there.
pub(crate) fn spend_nullifiers(calldata: &[u8]) -> Option<Vec<[u8; 32]>> {
	let selector: [u8; 4] = calldata.get(..4)?.try_into().ok()?;
	let params = &calldata[4..];
	let word = |at: usize| params.get(at..at.checked_add(32)?);
	let nullifiers: Vec<[u8; 32]> = if selector == SELECTOR_UNSHIELD {
		vec![word(64)?.try_into().ok()?]
	} else if selector == SELECTOR_PRIVATE_TRANSFER {
		let offset = usize::try_from(U256::from_big_endian(word(64)?)).ok()?;
		let count = usize::try_from(U256::from_big_endian(word(offset)?)).ok()?;
		if count == 0 || count > MAX_SPEND_INPUTS as usize {
			return None;
		}
		(0..count)
			.map(|i| word(offset + 32 + 32 * i)?.try_into().ok())
			.collect::<Option<_>>()?
	} else {
		return None;
	};
	let real: Vec<[u8; 32]> = nullifiers.into_iter().filter(|n| n != &[0u8; 32]).collect();
	(!real.is_empty()).then_some(real)
}

#[derive(Clone, Copy)]
enum Claim {
	/// A request is working on the spend; it releases or submits the claim.
	InProgress,
	/// The spend was submitted at this instant.
	Submitted(Instant),
}

/// Nullifiers the relay is working on or has submitted.
///
/// A claim in progress never lapses: the request holding it releases it, or
/// marks it submitted. A submitted one lapses after a TTL, so a spend that
/// never lands can be relayed again.
#[derive(Default)]
pub(crate) struct InFlight {
	held: HashMap<[u8; 32], Claim>,
}

impl InFlight {
	/// Claim every nullifier, or none: `false` if any is already held and live.
	pub(crate) fn try_claim(
		&mut self,
		nullifiers: &[[u8; 32]],
		now: Instant,
		ttl: Duration,
	) -> bool {
		self.held.retain(|_, claim| match claim {
			Claim::InProgress => true,
			Claim::Submitted(at) => now.duration_since(*at) < ttl,
		});
		if nullifiers.iter().any(|n| self.held.contains_key(n)) {
			return false;
		}
		for n in nullifiers {
			self.held.insert(*n, Claim::InProgress);
		}
		true
	}

	/// The spend was submitted: from here its claim lapses after the TTL.
	pub(crate) fn mark_submitted(&mut self, nullifiers: &[[u8; 32]], now: Instant) {
		for n in nullifiers {
			if let Some(claim) = self.held.get_mut(n) {
				*claim = Claim::Submitted(now);
			}
		}
	}

	/// Give the nullifiers back, when the relay did not submit their spend.
	pub(crate) fn release(&mut self, nullifiers: &[[u8; 32]]) {
		for n in nullifiers {
			self.held.remove(n);
		}
	}
}

/// A spend's claim on its nullifiers for the life of one relay request. Dropped
/// without [`ClaimGuard::submitted`] — an error, or the caller disconnecting
/// mid-request — it releases them.
pub(crate) struct ClaimGuard {
	in_flight: std::sync::Arc<std::sync::Mutex<InFlight>>,
	nullifiers: Vec<[u8; 32]>,
	submitted: bool,
}

impl ClaimGuard {
	pub(crate) fn take(
		in_flight: &std::sync::Arc<std::sync::Mutex<InFlight>>,
		nullifiers: Vec<[u8; 32]>,
	) -> Option<Self> {
		let claimed =
			lock(in_flight).try_claim(&nullifiers, std::time::Instant::now(), IN_FLIGHT_TTL);
		claimed.then(|| Self {
			in_flight: in_flight.clone(),
			nullifiers,
			submitted: false,
		})
	}

	/// The spend is in the pool: keep the claim until it lapses.
	pub(crate) fn submitted(mut self) {
		lock(&self.in_flight).mark_submitted(&self.nullifiers, std::time::Instant::now());
		self.submitted = true;
	}
}

impl Drop for ClaimGuard {
	fn drop(&mut self) {
		if !self.submitted {
			lock(&self.in_flight).release(&self.nullifiers);
		}
	}
}

fn lock(in_flight: &std::sync::Mutex<InFlight>) -> std::sync::MutexGuard<'_, InFlight> {
	in_flight
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Where a relay commit ranks: its recording block, then its hash. The chain
/// credits the earliest block, and a same-block tie to the lowest hash.
pub(crate) type CommitRank = (u32, [u8; 32]);

/// Whether a rival's live commit takes the fee from ours. Before ours is
/// recorded (`None`), any rival commit does.
pub(crate) fn rival_wins(ours: Option<CommitRank>, rival: CommitRank) -> bool {
	ours.is_none_or(|ours| rival < ours)
}

/// The nonce for the next submission.
///
/// Several submissions within one block take N, N+1, … from memory while the
/// confirmed nonce lags. A transaction that never lands leaves a gap nothing
/// fills, so once the confirmed nonce has not moved for `stall` blocks while
/// memory is ahead of it, memory is dropped and the confirmed nonce is reused.
#[derive(Default)]
pub(crate) struct NonceTracker {
	next: Option<U256>,
	/// The confirmed nonce last seen, and the block it was first seen at.
	confirmed: Option<(U256, u64)>,
}

impl NonceTracker {
	pub(crate) fn nonce(&mut self, confirmed: U256, best: u64, stall: u64) -> U256 {
		match self.confirmed {
			Some((seen, _)) if seen == confirmed => {}
			_ => self.confirmed = Some((confirmed, best)),
		}
		let since = self.confirmed.map_or(best, |(_, at)| at);
		match self.next {
			Some(next) if next > confirmed && best.saturating_sub(since) < stall => next,
			_ => {
				self.next = None;
				confirmed
			}
		}
	}

	/// `nonce` was accepted by the pool.
	pub(crate) fn submitted(&mut self, nonce: U256) {
		self.next = Some(nonce + U256::one());
	}
}
