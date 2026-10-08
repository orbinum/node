// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! One relay per spend, the commit ranking, and nonces across submissions.

use std::time::{Duration, Instant};

use ethereum_types::U256;

use crate::relay::{
	guard::{rival_wins, spend_nullifiers, ClaimGuard, InFlight, NonceTracker},
	operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD},
};

fn word(v: usize) -> [u8; 32] {
	U256::from(v).to_big_endian()
}

fn unshield(nullifier: [u8; 32]) -> Vec<u8> {
	let mut data = SELECTOR_UNSHIELD.to_vec();
	data.extend_from_slice(&word(320)); // proof offset
	data.extend_from_slice(&[0x11; 32]); // root
	data.extend_from_slice(&nullifier);
	data.resize(4 + 320, 0);
	data
}

fn transfer(nullifiers: &[[u8; 32]]) -> Vec<u8> {
	let mut data = SELECTOR_PRIVATE_TRANSFER.to_vec();
	data.extend_from_slice(&word(256)); // proof offset
	data.extend_from_slice(&word(256 + 32 + 32 * nullifiers.len())); // roots offset
	data.extend_from_slice(&word(256)); // nullifiers offset
	data.resize(4 + 256, 0);
	data.extend_from_slice(&word(nullifiers.len()));
	for n in nullifiers {
		data.extend_from_slice(n);
	}
	data.extend_from_slice(&word(2));
	data.extend_from_slice(&[[0x11; 32], [0x12; 32]].concat());
	data
}

// ── spend_nullifiers ─────────────────────────────────────────────────────────

#[test]
fn reads_the_unshield_nullifier() {
	assert_eq!(
		spend_nullifiers(&unshield([0x22; 32])),
		Some(vec![[0x22; 32]])
	);
}

#[test]
fn reads_the_transfer_nullifiers_without_dummies() {
	assert_eq!(
		spend_nullifiers(&transfer(&[[0x33; 32], [0x44; 32]])),
		Some(vec![[0x33; 32], [0x44; 32]])
	);
	assert_eq!(
		spend_nullifiers(&transfer(&[[0x33; 32], [0; 32]])),
		Some(vec![[0x33; 32]])
	);
}

#[test]
fn refuses_calldata_that_names_no_note() {
	assert_eq!(
		spend_nullifiers(&unshield([0; 32])),
		None,
		"a zero nullifier identifies nothing"
	);
	assert_eq!(spend_nullifiers(&transfer(&[])), None);
	assert_eq!(
		spend_nullifiers(&transfer(&[[1; 32]; 3])),
		None,
		"more inputs than the circuit"
	);
	assert_eq!(
		spend_nullifiers(&[0xde, 0xad, 0xbe, 0xef]),
		None,
		"unknown selector"
	);
	assert_eq!(
		spend_nullifiers(&unshield([0x22; 32])[..40]),
		None,
		"truncated"
	);
	let mut bad_offset = transfer(&[[0x33; 32]]);
	bad_offset[4 + 64..4 + 96].copy_from_slice(&[0xff; 32]);
	assert_eq!(spend_nullifiers(&bad_offset), None, "offset past the input");
}

/// Offsets and lengths at the edge of `usize` read nothing and never overflow:
/// the guard runs on calldata from anyone, before the dry-run.
#[test]
fn hostile_offsets_and_lengths_read_nothing() {
	let near_max = U256::from(usize::MAX - 16).to_big_endian();
	let mut offset = transfer(&[[0x33; 32]]);
	offset[4 + 64..4 + 96].copy_from_slice(&near_max);
	assert_eq!(spend_nullifiers(&offset), None);

	let mut length = transfer(&[[0x33; 32]]);
	length[4 + 256..4 + 288].copy_from_slice(&near_max);
	assert_eq!(spend_nullifiers(&length), None);

	let mut short = transfer(&[[0x33; 32], [0x44; 32]]);
	short.truncate(4 + 256 + 32 + 32);
	assert_eq!(spend_nullifiers(&short), None, "second nullifier missing");
}

/// The nullifiers come from head slot 2 whatever slot 1 holds: in the
/// two-root layout slot 1 is the roots' offset, never a nullifier.
#[test]
fn the_roots_array_is_never_read_as_nullifiers() {
	let mut data = transfer(&[[0x33; 32], [0x44; 32]]);
	// Point the roots at the nullifiers and the nullifiers at the roots.
	let roots = data[4 + 32..4 + 64].to_vec();
	let nullifiers = data[4 + 64..4 + 96].to_vec();
	data[4 + 32..4 + 64].copy_from_slice(&nullifiers);
	data[4 + 64..4 + 96].copy_from_slice(&roots);
	assert_eq!(
		spend_nullifiers(&data),
		Some(vec![[0x11; 32], [0x12; 32]]),
		"slot 2 decides, as it does for the precompile"
	);
}

// ── InFlight ─────────────────────────────────────────────────────────────────

const TTL: Duration = Duration::from_secs(120);

#[test]
fn a_spend_is_relayed_once_while_in_flight() {
	let mut in_flight = InFlight::default();
	let now = Instant::now();
	assert!(in_flight.try_claim(&[[1; 32]], now, TTL));
	assert!(
		!in_flight.try_claim(&[[1; 32]], now, TTL),
		"a copy is refused"
	);
	// A transfer sharing one note with it is refused too, and claims nothing.
	assert!(!in_flight.try_claim(&[[2; 32], [1; 32]], now, TTL));
	assert!(
		in_flight.try_claim(&[[2; 32]], now, TTL),
		"the refused claim took nothing"
	);
}

#[test]
fn a_released_claim_frees_the_spend() {
	let mut in_flight = InFlight::default();
	let now = Instant::now();
	assert!(in_flight.try_claim(&[[1; 32]], now, TTL));
	in_flight.release(&[[1; 32]]);
	assert!(
		in_flight.try_claim(&[[1; 32]], now, TTL),
		"released after a failed relay"
	);
}

/// A request still working on a spend (waiting for its commit, say) keeps the
/// claim however long it takes; only a submitted spend's claim lapses.
#[test]
fn only_a_submitted_claim_lapses() {
	let mut in_flight = InFlight::default();
	let now = Instant::now();
	assert!(in_flight.try_claim(&[[1; 32]], now, TTL));
	assert!(
		!in_flight.try_claim(&[[1; 32]], now + TTL * 10, TTL),
		"in progress: never lapses"
	);
	in_flight.mark_submitted(&[[1; 32]], now);
	assert!(!in_flight.try_claim(&[[1; 32]], now + TTL / 2, TTL));
	assert!(
		in_flight.try_claim(&[[1; 32]], now + TTL, TTL),
		"submitted: lapses after the TTL"
	);
}

// ── ClaimGuard ───────────────────────────────────────────────────────────────

/// A request that errors, or whose caller disconnects, drops its guard: the
/// claim goes back. A submitted one keeps it until it lapses.
#[test]
fn a_dropped_claim_is_released_and_a_submitted_one_kept() {
	let in_flight = std::sync::Arc::new(std::sync::Mutex::new(InFlight::default()));
	let claim = ClaimGuard::take(&in_flight, vec![[1; 32]]).expect("free");
	assert!(
		ClaimGuard::take(&in_flight, vec![[1; 32]]).is_none(),
		"held"
	);
	drop(claim);
	let claim = ClaimGuard::take(&in_flight, vec![[1; 32]]).expect("released on drop");
	claim.submitted();
	assert!(
		ClaimGuard::take(&in_flight, vec![[1; 32]]).is_none(),
		"a submitted spend stays claimed"
	);
}

// ── rival_wins ───────────────────────────────────────────────────────────────

#[test]
fn a_rival_commit_wins_by_the_chains_rule() {
	let ours = Some((10, [0x50; 32]));
	assert!(rival_wins(ours, (9, [0xFF; 32])), "earlier block wins");
	assert!(!rival_wins(ours, (11, [0x00; 32])), "later block loses");
	assert!(
		rival_wins(ours, (10, [0x40; 32])),
		"same block, lower hash wins"
	);
	assert!(
		!rival_wins(ours, (10, [0x60; 32])),
		"same block, higher hash loses"
	);
	assert!(
		rival_wins(None, (99, [0xFF; 32])),
		"before ours is recorded, any rival wins"
	);
}

// ── NonceTracker ─────────────────────────────────────────────────────────────

#[test]
fn submissions_in_one_block_take_successive_nonces() {
	let mut nonces = NonceTracker::default();
	let n = nonces.nonce(5.into(), 100, 10);
	assert_eq!(n, 5.into());
	nonces.submitted(n);
	assert_eq!(nonces.nonce(5.into(), 100, 10), 6.into());
	// The chain catches up: confirmed wins again.
	assert_eq!(nonces.nonce(6.into(), 101, 10), 6.into());
}

/// A submitted transaction that never lands leaves a gap: once the confirmed
/// nonce has not moved for the stall window, signing restarts from it.
#[test]
fn a_dropped_transaction_does_not_wedge_the_nonce() {
	let mut nonces = NonceTracker::default();
	nonces.nonce(5.into(), 100, 10);
	nonces.submitted(5.into()); // never lands
	assert_eq!(nonces.nonce(5.into(), 109, 10), 6.into(), "still waiting");
	assert_eq!(nonces.nonce(5.into(), 110, 10), 5.into(), "gap abandoned");
}
