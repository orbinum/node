// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The declared weights: they grow with what they are charged for, and no regeneration
//! slips an absurd proof size past the tests.

use crate::tests::util::*;
use crate::{AcceptedSources, inbound::IsmpModuleCallback, payload::Message, tests::mock::*};
use ismp::module::IsmpModule;
use scale_codec::Encode;

#[test]
fn on_accept_weight_grows_with_body_length() {
	new_test_ext().execute_with(|| {
		AcceptedSources::<Test>::insert(COPROCESSOR, ());
		let module = IsmpModuleCallback::<Test>::default();

		let small = module
			.on_accept(post_from(COPROCESSOR, Message::Ping { nonce: 1 }.encode()))
			.unwrap();
		let large = module
			.on_accept(post_from(
				COPROCESSOR,
				Message::Data {
					nonce: 2,
					data: alloc::vec![0u8; 4096],
				}
				.encode(),
			))
			.unwrap();

		// Discarded today (`POLICY = false`), but becomes the block's accounted weight
		// the moment relayer fees are switched on.
		assert!(
			small.ref_time() > 0,
			"a callback must never report zero weight"
		);
		assert!(
			large.ref_time() > small.ref_time(),
			"weight must scale with the body"
		);
	});
}

/// The guard the header comment in `weights.rs` asks for, and cannot itself provide.
///
/// The benchmark CLI has a bug that emits a `proof_size` around 2.5 EXABYTES for
/// `dispatch_post` — `2_585_700_789_447_993_344` on one run, `8_126_544_059_662_763_008` on
/// the next, non-deterministically. `weights.rs` documents it at length and carries a
/// hand-corrected 3550. But **the generator overwrites that header on every regeneration**,
/// so the only thing standing between a fresh run and an absurd value is a comment that the
/// run itself deletes.
///
/// This test survives regeneration. The pallet's real `proof_size` values span 1504 to 3606,
/// and the bad ones are ~10^18 — sixteen orders apart, so a generous ceiling separates them
/// with no risk of a false alarm. Anyone regenerating gets a failing test rather than a
/// runtime that believes one extrinsic consumes every block's proof budget.
#[test]
fn declared_proof_sizes_stay_within_a_sane_ceiling() {
	use frame_support::traits::Get;

	// The intercepts sit in 1504-3606, but the per-component terms dominate at the top of a
	// range: `dispatch_post(8192)` legitimately declares `3550 + 8192 x 21` = 175,582, and
	// `dispatch_get` at the runtime's 16 keys reaches `3550 + 16 x 5376` = 89,566.
	//
	// The ceiling inside `check` is ten million: ~57x above every honest value, eleven orders
	// below a corrupted one (~10^18). That gap is what makes this test impossible to trip by
	// accident and impossible for the real bug to slip through.

	let body_max = <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get();
	let keys_max = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get();

	// BOTH impls. The generator writes the same numbers into `SubstrateWeight` and into `()`,
	// and the runtime uses `SubstrateWeight` (`configs/stacks/ismp/mod.rs`) while this mock uses
	// `()`. Checking only the one the mock happens to use would leave the one production
	// actually runs unguarded — and an earlier draft of this test did exactly that, which a
	// mutation caught: injecting the exabyte value into `SubstrateWeight` left it green.
	fn check<W: crate::weights::WeightInfo>(label: &str, body_max: u32, keys_max: u32) {
		const CEILING: u64 = 10_000_000;

		// Both ends of every component: the corruption lands in the intercept, so it shows at
		// zero as readily as at the maximum.
		for b in [0, body_max] {
			let w = W::dispatch_post(b);
			assert!(
				w.proof_size() < CEILING,
				"{label}: dispatch_post({b}) declares proof_size {} — regenerated with an \
				 unfixed CLI? See the header of weights.rs; the corrected value is 3550",
				w.proof_size()
			);
			let w = W::on_accept(b);
			assert!(
				w.proof_size() < CEILING,
				"{label}: on_accept({b}): {}",
				w.proof_size()
			);
		}

		for k in [1, keys_max] {
			let w = W::dispatch_get(k);
			assert!(
				w.proof_size() < CEILING,
				"{label}: dispatch_get({k}) declares proof_size {} — it walks the same \
				 RequestCommitments path as dispatch_post and is exposed to the same bug",
				w.proof_size()
			);
		}

		for w in [
			W::accept_source(),
			W::remove_source(),
			W::set_message_fee(),
			W::set_outbound_paused(),
			W::on_timeout(),
			W::on_response(0),
			// The component's own maximum, not a literal: the benchmark range is
			// `Linear<0, MaxGetKeys>`, and 64 was left over from an older hardcoded bound.
			W::on_response(keys_max),
		] {
			assert!(
				w.proof_size() < CEILING,
				"{label}: proof_size {}",
				w.proof_size()
			);
		}
	}

	check::<()>("()", body_max, keys_max);
	check::<crate::weights::SubstrateWeight<Test>>("SubstrateWeight", body_max, keys_max);
}
