//! Core Groth16 proof verification.
//!
//! Resolves the circuit version, loads and prepares its key once, picks the
//! [`InputLayout`] the key implies, and records statistics. Encoding the inputs
//! is the caller's (see [`crate::encoding`]).

use crate::{
	Error,
	pallet::{ActiveCircuitVersion, Config, RetiredVersions, VerificationKeys, VerificationStats},
	types::CircuitId,
};
use alloc::vec::Vec;
use orbinum_zk_verifier::{
	Bn254, InputLayout, PreparedVerifyingKey, VerifyingKey, has_memo_layout, input_layout,
};

/// Verify a proof of a circuit statement, encoded for the layout of the key it
/// is checked against.
///
/// Returns `(valid, resolved_version)`. A key of a layout the pallet does not
/// admit, a statement the key cannot attest to (`encode` returns `None`), or
/// inputs that do not fill it, are `valid = false`.
pub fn verify_statement<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof: &[u8],
	encode: impl FnOnce(InputLayout) -> Option<Vec<[u8; 32]>>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	check::<T>(circuit_id, version, proof, |layout, arity| {
		encode(layout).filter(|raw| raw.len() == arity)
	})
}

/// Verify a proof against caller-supplied inputs, taken as-is. Serves the
/// `verify_proof` extrinsic, whose caller encodes every input itself.
pub fn verify_raw<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof: &[u8],
	raw_inputs: Vec<[u8; 32]>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	frame_support::ensure!(!raw_inputs.is_empty(), Error::<T>::EmptyPublicInputs);
	check::<T>(circuit_id, version, proof, |_, _| Some(raw_inputs))
}

/// The layout a key of `arity` inputs gives `circuit_id`, if admitted. A spend
/// circuit never takes the base layout, which binds neither its memos nor the
/// full recipient: such a key verifies nothing, however it reached storage.
pub(crate) fn admitted_layout(circuit_id: CircuitId, arity: usize) -> Option<InputLayout> {
	let id = u8::try_from(circuit_id.0).ok()?;
	input_layout(id, arity).filter(|layout| !(has_memo_layout(id) && *layout == InputLayout::Base))
}

/// Shared path: resolve and prepare the key, build the inputs for its layout,
/// verify, record. `inputs` returns `None` to fail the proof without verifying.
fn check<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof: &[u8],
	inputs: impl FnOnce(InputLayout, usize) -> Option<Vec<[u8; 32]>>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	frame_support::ensure!(!proof.is_empty(), Error::<T>::EmptyProof);
	let (key_data, resolved) = resolve_key::<T>(circuit_id, version)?;

	// Registration checked the key deserializes; if one ever did not, the proof
	// fails rather than verifying under guessed inputs.
	let result = match VerifyingKey::new(key_data).prepare() {
		Ok(pvk) => {
			let arity = pvk.vk.gamma_abc_g1.len().saturating_sub(1);
			admitted_layout(circuit_id, arity)
				.and_then(|layout| inputs(layout, arity))
				.is_some_and(|raw| do_verify(&pvk, proof, raw))
		}
		Err(_) => false,
	};
	record_stats::<T>(circuit_id, resolved, result);
	Ok((result, resolved))
}

/// The key bytes and version to verify against: `version`, or the active one.
fn resolve_key<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
) -> Result<(Vec<u8>, u32), Error<T>> {
	let resolved = version
		.or_else(|| ActiveCircuitVersion::<T>::get(circuit_id))
		.ok_or(Error::<T>::CircuitNotFound)?;
	frame_support::ensure!(
		!RetiredVersions::<T>::contains_key(circuit_id, resolved),
		Error::<T>::UnsupportedCircuitVersion
	);
	let info = VerificationKeys::<T>::get(circuit_id, resolved).ok_or(if version.is_some() {
		Error::<T>::UnsupportedCircuitVersion
	} else {
		Error::<T>::VerificationKeyNotFound
	})?;
	Ok((info.key_data.into_inner(), resolved))
}

/// Record a verification outcome into `VerificationStats`.
///
/// Failed attempts are counted too. Note the asymmetry between call paths:
/// the `verify_proof` extrinsic returns `Err` on failure, so the runtime
/// reverts this write; the Port path returns `Ok((false, _))`, so the write
/// **persists**. This is deliberate — persisting Port-side failures gives
/// observability into invalid proofs reaching the pool (client bugs / attacks).
fn record_stats<T: Config>(circuit_id: CircuitId, version: u32, result: bool) {
	VerificationStats::<T>::mutate(circuit_id, version, |s| {
		s.total_verifications = s.total_verifications.saturating_add(1);
		if result {
			s.successful_verifications = s.successful_verifications.saturating_add(1);
		} else {
			s.failed_verifications = s.failed_verifications.saturating_add(1);
		}
	});
}

/// The pairing check.
///
/// Always `true` in **test** builds: unit tests use keys that deserialize but
/// no real proofs. Benchmarks run the full pairing so weights reflect its cost.
fn do_verify(pvk: &PreparedVerifyingKey<Bn254>, proof: &[u8], raw_inputs: Vec<[u8; 32]>) -> bool {
	#[cfg(test)]
	{
		let _ = (pvk, proof, raw_inputs);
		true
	}

	#[cfg(not(test))]
	{
		use orbinum_zk_verifier::{Groth16Verifier, Proof, PublicInputs};
		Groth16Verifier::verify_with_prepared_vk(
			pvk,
			&PublicInputs::new(raw_inputs),
			&Proof::new(proof.to_vec()),
		)
		.is_ok()
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, activate, insert_key, insert_vk, new_test_ext},
		pallet::VerificationStats,
	};
	use frame_support::assert_err;
	use orbinum_zk_verifier::{MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS};

	const BASE: usize = TRANSFER_PUBLIC_INPUTS;
	/// A transfer key the pallet admits: the memo-bound layout.
	const KEY: usize = BASE + MEMO_HASH_INPUTS;

	fn proof() -> Vec<u8> {
		vec![0x01; 128]
	}

	/// Encoder that records the layout it was asked for and fills `len` inputs.
	fn encoder(
		seen: &mut Option<InputLayout>,
		len: usize,
	) -> impl FnOnce(InputLayout) -> Option<Vec<[u8; 32]>> + '_ {
		move |layout| {
			*seen = Some(layout);
			Some(vec![[0x02; 32]; len])
		}
	}

	fn stats(circuit_id: CircuitId, version: u32) -> (u64, u64, u64) {
		let s = VerificationStats::<Test>::get(circuit_id, version);
		(
			s.total_verifications,
			s.successful_verifications,
			s.failed_verifications,
		)
	}

	// ── verify_statement ──────────────────────────────────────────────────────

	#[test]
	fn a_base_shield_key_gets_the_base_layout() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::SHIELD, 1, SHIELD_PUBLIC_INPUTS);
			let mut seen = None;
			let res = verify_statement::<Test>(
				CircuitId::SHIELD,
				Some(1),
				&proof(),
				encoder(&mut seen, SHIELD_PUBLIC_INPUTS),
			);
			assert_eq!(res, Ok((true, 1)));
			assert_eq!(seen, Some(InputLayout::Base));
		});
	}

	/// A base spend key binds no memo: wherever it came from, it verifies
	/// nothing, on either path, and the attempt is counted.
	#[test]
	fn a_base_spend_key_verifies_nothing() {
		new_test_ext().execute_with(|| {
			for cid in [CircuitId::TRANSFER, CircuitId::UNSHIELD] {
				insert_vk(cid, 1, BASE);
				let mut seen = None;
				let res =
					verify_statement::<Test>(cid, Some(1), &proof(), encoder(&mut seen, BASE));
				assert_eq!(res, Ok((false, 1)));
				assert_eq!(seen, None);
				let raw = verify_raw::<Test>(cid, Some(1), &proof(), vec![[0x02; 32]; BASE]);
				assert_eq!(raw, Ok((false, 1)));
				assert_eq!(stats(cid, 1), (2, 0, 2));
			}
		});
	}

	#[test]
	fn a_memo_bound_key_gets_the_memo_bound_layout() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 2, BASE + MEMO_HASH_INPUTS);
			let mut seen = None;
			let res = verify_statement::<Test>(
				CircuitId::TRANSFER,
				Some(2),
				&proof(),
				encoder(&mut seen, BASE + MEMO_HASH_INPUTS),
			);
			assert_eq!(res, Ok((true, 2)));
			assert_eq!(seen, Some(InputLayout::MemoBound));
		});
	}

	/// An encoder that cannot attest to the statement fails the proof without
	/// a pairing, and the attempt is still counted.
	#[test]
	fn a_statement_the_key_cannot_attest_to_fails_and_is_counted() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, KEY);
			let res = verify_statement::<Test>(CircuitId::TRANSFER, Some(1), &proof(), |_| None);
			assert_eq!(res, Ok((false, 1)));
			assert_eq!(stats(CircuitId::TRANSFER, 1), (1, 0, 1));
		});
	}

	#[test]
	fn a_key_of_foreign_arity_fails_without_encoding() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, BASE + 3);
			let mut seen = None;
			let res = verify_statement::<Test>(
				CircuitId::TRANSFER,
				Some(1),
				&proof(),
				encoder(&mut seen, BASE + 3),
			);
			assert_eq!(res, Ok((false, 1)));
			assert_eq!(seen, None);
			assert_eq!(stats(CircuitId::TRANSFER, 1), (1, 0, 1));
		});
	}

	#[test]
	fn inputs_that_do_not_fill_the_key_fail() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, KEY);
			let mut seen = None;
			let res = verify_statement::<Test>(
				CircuitId::TRANSFER,
				Some(1),
				&proof(),
				encoder(&mut seen, KEY - 2),
			);
			assert_eq!(res, Ok((false, 1)));
		});
	}

	#[test]
	fn a_key_that_does_not_deserialize_fails_closed() {
		new_test_ext().execute_with(|| {
			insert_key(CircuitId::TRANSFER, 1, vec![0xAB; 300].try_into().unwrap());
			let mut seen = None;
			let res = verify_statement::<Test>(
				CircuitId::TRANSFER,
				Some(1),
				&proof(),
				encoder(&mut seen, BASE),
			);
			assert_eq!(res, Ok((false, 1)));
			assert_eq!(seen, None, "no inputs are built for an unreadable key");
		});
	}

	#[test]
	fn an_unknown_circuit_takes_the_base_layout_at_any_arity() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId(200), 1, 3);
			let mut seen = None;
			let res =
				verify_statement::<Test>(CircuitId(200), Some(1), &proof(), encoder(&mut seen, 3));
			assert_eq!(res, Ok((true, 1)));
			assert_eq!(seen, Some(InputLayout::Base));
		});
	}

	// ── verify_raw ────────────────────────────────────────────────────────────

	#[test]
	fn empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_raw::<Test>(CircuitId::TRANSFER, Some(1), &[], vec![[0x02; 32]]),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn empty_public_inputs_are_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_raw::<Test>(CircuitId::TRANSFER, Some(1), &proof(), vec![]),
				Error::<Test>::EmptyPublicInputs
			);
		});
	}

	/// Raw inputs are not encoded or counted here; the count check against the
	/// key is ark-groth16's, which the test build stubs out.
	#[test]
	fn verify_raw_does_not_encode_inputs() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, KEY);
			activate(CircuitId::TRANSFER, 1);
			assert_eq!(
				verify_raw::<Test>(CircuitId::TRANSFER, None, &proof(), vec![[0x02; 32]]),
				Ok((true, 1))
			);
		});
	}

	// ── version resolution ────────────────────────────────────────────────────

	#[test]
	fn no_active_version_is_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_raw::<Test>(CircuitId::TRANSFER, None, &proof(), vec![[0x02; 32]]),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn an_explicit_version_without_a_key_is_unsupported() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_raw::<Test>(CircuitId::TRANSFER, Some(99), &proof(), vec![[0x02; 32]]),
				Error::<Test>::UnsupportedCircuitVersion
			);
		});
	}

	#[test]
	fn an_active_version_without_a_key_is_key_not_found() {
		new_test_ext().execute_with(|| {
			activate(CircuitId::TRANSFER, 3);
			assert_err!(
				verify_raw::<Test>(CircuitId::TRANSFER, None, &proof(), vec![[0x02; 32]]),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn an_explicit_version_overrides_the_active_one() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, KEY);
			insert_vk(CircuitId::TRANSFER, 2, KEY);
			activate(CircuitId::TRANSFER, 1);
			let (_, version) =
				verify_raw::<Test>(CircuitId::TRANSFER, Some(2), &proof(), vec![[0x02; 32]])
					.unwrap();
			assert_eq!(version, 2);
		});
	}

	// ── statistics ────────────────────────────────────────────────────────────

	#[test]
	fn stats_count_per_circuit_and_version() {
		new_test_ext().execute_with(|| {
			for cid in [CircuitId::TRANSFER, CircuitId::UNSHIELD] {
				insert_vk(cid, 1, KEY);
			}
			let raw = || vec![[0x02; 32]];
			verify_raw::<Test>(CircuitId::TRANSFER, Some(1), &proof(), raw()).unwrap();
			verify_raw::<Test>(CircuitId::UNSHIELD, Some(1), &proof(), raw()).unwrap();
			verify_raw::<Test>(CircuitId::UNSHIELD, Some(1), &proof(), raw()).unwrap();
			assert_eq!(stats(CircuitId::TRANSFER, 1), (1, 1, 0));
			assert_eq!(stats(CircuitId::UNSHIELD, 1), (2, 2, 0));
		});
	}

	#[test]
	fn record_stats_persists_failures() {
		new_test_ext().execute_with(|| {
			record_stats::<Test>(CircuitId::TRANSFER, 1, false);
			record_stats::<Test>(CircuitId::TRANSFER, 1, false);
			record_stats::<Test>(CircuitId::TRANSFER, 1, true);
			assert_eq!(stats(CircuitId::TRANSFER, 1), (3, 1, 2));
		});
	}
}
