//! Core Groth16 proof verification.
//!
//! Resolves the circuit version, loads its key — prepared at registration —
//! picks the [`InputLayout`] the key implies — only an admitted one — and
//! records statistics. Encoding the inputs is the caller's (see
//! [`crate::encoding`]).

use super::keys::StoredKey;
use crate::{
	Error, Pallet,
	pallet::{ActiveCircuitVersion, Config, RetiredVersions, VerificationStats, VkHashes},
	types::CircuitId,
};
use alloc::vec::Vec;
use orbinum_zk_verifier::{
	InputLayout, VerifyingKey, has_memo_layout, input_layout, prepared_arity,
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
	check::<T>(circuit_id, version, proof, encode)
}

/// Verify a proof against caller-encoded inputs, taken as-is (the
/// `verify_proof` extrinsic). Inputs that do not fill the key are
/// `valid = false`, as for a statement.
pub fn verify_raw<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof: &[u8],
	raw_inputs: Vec<[u8; 32]>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	frame_support::ensure!(!raw_inputs.is_empty(), Error::<T>::EmptyPublicInputs);
	check::<T>(circuit_id, version, proof, |_| Some(raw_inputs))
}

/// The layout a key of `arity` inputs gives `circuit_id`, if admitted.
///
/// A spend circuit never takes the base layout, which binds neither its memos
/// nor the full recipient: such a key verifies nothing, however it reached
/// storage. An id past `u8::MAX` gets none rather than aliasing a known one
/// (`as u8` maps 257 to 1).
pub(crate) fn admitted_layout(circuit_id: CircuitId, arity: usize) -> Option<InputLayout> {
	let id = u8::try_from(circuit_id.0).ok()?;
	input_layout(id, arity).filter(|layout| !(has_memo_layout(id) && *layout == InputLayout::Base))
}

/// The path both entry points share:
///
/// 1. Resolve the version and load its key, in prepared form.
/// 2. Read the key's arity and the layout it gives the circuit, if admitted.
/// 3. Build the inputs for that layout (`inputs` returns `None` to fail).
/// 4. Verify, if the inputs fill the key exactly.
/// 5. Count the outcome.
///
/// Any step that fails makes the proof invalid; only an unknown circuit or
/// version is an error.
fn check<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof: &[u8],
	inputs: impl FnOnce(InputLayout) -> Option<Vec<[u8; 32]>>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	frame_support::ensure!(!proof.is_empty(), Error::<T>::EmptyProof);
	let (key, resolved) = resolve_key::<T>(circuit_id, version)?;

	// 1. A key without a prepared form (storage written outside `keys`) is
	// prepared here; one that does not prepare fails the proof.
	let prepared = match key {
		StoredKey::Prepared(bytes) => Some(bytes),
		StoredKey::Raw(bytes) => VerifyingKey::new(bytes).prepared_bytes().ok(),
	};
	// 2–4.
	let result = prepared.is_some_and(|prepared| {
		prepared_arity(&prepared).is_some_and(|arity| {
			admitted_layout(circuit_id, arity)
				.and_then(inputs)
				.filter(|raw| raw.len() == arity)
				.is_some_and(|raw| do_verify(&prepared, proof, &raw))
		})
	});
	// 5.
	record_stats::<T>(circuit_id, resolved, result);
	Ok((result, resolved))
}

/// The key and version to verify against: `version`, or the active one.
fn resolve_key<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
) -> Result<(StoredKey, u32), Error<T>> {
	let resolved = version
		.or_else(|| ActiveCircuitVersion::<T>::get(circuit_id))
		.ok_or(Error::<T>::CircuitNotFound)?;
	frame_support::ensure!(
		!RetiredVersions::<T>::contains_key(circuit_id, resolved)
			&& !VkHashes::<T>::get(circuit_id, resolved)
				.is_some_and(|h| Pallet::<T>::is_denied(&h)),
		Error::<T>::UnsupportedCircuitVersion
	);
	let key = Pallet::<T>::load_vk(circuit_id, resolved).ok_or(if version.is_some() {
		Error::<T>::UnsupportedCircuitVersion
	} else {
		Error::<T>::VerificationKeyNotFound
	})?;
	Ok((key, resolved))
}

/// Count a verification outcome in `VerificationStats`.
///
/// A failure is counted here but never reaches a block: `verify_proof` returns
/// `Err`, and the pool turns the port's `Ok(false)` into
/// `ProofVerificationFailed`, so either way the dispatch reverts this write.
/// Invalid spends are also refused at pool admission, before any block.
pub(crate) fn record_stats<T: Config>(circuit_id: CircuitId, version: u32, result: bool) {
	VerificationStats::<T>::mutate(circuit_id, version, |s| {
		s.total_verifications = s.total_verifications.saturating_add(1);
		if result {
			s.successful_verifications = s.successful_verifications.saturating_add(1);
		} else {
			s.failed_verifications = s.failed_verifications.saturating_add(1);
		}
	});
}

/// The pairing, under a key in prepared form: [`verify_prepared`], natively
/// through the node's `bn254_groth16_verify` host function under
/// `groth16-native`, in Wasm otherwise.
///
/// Always `true` in **test** builds, whose keys deserialize but carry no real
/// proofs. Benchmarks run the full pairing, so weights include it.
///
/// [`verify_prepared`]: orbinum_zk_verifier::verify_prepared
fn do_verify(prepared: &[u8], proof: &[u8], inputs: &[[u8; 32]]) -> bool {
	#[cfg(test)]
	{
		let _ = (prepared, proof, inputs);
		true
	}

	#[cfg(all(not(test), feature = "groth16-native"))]
	{
		orbinum_zk_verifier::host_interface::groth_16_host_interface::bn254_groth16_verify(
			prepared,
			proof,
			&inputs.concat(),
		)
	}

	#[cfg(all(not(test), not(feature = "groth16-native")))]
	{
		orbinum_zk_verifier::verify_prepared(prepared, proof, &inputs.concat())
	}
}
