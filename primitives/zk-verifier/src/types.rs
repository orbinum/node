//! Core ZK types: proofs, keys, inputs, errors, and circuit constants.

use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt;

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

// ─── Circuit constants ────────────────────────────────────────────────────────

/// Circuit identifier for transfer operations.
pub const CIRCUIT_ID_TRANSFER: u8 = 1;
/// Circuit identifier for unshield (withdraw) operations.
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;
/// Circuit identifier for value proof operations (proves note commitment encodes declared value).
pub const CIRCUIT_ID_VALUE_PROOF: u8 = 6;

/// Number of public inputs for the transfer circuit.
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2, asset_id, fee]
pub const TRANSFER_PUBLIC_INPUTS: usize = 7;
/// Number of public inputs for the unshield circuit.
/// Public inputs: [merkle_root, nullifier, amount, recipient, asset_id, fee, change_commitment]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 7;
/// Number of public signals for the value proof circuit.
/// Signals: [commitment(32B), value(8B), asset_id(4B), owner_hash(32B)] = 4 field elements.
pub const VALUE_PROOF_PUBLIC_INPUTS: usize = 4;

/// Base cost for Groth16 verification (pairing operations).
pub const BASE_VERIFICATION_COST: u64 = 100_000;
/// Cost per public input (scalar multiplication).
pub const PER_INPUT_COST: u64 = 10_000;
/// Maximum number of public inputs supported.
pub const MAX_PUBLIC_INPUTS: usize = 32;

/// Largest verifying key this crate will attempt to deserialize.
///
/// `ark-serialize` reads a `Vec` by taking an 8-byte length prefix and calling
/// `Vec::with_capacity` on it **before** reading a single element, so a key
/// declaring 2^40 points asks the allocator for tens of gigabytes on nothing but
/// attacker-supplied bytes. Rejecting oversized input up front keeps that
/// allocation from ever being attempted.
///
/// A real BN254 key is ~488 bytes; the on-chain extrinsics bound their argument
/// at 8 KiB. This matches that bound so the crate is not the narrower gate, but
/// unlike the extrinsic bound it also covers callers that never pass through a
/// dispatchable.
pub const MAX_VK_BYTES: usize = 8192;

/// Largest proof this crate will attempt to deserialize.
///
/// A compressed Groth16 proof over BN254 is three curve points — 128 bytes,
/// fixed. The margin is for encoding variations, not for growth: anything an
/// order of magnitude past this is malformed, and letting it through only gives
/// the deserializer a length prefix to act on.
pub const MAX_PROOF_BYTES: usize = 1024;

/// Expected public-input count for a known circuit id, or `None` if unknown.
/// A VK for the circuit must have `gamma_abc_g1.len() == expected + 1`.
pub const fn expected_public_inputs(circuit_id: u8) -> Option<usize> {
	match circuit_id {
		CIRCUIT_ID_TRANSFER => Some(TRANSFER_PUBLIC_INPUTS),
		CIRCUIT_ID_UNSHIELD => Some(UNSHIELD_PUBLIC_INPUTS),
		CIRCUIT_ID_VALUE_PROOF => Some(VALUE_PROOF_PUBLIC_INPUTS),
		_ => None,
	}
}

// ─── VerifierError ────────────────────────────────────────────────────────────

/// Errors that can occur during proof verification.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub enum VerifierError {
	/// The proof is invalid or malformed.
	InvalidProof,
	/// The verifying key is invalid or malformed.
	InvalidVerifyingKey,
	/// Public input is invalid.
	InvalidPublicInput,
	/// Public input count mismatch.
	InvalidPublicInputCount { expected: u32, got: u32 },
	/// Proof verification failed (proof is incorrect).
	VerificationFailed,
	/// Serialization/deserialization error.
	SerializationError,
	/// Invalid proof size.
	InvalidProofSize,
	/// Invalid verifying key size.
	InvalidVKSize,
	/// Invalid circuit ID (not recognized).
	InvalidCircuitId(u8),
}

impl fmt::Display for VerifierError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			VerifierError::InvalidProof => write!(f, "Invalid proof"),
			VerifierError::InvalidVerifyingKey => write!(f, "Invalid verifying key"),
			VerifierError::InvalidPublicInput => write!(f, "Invalid public input"),
			VerifierError::InvalidPublicInputCount { expected, got } => {
				write!(
					f,
					"Invalid public input count: expected {expected}, got {got}"
				)
			}
			VerifierError::VerificationFailed => write!(f, "Verification failed"),
			VerifierError::SerializationError => write!(f, "Serialization error"),
			VerifierError::InvalidProofSize => write!(f, "Invalid proof size"),
			VerifierError::InvalidVKSize => write!(f, "Invalid verifying key size"),
			VerifierError::InvalidCircuitId(id) => write!(f, "Invalid circuit ID: {id}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for VerifierError {}

// ─── Proof ────────────────────────────────────────────────────────────────────

/// A Groth16 proof in compressed serialized form.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct Proof {
	pub bytes: Vec<u8>,
}

impl Proof {
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	pub fn to_ark_proof(&self) -> Result<ArkProof<Bn254>, VerifierError> {
		if self.bytes.len() > MAX_PROOF_BYTES {
			return Err(VerifierError::InvalidProof);
		}
		ArkProof::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidProof)
	}

	pub fn from_ark_proof(proof: &ArkProof<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		proof
			.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}
}

// ─── VerifyingKey ─────────────────────────────────────────────────────────────

/// A Groth16 verifying key in compressed serialized form.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct VerifyingKey {
	pub bytes: Vec<u8>,
}

impl VerifyingKey {
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	pub fn to_ark_vk(&self) -> Result<ArkVK<Bn254>, VerifierError> {
		if self.bytes.len() > MAX_VK_BYTES {
			return Err(VerifierError::InvalidVerifyingKey);
		}
		ArkVK::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidVerifyingKey)
	}

	pub fn from_ark_vk(vk: &ArkVK<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		vk.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}

	pub fn prepare(&self) -> Result<PreparedVerifyingKey<Bn254>, VerifierError> {
		let vk = self.to_ark_vk()?;
		Ok(PreparedVerifyingKey::from(vk))
	}

	pub fn num_public_inputs(&self) -> Result<usize, VerifierError> {
		let vk = self.to_ark_vk()?;
		vk.gamma_abc_g1
			.len()
			.checked_sub(1)
			.ok_or(VerifierError::InvalidVerifyingKey)
	}
}

// ─── PublicInputs ─────────────────────────────────────────────────────────────

/// Public inputs for a Groth16 proof — each input is a field element in LE bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct PublicInputs {
	pub inputs: Vec<[u8; 32]>,
}

impl PublicInputs {
	pub fn new(inputs: Vec<[u8; 32]>) -> Self {
		Self { inputs }
	}

	pub fn len(&self) -> usize {
		self.inputs.len()
	}

	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty()
	}

	pub fn to_field_elements(&self) -> Result<Vec<Bn254Fr>, VerifierError> {
		use ark_ff::{BigInteger, PrimeField};
		if self.inputs.len() > MAX_PUBLIC_INPUTS {
			return Err(VerifierError::InvalidPublicInput);
		}
		self.inputs
			.iter()
			.map(|bytes| {
				let fe = Bn254Fr::from_le_bytes_mod_order(bytes);
				if fe.into_bigint().to_bytes_le().as_slice() != &bytes[..] {
					return Err(VerifierError::InvalidPublicInput);
				}
				Ok(fe)
			})
			.collect()
	}

	pub fn from_field_elements(elements: &[Bn254Fr]) -> Self {
		use ark_ff::{BigInteger, PrimeField};
		let inputs = elements
			.iter()
			.map(|elem| {
				let elem_bytes = elem.into_bigint().to_bytes_le();
				debug_assert_eq!(elem_bytes.len(), 32, "BN254 Fr must be 32 LE bytes");
				let mut bytes = [0u8; 32];
				let len = elem_bytes.len().min(32);
				bytes[..len].copy_from_slice(&elem_bytes[..len]);
				bytes
			})
			.collect();
		Self { inputs }
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;
	use ark_ff::PrimeField;

	// ─── VerifierError ───────────────────────────────────────────────────

	#[test]
	fn test_error_equality_and_clone() {
		let a = VerifierError::InvalidProof;
		let b = a.clone();
		assert_eq!(a, b);
		let c = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		assert_eq!(c.clone(), c);
	}

	#[test]
	fn test_display_messages() {
		assert_eq!(VerifierError::InvalidProof.to_string(), "Invalid proof");
		assert_eq!(
			VerifierError::InvalidVerifyingKey.to_string(),
			"Invalid verifying key"
		);
		assert_eq!(
			VerifierError::InvalidPublicInput.to_string(),
			"Invalid public input"
		);
		assert_eq!(
			VerifierError::VerificationFailed.to_string(),
			"Verification failed"
		);
		assert_eq!(
			VerifierError::SerializationError.to_string(),
			"Serialization error"
		);
		assert_eq!(
			VerifierError::InvalidProofSize.to_string(),
			"Invalid proof size"
		);
		assert_eq!(
			VerifierError::InvalidVKSize.to_string(),
			"Invalid verifying key size"
		);
	}

	#[test]
	fn test_display_dynamic_messages() {
		let msg = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 2,
		}
		.to_string();
		assert_eq!(msg, "Invalid public input count: expected 5, got 2");
		let msg = VerifierError::InvalidCircuitId(9).to_string();
		assert_eq!(msg, "Invalid circuit ID: 9");
	}

	// ─── Circuit constants ───────────────────────────────────────────────

	#[test]
	fn test_circuit_ids_are_stable() {
		assert_eq!(CIRCUIT_ID_TRANSFER, 1);
		assert_eq!(CIRCUIT_ID_UNSHIELD, 2);
		assert_eq!(CIRCUIT_ID_VALUE_PROOF, 6);
	}

	#[test]
	fn test_public_input_counts_are_expected() {
		assert_eq!(TRANSFER_PUBLIC_INPUTS, 7);
		assert_eq!(UNSHIELD_PUBLIC_INPUTS, 7);
		assert_eq!(VALUE_PROOF_PUBLIC_INPUTS, 4);
	}

	#[test]
	fn expected_public_inputs_maps_known_circuits() {
		assert_eq!(expected_public_inputs(CIRCUIT_ID_TRANSFER), Some(7));
		assert_eq!(expected_public_inputs(CIRCUIT_ID_UNSHIELD), Some(7));
		assert_eq!(expected_public_inputs(CIRCUIT_ID_VALUE_PROOF), Some(4));
		// Unknown / unmapped circuit ids (e.g. shield=3) return None.
		assert_eq!(expected_public_inputs(3), None);
		// Circuit 5 (retired private-link) is no longer a known circuit: a VK
		// registered under that id would skip arity validation entirely.
		assert_eq!(expected_public_inputs(5), None);
		assert_eq!(expected_public_inputs(0), None);
		assert_eq!(expected_public_inputs(99), None);
	}

	// ─── Proof ──────────────────────────────────────────────────────────

	#[test]
	fn test_proof_new() {
		let bytes = vec![1, 2, 3, 4, 5];
		let proof = Proof::new(bytes.clone());
		assert_eq!(proof.bytes, bytes);
	}

	#[test]
	fn test_proof_as_bytes() {
		let bytes = vec![1, 2, 3, 4, 5];
		let proof = Proof::new(bytes.clone());
		assert_eq!(proof.as_bytes(), &bytes[..]);
	}

	#[test]
	fn test_proof_to_ark_proof_invalid() {
		let proof = Proof::new(vec![0u8; 10]);
		let result = proof.to_ark_proof();
		assert!(matches!(result, Err(VerifierError::InvalidProof)));
	}

	#[test]
	fn test_proof_clone() {
		let proof1 = Proof::new(vec![1, 2, 3]);
		assert_eq!(proof1.clone(), proof1);
	}

	#[test]
	fn test_proof_empty_bytes() {
		assert!(Proof::new(vec![]).as_bytes().is_empty());
	}

	// ─── VerifyingKey ────────────────────────────────────────────────────

	#[test]
	fn test_vk_new() {
		let bytes = vec![1, 2, 3, 4, 5];
		let vk = VerifyingKey::new(bytes.clone());
		assert_eq!(vk.bytes, bytes);
	}

	#[test]
	fn test_vk_as_bytes() {
		let bytes = vec![1, 2, 3, 4, 5];
		let vk = VerifyingKey::new(bytes.clone());
		assert_eq!(vk.as_bytes(), &bytes[..]);
	}

	#[test]
	fn test_vk_to_ark_vk_invalid() {
		let vk = VerifyingKey::new(vec![0u8; 10]);
		assert!(matches!(
			vk.to_ark_vk(),
			Err(VerifierError::InvalidVerifyingKey)
		));
	}

	#[test]
	fn test_vk_prepare_invalid() {
		assert!(VerifyingKey::new(vec![0u8; 10]).prepare().is_err());
	}

	#[test]
	fn test_vk_clone() {
		let vk1 = VerifyingKey::new(vec![1, 2, 3]);
		assert_eq!(vk1.clone(), vk1);
	}

	#[test]
	fn test_vk_empty_bytes() {
		assert!(VerifyingKey::new(vec![]).as_bytes().is_empty());
	}

	// ─── PublicInputs ────────────────────────────────────────────────────

	#[test]
	fn test_public_inputs_new() {
		let inputs = vec![[1u8; 32], [2u8; 32]];
		let pi = PublicInputs::new(inputs.clone());
		assert_eq!(pi.inputs, inputs);
	}

	#[test]
	fn test_public_inputs_len() {
		assert_eq!(PublicInputs::new(vec![[0u8; 32]; 5]).len(), 5);
	}

	#[test]
	fn test_public_inputs_is_empty() {
		assert!(PublicInputs::new(vec![]).is_empty());
		assert!(!PublicInputs::new(vec![[0u8; 32]]).is_empty());
	}

	#[test]
	fn test_public_inputs_to_field_elements() {
		let result = PublicInputs::new(vec![[1u8; 32], [2u8; 32]]).to_field_elements();
		assert_eq!(result.unwrap().len(), 2);
	}

	#[test]
	fn to_field_elements_rejects_non_canonical() {
		use ark_ff::{BigInteger, PrimeField};
		// 0xff..ff is >= p → rejected.
		let result = PublicInputs::new(vec![[0xffu8; 32]]).to_field_elements();
		assert_eq!(result, Err(VerifierError::InvalidPublicInput));

		let n = Bn254Fr::from(7u64);
		let n_bytes: [u8; 32] = {
			let mut b = [0u8; 32];
			let le = n.into_bigint().to_bytes_le();
			b[..le.len()].copy_from_slice(&le);
			b
		};
		// Canonical n is accepted.
		let ok = PublicInputs::new(vec![n_bytes]).to_field_elements();
		assert_eq!(ok.unwrap(), vec![n]);

		// n + p: same field element, non-canonical bytes.
		let p_bytes: [u8; 32] = {
			let mut p = [0u8; 32];
			let pm1 = (-Bn254Fr::from(1u64)).into_bigint().to_bytes_le();
			p[..pm1.len()].copy_from_slice(&pm1);
			let mut carry = 1u16;
			for b in p.iter_mut() {
				let v = *b as u16 + carry;
				*b = (v & 0xff) as u8;
				carry = v >> 8;
			}
			p
		};
		let mut n_plus_p = [0u8; 32];
		let mut carry = 0u16;
		for i in 0..32 {
			let v = p_bytes[i] as u16 + n_bytes[i] as u16 + carry;
			n_plus_p[i] = (v & 0xff) as u8;
			carry = v >> 8;
		}
		assert_eq!(carry, 0, "n+p must fit in 32 bytes for this test");
		assert_eq!(Bn254Fr::from_le_bytes_mod_order(&n_plus_p), n);
		let rejected = PublicInputs::new(vec![n_plus_p]).to_field_elements();
		assert_eq!(rejected, Err(VerifierError::InvalidPublicInput));
	}

	#[test]
	fn test_public_inputs_from_field_elements() {
		let elements = vec![Bn254Fr::from(123u64), Bn254Fr::from(456u64)];
		assert_eq!(PublicInputs::from_field_elements(&elements).len(), 2);
	}

	#[test]
	fn from_field_elements_encodes_full_32_bytes() {
		// 0, 1, and p-1 (largest Fr) all encode without truncation.
		let elements = vec![
			Bn254Fr::from(0u64),
			Bn254Fr::from(1u64),
			-Bn254Fr::from(1u64),
		];
		let pi = PublicInputs::from_field_elements(&elements);
		// Round-trip must recover the exact elements — a truncated high byte would not.
		assert_eq!(pi.to_field_elements().unwrap(), elements);
	}

	#[test]
	fn test_public_inputs_roundtrip_conversion() {
		let original = vec![
			Bn254Fr::from(123u64),
			Bn254Fr::from(456u64),
			Bn254Fr::from(789u64),
		];
		let converted = PublicInputs::from_field_elements(&original)
			.to_field_elements()
			.unwrap();
		assert_eq!(converted, original);
	}

	#[test]
	fn test_public_inputs_clone() {
		let pi = PublicInputs::new(vec![[1u8; 32], [2u8; 32]]);
		assert_eq!(pi.clone(), pi);
	}

	#[test]
	fn test_public_inputs_empty() {
		let empty = PublicInputs::new(vec![]);
		assert_eq!(empty.len(), 0);
		assert_eq!(empty.to_field_elements().unwrap().len(), 0);
	}

	#[test]
	fn test_public_inputs_large_values() {
		// from_field_elements re-encodes canonically, so the round-trip is accepted.
		let max = Bn254Fr::from_le_bytes_mod_order(&[0xff; 32]);
		let elements = vec![max, Bn254Fr::from(0u64), max];
		let converted = PublicInputs::from_field_elements(&elements)
			.to_field_elements()
			.unwrap();
		assert_eq!(converted, elements);
	}

	#[test]
	fn test_public_inputs_many_elements() {
		let elements: Vec<Bn254Fr> = (0..32).map(|i| Bn254Fr::from(i as u64)).collect();
		let pi = PublicInputs::from_field_elements(&elements);
		assert_eq!(pi.len(), 32);
		let converted = pi.to_field_elements().unwrap();
		for (i, (orig, conv)) in elements.iter().zip(converted.iter()).enumerate() {
			assert_eq!(orig, conv, "Mismatch at index {i}");
		}
	}

	// ─── Deserialization bounds ───────────────────────────────────────────────

	/// Build a genuine BN254 verifying key with `arity` public inputs.
	///
	/// Real, not random bytes: the point of the size guard is to reject input
	/// that *would* deserialize, so a test built on garbage would pass whether
	/// or not the guard exists.
	#[cfg(test)]
	fn well_formed_vk(arity: usize) -> Vec<u8> {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;

		let vk = ArkVK::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
		};
		VerifyingKey::from_ark_vk(&vk).expect("serializes").bytes
	}

	/// `ark-serialize` sizes a `Vec` from an 8-byte length prefix and calls
	/// `Vec::with_capacity` before reading a single element, so a key declaring
	/// 2^40 points asks the allocator for tens of gigabytes on attacker-supplied
	/// bytes alone. The length has to be checked first.
	///
	/// The key here is well-formed and would deserialize — only its size makes it
	/// unacceptable. That is what separates this from a malformed-input test.
	#[test]
	fn oversized_but_valid_vk_is_rejected_on_size() {
		// Each G1 point is 32 bytes compressed, so this clears 8 KiB comfortably.
		let bytes = well_formed_vk(400);
		assert!(
			bytes.len() > MAX_VK_BYTES,
			"fixture must exceed the bound to test it: {} bytes",
			bytes.len()
		);

		assert_eq!(
			VerifyingKey::new(bytes).to_ark_vk(),
			Err(VerifierError::InvalidVerifyingKey)
		);
	}

	/// The same key just inside the bound must still work, or the guard would be
	/// rejecting legitimate input.
	#[test]
	fn valid_vk_within_the_bound_is_accepted() {
		let bytes = well_formed_vk(7);
		assert!(bytes.len() <= MAX_VK_BYTES);
		assert!(VerifyingKey::new(bytes).to_ark_vk().is_ok());
	}

	/// The guard covers every entry point, not just the one that deserializes:
	/// `prepare` and `num_public_inputs` both route through `to_ark_vk`.
	#[test]
	fn oversized_vk_is_rejected_on_every_path() {
		let vk = VerifyingKey::new(well_formed_vk(400));

		assert!(vk.prepare().is_err());
		assert!(vk.num_public_inputs().is_err());
	}

	/// A proof past the bound is refused on size alone.
	///
	/// `deserialize_compressed` ignores trailing bytes, so a real proof padded
	/// out still deserializes — which makes it a fixture the guard is the only
	/// thing rejecting.
	#[test]
	fn oversized_proof_is_rejected_on_size() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;

		let proof = ArkProof::<Bn254> {
			a: G1Affine::generator(),
			b: G2Affine::generator(),
			c: G1Affine::generator(),
		};
		let mut bytes = Proof::from_ark_proof(&proof).expect("serializes").bytes;
		assert!(
			Proof::new(bytes.clone()).to_ark_proof().is_ok(),
			"fixture must be valid first"
		);

		bytes.resize(MAX_PROOF_BYTES + 1, 0u8);
		assert_eq!(
			Proof::new(bytes).to_ark_proof(),
			Err(VerifierError::InvalidProof)
		);
	}

	/// The limits must not shadow real input: a genuine BN254 key is ~488 bytes
	/// and a compressed proof 128, both far below their bound.
	#[test]
	fn bounds_leave_room_for_real_artifacts() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;

		assert!(
			well_formed_vk(7).len() * 4 < MAX_VK_BYTES,
			"VK bound too tight"
		);

		// Measured, not hardcoded: a literal here would drift from the real
		// encoding the moment it changed, which is exactly what this guards.
		let proof = ArkProof::<Bn254> {
			a: G1Affine::generator(),
			b: G2Affine::generator(),
			c: G1Affine::generator(),
		};
		let real = Proof::from_ark_proof(&proof)
			.expect("serializes")
			.bytes
			.len();
		assert!(
			real * 4 < MAX_PROOF_BYTES,
			"proof bound too tight: {real} bytes"
		);
	}

	/// `MAX_PUBLIC_INPUTS` was declared but never applied: the pallet bounds its
	/// extrinsic argument, yet the `ZkVerifierPort` path does not go through it.
	#[test]
	fn too_many_public_inputs_are_rejected() {
		let inputs = alloc::vec![[0u8; 32]; MAX_PUBLIC_INPUTS + 1];
		assert_eq!(
			PublicInputs::new(inputs).to_field_elements(),
			Err(VerifierError::InvalidPublicInput)
		);
	}

	/// Exactly at the limit still works — the check is `>`, not `>=`.
	#[test]
	fn public_inputs_at_the_limit_are_accepted() {
		let inputs = alloc::vec![[0u8; 32]; MAX_PUBLIC_INPUTS];
		assert!(PublicInputs::new(inputs).to_field_elements().is_ok());
	}

	/// Every circuit in use sits far below the cap, so enforcing it cannot break
	/// a real verification.
	///
	/// A `const` block rather than a `#[test]`: these are all constants, so the
	/// comparison is decided at compile time either way — this way raising a
	/// circuit's arity past the cap fails the build instead of a test run.
	const _: () = {
		assert!(
			TRANSFER_PUBLIC_INPUTS * 4 < MAX_PUBLIC_INPUTS,
			"transfer arity is too close to MAX_PUBLIC_INPUTS"
		);
		assert!(
			UNSHIELD_PUBLIC_INPUTS * 4 < MAX_PUBLIC_INPUTS,
			"unshield arity is too close to MAX_PUBLIC_INPUTS"
		);
		assert!(
			VALUE_PROOF_PUBLIC_INPUTS * 4 < MAX_PUBLIC_INPUTS,
			"value-proof arity is too close to MAX_PUBLIC_INPUTS"
		);
	};
}
