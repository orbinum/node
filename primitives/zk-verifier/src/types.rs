//! Core Groth16 types: proofs, keys, public inputs, errors, and size limits.

use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt;

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

// ─── Limits ───────────────────────────────────────────────────────────────────
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

/// Exact size of a compressed Groth16 proof over BN254: `A` (G1, 32) + `B` (G2,
/// 64) + `C` (G1, 32). The deserializer ignores trailing bytes, so without this
/// bound a proof padded out would be a second encoding of the same proof.
pub const PROOF_BYTES: usize = 128;

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
		if self.bytes.len() != PROOF_BYTES {
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

	/// Deserialize, refusing any key that is not exactly a well-formed BN254
	/// Groth16 key.
	///
	/// The layout is checked before deserializing: `ark-serialize` reserves a
	/// `Vec` from its length prefix before reading an element, so a short key
	/// declaring 2^25 points would ask for gigabytes. Points at infinity are
	/// refused too — an identity `gamma_abc` entry would leave its public input
	/// out of the verification equation entirely.
	pub fn to_ark_vk(&self) -> Result<ArkVK<Bn254>, VerifierError> {
		use ark_ec::AffineRepr;
		// alpha (G1) + beta, gamma, delta (G2), compressed; then the u64 length
		// of `gamma_abc` and its G1 points.
		const HEADER: usize = 32 + 3 * 64;
		const G1: usize = 32;
		let bytes = &self.bytes[..];
		if bytes.len() > MAX_VK_BYTES {
			return Err(VerifierError::InvalidVerifyingKey);
		}
		let declared = bytes
			.get(HEADER..HEADER + 8)
			.and_then(|len| <[u8; 8]>::try_from(len).ok())
			.map(u64::from_le_bytes)
			.ok_or(VerifierError::InvalidVerifyingKey)?;
		if declared == 0 || declared > (MAX_PUBLIC_INPUTS as u64 + 1) {
			return Err(VerifierError::InvalidVerifyingKey);
		}
		if bytes.len() != HEADER + 8 + declared as usize * G1 {
			return Err(VerifierError::InvalidVerifyingKey);
		}

		let vk = ArkVK::<Bn254>::deserialize_compressed(bytes)
			.map_err(|_| VerifierError::InvalidVerifyingKey)?;
		let identity = vk.alpha_g1.is_zero()
			|| vk.beta_g2.is_zero()
			|| vk.gamma_g2.is_zero()
			|| vk.delta_g2.is_zero()
			|| vk.gamma_abc_g1.iter().any(|p| p.is_zero());
		if identity {
			return Err(VerifierError::InvalidVerifyingKey);
		}
		Ok(vk)
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

/// Reduce 32 little-endian bytes mod BN254 `r`: the canonical field element the
/// verifier accepts as a public input.
pub fn to_field_le(bytes: &[u8; 32]) -> [u8; 32] {
	use ark_ff::{BigInteger, PrimeField};
	let mut out = [0u8; 32];
	out.copy_from_slice(
		&Bn254Fr::from_le_bytes_mod_order(bytes)
			.into_bigint()
			.to_bytes_le(),
	);
	out
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use ark_ff::PrimeField;

	// ─── Helpers ──────────────────────────────────────────────────────────────
	/// A genuine BN254 verifying key with `arity` public inputs; `tweak` edits it
	/// before encoding.
	///
	/// Real, not random bytes: a size or layout guard must reject input that
	/// *would* deserialize, so a test built on garbage would pass whether or not
	/// the guard exists.
	fn vk_bytes(arity: usize, tweak: impl FnOnce(&mut ArkVK<Bn254>)) -> Vec<u8> {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		let mut vk = ArkVK::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
		};
		tweak(&mut vk);
		VerifyingKey::from_ark_vk(&vk).expect("serializes").bytes
	}

	fn well_formed_vk(arity: usize) -> Vec<u8> {
		vk_bytes(arity, |_| {})
	}

	// ─── VerifierError ────────────────────────────────────────────────────────
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

	// ─── Proof ────────────────────────────────────────────────────────────────
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

	// ─── VerifyingKey ─────────────────────────────────────────────────────────
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
	fn to_ark_vk_accepts_a_well_formed_key() {
		assert!(VerifyingKey::new(vk_bytes(8, |_| {})).to_ark_vk().is_ok());
	}

	#[test]
	fn to_ark_vk_refuses_a_huge_declared_length_without_allocating() {
		let mut bytes = vk_bytes(1, |_| {});
		bytes[224..232].copy_from_slice(&(1u64 << 25).to_le_bytes());
		assert_eq!(
			VerifyingKey::new(bytes).to_ark_vk(),
			Err(VerifierError::InvalidVerifyingKey)
		);
	}

	#[test]
	fn to_ark_vk_refuses_trailing_bytes() {
		let mut bytes = vk_bytes(2, |_| {});
		bytes.push(0);
		assert!(VerifyingKey::new(bytes).to_ark_vk().is_err());
	}

	#[test]
	fn to_ark_vk_refuses_points_at_infinity() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		let zero_input = vk_bytes(3, |vk| vk.gamma_abc_g1[2] = G1Affine::zero());
		assert!(VerifyingKey::new(zero_input).to_ark_vk().is_err());
		let zero_delta = vk_bytes(3, |vk| vk.delta_g2 = G2Affine::zero());
		assert!(VerifyingKey::new(zero_delta).to_ark_vk().is_err());
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

	// ─── PublicInputs ─────────────────────────────────────────────────────────
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

	/// A point on the twist curve outside the prime-order G2 subgroup. Found by
	/// walking x coordinates: the cofactor is huge, so almost any curve point
	/// qualifies, and the check says which.
	fn off_subgroup_g2() -> ark_bn254::G2Affine {
		use ark_bn254::{Fq, Fq2, G2Affine};
		(1u64..)
			.filter_map(|i| {
				G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::from(1u64)), false)
			})
			.find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
			.expect("a curve point outside the subgroup exists")
	}

	fn proof_bytes(
		a: ark_bn254::G1Affine,
		b: ark_bn254::G2Affine,
		c: ark_bn254::G1Affine,
	) -> Vec<u8> {
		use ark_serialize::CanonicalSerialize;
		let mut bytes = Vec::new();
		a.serialize_compressed(&mut bytes).unwrap();
		b.serialize_compressed(&mut bytes).unwrap();
		c.serialize_compressed(&mut bytes).unwrap();
		bytes
	}

	/// Pairings on a G2 point outside the subgroup are not bilinear, which is how
	/// a forged proof could pass a verifier that skips the subgroup check. The
	/// deserializer must refuse the point, for a proof's `B` and for every G2
	/// element of a key.
	#[test]
	fn a_g2_point_outside_the_subgroup_is_refused_in_proofs_and_keys() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		let off = off_subgroup_g2();
		assert!(off.is_on_curve());
		assert!(!off.is_in_correct_subgroup_assuming_on_curve());

		let proof = Proof::new(proof_bytes(
			G1Affine::generator(),
			off,
			G1Affine::generator(),
		));
		assert!(proof.to_ark_proof().is_err());
		// The same bytes with a subgroup point deserialize: the refusal is the point.
		let fine = Proof::new(proof_bytes(
			G1Affine::generator(),
			G2Affine::generator(),
			G1Affine::generator(),
		));
		assert!(fine.to_ark_proof().is_ok());

		assert!(VerifyingKey::new(vk_bytes(3, |vk| vk.beta_g2 = off))
			.to_ark_vk()
			.is_err());
		assert!(VerifyingKey::new(vk_bytes(3, |vk| vk.gamma_g2 = off))
			.to_ark_vk()
			.is_err());
		assert!(VerifyingKey::new(vk_bytes(3, |vk| vk.delta_g2 = off))
			.to_ark_vk()
			.is_err());
	}

	/// Proof points at infinity, all-zero and all-0xff bytes: refused or failing
	/// verification, never a panic.
	#[test]
	fn degenerate_proof_bytes_never_verify_or_panic() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		let pvk = VerifyingKey::new(well_formed_vk(2)).prepare().unwrap();
		let inputs = PublicInputs::new(vec![[1u8; 32], [2u8; 32]]);
		let len = proof_bytes(
			G1Affine::generator(),
			G2Affine::generator(),
			G1Affine::generator(),
		)
		.len();
		let candidates = [
			proof_bytes(G1Affine::zero(), G2Affine::zero(), G1Affine::zero()),
			proof_bytes(
				G1Affine::zero(),
				G2Affine::generator(),
				G1Affine::generator(),
			),
			vec![0u8; len],
			vec![0xffu8; len],
			vec![0u8; len - 1],
			vec![0u8; len + 1],
		];
		for bytes in candidates {
			let proof = Proof::new(bytes);
			let res = proof
				.to_ark_proof()
				.map_err(|_| VerifierError::VerificationFailed)
				.and_then(|_| {
					crate::Groth16Verifier::verify_with_prepared_vk(&pvk, &inputs, &proof)
				});
			assert!(res.is_err());
		}
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

	#[test]
	fn to_field_le_reduces_mod_r() {
		use ark_ff::{BigInteger, PrimeField};
		let r: [u8; 32] = Bn254Fr::MODULUS.to_bytes_le().try_into().unwrap();
		let mut r_plus_one = r;
		r_plus_one[0] += 1;
		let mut one = [0u8; 32];
		one[0] = 1;

		assert_eq!(to_field_le(&r), [0u8; 32]);
		assert_eq!(to_field_le(&r_plus_one), one);
		assert_eq!(to_field_le(&one), one, "canonical input is unchanged");
		let max = to_field_le(&[0xFF; 32]);
		assert_eq!(to_field_le(&max), max, "output is canonical");
		assert!(PublicInputs::new(alloc::vec![max])
			.to_field_elements()
			.is_ok());
	}
	// ─── Deserialization bounds ───────────────────────────────────────────────
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

	/// `deserialize_compressed` ignores trailing bytes, so a real proof padded
	/// out would still deserialize: another byte string for the same proof. Only
	/// the exact compressed size is a proof.
	#[test]
	fn a_proof_with_trailing_bytes_is_refused() {
		use ark_bn254::{G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		let bytes = proof_bytes(
			G1Affine::generator(),
			G2Affine::generator(),
			G1Affine::generator(),
		);
		assert_eq!(bytes.len(), PROOF_BYTES);
		assert!(Proof::new(bytes.clone()).to_ark_proof().is_ok());
		for padding in [vec![0u8], vec![0xffu8; 8], vec![0u8; 896]] {
			let padded = [bytes.clone(), padding].concat();
			assert_eq!(
				Proof::new(padded).to_ark_proof(),
				Err(VerifierError::InvalidProof)
			);
		}
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
		assert_eq!(real, PROOF_BYTES, "proof bound too tight: {real} bytes");
	}

	/// `MAX_PUBLIC_INPUTS` is enforced here: the pallet bounds its extrinsic
	/// argument, but the `ZkVerifierPort` path does not go through it.
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
}
