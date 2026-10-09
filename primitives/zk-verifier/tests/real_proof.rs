//! End-to-end Groth16 verification against a real proof generated in-test.
//!
//! The pallet's `do_verify` short-circuits to `true` under `#[cfg(test)]`, so the
//! pairing is never exercised there. Here we run a real Groth16 setup + prove over
//! a small circuit, serialize the VK/proof exactly as the crate expects, and drive
//! `Groth16Verifier::verify`. This also covers the canonical-input rejection: the
//! same valid proof must stop verifying if an input is swapped for its `n + p`
//! non-canonical twin.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use orbinum_zk_verifier::{
	prepared_from_stored, Groth16Verifier, Proof, PublicInputs, VerifierError, VerifyingKey,
};

/// Circuit proving knowledge of `a`, `b` with `a * b == c`, where `c` is public.
#[derive(Clone)]
struct MulCircuit {
	a: Option<Fr>,
	b: Option<Fr>,
	c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
		use ark_relations::r1cs::LinearCombination;
		let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
		let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
		let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
		cs.enforce_constraint(
			LinearCombination::from(a),
			LinearCombination::from(b),
			LinearCombination::from(c),
		)?;
		Ok(())
	}
}

/// Serialize an arkworks proof/VK to the compressed bytes the crate consumes.
fn setup_and_prove() -> (VerifyingKey, Proof, Vec<[u8; 32]>) {
	let mut rng = StdRng::seed_from_u64(42);
	let a = Fr::from(3u64);
	let b = Fr::from(11u64);
	let c = a * b;

	let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
		MulCircuit {
			a: None,
			b: None,
			c: None,
		},
		&mut rng,
	)
	.unwrap();
	let proof = Groth16::<Bn254>::prove(
		&pk,
		MulCircuit {
			a: Some(a),
			b: Some(b),
			c: Some(c),
		},
		&mut rng,
	)
	.unwrap();

	let vk_bytes = VerifyingKey::from_ark_vk(&vk).unwrap();
	let proof_bytes = Proof::from_ark_proof(&proof).unwrap();

	// Single public input `c`, little-endian — the crate's `to_field_elements` reads LE.
	let mut c_le = [0u8; 32];
	let le = c.into_bigint().to_bytes_le();
	c_le[..le.len()].copy_from_slice(&le);

	(vk_bytes, proof_bytes, vec![c_le])
}

#[test]
fn real_proof_verifies() {
	let (vk, proof, inputs) = setup_and_prove();
	assert_eq!(
		Groth16Verifier::verify(&vk, &PublicInputs::new(inputs), &proof),
		Ok(())
	);
}

#[test]
fn real_proof_fails_with_wrong_public_input() {
	let (vk, proof, mut inputs) = setup_and_prove();
	// Claim c = 34 instead of 33 — the proof must not verify.
	let mut wrong = [0u8; 32];
	wrong[0] = 34;
	inputs[0] = wrong;
	assert_eq!(
		Groth16Verifier::verify(&vk, &PublicInputs::new(inputs), &proof),
		Err(VerifierError::VerificationFailed)
	);
}

#[test]
fn real_proof_rejects_non_canonical_input() {
	let (vk, proof, inputs) = setup_and_prove();
	let n_bytes = inputs[0];

	// n + p: same field element, non-canonical bytes → rejected before the pairing.
	let p_bytes = {
		let mut p = [0u8; 32];
		let pm1 = (-Fr::from(1u64)).into_bigint().to_bytes_le();
		p[..pm1.len()].copy_from_slice(&pm1);
		let mut carry = 1u16;
		for byte in p.iter_mut() {
			let v = *byte as u16 + carry;
			*byte = (v & 0xff) as u8;
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
	assert_eq!(carry, 0, "n + p must fit in 32 bytes");
	assert_eq!(
		Fr::from_le_bytes_mod_order(&n_plus_p),
		Fr::from_le_bytes_mod_order(&n_bytes)
	);
	assert_eq!(
		Groth16Verifier::verify(&vk, &PublicInputs::new(vec![n_plus_p]), &proof),
		Err(VerifierError::InvalidPublicInput)
	);
}

/// A key stored prepared and read back unchecked verifies exactly like one
/// prepared from the VK: the valid statement passes, a wrong one fails.
#[test]
fn a_stored_prepared_key_verifies_like_a_fresh_one() {
	let (vk, proof, inputs) = setup_and_prove();
	let pvk = prepared_from_stored(&vk.prepared_bytes().unwrap()).unwrap();
	assert_eq!(
		Groth16Verifier::verify_with_prepared_vk(&pvk, &PublicInputs::new(inputs), &proof),
		Ok(())
	);
	let mut wrong = [0u8; 32];
	wrong[0] = 34;
	assert_eq!(
		Groth16Verifier::verify_with_prepared_vk(&pvk, &PublicInputs::new(vec![wrong]), &proof),
		Err(VerifierError::VerificationFailed)
	);
}

/// No corruption of a stored prepared key makes an invalid proof verify, and
/// none panics. Each case flips one random bit; a key that still loads (the
/// flip landed in a coordinate) is driven through the verifier with a wrong
/// public input, which must never pass.
#[test]
fn a_corrupted_stored_key_never_verifies_an_invalid_proof() {
	use ark_std::rand::Rng;
	let (vk, proof, inputs) = setup_and_prove();
	let good = vk.prepared_bytes().unwrap();
	let mut wrong = [0u8; 32];
	wrong[0] = 34;
	let wrong = PublicInputs::new(vec![wrong]);
	let right = PublicInputs::new(inputs);

	let mut rng = StdRng::seed_from_u64(7);
	let (mut loaded, mut still_valid) = (0, 0);
	for _ in 0..400 {
		let mut bad = good.clone();
		let at = rng.gen_range(0..bad.len());
		bad[at] ^= 1 << rng.gen_range(0..8);
		let Ok(pvk) = prepared_from_stored(&bad) else {
			continue;
		};
		loaded += 1;
		assert!(
			Groth16Verifier::verify_with_prepared_vk(&pvk, &wrong, &proof).is_err(),
			"a flip at byte {at} let a wrong input verify"
		);
		if Groth16Verifier::verify_with_prepared_vk(&pvk, &right, &proof).is_ok() {
			still_valid += 1;
		}
	}
	// Most flips land in a coordinate and load; the pairing then rejects them. A
	// few land in `beta`/`gamma`/`delta` of the embedded key, which verification
	// never reads, and the valid proof still passes.
	assert!(loaded > 300, "only {loaded} corrupted keys loaded");
	println!("{loaded} corrupted keys loaded, {still_valid} still verify the valid proof");
}
