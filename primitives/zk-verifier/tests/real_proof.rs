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
	prepared_from_stored, verify_prepared, Groth16Verifier, Proof, PublicInputs, VerifierError,
	VerifyingKey,
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
			assert!(
				!flat(&bad, &proof.bytes, &right),
				"byte {at}: refused, yet verified"
			);
			continue;
		};
		loaded += 1;
		assert!(
			Groth16Verifier::verify_with_prepared_vk(&pvk, &wrong, &proof).is_err(),
			"a flip at byte {at} let a wrong input verify"
		);
		let valid = Groth16Verifier::verify_with_prepared_vk(&pvk, &right, &proof).is_ok();
		if valid {
			still_valid += 1;
		}
		assert!(!flat(&bad, &proof.bytes, &wrong), "byte {at}: diverged");
		assert_eq!(
			flat(&bad, &proof.bytes, &right),
			valid,
			"byte {at}: diverged"
		);
	}
	// Most flips land in a coordinate and load; the pairing then rejects them. A
	// few land in `beta`/`gamma`/`delta` of the embedded key, which verification
	// never reads, and the valid proof still passes.
	assert!(loaded > 300, "only {loaded} corrupted keys loaded");
	println!("{loaded} corrupted keys loaded, {still_valid} still verify the valid proof");
}

// ─── verify_prepared ──────────────────────────────────────────────────────────

/// [`verify_prepared`] on a statement, with its inputs concatenated.
fn flat(prepared: &[u8], proof: &[u8], inputs: &PublicInputs) -> bool {
	verify_prepared(prepared, proof, &inputs.inputs.concat())
}

/// Answers as an independent oracle (the raw key, prepared from scratch): the
/// valid statement passes, a wrong or non-canonical input fails.
#[test]
fn verify_prepared_answers_as_the_raw_key() {
	let (vk, proof, inputs) = setup_and_prove();
	let prepared = vk.prepared_bytes().unwrap();
	let mut wrong = [0u8; 32];
	wrong[0] = 34;
	let mut non_canonical = inputs[0];
	// `c + p`: same field element, non-canonical bytes. `c = 33` and `p` leaves
	// the top byte room, so the sum fits.
	let p = ark_bn254::Fr::MODULUS.to_bytes_le();
	let mut carry = 0u16;
	for (byte, p) in non_canonical.iter_mut().zip(p) {
		let v = *byte as u16 + p as u16 + carry;
		*byte = v as u8;
		carry = v >> 8;
	}
	assert_eq!(carry, 0, "c + p must fit in 32 bytes");
	for (statement, expected) in [
		(PublicInputs::new(inputs), true),
		(PublicInputs::new(vec![wrong]), false),
		(PublicInputs::new(vec![non_canonical]), false),
	] {
		assert_eq!(
			Groth16Verifier::verify(&vk, &statement, &proof).is_ok(),
			expected
		);
		assert_eq!(flat(&prepared, &proof.bytes, &statement), expected);
	}
}

/// Every malformed argument is `false`, never a panic.
#[test]
fn verify_prepared_refuses_malformed_arguments() {
	let (vk, proof, inputs) = setup_and_prove();
	let prepared = vk.prepared_bytes().unwrap();
	let flat = inputs.concat();
	let verify = verify_prepared;
	assert!(
		verify(&prepared, &proof.bytes, &flat),
		"the well-formed call verifies"
	);

	let mut longer_proof = proof.bytes.clone();
	longer_proof.push(0);
	for bad_proof in [
		&[][..],
		&proof.bytes[..127],
		&longer_proof[..],
		&[0xFF; 128][..],
	] {
		assert!(
			!verify(&prepared, bad_proof, &flat),
			"proof of {} bytes",
			bad_proof.len()
		);
	}

	let two_inputs = [flat.clone(), flat.clone()].concat();
	for bad_inputs in [
		&[][..],
		&flat[..31],
		&[flat.clone(), vec![0]].concat()[..],
		&two_inputs[..],
	] {
		assert!(
			!verify(&prepared, &proof.bytes, bad_inputs),
			"inputs of {} bytes",
			bad_inputs.len()
		);
	}

	let mut longer_key = prepared.clone();
	longer_key.push(0);
	let mut absurd = prepared.clone();
	absurd[64 + 3 * 128..64 + 3 * 128 + 8].copy_from_slice(&u64::MAX.to_le_bytes());
	for bad_key in [
		&[][..],
		&prepared[..prepared.len() - 1],
		&longer_key[..],
		&absurd[..],
		&vk.bytes[..],
	] {
		assert!(
			!verify(bad_key, &proof.bytes, &flat),
			"key of {} bytes",
			bad_key.len()
		);
	}
	assert!(!verify(&[], &[], &[]));
}

/// Random proofs never verify and never panic.
#[test]
fn random_proofs_never_verify() {
	use ark_std::rand::RngCore;
	let (vk, _, inputs) = setup_and_prove();
	let prepared = vk.prepared_bytes().unwrap();
	let flat_inputs = inputs.concat();
	let mut rng = StdRng::seed_from_u64(11);
	for _ in 0..2000 {
		let mut proof = [0u8; 128];
		rng.fill_bytes(&mut proof);
		assert!(!verify_prepared(&prepared, &proof, &flat_inputs));
	}
}

/// No single-bit change to a valid proof verifies, nor swapping `A` and `C`.
#[test]
fn a_mutated_valid_proof_never_verifies() {
	let (vk, proof, inputs) = setup_and_prove();
	let prepared = vk.prepared_bytes().unwrap();
	let flat_inputs = inputs.concat();
	assert!(verify_prepared(&prepared, &proof.bytes, &flat_inputs));
	for bit in 0..proof.bytes.len() * 8 {
		let mut bad = proof.bytes.clone();
		bad[bit / 8] ^= 1 << (bit % 8);
		assert!(!verify_prepared(&prepared, &bad, &flat_inputs), "bit {bit}");
	}
	let mut swapped = proof.bytes.clone();
	swapped[..32].copy_from_slice(&proof.bytes[96..]);
	swapped[96..].copy_from_slice(&proof.bytes[..32]);
	assert!(!verify_prepared(&prepared, &swapped, &flat_inputs));
}

/// Random public inputs never verify the valid proof.
#[test]
fn random_inputs_never_verify() {
	use ark_std::rand::RngCore;
	let (vk, proof, _) = setup_and_prove();
	let prepared = vk.prepared_bytes().unwrap();
	let mut rng = StdRng::seed_from_u64(13);
	for _ in 0..500 {
		let mut input = [0u8; 32];
		rng.fill_bytes(&mut input);
		assert!(!verify_prepared(&prepared, &proof.bytes, &input));
	}
}
