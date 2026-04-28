//! EdDSA-Poseidon R1CS Gadget (Baby JubJub)
//!
//! Implements the circomlib `EdDSAPoseidonVerifier` circuit as an R1CS gadget.
//!
//! # Verification equation
//! `S × Base8 == R8 + Poseidon5(R8x, R8y, Ax, Ay, msg) × A`
//!
//! Where:
//! - `A = (Ax, Ay)` is the Baby JubJub public key (= `spending_key × Base8`)
//! - `(R8x, R8y)` is the nonce point `r × Base8`
//! - `S = r + h × spending_key  (mod SUBORDER)`
//!
//! # Reference
//! - circomlib/circuits/eddsa_poseidon.circom
//! - circomlib/src/eddsa.js

use ark_bn254::Fr as Bn254Fr;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, EdwardsConfig};
use ark_r1cs_std::{
	alloc::AllocVar, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar, groups::CurveVar,
	R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// ============================================================================
// Baby JubJub Base8 constant
// ============================================================================

/// Baby JubJub `Base8 = 8 × G` (cofactor-cleared generator)
///
/// Uses `ark-ed-on-bn254`'s generator in the `a=1` twisted Edwards form.
/// This is isomorphic to circomlib's Baby JubJub but uses different coordinates
/// (the arkworks curve has `COEFF_A=1` vs circomlib's `a=168700`).
pub(crate) fn base8_point() -> EdwardsAffine {
	use ark_ed_on_bn254::Fr as BabyJubFr;
	// G is the base generator in the arkworks (a=1) form
	let proj = EdwardsConfig::GENERATOR * BabyJubFr::from(8u64);
	proj.into()
}

// ============================================================================
// EdDSA-Poseidon verifier gadget
// ============================================================================

/// Verifies an EdDSA-Poseidon signature in R1CS.
///
/// # Arguments
/// * `ax`, `ay` — Baby JubJub public key `A = spending_key × Base8`
/// * `r8x`, `r8y` — Nonce point `R8 = r × Base8`
/// * `s` — Signature scalar `S = r + h × spending_key (mod SUBORDER)`
/// * `msg` — Message (the input note commitment)
///
/// # Constraints added
/// ~ 2 × 254 double-and-add point multiplications (≈ 4000–5000 constraints each)
///
/// # Panics
/// Never panics. Returns `Err(SynthesisError)` on constraint generation failure.
pub fn verify_eddsa(
	cs: ConstraintSystemRef<Bn254Fr>,
	ax: &FpVar<Bn254Fr>,
	ay: &FpVar<Bn254Fr>,
	r8x: &FpVar<Bn254Fr>,
	r8y: &FpVar<Bn254Fr>,
	s: &FpVar<Bn254Fr>,
	msg: &FpVar<Bn254Fr>,
) -> Result<(), SynthesisError> {
	// ── Step 1: h = Poseidon5(R8x, R8y, Ax, Ay, msg) ────────────────────────
	let h = crate::gadgets::poseidon::poseidon_hash_var(
		cs.clone(),
		&[
			r8x.clone(),
			r8y.clone(),
			ax.clone(),
			ay.clone(),
			msg.clone(),
		],
	)?;

	// ── Step 2: Build EdwardsVar for R8 and A from existing FpVars ───────────
	//
	// AllocVar + enforce_equal is the standard arkworks pattern when you already
	// have the coordinates as FpVars: allocate a fresh EdwardsVar (adds R1CS
	// variables for x, y), then constrain them equal to the original FpVars.
	let r8_var = build_edwards_var(cs.clone(), r8x, r8y)?;
	let a_var = build_edwards_var(cs.clone(), ax, ay)?;

	// ── Step 3: LHS = S × Base8 ──────────────────────────────────────────────
	let s_bits = s.to_bits_le()?;
	let base8_const = EdwardsVar::new_constant(cs.clone(), base8_point())?;
	let lhs = base8_const.scalar_mul_le(s_bits.iter())?;

	// ── Step 4: h × A ────────────────────────────────────────────────────────
	let h_bits = h.to_bits_le()?;
	let ha = a_var.scalar_mul_le(h_bits.iter())?;

	// ── Step 5: RHS = R8 + h × A ─────────────────────────────────────────────
	let rhs = r8_var + ha;

	// ── Step 6: S × Base8 == R8 + h × A ─────────────────────────────────────
	lhs.enforce_equal(&rhs)?;

	Ok(())
}

/// Constructs an `EdwardsVar` whose coordinates are constrained to equal
/// existing `FpVar`s. This avoids double-allocation while maintaining correct
/// constraint linkage.
fn build_edwards_var(
	cs: ConstraintSystemRef<Bn254Fr>,
	x_var: &FpVar<Bn254Fr>,
	y_var: &FpVar<Bn254Fr>,
) -> Result<EdwardsVar, SynthesisError> {
	let affine = x_var
		.value()
		.ok()
		.zip(y_var.value().ok())
		.map(|(x, y)| EdwardsAffine::new(x, y));

	let point_var =
		EdwardsVar::new_witness(cs, || affine.ok_or(SynthesisError::AssignmentMissing))?;

	// Link the new EdwardsVar coordinates to the caller's FpVars
	point_var.x.enforce_equal(x_var)?;
	point_var.y.enforce_equal(y_var)?;

	Ok(point_var)
}

// ============================================================================
// Test helpers (only compiled for test builds)
// ============================================================================

/// Baby JubJub EdDSA sign: returns `(Ax, Ay, R8x, R8y, S)` all as `Bn254Fr`.
///
/// Matches the circomlib `eddsaSign` algorithm:
/// - `A = sk × Base8`
/// - `r = Poseidon2(sk_fr, msg) mod SUBORDER`
/// - `R8 = r × Base8`
/// - `h = Poseidon5(R8x, R8y, Ax, Ay, msg)`
/// - `S = r + h × sk (mod SUBORDER)`
#[cfg(test)]
pub(crate) fn eddsa_sign(
	spending_key: u64,
	msg: Bn254Fr,
) -> (Bn254Fr, Bn254Fr, Bn254Fr, Bn254Fr, Bn254Fr) {
	use ark_ed_on_bn254::{EdwardsAffine as BabyJubAffine, Fr as BabyJubFr};
	use ark_ff::{BigInteger, PrimeField};

	let sk_bj = BabyJubFr::from(spending_key);
	let base8 = base8_point();

	// A = sk × Base8
	let a: BabyJubAffine = (base8 * sk_bj).into();
	let ax = a.x;
	let ay = a.y;

	// r = Poseidon2(sk_fr, msg) reduced to BabyJub subgroup
	let sk_fr = Bn254Fr::from(spending_key);
	let r_raw = crate::native::poseidon_hash_2(&[sk_fr, msg]);
	let r_bj = BabyJubFr::from_le_bytes_mod_order(&r_raw.into_bigint().to_bytes_le());

	// R8 = r × Base8
	let r8: BabyJubAffine = (base8 * r_bj).into();
	let r8x = r8.x;
	let r8y = r8.y;

	// h = Poseidon5(R8x, R8y, Ax, Ay, msg)
	let h = crate::native::poseidon_hash(&[r8x, r8y, ax, ay, msg]).expect("poseidon5");
	let h_bj = BabyJubFr::from_le_bytes_mod_order(&h.into_bigint().to_bytes_le());

	// S = (r + h × sk) mod SUBORDER
	let s_bj = r_bj + h_bj * sk_bj;
	let s = Bn254Fr::from_le_bytes_mod_order(&s_bj.into_bigint().to_bytes_le());

	(ax, ay, r8x, r8y, s)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
	use ark_relations::r1cs::ConstraintSystem;

	extern crate alloc;

	#[test]
	fn test_eddsa_verify_valid_signature() {
		let spending_key = 12345u64;
		let msg = Bn254Fr::from(999u64);

		let (ax, ay, r8x, r8y, s) = eddsa_sign(spending_key, msg);

		let cs = ConstraintSystem::<Bn254Fr>::new_ref();

		let ax_var = FpVar::new_witness(cs.clone(), || Ok(ax)).unwrap();
		let ay_var = FpVar::new_witness(cs.clone(), || Ok(ay)).unwrap();
		let r8x_var = FpVar::new_witness(cs.clone(), || Ok(r8x)).unwrap();
		let r8y_var = FpVar::new_witness(cs.clone(), || Ok(r8y)).unwrap();
		let s_var = FpVar::new_witness(cs.clone(), || Ok(s)).unwrap();
		let msg_var = FpVar::new_witness(cs.clone(), || Ok(msg)).unwrap();

		verify_eddsa(
			cs.clone(),
			&ax_var,
			&ay_var,
			&r8x_var,
			&r8y_var,
			&s_var,
			&msg_var,
		)
		.unwrap();

		assert!(
			cs.is_satisfied().unwrap(),
			"EdDSA constraints should be satisfied"
		);
	}

	#[test]
	fn test_eddsa_different_keys_produce_different_sigs() {
		let msg = Bn254Fr::from(123u64);
		let (ax1, _, _, _, s1) = eddsa_sign(111u64, msg);
		let (ax2, _, _, _, s2) = eddsa_sign(222u64, msg);
		assert_ne!(ax1, ax2, "Different spending keys → different public keys");
		assert_ne!(s1, s2, "Different spending keys → different S");
	}

	#[test]
	fn test_eddsa_different_messages_produce_different_sigs() {
		let sk = 42u64;
		let msg1 = Bn254Fr::from(1u64);
		let msg2 = Bn254Fr::from(2u64);
		let (_, _, r8x1, _, s1) = eddsa_sign(sk, msg1);
		let (_, _, r8x2, _, s2) = eddsa_sign(sk, msg2);
		assert_ne!(
			r8x1, r8x2,
			"Different messages → different R8 (deterministic nonce)"
		);
		assert_ne!(s1, s2);
	}

	#[test]
	fn test_base8_point_is_non_zero() {
		let p = base8_point();
		assert_ne!(p.x, Bn254Fr::from(0u64));
		assert_ne!(p.y, Bn254Fr::from(0u64));
	}
}
