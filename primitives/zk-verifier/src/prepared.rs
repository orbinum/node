//! Verifying keys prepared once and stored, instead of prepared per proof.
//!
//! Preparing a key (deserializing it with point validation, computing
//! `e(alpha, beta)`, preparing `-gamma` and `-delta` in G2) is about half the
//! cost of a verification. [`VerifyingKey::prepared_bytes`] does it once, at
//! registration; [`prepared_from_stored`] reads the result back per proof.

use alloc::vec::Vec;

use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{VerifierError, VerifyingKey, MAX_PUBLIC_INPUTS};

/// Uncompressed sizes of the parts of a prepared key.
mod layout {
	/// `alpha` (G1) then `beta`, `gamma`, `delta` (G2).
	pub const KEY_HEADER: usize = 64 + 3 * 128;
	/// A `u64` length prefix.
	pub const LEN: usize = 8;
	pub const G1: usize = 64;
	/// `e(alpha, beta)`, an element of GT.
	pub const GT: usize = 384;
	/// One line coefficient of a G2-prepared point: three Fq2 elements.
	pub const LINE: usize = 3 * 64;
	/// Line coefficients of any G2-prepared point on BN254: fixed by the curve's
	/// Miller loop.
	pub const LINES: usize = 87;
	/// The `infinity` flag after the lines: a real key's `-gamma`, `-delta` are
	/// never the identity (`to_ark_vk` refuses it), so it is always 0.
	pub const FLAG: usize = 1;

	/// Size of the prepared key for a key of `points` `gamma_abc` points.
	pub const fn size(points: usize) -> usize {
		KEY_HEADER + LEN + points * G1 + GT + 2 * (LEN + LINES * LINE + FLAG)
	}
}

/// Largest prepared key [`VerifyingKey::prepared_bytes`] produces: one with
/// [`MAX_PUBLIC_INPUTS`] inputs. [`prepared_from_stored`] refuses anything longer.
pub const MAX_PREPARED_VK_BYTES: usize = layout::size(MAX_PUBLIC_INPUTS + 1);

impl VerifyingKey {
	/// The key validated and prepared once, uncompressed, to be stored and read
	/// back with [`prepared_from_stored`] instead of preparing it per proof.
	pub fn prepared_bytes(&self) -> Result<Vec<u8>, VerifierError> {
		let mut out = Vec::new();
		self.prepare()?
			.serialize_uncompressed(&mut out)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(out)
	}
}

/// Read back a key stored by [`VerifyingKey::prepared_bytes`], without
/// re-validating its points: the caller vouches that the bytes came from there.
///
/// The layout is checked first, as in [`VerifyingKey::to_ark_vk`]:
/// `ark-serialize` reserves every `Vec` from its length prefix before reading
/// it, so a prefix the bytes cannot back would ask for an absurd allocation.
pub fn prepared_from_stored(bytes: &[u8]) -> Result<PreparedVerifyingKey<Bn254>, VerifierError> {
	if !layout_fits(bytes) {
		return Err(VerifierError::InvalidVerifyingKey);
	}
	PreparedVerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(bytes)
		.map_err(|_| VerifierError::InvalidVerifyingKey)
}

/// Whether `bytes` has exactly the layout of a prepared key: a `gamma_abc`
/// count in range, then `-gamma` and `-delta` with [`layout::LINES`] lines each
/// and a clear infinity flag, and nothing after.
fn layout_fits(bytes: &[u8]) -> bool {
	use layout::*;
	let u64_at = |at: usize| {
		bytes
			.get(at..at + LEN)
			.and_then(|b| <[u8; LEN]>::try_from(b).ok())
			.map(u64::from_le_bytes)
	};
	// `-gamma` or `-delta` prepared, starting at `at`: the fixed line count and a
	// clear flag.
	let g2_prepared_fits = |at: usize| {
		u64_at(at) == Some(LINES as u64) && bytes.get(at + LEN + LINES * LINE) == Some(&0)
	};

	if bytes.len() > MAX_PREPARED_VK_BYTES {
		return false;
	}
	let Some(points) = u64_at(KEY_HEADER) else {
		return false;
	};
	if points == 0 || points > (MAX_PUBLIC_INPUTS + 1) as u64 {
		return false;
	}
	let points = points as usize;
	let gamma_at = KEY_HEADER + LEN + points * G1 + GT;
	let delta_at = gamma_at + LEN + LINES * LINE + FLAG;
	bytes.len() == size(points) && g2_prepared_fits(gamma_at) && g2_prepared_fits(delta_at)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::{layout::*, *};
	use alloc::vec;
	use ark_bn254::{G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_groth16::VerifyingKey as ArkVK;

	/// A genuine key of `arity` inputs, as registration stores it.
	fn key(arity: usize) -> VerifyingKey {
		let vk = ArkVK::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
		};
		VerifyingKey::from_ark_vk(&vk).expect("serializes")
	}

	fn stored(arity: usize) -> Vec<u8> {
		key(arity).prepared_bytes().expect("prepares")
	}

	fn reserialized(pvk: &PreparedVerifyingKey<Bn254>) -> Vec<u8> {
		let mut out = Vec::new();
		pvk.serialize_uncompressed(&mut out).unwrap();
		out
	}

	fn refused(bytes: &[u8]) -> bool {
		prepared_from_stored(bytes).err() == Some(VerifierError::InvalidVerifyingKey)
	}

	const GAMMA_AT_3: usize = KEY_HEADER + LEN + 4 * G1 + GT;
	const DELTA_AT_3: usize = GAMMA_AT_3 + LEN + LINES * LINE + FLAG;

	#[test]
	fn a_stored_key_reads_back_as_the_prepared_one() {
		for arity in [1, 3, 9] {
			let fresh = key(arity).prepare().unwrap();
			let read = prepared_from_stored(&stored(arity)).unwrap();
			assert_eq!(reserialized(&read), reserialized(&fresh), "arity {arity}");
		}
	}

	/// The layout constants describe what `ark-serialize` actually writes.
	#[test]
	fn the_layout_matches_the_serialized_key() {
		for arity in [0, 1, 9, MAX_PUBLIC_INPUTS] {
			assert_eq!(stored(arity).len(), size(arity + 1), "arity {arity}");
		}
		let pvk = key(3).prepare().unwrap();
		assert_eq!(pvk.gamma_g2_neg_pc.ell_coeffs.len(), LINES);
		assert_eq!(pvk.delta_g2_neg_pc.ell_coeffs.len(), LINES);
	}

	/// The bound is exact: the widest key the crate accepts fills it.
	#[test]
	fn the_widest_key_fills_the_bound() {
		assert_eq!(stored(MAX_PUBLIC_INPUTS).len(), MAX_PREPARED_VK_BYTES);
		assert!(prepared_from_stored(&stored(MAX_PUBLIC_INPUTS)).is_ok());
		assert!(refused(&vec![0u8; MAX_PREPARED_VK_BYTES + 1]));
	}

	#[test]
	fn a_stored_key_of_the_wrong_length_is_refused() {
		let good = stored(3);
		let mut longer = good.clone();
		longer.push(0);
		for bad in [&good[..good.len() - 1], &longer[..], &good[..100], &[][..]] {
			assert!(refused(bad), "length {}", bad.len());
		}
	}

	/// A length prefix the bytes cannot back is refused before `ark-serialize`
	/// reserves memory for it.
	#[test]
	fn an_absurd_length_prefix_is_refused_before_allocating() {
		let good = stored(3);
		for (at, value) in [
			(KEY_HEADER, u64::MAX),
			(KEY_HEADER, 0),
			(KEY_HEADER, MAX_PUBLIC_INPUTS as u64 + 2),
			(GAMMA_AT_3, u64::MAX),
			(GAMMA_AT_3, 1 << 40),
			(DELTA_AT_3, u64::MAX),
		] {
			let mut bad = good.clone();
			bad[at..at + LEN].copy_from_slice(&value.to_le_bytes());
			assert!(refused(&bad), "prefix at {at} = {value}");
		}
	}

	/// Prefixes that still add up to the right length are refused too: the line
	/// counts are fixed by the curve.
	#[test]
	fn line_counts_that_add_up_but_differ_are_refused() {
		let good = stored(3);
		for (gamma, delta) in [
			(LINES - 1, LINES + 1),
			(LINES + 1, LINES - 1),
			(0, 2 * LINES),
		] {
			let mut bad = good.clone();
			bad[GAMMA_AT_3..GAMMA_AT_3 + LEN].copy_from_slice(&(gamma as u64).to_le_bytes());
			bad[DELTA_AT_3..DELTA_AT_3 + LEN].copy_from_slice(&(delta as u64).to_le_bytes());
			assert!(refused(&bad), "lines {gamma} / {delta}");
		}
	}

	#[test]
	fn a_set_infinity_flag_is_refused() {
		let good = stored(3);
		for flag_at in [
			GAMMA_AT_3 + LEN + LINES * LINE,
			DELTA_AT_3 + LEN + LINES * LINE,
		] {
			for value in [1u8, 2, 0xFF] {
				let mut bad = good.clone();
				bad[flag_at] = value;
				assert!(refused(&bad), "flag at {flag_at} = {value}");
			}
		}
	}
}
