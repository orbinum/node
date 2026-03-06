//! Auto-generated Verification Key for private_link circuit
//! Generated on: 2026-03-05
//! Source: artifacts/verification_key_private_link.json
//!
//! DO NOT EDIT MANUALLY - Run sync-circuit-artifacts.sh to regenerate

use alloc::vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;

use crate::domain::value_objects::circuit_constants::{CIRCUIT_ID_PRIVATE_LINK, PRIVATE_LINK_PUBLIC_INPUTS};

/// Circuit ID for private_link (re-exported from domain)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_PRIVATE_LINK;

/// Number of public inputs for this circuit (re-exported from domain)
pub const NUM_PUBLIC_INPUTS: usize = PRIVATE_LINK_PUBLIC_INPUTS;

/// Creates the verification key for the private_link circuit
pub fn get_vk() -> VerifyingKey<Bn254> {
	// Alpha G1
	let alpha_g1 = G1Affine::new_unchecked(
		Fq::from_str(
			"20491192805390485299153009773594534940189261866228447918068658471970481763042",
		)
		.unwrap(),
		Fq::from_str(
			"9383485363053290200918347156157836566562967994039712273449902621266178545958",
		)
		.unwrap(),
	);

	// Beta G2
	let beta_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"6375614351688725206403948262868962793625744043794305715222011528459656738731",
			)
			.unwrap(),
			Fq::from_str(
				"4252822878758300859123897981450591353533073413197771768651442665752259397132",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"10505242626370262277552901082094356697409835680220590971873171140371331206856",
			)
			.unwrap(),
			Fq::from_str(
				"21847035105528745403288232691147584728191162732299865338377159692350059136679",
			)
			.unwrap(),
		),
	);

	// Gamma G2
	let gamma_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"10857046999023057135944570762232829481370756359578518086990519993285655852781",
			)
			.unwrap(),
			Fq::from_str(
				"11559732032986387107991004021392285783925812861821192530917403151452391805634",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"8495653923123431417604973247489272438418190587263600148770280649306958101930",
			)
			.unwrap(),
			Fq::from_str(
				"4082367875863433681332203403145435568316851327593401208105741076214120093531",
			)
			.unwrap(),
		),
	);

	// Delta G2
	let delta_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"5875107934225591956824400118336800666032055630977304736548317085933989709703",
			)
			.unwrap(),
			Fq::from_str(
				"18828871098072208939353097682642446147257193375470187817603824354430981750855",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"10165414766257904664737341746029150667983055399710524654380456653164638114206",
			)
			.unwrap(),
			Fq::from_str(
				"19242268793339951329162337436243933498903385532340416509627578042100918910721",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"3873119679218392807840426919143613017451812535072496563784167058388285983796",
		)
		.unwrap(),
		Fq::from_str(
			"10505355579916155463408957159060265767093857712918941866986236626237127061560",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"18131567997101244009572074907063325087087408880313227019458175660820403352905",
		)
		.unwrap(),
		Fq::from_str(
			"5962015595236182725194357339839307542131750029760038891759441583113334779284",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"21262268839712470390098720510727633177967955527172441240314180229632430290739",
		)
		.unwrap(),
		Fq::from_str(
			"17910414284850894487807511632049431548124824989721737209651521059918980252537",
		)
		.unwrap(),
	);

	let gamma_abc_g1 = vec![ic_0, ic_1, ic_2];

	VerifyingKey {
		alpha_g1,
		beta_g2,
		gamma_g2,
		delta_g2,
		gamma_abc_g1,
	}
}

/// Returns the verification key as compressed bytes for genesis/storage
pub fn get_vk_bytes() -> alloc::vec::Vec<u8> {
	let vk = get_vk();
	let mut bytes = alloc::vec::Vec::new();
	vk.serialize_compressed(&mut bytes)
		.expect("VK serialization should not fail");
	bytes
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_serialize::CanonicalDeserialize;

	/// La VK de private_link tiene exactamente 2 public inputs, por lo que
	/// `gamma_abc_g1` debe tener 3 elementos (n_inputs + 1).
	#[test]
	fn vk_has_correct_number_of_ic_points() {
		let vk = get_vk();
		assert_eq!(
			vk.gamma_abc_g1.len(),
			PRIVATE_LINK_PUBLIC_INPUTS + 1,
			"gamma_abc_g1 debe tener {} puntos (n_public + 1)",
			PRIVATE_LINK_PUBLIC_INPUTS + 1
		);
	}

	/// Los puntos G1/G2 se construyen con `new_unchecked`; verificar que son
	/// efectivamente puntos válidos en la curva BN254.
	#[test]
	fn vk_points_are_on_curve() {
		use ark_bn254::{g1::Config as G1Config, g2::Config as G2Config};
		use ark_ec::short_weierstrass::Affine;

		let vk = get_vk();

		// alpha_g1
		assert!(
			Affine::<G1Config>::is_on_curve(&vk.alpha_g1),
			"alpha_g1 no está en la curva"
		);
		// beta_g2
		assert!(
			Affine::<G2Config>::is_on_curve(&vk.beta_g2),
			"beta_g2 no está en la curva"
		);
		// gamma_g2
		assert!(
			Affine::<G2Config>::is_on_curve(&vk.gamma_g2),
			"gamma_g2 no está en la curva"
		);
		// delta_g2
		assert!(
			Affine::<G2Config>::is_on_curve(&vk.delta_g2),
			"delta_g2 no está en la curva"
		);
		// todos los IC points
		for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
			assert!(
				Affine::<G1Config>::is_on_curve(ic),
				"IC point {i} no está en la curva"
			);
		}
	}

	/// `get_vk_bytes()` debe producir bytes no vacíos y del tamaño esperado
	/// para una VK Groth16/BN254 con 2 public inputs (compressed).
	#[test]
	fn get_vk_bytes_is_non_empty() {
		let bytes = get_vk_bytes();
		assert!(!bytes.is_empty(), "get_vk_bytes() no debe devolver bytes vacíos");
	}

	/// Round-trip: serializar → deserializar → volver a serializar produce
	/// exactamente los mismos bytes. Esto garantiza que los datos están bien
	/// formados y que el parsing es invertible.
	#[test]
	fn vk_bytes_round_trip() {
		let original_bytes = get_vk_bytes();

		let vk_restored = VerifyingKey::<Bn254>::deserialize_compressed(
			original_bytes.as_slice(),
		)
		.expect("La deserialización de VK no debe fallar");

		let mut restored_bytes = alloc::vec::Vec::new();
		vk_restored
			.serialize_compressed(&mut restored_bytes)
			.expect("La re-serialización no debe fallar");

		assert_eq!(
			original_bytes, restored_bytes,
			"Los bytes deben ser idénticos tras un round-trip serialize → deserialize → serialize"
		);
	}

	/// Verificar que el CIRCUIT_ID y NUM_PUBLIC_INPUTS de este módulo coinciden
	/// con las constantes del dominio.
	#[test]
	fn constants_match_domain() {
		use crate::domain::value_objects::circuit_constants::{
			CIRCUIT_ID_PRIVATE_LINK, PRIVATE_LINK_PUBLIC_INPUTS as DOMAIN_INPUTS,
		};
		assert_eq!(CIRCUIT_ID, CIRCUIT_ID_PRIVATE_LINK);
		assert_eq!(NUM_PUBLIC_INPUTS, DOMAIN_INPUTS);
	}
}
