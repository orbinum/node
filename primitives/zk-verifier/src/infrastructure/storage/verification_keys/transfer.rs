//! Auto-generated Verification Key for transfer circuit
//! Generated on: 2026-01-29
//! Source: artifacts/verification_key_transfer.json
//!
//! DO NOT EDIT MANUALLY - Run sync-circuit-artifacts.sh to regenerate

use alloc::vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;

use crate::domain::value_objects::circuit_constants::{
	CIRCUIT_ID_TRANSFER, TRANSFER_PUBLIC_INPUTS,
};

/// Circuit ID for transfer (re-exported from core)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_TRANSFER;

/// Number of public inputs for this circuit (re-exported from core)
pub const NUM_PUBLIC_INPUTS: usize = TRANSFER_PUBLIC_INPUTS;

/// Creates the verification key for the transfer circuit
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
				"4066667103933237001358769304643672656732008857298180907033093762212084286733",
			)
			.unwrap(),
			Fq::from_str(
				"9246265017486699567757505080463732748534369707414722827986515422093586221143",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"12494434054136414084752676734485286069834583810521763176304870440186182078688",
			)
			.unwrap(),
			Fq::from_str(
				"14834101484710336070389659744892339008941055661164130330202523250054784765457",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"1966048745967271659690731985817152161896932148353434032417994178951456098677",
		)
		.unwrap(),
		Fq::from_str(
			"18547351416994791538512210090861643093465500783924731349613797842962660465793",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"3247596314751791827937113646181335469274675229295376136135173388928543707303",
		)
		.unwrap(),
		Fq::from_str(
			"9986435598957867322055502477774218152900452352473976302525196696736166057918",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"14712156563022212299517063318724451247264425422558612666793298953188268472754",
		)
		.unwrap(),
		Fq::from_str(
			"3546603963612890248184170281415395614773716445199444996219929625208201148176",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"6492549827431371331906007027147293243980604741632895415799088391004189404042",
		)
		.unwrap(),
		Fq::from_str(
			"15520307967575805661187754748986353320468247949185351945267452987579134101247",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"7698116388689409170797463557843402721001046498589742027966196456335697945252",
		)
		.unwrap(),
		Fq::from_str(
			"19496512074146521797474722387106023817067805152321450801801714643269312114541",
		)
		.unwrap(),
	);

	let ic_5 = G1Affine::new_unchecked(
		Fq::from_str(
			"18018829288594843113838468782351565978383206609085746829513443288600819371846",
		)
		.unwrap(),
		Fq::from_str("574513036642887995308766560787260721995633444018793147549923509872721537303")
			.unwrap(),
	);

	let gamma_abc_g1 = vec![ic_0, ic_1, ic_2, ic_3, ic_4, ic_5];

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

	#[test]
	fn test_circuit_constants() {
		assert_eq!(CIRCUIT_ID, CIRCUIT_ID_TRANSFER);
		assert_eq!(NUM_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS);
	}

	#[test]
	fn test_get_vk_does_not_panic() {
		let vk = get_vk();
		assert_eq!(vk.gamma_abc_g1.len(), NUM_PUBLIC_INPUTS + 1);
	}

	#[test]
	fn test_get_vk_bytes_not_empty() {
		let bytes = get_vk_bytes();
		assert!(!bytes.is_empty());
		assert!(bytes.len() > 200);
	}

	#[test]
	fn test_vk_serialization_deserialization_roundtrip() {
		let vk_original = get_vk();
		let bytes = get_vk_bytes();

		let vk_deserialized = VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..]);
		assert!(vk_deserialized.is_ok());

		let vk_deserialized = vk_deserialized.unwrap();
		assert_eq!(vk_deserialized.alpha_g1, vk_original.alpha_g1);
		assert_eq!(vk_deserialized.beta_g2, vk_original.beta_g2);
		assert_eq!(vk_deserialized.gamma_g2, vk_original.gamma_g2);
		assert_eq!(vk_deserialized.delta_g2, vk_original.delta_g2);
		assert_eq!(
			vk_deserialized.gamma_abc_g1.len(),
			vk_original.gamma_abc_g1.len()
		);
	}

	#[test]
	fn test_gamma_abc_g1_length() {
		let vk = get_vk();
		assert_eq!(vk.gamma_abc_g1.len(), NUM_PUBLIC_INPUTS + 1);
	}

	#[test]
	fn test_vk_points_on_curve() {
		let vk = get_vk();
		assert!(vk.alpha_g1.is_on_curve());
		assert!(vk.beta_g2.is_on_curve());
		assert!(vk.gamma_g2.is_on_curve());
		assert!(vk.delta_g2.is_on_curve());

		for point in &vk.gamma_abc_g1 {
			assert!(point.is_on_curve());
		}
	}
}
