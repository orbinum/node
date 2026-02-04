//! Auto-generated Verification Key for unshield circuit
//! Generated on: 2026-01-29
//! Source: artifacts/verification_key_unshield.json
//!
//! DO NOT EDIT MANUALLY - Run sync-circuit-artifacts.sh to regenerate

use alloc::vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;

use crate::domain::value_objects::circuit_constants::{
	CIRCUIT_ID_UNSHIELD, UNSHIELD_PUBLIC_INPUTS,
};

/// Circuit ID for unshield (re-exported from core)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_UNSHIELD;

/// Number of public inputs for this circuit (re-exported from core)
pub const NUM_PUBLIC_INPUTS: usize = UNSHIELD_PUBLIC_INPUTS;

/// Creates the verification key for the unshield circuit
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
				"5164894844635586629422630419290975671508067803052824880915648552282889009006",
			)
			.unwrap(),
			Fq::from_str(
				"1495179534890747141422768378733972726717346836187716706250042561072473723115",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"1780059888441966309831105400345895468639071445602419194538262190252986629776",
			)
			.unwrap(),
			Fq::from_str(
				"13847327108044167853450582454494743265312552610982822441323575939225314838997",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"3791652952762766576456772942332930874416323443583650640307031208126897023347",
		)
		.unwrap(),
		Fq::from_str(
			"1444382082201784227131492965380730244659946368555890761649591396978491841190",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"12745071339817817982085758703270782635430439174681091660921937409706187644814",
		)
		.unwrap(),
		Fq::from_str(
			"1093329777465162135025843952875696580500091823873378759677632904044118779946",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"7080080136840729418774725968685835380140451745514070938364389425686711816903",
		)
		.unwrap(),
		Fq::from_str(
			"9181293857588371726342738752740711996472365629989528547839351853280295811014",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"5332905788061312722800657651892374162379227801033088262000022804729983719767",
		)
		.unwrap(),
		Fq::from_str(
			"17505500046504307777660874302954718007346199177830667435850863312070825393440",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"2424429808854779488107734502502842386310369098340187330302986802889387616004",
		)
		.unwrap(),
		Fq::from_str(
			"6123745780343856572777199153986766289975405386603185483577673996972026715922",
		)
		.unwrap(),
	);

	let ic_5 = G1Affine::new_unchecked(
		Fq::from_str(
			"14845863620398137863610772620471502187309357591581718955783685552667259940486",
		)
		.unwrap(),
		Fq::from_str(
			"3020757416089395124222218392421542421476465671058441197801068960374483038601",
		)
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
		assert_eq!(CIRCUIT_ID, CIRCUIT_ID_UNSHIELD);
		assert_eq!(NUM_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS);
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
