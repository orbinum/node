//! Auto-generated Verification Key for disclosure circuit
//! Generated on: 2026-03-08 04:16:43 -03
//! Source: artifacts/verification_key_disclosure.json
//!
//! DO NOT EDIT MANUALLY - Run sync-circuit-artifacts.sh to regenerate

use alloc::vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;

use crate::domain::value_objects::circuit_constants::{
	CIRCUIT_ID_DISCLOSURE, DISCLOSURE_PUBLIC_INPUTS,
};

/// Circuit ID for disclosure (re-exported from domain)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_DISCLOSURE;

/// Number of public inputs for this circuit (re-exported from domain)
pub const NUM_PUBLIC_INPUTS: usize = DISCLOSURE_PUBLIC_INPUTS;

/// Creates the verification key for the disclosure circuit
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
				"15891488507266392457506126879904299590646143497545573658070845046860313168900",
			)
			.unwrap(),
			Fq::from_str(
				"17932936512660402537945596421514282776231371752944152874563145263497597450760",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"3499547373407916183334246733416920057398428467450155425825370305197257091551",
			)
			.unwrap(),
			Fq::from_str(
				"19552021655696733860272339514203367725306524797267373214782737566735379534814",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"6644748364555260156129836591732737035335621695080778806388447252072453264467",
		)
		.unwrap(),
		Fq::from_str(
			"10610642146156976560376495047404935702633534022449707341891080731675746231253",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str("183134578389976222585405159394158569606775062068994230403943610204972975767")
			.unwrap(),
		Fq::from_str(
			"15054648499092315861645561422738683794978556709561861191491884453856553469905",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str("493520193857930353251666059324898401214741181272007719287807840978613988477")
			.unwrap(),
		Fq::from_str(
			"10264986083735592766931550000553739417058119237687694821992136482252428841397",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"5492305139060809765159611331626218846385097649258248123630030121029127011914",
		)
		.unwrap(),
		Fq::from_str(
			"5446602556882136775071030748686569953554848855704744256354078506327754517408",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"6683987345206773829248627085474671868955168998214070623081328408136754507564",
		)
		.unwrap(),
		Fq::from_str(
			"9802225858000274674026213007893473356239169831801995329067584222663521521648",
		)
		.unwrap(),
	);

	let gamma_abc_g1 = vec![ic_0, ic_1, ic_2, ic_3, ic_4];

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
