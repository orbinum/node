//! Auto-generated Verification Key for unshield circuit
//! Generated on: 2026-02-15
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

/// Circuit ID for unshield (re-exported from domain)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_UNSHIELD;

/// Number of public inputs for this circuit (re-exported from domain)
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
				"17447850509502413500922534249490152642088360304398927533410993280334881184923",
			)
			.unwrap(),
			Fq::from_str(
				"20885456245844682377728788629324843068751103404003544176149786026459068697174",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"20604444392908579961406246999960824363396616878569322333806711263912998707285",
			)
			.unwrap(),
			Fq::from_str(
				"15919872506598808790062152411541187924467118965299215032467778864841275356301",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"4759917404823790432407520088534459023356590579383652181465364916912449624695",
		)
		.unwrap(),
		Fq::from_str(
			"3832863574771841234331076301811290460934931101437953774708549890327258738564",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"5336337706419091211868472399687230066131810167568242892809804587865519165344",
		)
		.unwrap(),
		Fq::from_str(
			"11353185051357039508206677538186633821853103335512576778299092029039610062882",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"15084681146036149779834232651527344012418671089935933939397885561760086121969",
		)
		.unwrap(),
		Fq::from_str(
			"10673952063622217067979641197117245279252423258914282179285754313970092562596",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"21039779822942533132271658631716796333199025786313218659510617689739394153598",
		)
		.unwrap(),
		Fq::from_str(
			"11163282276070815586063767846812914624591347999168289386275553753092237495248",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"3095712311814508041135867864726006035419219310141511809667041762596327080341",
		)
		.unwrap(),
		Fq::from_str(
			"17159247848061658623919878194408282495395946967527260450426770075448330620486",
		)
		.unwrap(),
	);

	let ic_5 = G1Affine::new_unchecked(
		Fq::from_str(
			"4168950959496505617599330781731644101559373119770356275626759863667568305184",
		)
		.unwrap(),
		Fq::from_str(
			"5644689731760572677103844719463014317690882565098456772580613601327065049357",
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
