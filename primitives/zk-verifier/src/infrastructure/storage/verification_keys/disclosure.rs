//! Auto-generated Verification Key for disclosure circuit
//! Generated on: 2026-02-15
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
				"2381173057563833764233815915068000834834115452056520237556247865255806971249",
			)
			.unwrap(),
			Fq::from_str(
				"14925087808722726730908922825409111491604984585967959067713802713576688599264",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"3647003627059138544808423335602440346505630062835555901870537472515929888599",
			)
			.unwrap(),
			Fq::from_str(
				"18046788152159239766494427734682464055750108324022225733392731051350401204337",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"15964950830910202244217667436665733776997447861553802623999698138484110595957",
		)
		.unwrap(),
		Fq::from_str(
			"1040079402286714073647109609323335894210500907477000571792043915719024030224",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"3340210474460277437662732981813692576850795858372732555286041366326257354427",
		)
		.unwrap(),
		Fq::from_str(
			"9836565355755721050636876037692518662635375900213403984966267475206475658524",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"12060419398997673887064863238328225795227850230778535632787590613985993920427",
		)
		.unwrap(),
		Fq::from_str(
			"5881790740170267272776729282842338197965403298580720322757247992346504212644",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"14940581636929495647429694768793509851524492245737760358779578356534185051021",
		)
		.unwrap(),
		Fq::from_str(
			"8199470560675183315870564454703278914683812654862355184904152407412888877972",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"10409564891268817626963180756840234046972055191382429263672757341041082599476",
		)
		.unwrap(),
		Fq::from_str(
			"20153095266914888386311759097574228223575358889458887322529392137999194059340",
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
