//! Auto-generated Verification Key for transfer circuit
//! Generated on: 2026-02-15
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

/// Circuit ID for transfer (re-exported from domain)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_TRANSFER;

/// Number of public inputs for this circuit (re-exported from domain)
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
				"6128887458088249554860395918118246705861422303056882185490762080648320621170",
			)
			.unwrap(),
			Fq::from_str(
				"4392716790709150487971950457548426651027717797967422679982836156265069267378",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"6862579306496809164234032958633900420354507233456088930175888498992887907124",
			)
			.unwrap(),
			Fq::from_str(
				"11320937609295642066952076896464842220914857834192185407806271953305006523919",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
	let ic_0 = G1Affine::new_unchecked(
		Fq::from_str(
			"12521353044701549515327655017850372472462274389676752451261564850795277210784",
		)
		.unwrap(),
		Fq::from_str(
			"17537427920533725255683527309076964578961889733887641292864968986005206833227",
		)
		.unwrap(),
	);

	let ic_1 = G1Affine::new_unchecked(
		Fq::from_str(
			"9054540875357326821742569992875343778082451382872166255139682380736118336965",
		)
		.unwrap(),
		Fq::from_str(
			"19145371190592659949158552383366523068893276589381638814741619309597554902109",
		)
		.unwrap(),
	);

	let ic_2 = G1Affine::new_unchecked(
		Fq::from_str(
			"4742393298120554619433281305566496971436669707311583698440427823952632276050",
		)
		.unwrap(),
		Fq::from_str(
			"3877416000326877112020382111726729873163167304724326109191809999398145068082",
		)
		.unwrap(),
	);

	let ic_3 = G1Affine::new_unchecked(
		Fq::from_str(
			"13596656322317975043597922138537730020108978263529423575433634179437267442285",
		)
		.unwrap(),
		Fq::from_str(
			"9742436487435369435567344764161265311134349467077942742196530523569923539419",
		)
		.unwrap(),
	);

	let ic_4 = G1Affine::new_unchecked(
		Fq::from_str(
			"10688916237036738808967339930842102783882829011167399097753073924876231581798",
		)
		.unwrap(),
		Fq::from_str(
			"15541123047651505099565506020079072290645702361358638026159150320227489549290",
		)
		.unwrap(),
	);

	let ic_5 = G1Affine::new_unchecked(
		Fq::from_str(
			"10594341809050651078348790198511832237136162370751007990030736876706319494726",
		)
		.unwrap(),
		Fq::from_str(
			"8811599578125639162916289173502210672259754599803755307954551465982761005752",
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
