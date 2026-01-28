#!/usr/bin/env rust-script
//! Convert snarkjs proof JSON to arkworks compressed bytes
//!
//! Usage: cargo run --package fp-zk-verifier --example convert_proof < proof.json
//!
//! Or use the test to generate bytes for a known proof

use fp_zk_verifier::snarkjs::{parse_proof_from_snarkjs, SnarkjsProofPoints};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut input = String::new();
	io::stdin().read_to_string(&mut input)?;

	let json: serde_json::Value = serde_json::from_str(&input)?;

	let proof = parse_proof_from_snarkjs(SnarkjsProofPoints {
		a_x: json["pi_a"][0].as_str().unwrap(),
		a_y: json["pi_a"][1].as_str().unwrap(),
		b_x0: json["pi_b"][0][0].as_str().unwrap(),
		b_x1: json["pi_b"][0][1].as_str().unwrap(),
		b_y0: json["pi_b"][1][0].as_str().unwrap(),
		b_y1: json["pi_b"][1][1].as_str().unwrap(),
		c_x: json["pi_c"][0].as_str().unwrap(),
		c_y: json["pi_c"][1].as_str().unwrap(),
	})?;

	let hex: String = proof
		.as_bytes()
		.iter()
		.map(|b| format!("{:02x}", b))
		.collect();
	println!("0x{}", hex);

	Ok(())
}
