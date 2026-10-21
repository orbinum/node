//! Golden vectors for the frozen `bn254_groth16_verify` host function (version 1).
//!
//! Blocks already executed called version 1 with prepared keys written by earlier
//! runtimes, and syncing nodes re-run them, so a node release must return exactly
//! what version 1 returned for the same bytes. These vectors pin that: a real
//! production key (unshield v3, `@orbinum/circuits` 0.17.1), its prepared form as
//! stored on chain, and a real proof.
//!
//! A failure here means a change (an arkworks upgrade, a constant, the parser) alters
//! what version 1 answers. Do not update the fixtures to make it pass: add a new
//! `#[version(N)]` of the host function and leave version 1 as it was.
//!
//! The fixtures were generated once (`regenerate_prepared_fixture`, ignored).

use orbinum_zk_verifier::{
	host_interface::groth_16_host_interface::bn254_groth16_verify, verify_prepared, VerifyingKey,
	MAX_PREPARED_VK_BYTES, MAX_PUBLIC_INPUTS, PROOF_BYTES,
};

const VECTORS: &str = include_str!("fixtures/host_v1_unshield_v3.txt");
const PREPARED: &str = include_str!("fixtures/host_v1_unshield_v3.prepared.hex");

/// r, the BN254 scalar field order, little-endian.
const R_LE: [u8; 32] = [
	0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
	0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

fn unhex(s: &str) -> Vec<u8> {
	let s = s.trim().trim_start_matches("0x");
	(0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
		.collect()
}

fn vector(name: &str) -> Vec<u8> {
	let line = VECTORS
		.lines()
		.find_map(|l| l.strip_prefix(&format!("{name}=")))
		.unwrap_or_else(|| panic!("fixture has no `{name}`"));
	unhex(line)
}

struct Golden {
	vk: Vec<u8>,
	prepared: Vec<u8>,
	proof: Vec<u8>,
	inputs: Vec<u8>,
}

fn golden() -> Golden {
	Golden {
		vk: vector("vk"),
		prepared: unhex(PREPARED),
		proof: vector("proof"),
		inputs: vector("inputs"),
	}
}

/// Both entry points version 1 is built on, which must always agree.
fn verifies(prepared: &[u8], proof: &[u8], inputs: &[u8]) -> bool {
	let library = verify_prepared(prepared, proof, inputs);
	let host = bn254_groth16_verify(prepared, proof, inputs);
	assert_eq!(library, host, "host function and verify_prepared disagree");
	host
}

// ─── The accepted vector ──────────────────────────────────────────────────────

#[test]
fn the_pinned_prepared_key_verifies_the_real_proof() {
	let g = golden();
	assert_eq!(g.proof.len(), 128);
	assert_eq!(g.inputs.len(), 8 * 32);
	assert!(verifies(&g.prepared, &g.proof, &g.inputs));
}

/// Preparing the key today gives the bytes chains store: keys registered by any
/// runtime and read back by any node mean the same thing.
#[test]
fn preparing_the_key_gives_the_pinned_bytes() {
	let g = golden();
	let prepared = VerifyingKey::new(g.vk).prepared_bytes().unwrap();
	assert_eq!(
		prepared.len(),
		g.prepared.len(),
		"prepared layout size changed"
	);
	assert!(prepared == g.prepared, "prepared bytes changed");
}

// ─── Refused vectors: false, never a panic ────────────────────────────────────

#[test]
fn a_tampered_proof_is_refused() {
	let g = golden();
	for i in [0, 31, 32, 64, 95, 96, 127] {
		let mut proof = g.proof.clone();
		proof[i] ^= 0x01;
		assert!(!verifies(&g.prepared, &proof, &g.inputs), "byte {i}");
	}
}

#[test]
fn a_changed_input_is_refused() {
	let g = golden();
	for k in 0..8 {
		let mut inputs = g.inputs.clone();
		inputs[k * 32] ^= 0x01;
		assert!(!verifies(&g.prepared, &g.proof, &inputs), "input {k}");
	}
}

/// `x + r` is the same field element under another encoding: refused, not reduced.
#[test]
fn a_non_canonical_input_is_refused() {
	let g = golden();
	let mut inputs = g.inputs.clone();
	let mut carry = 0u16;
	for (byte, r) in inputs[..32].iter_mut().zip(R_LE) {
		let sum = *byte as u16 + r as u16 + carry;
		*byte = sum as u8;
		carry = sum >> 8;
	}
	assert_eq!(carry, 0, "the first input plus r must still fit 32 bytes");
	assert!(!verifies(&g.prepared, &g.proof, &inputs));
}

#[test]
fn the_wrong_number_of_inputs_is_refused() {
	let g = golden();
	assert!(!verifies(&g.prepared, &g.proof, &g.inputs[..7 * 32]));
	let mut more = g.inputs.clone();
	more.extend_from_slice(&[0u8; 32]);
	assert!(!verifies(&g.prepared, &g.proof, &more));
	assert!(!verifies(&g.prepared, &g.proof, &[]));
	assert!(!verifies(
		&g.prepared,
		&g.proof,
		&vec![0u8; (MAX_PUBLIC_INPUTS + 1) * 32]
	));
}

#[test]
fn malformed_lengths_are_refused() {
	let g = golden();
	assert!(!verifies(&g.prepared, &g.proof[..127], &g.inputs));
	let mut long = g.proof.clone();
	long.push(0);
	assert!(!verifies(&g.prepared, &long, &g.inputs));
	assert!(!verifies(&g.prepared, &g.proof, &g.inputs[..8 * 32 - 1]));
}

#[test]
fn malformed_prepared_keys_are_refused() {
	let g = golden();
	assert!(!verifies(&[], &g.proof, &g.inputs));
	assert!(!verifies(
		&g.prepared[..g.prepared.len() - 1],
		&g.proof,
		&g.inputs
	));
	let mut longer = g.prepared.clone();
	longer.push(0);
	assert!(!verifies(&longer, &g.proof, &g.inputs));
	assert!(!verifies(&vec![0u8; g.prepared.len()], &g.proof, &g.inputs));
	assert!(!verifies(
		&vec![0xffu8; MAX_PREPARED_VK_BYTES + 1],
		&g.proof,
		&g.inputs
	));
	// The raw key is not a prepared one.
	assert!(!verifies(&g.vk, &g.proof, &g.inputs));
}

// ─── The constants version 1 depends on ───────────────────────────────────────

/// Changing any of these changes what version 1 accepts.
#[test]
fn the_constants_version_1_depends_on_are_unchanged() {
	assert_eq!(MAX_PUBLIC_INPUTS, 32);
	assert_eq!(PROOF_BYTES, 128);
	assert_eq!(MAX_PREPARED_VK_BYTES, 36_378);
	assert_eq!(golden().prepared.len(), 34_842);
}

/// Writes the prepared fixture from the raw key. Only for new vectors: never to
/// make the tests above pass.
#[test]
#[ignore]
fn regenerate_prepared_fixture() {
	let prepared = VerifyingKey::new(vector("vk")).prepared_bytes().unwrap();
	let hex: String = prepared.iter().map(|b| format!("{b:02x}")).collect();
	std::fs::write(
		concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/tests/fixtures/host_v1_unshield_v3.prepared.hex"
		),
		format!("0x{hex}\n"),
	)
	.unwrap();
}
