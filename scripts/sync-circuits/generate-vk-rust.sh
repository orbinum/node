#!/usr/bin/env bash
#
# Generate a Rust VK file from a JSON verification key.
#
# Requires: jq (https://jqlang.org) — available on all platforms, no Python needed.
#
# Usage:
#   ./scripts/generate-vk-rust.sh <circuit_name> <json_path> <output_path>
#
# Example:
#   ./scripts/generate-vk-rust.sh disclosure \
#       artifacts/verification_key_disclosure.json \
#       primitives/zk-verifier/src/infrastructure/storage/verification_keys/disclosure.rs
#
set -euo pipefail

if [ $# -ne 3 ]; then
    echo "Usage: generate-vk-rust.sh <circuit_name> <json_path> <output_path>" >&2
    exit 1
fi

CIRCUIT_NAME="$1"
JSON_PATH="$2"
OUTPUT_PATH="$3"

if [ ! -f "$JSON_PATH" ]; then
    echo "Error: JSON file not found: $JSON_PATH" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "Error: 'jq' is required but not installed." >&2
    echo "  macOS:  brew install jq" >&2
    echo "  Ubuntu: apt-get install -y jq" >&2
    exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

# jq path shortcuts
JQ="jq -r"
JSON="$JSON_PATH"

CIRCUIT_UPPER="$(echo "$CIRCUIT_NAME" | tr '[:lower:]' '[:upper:]')"
CIRCUIT_TITLE="$(echo "$CIRCUIT_NAME" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
GENERATED_AT="$(date +"%Y-%m-%d %H:%M:%S %Z")"

# Read scalar field elements
alpha_g1_x=$($JQ '.vk_alpha_1[0]' "$JSON")
alpha_g1_y=$($JQ '.vk_alpha_1[1]' "$JSON")

beta_g2_x0=$($JQ '.vk_beta_2[0][0]' "$JSON")
beta_g2_x1=$($JQ '.vk_beta_2[0][1]' "$JSON")
beta_g2_y0=$($JQ '.vk_beta_2[1][0]' "$JSON")
beta_g2_y1=$($JQ '.vk_beta_2[1][1]' "$JSON")

gamma_g2_x0=$($JQ '.vk_gamma_2[0][0]' "$JSON")
gamma_g2_x1=$($JQ '.vk_gamma_2[0][1]' "$JSON")
gamma_g2_y0=$($JQ '.vk_gamma_2[1][0]' "$JSON")
gamma_g2_y1=$($JQ '.vk_gamma_2[1][1]' "$JSON")

delta_g2_x0=$($JQ '.vk_delta_2[0][0]' "$JSON")
delta_g2_x1=$($JQ '.vk_delta_2[0][1]' "$JSON")
delta_g2_y0=$($JQ '.vk_delta_2[1][0]' "$JSON")
delta_g2_y1=$($JQ '.vk_delta_2[1][1]' "$JSON")

# Number of IC points
IC_LEN=$($JQ '.IC | length' "$JSON")

# ── Begin generating output ───────────────────────────────────────────────────

mkdir -p "$(dirname "$OUTPUT_PATH")"

{
cat <<HEADER
//! Auto-generated Verification Key for ${CIRCUIT_NAME} circuit
//! Generated on: ${GENERATED_AT}
//! Source: artifacts/verification_key_${CIRCUIT_NAME}.json
//!
//! DO NOT EDIT MANUALLY - Run sync-circuit-artifacts.sh to regenerate

use alloc::vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;

use crate::domain::value_objects::circuit_constants::{CIRCUIT_ID_${CIRCUIT_UPPER}, ${CIRCUIT_UPPER}_PUBLIC_INPUTS};

/// Circuit ID for ${CIRCUIT_NAME} (re-exported from domain)
pub const CIRCUIT_ID: u8 = CIRCUIT_ID_${CIRCUIT_UPPER};

/// Number of public inputs for this circuit (re-exported from domain)
pub const NUM_PUBLIC_INPUTS: usize = ${CIRCUIT_UPPER}_PUBLIC_INPUTS;

/// Creates the verification key for the ${CIRCUIT_NAME} circuit
pub fn get_vk() -> VerifyingKey<Bn254> {
	// Alpha G1
	let alpha_g1 = G1Affine::new_unchecked(
		Fq::from_str(
			"${alpha_g1_x}",
		)
		.unwrap(),
		Fq::from_str(
			"${alpha_g1_y}",
		)
		.unwrap(),
	);

	// Beta G2
	let beta_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"${beta_g2_x0}",
			)
			.unwrap(),
			Fq::from_str(
				"${beta_g2_x1}",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"${beta_g2_y0}",
			)
			.unwrap(),
			Fq::from_str(
				"${beta_g2_y1}",
			)
			.unwrap(),
		),
	);

	// Gamma G2
	let gamma_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"${gamma_g2_x0}",
			)
			.unwrap(),
			Fq::from_str(
				"${gamma_g2_x1}",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"${gamma_g2_y0}",
			)
			.unwrap(),
			Fq::from_str(
				"${gamma_g2_y1}",
			)
			.unwrap(),
		),
	);

	// Delta G2
	let delta_g2 = G2Affine::new_unchecked(
		Fq2::new(
			Fq::from_str(
				"${delta_g2_x0}",
			)
			.unwrap(),
			Fq::from_str(
				"${delta_g2_x1}",
			)
			.unwrap(),
		),
		Fq2::new(
			Fq::from_str(
				"${delta_g2_y0}",
			)
			.unwrap(),
			Fq::from_str(
				"${delta_g2_y1}",
			)
			.unwrap(),
		),
	);

	// IC points (gamma_abc_g1)
HEADER

# Generate one let binding per IC point
for (( i=0; i<IC_LEN; i++ )); do
    ic_x=$($JQ ".IC[${i}][0]" "$JSON")
    ic_y=$($JQ ".IC[${i}][1]" "$JSON")
    cat <<IC
	let ic_${i} = G1Affine::new_unchecked(
		Fq::from_str(
			"${ic_x}",
		)
		.unwrap(),
		Fq::from_str(
			"${ic_y}",
		)
		.unwrap(),
	);

IC
done

# Build the vec![ic_0, ic_1, ...] expression
IC_VARS=""
for (( i=0; i<IC_LEN; i++ )); do
    [ -n "$IC_VARS" ] && IC_VARS="${IC_VARS}, "
    IC_VARS="${IC_VARS}ic_${i}"
done

cat <<FOOTER
	let gamma_abc_g1 = vec![${IC_VARS}];

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
FOOTER

} > "$OUTPUT_PATH"

echo "✓ Generated $OUTPUT_PATH"
