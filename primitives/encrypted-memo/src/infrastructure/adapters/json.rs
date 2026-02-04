//! JSON serialization adapter with hex encoding for cross-language compatibility

use crate::domain::aggregates::disclosure::{
	DisclosureMask, DisclosureProof, DisclosurePublicSignals, PartialMemoData,
};
use alloc::string::String;
use serde::{Deserialize, Serialize};

// ============================================================================
// JSON Types (with hex encoding for bytes)
// ============================================================================

/// DisclosureProof with hex-encoded byte fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureProofJson {
	pub proof: String,
	pub public_signals: DisclosurePublicSignalsJson,
	pub mask: DisclosureMaskJson,
}

/// DisclosurePublicSignals with hex-encoded fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosurePublicSignalsJson {
	pub commitment: String,
	pub revealed_value: u64,
	pub revealed_asset_id: u32,
	pub revealed_owner_hash: String,
}

/// DisclosureMask flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureMaskJson {
	pub disclose_value: bool,
	pub disclose_owner: bool,
	pub disclose_blinding: bool,
	pub disclose_asset_id: bool,
}

/// PartialMemoData with optional hex-encoded fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialMemoDataJson {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub value: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub owner_pk: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub blinding: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub asset_id: Option<u32>,
}

// ============================================================================
// Conversion: Rust → JSON
// ============================================================================

impl From<DisclosureProof> for DisclosureProofJson {
	fn from(proof: DisclosureProof) -> Self {
		Self {
			proof: hex::encode(&proof.proof),
			public_signals: proof.public_signals.into(),
			mask: proof.mask.into(),
		}
	}
}

impl From<DisclosurePublicSignals> for DisclosurePublicSignalsJson {
	fn from(signals: DisclosurePublicSignals) -> Self {
		Self {
			commitment: hex::encode(signals.commitment),
			revealed_value: signals.revealed_value,
			revealed_asset_id: signals.revealed_asset_id,
			revealed_owner_hash: hex::encode(signals.revealed_owner_hash),
		}
	}
}

impl From<DisclosureMask> for DisclosureMaskJson {
	fn from(mask: DisclosureMask) -> Self {
		Self {
			disclose_value: mask.disclose_value,
			disclose_owner: mask.disclose_owner,
			disclose_blinding: mask.disclose_blinding,
			disclose_asset_id: mask.disclose_asset_id,
		}
	}
}

impl From<PartialMemoData> for PartialMemoDataJson {
	fn from(data: PartialMemoData) -> Self {
		Self {
			value: data.value,
			owner_pk: data.owner_pk.map(hex::encode),
			blinding: data.blinding.map(hex::encode),
			asset_id: data.asset_id,
		}
	}
}

// ============================================================================
// Conversion: JSON → Rust
// ============================================================================

impl TryFrom<DisclosureProofJson> for DisclosureProof {
	type Error = &'static str;

	fn try_from(json: DisclosureProofJson) -> Result<Self, Self::Error> {
		let proof = hex::decode(&json.proof).map_err(|_| "Invalid proof hex")?;
		let public_signals = json.public_signals.try_into()?;
		let mask = json.mask.into();

		Ok(Self {
			proof,
			public_signals,
			mask,
		})
	}
}

impl TryFrom<DisclosurePublicSignalsJson> for DisclosurePublicSignals {
	type Error = &'static str;

	fn try_from(json: DisclosurePublicSignalsJson) -> Result<Self, Self::Error> {
		let commitment = hex::decode(&json.commitment)
			.map_err(|_| "Invalid commitment hex")?
			.try_into()
			.map_err(|_| "Commitment must be 32 bytes")?;

		let revealed_owner_hash = hex::decode(&json.revealed_owner_hash)
			.map_err(|_| "Invalid revealed_owner_hash hex")?
			.try_into()
			.map_err(|_| "Revealed owner hash must be 32 bytes")?;

		Ok(Self {
			commitment,
			revealed_value: json.revealed_value,
			revealed_asset_id: json.revealed_asset_id,
			revealed_owner_hash,
		})
	}
}

impl From<DisclosureMaskJson> for DisclosureMask {
	fn from(json: DisclosureMaskJson) -> Self {
		Self {
			disclose_value: json.disclose_value,
			disclose_owner: json.disclose_owner,
			disclose_blinding: json.disclose_blinding,
			disclose_asset_id: json.disclose_asset_id,
		}
	}
}

impl TryFrom<PartialMemoDataJson> for PartialMemoData {
	type Error = &'static str;

	fn try_from(json: PartialMemoDataJson) -> Result<Self, Self::Error> {
		let owner_pk = json
			.owner_pk
			.map(|hex_str| {
				hex::decode(&hex_str)
					.map_err(|_| "Invalid owner_pk hex")
					.and_then(|bytes| bytes.try_into().map_err(|_| "Owner pk must be 32 bytes"))
			})
			.transpose()?;

		let blinding = json
			.blinding
			.map(|hex_str| {
				hex::decode(&hex_str)
					.map_err(|_| "Invalid blinding hex")
					.and_then(|bytes| bytes.try_into().map_err(|_| "Blinding must be 32 bytes"))
			})
			.transpose()?;

		Ok(Self {
			value: json.value,
			owner_pk,
			blinding,
			asset_id: json.asset_id,
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Serializes DisclosureProof to JSON string
pub fn proof_to_json(proof: &DisclosureProof) -> Result<String, &'static str> {
	let json: DisclosureProofJson = proof.clone().into();
	serde_json::to_string(&json).map_err(|_| "JSON serialization failed")
}

/// Deserializes DisclosureProof from JSON string
pub fn proof_from_json(json_str: &str) -> Result<DisclosureProof, &'static str> {
	let json: DisclosureProofJson =
		serde_json::from_str(json_str).map_err(|_| "JSON deserialization failed")?;
	json.try_into()
}

/// Serializes PartialMemoData to JSON string
pub fn partial_memo_to_json(data: &PartialMemoData) -> Result<String, &'static str> {
	let json: PartialMemoDataJson = data.clone().into();
	serde_json::to_string(&json).map_err(|_| "JSON serialization failed")
}

/// Deserializes PartialMemoData from JSON string
pub fn partial_memo_from_json(json_str: &str) -> Result<PartialMemoData, &'static str> {
	let json: PartialMemoDataJson =
		serde_json::from_str(json_str).map_err(|_| "JSON deserialization failed")?;
	json.try_into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== DisclosureMask Conversion Tests =====

	#[test]
	fn test_disclosure_mask_to_json() {
		let mask = DisclosureMask {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: true,
			disclose_asset_id: false,
		};

		let json: DisclosureMaskJson = mask.into();

		assert_eq!(json.disclose_value, true);
		assert_eq!(json.disclose_owner, false);
		assert_eq!(json.disclose_blinding, true);
		assert_eq!(json.disclose_asset_id, false);
	}

	#[test]
	fn test_disclosure_mask_from_json() {
		let json = DisclosureMaskJson {
			disclose_value: false,
			disclose_owner: true,
			disclose_blinding: false,
			disclose_asset_id: true,
		};

		let mask: DisclosureMask = json.into();

		assert_eq!(mask.disclose_value, false);
		assert_eq!(mask.disclose_owner, true);
		assert_eq!(mask.disclose_blinding, false);
		assert_eq!(mask.disclose_asset_id, true);
	}

	#[test]
	fn test_disclosure_mask_roundtrip() {
		let original = DisclosureMask {
			disclose_value: true,
			disclose_owner: true,
			disclose_blinding: false,
			disclose_asset_id: true,
		};

		let json: DisclosureMaskJson = original.clone().into();
		let restored: DisclosureMask = json.into();

		assert_eq!(restored, original);
	}

	// ===== DisclosurePublicSignals Conversion Tests =====

	#[test]
	fn test_public_signals_to_json() {
		let signals = DisclosurePublicSignals {
			commitment: [1u8; 32],
			revealed_value: 1000,
			revealed_asset_id: 42,
			revealed_owner_hash: [2u8; 32],
		};

		let json: DisclosurePublicSignalsJson = signals.into();

		assert_eq!(json.commitment, hex::encode([1u8; 32]));
		assert_eq!(json.revealed_value, 1000);
		assert_eq!(json.revealed_asset_id, 42);
		assert_eq!(json.revealed_owner_hash, hex::encode([2u8; 32]));
	}

	#[test]
	fn test_public_signals_from_json() {
		let json = DisclosurePublicSignalsJson {
			commitment: hex::encode([1u8; 32]),
			revealed_value: 500,
			revealed_asset_id: 99,
			revealed_owner_hash: hex::encode([2u8; 32]),
		};

		let signals: DisclosurePublicSignals = json.try_into().unwrap();

		assert_eq!(signals.commitment, [1u8; 32]);
		assert_eq!(signals.revealed_value, 500);
		assert_eq!(signals.revealed_asset_id, 99);
		assert_eq!(signals.revealed_owner_hash, [2u8; 32]);
	}

	#[test]
	fn test_public_signals_roundtrip() {
		let original = DisclosurePublicSignals {
			commitment: [42u8; 32],
			revealed_value: 999,
			revealed_asset_id: 1,
			revealed_owner_hash: [99u8; 32],
		};

		let json: DisclosurePublicSignalsJson = original.clone().into();
		let restored: DisclosurePublicSignals = json.try_into().unwrap();

		assert_eq!(restored, original);
	}

	#[test]
	fn test_public_signals_invalid_commitment_hex() {
		let json = DisclosurePublicSignalsJson {
			commitment: "invalid_hex".to_string(),
			revealed_value: 100,
			revealed_asset_id: 1,
			revealed_owner_hash: hex::encode([1u8; 32]),
		};

		let result: Result<DisclosurePublicSignals, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid commitment hex");
	}

	#[test]
	fn test_public_signals_invalid_commitment_length() {
		let json = DisclosurePublicSignalsJson {
			commitment: hex::encode([1u8; 16]), // Wrong length
			revealed_value: 100,
			revealed_asset_id: 1,
			revealed_owner_hash: hex::encode([1u8; 32]),
		};

		let result: Result<DisclosurePublicSignals, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Commitment must be 32 bytes");
	}

	#[test]
	fn test_public_signals_invalid_owner_hash() {
		let json = DisclosurePublicSignalsJson {
			commitment: hex::encode([1u8; 32]),
			revealed_value: 100,
			revealed_asset_id: 1,
			revealed_owner_hash: "bad_hex".to_string(),
		};

		let result: Result<DisclosurePublicSignals, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid revealed_owner_hash hex");
	}

	// ===== DisclosureProof Conversion Tests =====

	#[test]
	fn test_disclosure_proof_to_json() {
		let proof = DisclosureProof {
			proof: vec![1, 2, 3, 4],
			public_signals: DisclosurePublicSignals {
				commitment: [10u8; 32],
				revealed_value: 500,
				revealed_asset_id: 5,
				revealed_owner_hash: [20u8; 32],
			},
			mask: DisclosureMask {
				disclose_value: true,
				disclose_owner: false,
				disclose_blinding: true,
				disclose_asset_id: false,
			},
		};

		let json: DisclosureProofJson = proof.into();

		assert_eq!(json.proof, hex::encode([1, 2, 3, 4]));
		assert_eq!(json.public_signals.revealed_value, 500);
		assert_eq!(json.mask.disclose_value, true);
	}

	#[test]
	fn test_disclosure_proof_from_json() {
		let json = DisclosureProofJson {
			proof: hex::encode([5, 6, 7, 8]),
			public_signals: DisclosurePublicSignalsJson {
				commitment: hex::encode([1u8; 32]),
				revealed_value: 200,
				revealed_asset_id: 3,
				revealed_owner_hash: hex::encode([2u8; 32]),
			},
			mask: DisclosureMaskJson {
				disclose_value: false,
				disclose_owner: true,
				disclose_blinding: false,
				disclose_asset_id: true,
			},
		};

		let proof: DisclosureProof = json.try_into().unwrap();

		assert_eq!(proof.proof, vec![5, 6, 7, 8]);
		assert_eq!(proof.public_signals.revealed_value, 200);
		assert_eq!(proof.mask.disclose_owner, true);
	}

	#[test]
	fn test_disclosure_proof_roundtrip() {
		let original = DisclosureProof {
			proof: vec![9, 8, 7, 6, 5, 4, 3, 2, 1],
			public_signals: DisclosurePublicSignals {
				commitment: [42u8; 32],
				revealed_value: 999,
				revealed_asset_id: 7,
				revealed_owner_hash: [99u8; 32],
			},
			mask: DisclosureMask {
				disclose_value: true,
				disclose_owner: true,
				disclose_blinding: false,
				disclose_asset_id: false,
			},
		};

		let json: DisclosureProofJson = original.clone().into();
		let restored: DisclosureProof = json.try_into().unwrap();

		assert_eq!(restored, original);
	}

	#[test]
	fn test_disclosure_proof_invalid_proof_hex() {
		let json = DisclosureProofJson {
			proof: "not_valid_hex".to_string(),
			public_signals: DisclosurePublicSignalsJson {
				commitment: hex::encode([1u8; 32]),
				revealed_value: 100,
				revealed_asset_id: 1,
				revealed_owner_hash: hex::encode([1u8; 32]),
			},
			mask: DisclosureMaskJson {
				disclose_value: true,
				disclose_owner: false,
				disclose_blinding: false,
				disclose_asset_id: false,
			},
		};

		let result: Result<DisclosureProof, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid proof hex");
	}

	// ===== PartialMemoData Conversion Tests =====

	#[test]
	fn test_partial_memo_all_fields() {
		let data = PartialMemoData {
			value: Some(1000),
			owner_pk: Some([1u8; 32]),
			blinding: Some([2u8; 32]),
			asset_id: Some(42),
		};

		let json: PartialMemoDataJson = data.into();

		assert_eq!(json.value, Some(1000));
		assert_eq!(json.owner_pk, Some(hex::encode([1u8; 32])));
		assert_eq!(json.blinding, Some(hex::encode([2u8; 32])));
		assert_eq!(json.asset_id, Some(42));
	}

	#[test]
	fn test_partial_memo_no_fields() {
		let data = PartialMemoData {
			value: None,
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};

		let json: PartialMemoDataJson = data.into();

		assert_eq!(json.value, None);
		assert_eq!(json.owner_pk, None);
		assert_eq!(json.blinding, None);
		assert_eq!(json.asset_id, None);
	}

	#[test]
	fn test_partial_memo_some_fields() {
		let data = PartialMemoData {
			value: Some(500),
			owner_pk: None,
			blinding: Some([3u8; 32]),
			asset_id: None,
		};

		let json: PartialMemoDataJson = data.into();

		assert_eq!(json.value, Some(500));
		assert_eq!(json.owner_pk, None);
		assert_eq!(json.blinding, Some(hex::encode([3u8; 32])));
		assert_eq!(json.asset_id, None);
	}

	#[test]
	fn test_partial_memo_from_json_all_fields() {
		let json = PartialMemoDataJson {
			value: Some(200),
			owner_pk: Some(hex::encode([5u8; 32])),
			blinding: Some(hex::encode([6u8; 32])),
			asset_id: Some(10),
		};

		let data: PartialMemoData = json.try_into().unwrap();

		assert_eq!(data.value, Some(200));
		assert_eq!(data.owner_pk, Some([5u8; 32]));
		assert_eq!(data.blinding, Some([6u8; 32]));
		assert_eq!(data.asset_id, Some(10));
	}

	#[test]
	fn test_partial_memo_roundtrip() {
		let original = PartialMemoData {
			value: Some(777),
			owner_pk: Some([42u8; 32]),
			blinding: None,
			asset_id: Some(5),
		};

		let json: PartialMemoDataJson = original.clone().into();
		let restored: PartialMemoData = json.try_into().unwrap();

		assert_eq!(restored, original);
	}

	#[test]
	fn test_partial_memo_invalid_owner_pk_hex() {
		let json = PartialMemoDataJson {
			value: Some(100),
			owner_pk: Some("bad_hex".to_string()),
			blinding: None,
			asset_id: None,
		};

		let result: Result<PartialMemoData, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid owner_pk hex");
	}

	#[test]
	fn test_partial_memo_invalid_blinding_hex() {
		let json = PartialMemoDataJson {
			value: Some(100),
			owner_pk: None,
			blinding: Some("xyz".to_string()),
			asset_id: None,
		};

		let result: Result<PartialMemoData, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Invalid blinding hex");
	}

	#[test]
	fn test_partial_memo_invalid_owner_pk_length() {
		let json = PartialMemoDataJson {
			value: Some(100),
			owner_pk: Some(hex::encode([1u8; 16])), // Wrong length
			blinding: None,
			asset_id: None,
		};

		let result: Result<PartialMemoData, _> = json.try_into();
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Owner pk must be 32 bytes");
	}

	// ===== Helper Functions Tests =====

	#[test]
	fn test_proof_to_json() {
		let proof = DisclosureProof {
			proof: vec![1, 2, 3],
			public_signals: DisclosurePublicSignals {
				commitment: [1u8; 32],
				revealed_value: 100,
				revealed_asset_id: 1,
				revealed_owner_hash: [2u8; 32],
			},
			mask: DisclosureMask {
				disclose_value: true,
				disclose_owner: false,
				disclose_blinding: false,
				disclose_asset_id: true,
			},
		};

		let json_str = proof_to_json(&proof).unwrap();

		assert!(json_str.contains("proof"));
		assert!(json_str.contains("public_signals"));
		assert!(json_str.contains("mask"));
	}

	#[test]
	fn test_proof_from_json() {
		let json_str = r#"{
			"proof": "01020304",
			"public_signals": {
				"commitment": "0101010101010101010101010101010101010101010101010101010101010101",
				"revealed_value": 500,
				"revealed_asset_id": 2,
				"revealed_owner_hash": "0202020202020202020202020202020202020202020202020202020202020202"
			},
			"mask": {
				"disclose_value": true,
				"disclose_owner": true,
				"disclose_blinding": false,
				"disclose_asset_id": false
			}
		}"#;

		let proof = proof_from_json(json_str).unwrap();

		assert_eq!(proof.proof, vec![1, 2, 3, 4]);
		assert_eq!(proof.public_signals.revealed_value, 500);
		assert_eq!(proof.mask.disclose_value, true);
	}

	#[test]
	fn test_proof_json_roundtrip() {
		let original = DisclosureProof {
			proof: vec![5, 6, 7, 8, 9],
			public_signals: DisclosurePublicSignals {
				commitment: [42u8; 32],
				revealed_value: 1234,
				revealed_asset_id: 99,
				revealed_owner_hash: [99u8; 32],
			},
			mask: DisclosureMask {
				disclose_value: false,
				disclose_owner: true,
				disclose_blinding: true,
				disclose_asset_id: false,
			},
		};

		let json_str = proof_to_json(&original).unwrap();
		let restored = proof_from_json(&json_str).unwrap();

		assert_eq!(restored, original);
	}

	#[test]
	fn test_partial_memo_to_json() {
		let data = PartialMemoData {
			value: Some(300),
			owner_pk: Some([10u8; 32]),
			blinding: None,
			asset_id: Some(5),
		};

		let json_str = partial_memo_to_json(&data).unwrap();

		assert!(json_str.contains("value"));
		assert!(json_str.contains("300"));
		assert!(json_str.contains("owner_pk"));
		assert!(!json_str.contains("blinding")); // Should be omitted
	}

	#[test]
	fn test_partial_memo_from_json_helper() {
		let json_str = r#"{
			"value": 400,
			"asset_id": 7
		}"#;

		let data = partial_memo_from_json(json_str).unwrap();

		assert_eq!(data.value, Some(400));
		assert_eq!(data.asset_id, Some(7));
		assert_eq!(data.owner_pk, None);
		assert_eq!(data.blinding, None);
	}

	#[test]
	fn test_partial_memo_json_roundtrip() {
		let original = PartialMemoData {
			value: Some(888),
			owner_pk: None,
			blinding: Some([77u8; 32]),
			asset_id: Some(3),
		};

		let json_str = partial_memo_to_json(&original).unwrap();
		let restored = partial_memo_from_json(&json_str).unwrap();

		assert_eq!(restored, original);
	}

	#[test]
	fn test_proof_from_json_invalid_json() {
		let bad_json = "not valid json";
		let result = proof_from_json(bad_json);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "JSON deserialization failed");
	}

	#[test]
	fn test_partial_memo_from_json_invalid() {
		let bad_json = "{ invalid }";
		let result = partial_memo_from_json(bad_json);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "JSON deserialization failed");
	}

	// ===== Integration Tests =====

	#[test]
	fn test_complex_disclosure_proof_serialization() {
		let proof = DisclosureProof {
			proof: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
			public_signals: DisclosurePublicSignals {
				commitment: [255u8; 32],
				revealed_value: u64::MAX,
				revealed_asset_id: u32::MAX,
				revealed_owner_hash: [128u8; 32],
			},
			mask: DisclosureMask {
				disclose_value: true,
				disclose_owner: true,
				disclose_blinding: true,
				disclose_asset_id: true,
			},
		};

		let json_str = proof_to_json(&proof).unwrap();
		let restored = proof_from_json(&json_str).unwrap();

		assert_eq!(restored.proof, proof.proof);
		assert_eq!(restored.public_signals.revealed_value, u64::MAX);
		assert_eq!(restored.public_signals.revealed_asset_id, u32::MAX);
	}

	#[test]
	fn test_hex_encoding_is_lowercase() {
		let signals = DisclosurePublicSignals {
			commitment: [255u8; 32],
			revealed_value: 100,
			revealed_asset_id: 1,
			revealed_owner_hash: [255u8; 32],
		};

		let json: DisclosurePublicSignalsJson = signals.into();

		// hex::encode produces lowercase
		assert!(json
			.commitment
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
	}

	#[test]
	fn test_json_serialization_omits_none_fields() {
		let data = PartialMemoData {
			value: Some(100),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};

		let json_str = partial_memo_to_json(&data).unwrap();

		// Should not contain null fields due to skip_serializing_if
		assert!(json_str.contains("value"));
		assert!(!json_str.contains("owner_pk"));
		assert!(!json_str.contains("blinding"));
		assert!(!json_str.contains("asset_id"));
	}
}
