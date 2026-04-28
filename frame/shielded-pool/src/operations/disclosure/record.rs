use crate::types::DisclosureRecord;

pub struct ParsedDisclosureSignals {
	pub revealed_value: Option<u64>,
	pub revealed_asset_id: Option<u32>,
	pub revealed_owner_hash: Option<[u8; 32]>,
}

impl ParsedDisclosureSignals {
	pub fn from_public_signals(public_signals: &[u8]) -> Self {
		let revealed_value = if public_signals.len() >= 40 {
			let value = u64::from_le_bytes(public_signals[32..40].try_into().unwrap_or([0u8; 8]));
			(value != 0).then_some(value)
		} else {
			None
		};

		let revealed_asset_id = if public_signals.len() >= 44 {
			let asset_id =
				u32::from_le_bytes(public_signals[40..44].try_into().unwrap_or([0u8; 4]));
			(asset_id != 0).then_some(asset_id)
		} else {
			None
		};

		let revealed_owner_hash = if public_signals.len() >= 76 {
			let owner_hash: [u8; 32] = public_signals[44..76].try_into().unwrap_or([0u8; 32]);
			(owner_hash != [0u8; 32]).then_some(owner_hash)
		} else {
			None
		};

		Self {
			revealed_value,
			revealed_asset_id,
			revealed_owner_hash,
		}
	}

	pub fn into_record<AccountId, BlockNumber>(
		self,
		requester: AccountId,
		timestamp: BlockNumber,
	) -> DisclosureRecord<AccountId, BlockNumber> {
		DisclosureRecord {
			revealed_value: self.revealed_value,
			revealed_asset_id: self.revealed_asset_id,
			revealed_owner_hash: self.revealed_owner_hash,
			requester,
			timestamp,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// ── helpers ──────────────────────────────────────────────────────────────

	/// 76-byte signals: commitment(32) | value_le(8) | asset_id_le(4) | owner_hash(32)
	fn signals(value: u64, asset_id: u32, owner_hash: [u8; 32]) -> [u8; 76] {
		let mut buf = [0u8; 76];
		buf[32..40].copy_from_slice(&value.to_le_bytes());
		buf[40..44].copy_from_slice(&asset_id.to_le_bytes());
		buf[44..76].copy_from_slice(&owner_hash);
		buf
	}

	// ── from_public_signals ──────────────────────────────────────────────────

	#[test]
	fn all_fields_present_when_nonzero() {
		let owner_hash = [0xABu8; 32];
		let s = signals(1000, 7, owner_hash);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);

		assert_eq!(parsed.revealed_value, Some(1000u64));
		assert_eq!(parsed.revealed_asset_id, Some(7u32));
		assert_eq!(parsed.revealed_owner_hash, Some(owner_hash));
	}

	#[test]
	fn zero_value_returns_none() {
		let s = signals(0, 5, [0xBBu8; 32]);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_value, None);
		assert_eq!(parsed.revealed_asset_id, Some(5u32));
	}

	#[test]
	fn zero_asset_id_returns_none() {
		let s = signals(42, 0, [0xCCu8; 32]);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_asset_id, None);
		assert_eq!(parsed.revealed_value, Some(42u64));
	}

	#[test]
	fn zero_owner_hash_returns_none() {
		let s = signals(1, 1, [0u8; 32]);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_owner_hash, None);
	}

	#[test]
	fn all_fields_none_when_all_zero() {
		let s = signals(0, 0, [0u8; 32]);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_value, None);
		assert_eq!(parsed.revealed_asset_id, None);
		assert_eq!(parsed.revealed_owner_hash, None);
	}

	#[test]
	fn short_input_returns_none_for_missing_fields() {
		// Only 33 bytes: not enough for value (needs 40), asset_id (needs 44), owner_hash (needs 76)
		let s = [0u8; 33];
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_value, None);
		assert_eq!(parsed.revealed_asset_id, None);
		assert_eq!(parsed.revealed_owner_hash, None);
	}

	#[test]
	fn exactly_40_bytes_gives_value_but_no_asset_or_owner() {
		let mut s = [0u8; 40];
		s[32..40].copy_from_slice(&500u64.to_le_bytes());
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_value, Some(500u64));
		assert_eq!(parsed.revealed_asset_id, None);
		assert_eq!(parsed.revealed_owner_hash, None);
	}

	#[test]
	fn exactly_44_bytes_gives_value_and_asset_but_no_owner() {
		let mut s = [0u8; 44];
		s[32..40].copy_from_slice(&9u64.to_le_bytes());
		s[40..44].copy_from_slice(&3u32.to_le_bytes());
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		assert_eq!(parsed.revealed_value, Some(9u64));
		assert_eq!(parsed.revealed_asset_id, Some(3u32));
		assert_eq!(parsed.revealed_owner_hash, None);
	}

	// ── into_record ──────────────────────────────────────────────────────────

	#[test]
	fn into_record_maps_fields_correctly() {
		let owner_hash = [0x01u8; 32];
		let s = signals(500, 2, owner_hash);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		let record = parsed.into_record(42u64, 10u64);

		assert_eq!(record.revealed_value, Some(500u64));
		assert_eq!(record.revealed_asset_id, Some(2u32));
		assert_eq!(record.revealed_owner_hash, Some(owner_hash));
		assert_eq!(record.requester, 42u64);
		assert_eq!(record.timestamp, 10u64);
	}

	#[test]
	fn into_record_with_none_fields() {
		let s = signals(0, 0, [0u8; 32]);
		let parsed = ParsedDisclosureSignals::from_public_signals(&s);
		let record = parsed.into_record(1u64, 5u64);

		assert_eq!(record.revealed_value, None);
		assert_eq!(record.revealed_asset_id, None);
		assert_eq!(record.revealed_owner_hash, None);
	}
}
