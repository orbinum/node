//! Texts shared with clients (`fixtures/ed25519_text_vectors.json`, copied to the app's
//! tests): the same payload must render the same text, byte for byte.

use super::*;

const VECTORS: &str = include_str!("../fixtures/ed25519_text_vectors.json");

/// `(name, msg)` for every vector: the bytes `verify` receives.
fn vector_messages() -> Vec<(&'static str, Vec<u8>)> {
	let claim = |asset_id, amount| {
		RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::claim_fees { asset_id, amount })
	};
	vec![
		(
			"transfer_keep_alive",
			payload_with_tip(&transfer(3 * ORB / 2), 0),
		),
		(
			"transfer_allow_death_one_wei",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_allow_death {
					dest: AccountId::from(BOB),
					value: 1,
				}),
				0,
			),
		),
		(
			"transfer_all",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_all {
					dest: AccountId::from(BOB),
					keep_alive: false,
				}),
				0,
			),
		),
		(
			"transfer_with_tip",
			payload_with_tip(&transfer(ORB), ORB / 100),
		),
		("claim_fees_orb", payload_with_tip(&claim(0, ORB / 4), 0)),
		("claim_fees_other_asset", payload_with_tip(&claim(7, 5), 0)),
		("remark", raw_payload(&remark(20), 0)),
		("remark_over_256_bytes", raw_payload(&remark(300), 0)),
		("shield", payload_with_tip(&shield(2 * ORB), 0)),
		("not_a_call", vec![0xff; 40]),
	]
}

fn render_vectors() -> serde_json::Value {
	let vectors: Vec<_> = vector_messages()
		.into_iter()
		.map(|(name, msg)| {
			// What the app gets from the pjs payload: the call and the tip.
			let input = &mut &msg[..];
			let (call, tip) = match RuntimeCall::decode(input) {
				Ok(call) => (call.encode(), SignedExtra::decode(input).unwrap().7.tip()),
				Err(_) => (msg.clone(), 0),
			};
			serde_json::json!({
				"name": name,
				"payload": format!("0x{}", to_hex(&msg)),
				"call": format!("0x{}", to_hex(&call)),
				"tip": tip.to_string(),
				"text": String::from_utf8(text_message(&TESTNET_GENESIS, &msg)).unwrap(),
			})
		})
		.collect();
	serde_json::json!({ "genesis": format!("0x{}", to_hex(&TESTNET_GENESIS)), "vectors": vectors })
}

/// The app renders these same texts; a change here must reach it, or its ed25519
/// accounts sign texts the runtime refuses.
#[test]
fn shared_vectors_match_the_runtime() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let pinned: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
		assert_eq!(pinned, render_vectors());
	});
}

/// Writes the fixture. Only when the format changes on purpose.
#[test]
#[ignore]
fn regenerate_shared_vectors() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		std::fs::write(
			concat!(
				env!("CARGO_MANIFEST_DIR"),
				"/src/runtime_tests/fixtures/ed25519_text_vectors.json"
			),
			serde_json::to_string_pretty(&render_vectors()).unwrap() + "\n",
		)
		.unwrap();
	});
}
