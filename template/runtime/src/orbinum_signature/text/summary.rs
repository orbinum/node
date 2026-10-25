//! What the signed text shows of a transaction: the call's name, the recipient and
//! amount of the calls that move ORB, and a non-zero tip.
//!
//! The runtime renders it from the payload when it verifies, so a summary that does not
//! match the payload signs nothing: a site cannot show one transaction and get another
//! signed. Clients render the same lines (the app's `services/substrate/ed25519Text`).

use super::format::{hex, line, orb};
use crate::{Balance, BalancesCall, Runtime, RuntimeCall, SignedExtra};
use alloc::vec::Vec;
use frame_support::{traits::GetCallMetadata, MAX_EXTRINSIC_DEPTH};
use scale_codec::{Decode, DecodeLimit};

/// A `key: value` line under `action:`.
type Line = (&'static [u8], Vec<u8>);

/// Appends the `action:` value and the lines under it. `payload` is the whole signing
/// payload, never its hash.
pub(super) fn render(out: &mut Vec<u8>, payload: &[u8]) {
	let Some((call, tip)) = decode(payload) else {
		out.extend_from_slice(b"unknown");
		return;
	};
	let meta = call.get_call_metadata();
	out.extend_from_slice(meta.pallet_name.as_bytes());
	out.push(b'.');
	out.extend_from_slice(meta.function_name.as_bytes());
	for (key, value) in details(&call).into_iter().chain(tip_line(tip)) {
		line(out, key, &value);
	}
}

/// The call and the tip a payload signs: the call comes first, then `SignedExtra`,
/// whose `ChargeTransactionPayment` holds the tip. `None` when no call decodes.
fn decode(payload: &[u8]) -> Option<(RuntimeCall, Balance)> {
	let input = &mut &payload[..];
	let call = RuntimeCall::decode_with_depth_limit(MAX_EXTRINSIC_DEPTH, input).ok()?;
	let tip = SignedExtra::decode(input).map_or(0, |extra| extra.7.tip());
	Some((call, tip))
}

/// Recipient and amount of the calls that move ORB; nothing for any other call.
fn details(call: &RuntimeCall) -> Vec<Line> {
	use pallet_shielded_pool::Call as ShieldedPoolCall;
	match call {
		RuntimeCall::Balances(
			BalancesCall::transfer_allow_death { dest, value }
			| BalancesCall::transfer_keep_alive { dest, value },
		) => alloc::vec![(b"to", hex(dest.as_ref())), (b"amount", orb(*value))],
		RuntimeCall::Balances(BalancesCall::transfer_all { dest, .. }) => {
			alloc::vec![(b"to", hex(dest.as_ref())), (b"amount", b"all".to_vec())]
		}
		// Other assets have their own decimals; their amounts are not rendered as ORB.
		RuntimeCall::ShieldedPool(
			ShieldedPoolCall::<Runtime>::shield {
				asset_id: 0,
				amount,
				..
			}
			| ShieldedPoolCall::<Runtime>::claim_fees {
				asset_id: 0,
				amount,
			},
		) => alloc::vec![(b"amount", orb(*amount))],
		_ => Vec::new(),
	}
}

fn tip_line(tip: Balance) -> Option<Line> {
	(tip != 0).then(|| (b"tip".as_slice(), orb(tip)))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::AccountId;
	use scale_codec::Encode;

	const ORB: u128 = 1_000_000_000_000_000_000;
	const BOB: [u8; 32] = [0xb0; 32];

	fn extra(tip: u128) -> SignedExtra {
		(
			frame_system::CheckNonZeroSender::new(),
			frame_system::CheckSpecVersion::new(),
			frame_system::CheckTxVersion::new(),
			frame_system::CheckGenesis::new(),
			frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
			frame_system::CheckNonce::from(0),
			frame_system::CheckWeight::new(),
			pallet_transaction_payment::ChargeTransactionPayment::from(tip),
			frame_metadata_hash_extension::CheckMetadataHash::new(false),
		)
	}

	/// The call and its extension: the part of a payload `render` reads.
	fn rendered(call: RuntimeCall, tip: u128) -> String {
		let mut out = Vec::new();
		render(&mut out, &[call.encode(), extra(tip).encode()].concat());
		String::from_utf8(out).unwrap()
	}

	fn transfer(value: u128) -> RuntimeCall {
		RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
			dest: AccountId::from(BOB),
			value,
		})
	}

	fn shielded(call: pallet_shielded_pool::Call<Runtime>) -> RuntimeCall {
		RuntimeCall::ShieldedPool(call)
	}

	fn shield(asset_id: u32, amount: u128) -> RuntimeCall {
		shielded(pallet_shielded_pool::Call::shield {
			asset_id,
			amount,
			commitment: pallet_shielded_pool::Commitment::new([0x1c; 32]),
			encrypted_memo: pallet_shielded_pool::FrameEncryptedMemo::new(vec![0x3e; 180]).unwrap(),
			proof: vec![0x9f; 128].try_into().unwrap(),
			circuit_version: 1,
		})
	}

	#[test]
	fn a_transfer_shows_its_recipient_and_amount() {
		let to = String::from_utf8(hex(&BOB)).unwrap();
		assert_eq!(
			rendered(transfer(3 * ORB / 2), 0),
			format!("Balances.transfer_keep_alive\nto: {to}\namount: 1.5 ORB")
		);
		let allow_death = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
			dest: AccountId::from(BOB),
			value: 1,
		});
		assert_eq!(
			rendered(allow_death, 0),
			format!("Balances.transfer_allow_death\nto: {to}\namount: 0.000000000000000001 ORB")
		);
	}

	#[test]
	fn transfer_all_shows_all() {
		let call = RuntimeCall::Balances(BalancesCall::transfer_all {
			dest: AccountId::from(BOB),
			keep_alive: true,
		});
		assert!(rendered(call, 0).ends_with("\namount: all"));
	}

	#[test]
	fn orb_shields_and_fee_claims_show_their_amount() {
		assert_eq!(
			rendered(shield(0, 2 * ORB), 0),
			"ShieldedPool.shield\namount: 2 ORB"
		);
		let claim = shielded(pallet_shielded_pool::Call::claim_fees {
			asset_id: 0,
			amount: ORB / 4,
		});
		assert_eq!(
			rendered(claim, 0),
			"ShieldedPool.claim_fees\namount: 0.25 ORB"
		);
	}

	#[test]
	fn other_assets_show_no_amount() {
		assert_eq!(rendered(shield(7, 5), 0), "ShieldedPool.shield");
		let claim = shielded(pallet_shielded_pool::Call::claim_fees {
			asset_id: 7,
			amount: 5,
		});
		assert_eq!(rendered(claim, 0), "ShieldedPool.claim_fees");
	}

	#[test]
	fn other_calls_show_their_name_only() {
		let remark = RuntimeCall::System(frame_system::Call::remark { remark: vec![1, 2] });
		assert_eq!(rendered(remark, 0), "System.remark");
	}

	#[test]
	fn a_tip_is_the_last_line_when_not_zero() {
		assert!(rendered(transfer(ORB), ORB / 100).ends_with("\namount: 1 ORB\ntip: 0.01 ORB"));
		assert!(!rendered(transfer(ORB), 0).contains("tip:"));
	}

	#[test]
	fn bytes_that_are_no_call_show_unknown() {
		let mut out = Vec::new();
		render(&mut out, &[0xff; 40]);
		assert_eq!(out, b"unknown");
	}

	/// A call without a readable extension still shows; only the tip line is lost.
	#[test]
	fn a_call_without_its_extension_shows_no_tip() {
		let mut out = Vec::new();
		render(&mut out, &transfer(ORB).encode());
		assert!(String::from_utf8(out).unwrap().ends_with("\namount: 1 ORB"));
	}
}
