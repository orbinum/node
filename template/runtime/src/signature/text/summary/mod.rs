//! What the signed text shows of a transaction: the call's name, the recipient and
//! amount of the calls that move ORB, what the staking and nomination pool calls bond,
//! pay to and back, when the transaction expires, its nonce, and a non-zero tip.
//!
//! The runtime renders it from the payload when it verifies, so a summary that does not
//! match the payload signs nothing: a site cannot show one transaction and get another
//! signed. Only calls whose lines show every parameter that moves value or authority are
//! text-signable ([`signable`]); any other call fails verification. Clients render the
//! same lines and refuse the same calls (ts-protocol's `chain/substrate/ed25519Text`).
//!
//! Each call family renders its own lines: `balances`, `shielded_pool`, `staking`,
//! `pools`, and `session` (session keys, validator-set and system calls). `labels`
//! writes the values they share.

mod balances;
mod labels;
mod pools;
mod session;
mod shielded_pool;
mod staking;
#[cfg(test)]
mod tests;

use super::format::{decimal, line, orb};
use crate::{Balance, Nonce, RuntimeCall, SignedExtra, SignedExtraFields};
use alloc::vec::Vec;
use frame_support::{traits::GetCallMetadata, MAX_EXTRINSIC_DEPTH};
use scale_codec::{Decode, DecodeLimit};
use sp_runtime::generic::Era;

/// A `key: value` line under `action:`.
type Line = (&'static [u8], Vec<u8>);

/// Appends the `action:` value and the lines under it. `payload` is the whole signing
/// payload, never its hash.
pub(super) fn render(out: &mut Vec<u8>, payload: &[u8]) {
	let Some((call, extra)) = decode(payload) else {
		out.extend_from_slice(b"unknown");
		return;
	};
	let meta = call.get_call_metadata();
	out.extend_from_slice(meta.pallet_name.as_bytes());
	out.push(b'.');
	out.extend_from_slice(meta.function_name.as_bytes());
	// A call that is not text-signable still renders its name, as a wallet shows it
	// before refusing; `signable` decides, not the text.
	let lines = details(&call).unwrap_or_default();
	let extension = extra.iter().flat_map(|extra| {
		[
			Some(expiry_line(&extra.era())),
			Some(nonce_line(extra.nonce())),
			tip_line(extra.tip()),
		]
		.into_iter()
		.flatten()
	});
	for (key, value) in lines.into_iter().chain(extension) {
		line(out, key, &value);
	}
}

/// The call and the extension a payload signs: the call comes first, then
/// `SignedExtra`, whose `CheckEra` holds the era, `CheckNonce` the nonce and
/// `ChargeTransactionPayment` the tip. `None` when no call decodes; no extension when
/// it does not decode.
fn decode(payload: &[u8]) -> Option<(RuntimeCall, Option<SignedExtra>)> {
	let input = &mut &payload[..];
	let call = RuntimeCall::decode_with_depth_limit(MAX_EXTRINSIC_DEPTH, input).ok()?;
	Some((call, SignedExtra::decode(input).ok()))
}

/// Most targets a text-signed `nominate` (staking's or a pool's) or `kick` may list: what
/// staking accepts (`MaxNominations`), which also bounds the text a wallet shows and the
/// runtime hashes.
pub(super) const MAX_LISTED_ACCOUNTS: usize = crate::staking::params::MAX_NOMINATIONS as usize;

/// Whether a text signature may authorise the call `payload` signs: only calls whose
/// lines show every parameter that moves value or authority. Any other call would show
/// its name alone, so a site could get it signed under a harmless-looking text.
pub(super) fn signable(payload: &[u8]) -> bool {
	decode(payload).is_some_and(|(call, _)| details(&call).is_some())
}

/// The lines of a call a text signature may authorise, or `None` for any other call:
/// recipient and amount of the calls that move ORB, what the staking and pool calls
/// bond, pay to and back, the session keys registered, and the calls without such
/// parameters.
fn details(call: &RuntimeCall) -> Option<Vec<Line>> {
	match call {
		RuntimeCall::Balances(call) => balances::lines(call),
		RuntimeCall::ShieldedPool(call) => shielded_pool::lines(call),
		RuntimeCall::Staking(call) => staking::lines(call),
		RuntimeCall::NominationPools(call) => pools::lines(call),
		RuntimeCall::Session(_) | RuntimeCall::ValidatorSet(_) | RuntimeCall::System(_) => {
			session::lines(call)
		}
		_ => None,
	}
}

/// When the transaction stops being valid: `within {period} blocks` of the block it was
/// signed against, or `never`. The payload carries the era, not that block's number.
fn expiry_line(era: &Era) -> Line {
	let value = match era {
		Era::Immortal => b"never".to_vec(),
		Era::Mortal(period, _) => {
			let mut out = b"within ".to_vec();
			out.extend_from_slice(&decimal(u128::from(*period)));
			out.extend_from_slice(b" blocks");
			out
		}
	};
	(b"expires", value)
}

/// The account nonce the transaction uses: a person can tell a replayed or queued
/// transaction from the one they meant.
fn nonce_line(nonce: Nonce) -> Line {
	(b"nonce", decimal(u128::from(nonce)))
}

fn tip_line(tip: Balance) -> Option<Line> {
	(tip != 0).then(|| (b"tip".as_slice(), orb(tip)))
}
