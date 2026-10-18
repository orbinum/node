//! Calldata decoding: the two selectors and their fixed-size arguments.

use crate::revert;
use fp_evm::PrecompileFailure;

// Verify with:  cast sig "transfer(bytes32,uint256)"
//               cast sig "transferKeepAlive(bytes32,uint256)"

/// `transfer(bytes32,uint256)` → 0x6a467394
pub const SEL_TRANSFER: [u8; 4] = [0x6a, 0x46, 0x73, 0x94];
/// `transferKeepAlive(bytes32,uint256)` → 0xac6ac4c4
pub const SEL_TRANSFER_KEEP_ALIVE: [u8; 4] = [0xac, 0x6a, 0xc4, 0xc4];

/// Selector + `bytes32` + `uint256`. Both functions take exactly this; longer
/// calldata is refused rather than silently ignored.
const INPUT_LEN: usize = 4 + 32 + 32;

/// A decoded transfer: who receives, how much, and whether the sender must stay
/// alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransferCall {
	pub dest: [u8; 32],
	pub value: u128,
	pub keep_alive: bool,
}

pub(crate) fn decode(input: &[u8]) -> Result<TransferCall, PrecompileFailure> {
	let selector: [u8; 4] = input
		.get(..4)
		.and_then(|s| s.try_into().ok())
		.ok_or_else(|| revert("input too short: missing selector"))?;
	let keep_alive = match selector {
		SEL_TRANSFER => false,
		SEL_TRANSFER_KEEP_ALIVE => true,
		_ => return Err(revert("unknown selector")),
	};
	if input.len() != INPUT_LEN {
		return Err(revert("calldata must be selector + bytes32 + uint256"));
	}

	let mut dest = [0u8; 32];
	dest.copy_from_slice(&input[4..36]);

	// uint256 big-endian; the high 16 bytes must be zero for it to fit in u128.
	let word = &input[36..68];
	if word[..16].iter().any(|&b| b != 0) {
		return Err(revert("value overflows u128"));
	}
	let mut low = [0u8; 16];
	low.copy_from_slice(&word[16..]);

	Ok(TransferCall {
		dest,
		value: u128::from_be_bytes(low),
		keep_alive,
	})
}
