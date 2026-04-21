//! Public traits exposed by pallet-relayer.
//!
//! Other pallets (e.g. `pallet-shielded-pool`) depend only on these traits,
//! never on the concrete `Pallet<T>` type.  Tests supply lightweight mock
//! implementations directly in their own `mock.rs`.

/// All relay-related behaviour that external pallets need.
///
/// Production impl: `pallet_relayer::Pallet<T>`.
/// Test impl: a lightweight struct in each dependent pallet's `mock.rs`.
pub trait RelayerInterface {
	type AccountId: Clone;

	/// Resolve an EVM address to a registered substrate AccountId.
	///
	/// Returns `Some(account)` when the EVM address was registered via
	/// `register_relayer`.  Returns `None` when not registered.
	///
	/// Used by `pallet-shielded-pool` to attribute relay fees to the node
	/// that signed the EVM transaction instead of the block author.
	fn resolve_relayer(evm_address: &sp_core::H160) -> Option<Self::AccountId>;

	/// Minimum fee (planck / wei) that must be embedded in relay calldata.
	fn min_relay_fee() -> u128;

	/// ABI selectors currently accepted by the relay whitelist.
	///
	/// An empty `Vec` means "use built-in defaults" (resolved by the Runtime
	/// API impl so the relay always has a non-empty list).
	fn allowed_selectors() -> sp_std::vec::Vec<[u8; 4]>;

	/// Current block author (relay fee recipient).
	///
	/// Returns `None` when unavailable (e.g. first block or no author pallet
	/// configured).
	fn block_author() -> Option<Self::AccountId>;

	/// Credit `amount` planck of relay fee for `asset_id` to `author`.
	///
	/// Called by pallet-shielded-pool after a successful `private_transfer`
	/// or `unshield` unsigned extrinsic.
	fn accumulate_relay_fee(author: &Self::AccountId, asset_id: u32, amount: u128);

	/// Return the total pending relay fees for (`who`, `asset_id`) in planck.
	fn pending_relay_fees(who: &Self::AccountId, asset_id: u32) -> u128;

	/// Deduct `amount` from the pending relay fees for (`who`, `asset_id`).
	///
	/// Returns `Err` when the pending balance is insufficient.  Called by
	/// pallet-shielded-pool's `claim_shielded_fees` before inserting the fee
	/// commitment into the Merkle tree.
	fn consume_relay_fee(
		who: &Self::AccountId,
		asset_id: u32,
		amount: u128,
	) -> frame_support::dispatch::DispatchResult;
}
