//! Public traits exposed by pallet-relayer.
//!
//! Other pallets (e.g. `pallet-shielded-pool`) depend only on these traits,
//! never on the concrete `Pallet<T>` type. Tests supply lightweight mock
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
	/// `register_relayer`. Returns `None` when not registered.
	///
	/// Used by `pallet-shielded-pool` to find whose fees an EVM caller of
	/// `claim_relay_fees` is claiming.
	fn resolve_relayer(evm_address: &sp_core::H160) -> Option<Self::AccountId>;

	/// Minimum fee (planck / wei) that must be embedded in relay calldata.
	fn min_relay_fee() -> u128;

	/// ABI selectors currently accepted by the relay whitelist.
	///
	/// An empty `Vec` means "use built-in defaults" (resolved by the Runtime
	/// API impl so the relay always has a non-empty list).
	fn allowed_selectors() -> sp_std::vec::Vec<[u8; 4]>;

	/// Current block author: the fee recipient of a spend no relayer committed to.
	///
	/// Returns `None` when unavailable (e.g. first block or no author pallet
	/// configured).
	fn block_author() -> Option<Self::AccountId>;

	/// Credit `amount` planck of relay fee for `asset_id` to `author`.
	///
	/// Called by pallet-shielded-pool after a successful `private_transfer`
	/// or `unshield` unsigned extrinsic.
	///
	/// **Caller contract:** `asset_id` must already be known to exist. This
	/// creates a `PendingRelayerFees` entry unconditionally, so an unchecked
	/// caller could bloat storage with rows for assets that were never
	/// registered. Both current callers validate first — `unshield` and
	/// `private_transfer` resolve the asset and reject `InvalidAssetId` before
	/// any fee path runs — and a new caller must do the same rather than
	/// rely on a check here, which would duplicate a lookup the caller has
	/// already performed.
	fn accumulate_relay_fee(author: &Self::AccountId, asset_id: u32, amount: u128);

	/// Return the total pending relay fees for (`who`, `asset_id`) in planck.
	fn pending_relay_fees(who: &Self::AccountId, asset_id: u32) -> u128;

	/// Deduct `amount` from the pending relay fees for (`who`, `asset_id`).
	///
	/// Returns `Err` when the pending balance is insufficient. Called by
	/// pallet-shielded-pool's `claim_relay_fees` before paying the fees out.
	fn consume_relay_fee(
		who: &Self::AccountId,
		asset_id: u32,
		amount: u128,
	) -> frame_support::dispatch::DispatchResult;

	/// Return the EVM address registered for a substrate account, if any.
	///
	/// Reverse lookup of `resolve_relayer`. Used by `pallet-shielded-pool`
	/// to derive the H160 mirror AccountId when paying relay fees directly
	/// to the EVM account.
	fn registered_evm_address(who: &Self::AccountId) -> Option<sp_core::H160>;

	/// Record relay commits (see [`crate::relay_commit_hash`]) on behalf of the
	/// registered `relayer`.
	///
	/// A commit already present is left as is, so it keeps its earlier block;
	/// only new ones count against the per-block quota, which belongs to the
	/// validator behind `relayer`. A batch with nothing new writes nothing. All
	/// or nothing: fails with `NotRegistered` for an unknown address and
	/// `TooManyCommits` past the quota, writing none of the batch.
	fn record_relay_commits(
		relayer: &sp_core::H160,
		commits: &[sp_core::H256],
	) -> frame_support::dispatch::DispatchResult;

	/// The relayer to credit for the spend identified by `op_hash`: the
	/// registered relayer with the earliest commit for it from a previous block.
	///
	/// Removes every commit found for `op_hash`, since the spend can only execute
	/// once. `None` when no relayer committed in time. Commits from the same
	/// block tie; the lowest commit hash wins. Scans the registry, so the cost
	/// grows with the number of registered relayers (one per validator). A commit
	/// made under an address its validator has since replaced does not match, so
	/// it earns nothing.
	fn take_committed_relayer(op_hash: &[u8; 32]) -> Option<Self::AccountId>;
}
