//! `pallet-ismp-messaging`: this chain's ISMP application, and what a signed
//! dispatch costs.

use super::{
	IsmpDefaultMessageByteFee, IsmpDefaultMessageFee, IsmpMaxMessageFee, IsmpMaxSignedTimeout,
	IsmpMinSignedTimeout, IsmpTreasuryAccount,
};
use crate::{configs::governance::CrossChainAdmin, AccountId, Runtime};
use frame_support::traits::ConstU32;
use frame_system::EnsureSigned;

impl pallet_ismp_messaging::Config for Runtime {
	/// Any signed account, paying `IsmpDefaultMessageFee`. Root always passes too, checked
	/// first and free, so automation such as `confirm_delivery` does not depend on this.
	///
	/// The fee is anti-spam pricing on a self-relayed channel, not relayer pay: paid to the
	/// treasury and never refunded (the pallet's `outbound::fee_for`).
	type DispatchOrigin = EnsureSigned<AccountId>;
	type AdminOrigin = CrossChainAdmin;
	type DefaultMessageFee = IsmpDefaultMessageFee;
	type DefaultMessageByteFee = IsmpDefaultMessageByteFee;
	type MaxMessageFee = IsmpMaxMessageFee;
	/// The ISMP treasury (`orb/ismp`), which Root can reach; not upstream's `ISMPFEES`
	/// account, which holds its escrow accounting.
	type FeeDestination = IsmpTreasuryAccount;
	type MinSignedTimeout = IsmpMinSignedTimeout;
	type MaxSignedTimeout = IsmpMaxSignedTimeout;

	/// Bounds the cost of decoding a remote party's bytes, and is the range the weights
	/// are measured over. Keep this and the benchmark's upper bound equal.
	type MaxBodyLen = ConstU32<8192>;

	/// Storage keys per GET. Low on purpose: each key is a membership proof the remote
	/// chain and relayer must produce. 16 covers a realistic read; more takes a second
	/// request.
	type MaxGetKeys = ConstU32<16>;

	/// 128 bytes per storage key: double the longest shape the protocol documents (52, an
	/// EVM address plus a slot hash), because nothing upstream enforces that spec. See the
	/// pallet's `Config::MaxGetKeyLen`.
	type MaxGetKeyLen = ConstU32<128>;

	type WeightInfo = pallet_ismp_messaging::weights::SubstrateWeight<Runtime>;
}
