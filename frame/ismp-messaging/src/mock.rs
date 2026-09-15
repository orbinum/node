//! Mock runtime for `pallet-ismp-messaging`.
//!
//! Carries a real `pallet_ismp` because our callbacks read its associated types
//! (`Coprocessor`, `HostStateMachine`) and dispatch through it. No pallet in this repo
//! had one before, so this is also the harness any future ISMP pallet can reuse.
//!
//! `ConsensusClients` is `()` and `OffchainDB` is `()`: these tests drive the module
//! callbacks directly rather than through the message pipeline, so no proof is ever
//! verified. Forging one would be testing upstream's verifier, which upstream already
//! tests; what is untested here is our own callback logic.
//!
//! Accounts `1` and `2` are funded with `10 × MESSAGE_FEE` at genesis; `3` is deliberately
//! not, so the unfunded-signer path has a subject. `DispatchOrigin` is `EnsureSigned`, the
//! same as the runtime, so a signed dispatch here is charged for real and dispatched
//! through the real `pallet-ismp` dispatcher.

use crate as pallet_ismp_messaging;
use frame_support::{PalletId, derive_impl, parameter_types, traits::ConstU32};
use ismp::{host::StateMachine, module::IsmpModule, router::IsmpRouter};
use sp_runtime::{BuildStorage, traits::IdentityLookup};

pub type AccountId = u64;
pub type Balance = u128;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Timestamp: pallet_timestamp,
		Balances: pallet_balances,
		Ismp: pallet_ismp,
		IsmpMessaging: pallet_ismp_messaging,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = Balance;

	/// Zero, as on the real chain (`configs/system.rs:65`); the prelude's default is `1`.
	/// Inheriting it made the mock disagree with the runtime about the property
	/// `outbound::fee_for` cites — that a sender may spend their last planck — so that case
	/// could not even be written.
	///
	/// It does not distinguish `Preserve` from `Expendable`: with ED zero those behave
	/// identically (`pallet-balances/src/impl_fungible.rs:60-70`).
	type ExistentialDeposit = frame_support::traits::ConstUint<0>;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

/// What a signed dispatch costs in this mock. Small and round, so balance assertions
/// read as arithmetic rather than as constants looked up elsewhere.
pub const MESSAGE_FEE: Balance = 1_000;
/// Per byte, deliberately non-zero so a test can tell the two terms apart.
pub const MESSAGE_BYTE_FEE: Balance = 10;

/// What the largest legal message costs a signed account, so tests can fund an account that
/// actually pays for one.
///
/// Reads `max_chargeable_size` rather than hard-coding `MaxBodyLen`: this mock configures a
/// full GET (24,576 bytes) to outweigh a full POST, so a constant pinned to the body alone
/// was a third of the real worst case.
pub fn worst_case_fee() -> Balance {
	MESSAGE_FEE + MESSAGE_BYTE_FEE * crate::outbound::max_chargeable_size::<Test>() as Balance
}

/// Where charges go. Any account the sender does not control will do.
pub const TREASURY: AccountId = 99;

parameter_types! {
	/// Mirrors the testnet build: Hyperbridge as a Kusama-anchored parachain.
	pub const Coprocessor: Option<StateMachine> = Some(StateMachine::Kusama(4009));
	pub const HostStateMachine: StateMachine = StateMachine::Substrate(*b"orbi");
	pub const TreasuryPalletId: PalletId = PalletId(*b"orb/ismp");
	pub const DefaultMessageFee: Balance = MESSAGE_FEE;
	pub const DefaultMessageByteFee: Balance = MESSAGE_BYTE_FEE;
	/// The ceiling bounds the WORST CASE — `fee + byte_fee × max_chargeable_size`, NOT
	/// `× MaxBodyLen`; writing the latter here is the very bug the helper exists to stop — so
	/// it must clear the defaults' own worst case (1_000 + 10 × 24_576 = 246,760) with room
	/// to reprice upward in a test. That leaves about 4x of headroom here; the runtime is
	/// more generous, 1 ORB against a ~0.02 ORB default worst case.
	pub const MaxMessageFee: Balance = 1_000_000;
	pub const FeeDestination: AccountId = TREASURY;
	/// Ten minutes and a week, as in the runtime.
	pub const MinSignedTimeout: u64 = 600;
	pub const MaxSignedTimeout: u64 = 7 * 24 * 60 * 60;
}

/// Routes the way the real runtime does: our id to us, everything else to a module
/// that answers rather than errs.
#[derive(Default)]
pub struct Router;

impl IsmpRouter for Router {
	fn module_for_id(
		&self,
		id: sp_std::vec::Vec<u8>,
	) -> Result<Box<dyn IsmpModule>, anyhow::Error> {
		if id.as_slice() == crate::PALLET_ID_BYTES {
			return Ok(Box::new(
				crate::inbound::IsmpModuleCallback::<Test>::default(),
			));
		}
		Ok(Box::new(Unrouted))
	}
}

/// Stands in for the runtime's `UnroutedModule`.
#[derive(Default)]
pub struct Unrouted;

impl IsmpModule for Unrouted {
	fn on_accept(
		&self,
		request: ismp::router::PostRequest,
	) -> Result<sp_runtime::Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(request.to).into())
	}
	fn on_response(
		&self,
		response: ismp::router::GetResponse,
	) -> Result<sp_runtime::Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(response.get.from).into())
	}
	fn on_timeout(&self, _: ismp::router::Request) -> Result<sp_runtime::Weight, anyhow::Error> {
		Ok(sp_runtime::Weight::zero())
	}
}

impl pallet_ismp::Config for Test {
	type AdminOrigin = frame_system::EnsureRoot<AccountId>;
	type HostStateMachine = HostStateMachine;
	type TimestampProvider = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type Router = Router;
	type Coprocessor = Coprocessor;
	type ConsensusClients = ();
	type OffchainDB = ();
	type FeeHandler = pallet_ismp::fee_handler::WeightFeeHandler<
		AccountId,
		Balances,
		frame_support::weights::IdentityFee<Balance>,
		TreasuryPalletId,
		false,
	>;
}

impl pallet_ismp_messaging::Config for Test {
	type DispatchOrigin = frame_system::EnsureSigned<AccountId>;
	type DefaultMessageFee = DefaultMessageFee;
	type DefaultMessageByteFee = DefaultMessageByteFee;
	type MaxMessageFee = MaxMessageFee;
	type FeeDestination = FeeDestination;
	type MinSignedTimeout = MinSignedTimeout;
	type MaxSignedTimeout = MaxSignedTimeout;
	type MaxBodyLen = ConstU32<8192>;
	// Small on purpose, so the TooManyKeys path is cheap to exercise.
	type MaxGetKeys = ConstU32<4>;

	/// 4096, deliberately LARGER than `MaxBodyLen / MaxGetKeys`, so that a full GET
	/// (`MaxGetKeys × MaxGetKeyLen` + context = 24,576 bytes) outweighs a full POST (8,224).
	///
	/// The runtime is configured the other way round — 16 × 128 is well under a body — and
	/// that is the safe ordering. The mock inverts it on purpose: with a GET that cannot
	/// exceed a body, `max_chargeable_size` returns `MaxBodyLen` either way and a ceiling
	/// computed from the body alone looks correct. That is exactly the bug this mock has to
	/// be able to see, so here the GET is the worst case.
	type MaxGetKeyLen = ConstU32<4096>;
	type WeightInfo = ();
}

/// Test externalities with block number 1, so events are collected.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = RuntimeGenesisConfig {
		balances: pallet_balances::GenesisConfig {
			// Enough for the worst case of ANY shape, not merely for the flat fee: the
			// dearest message here costs `MESSAGE_FEE + MESSAGE_BYTE_FEE × 24,576` = 246,760,
			// and funding `10 × MESSAGE_FEE` once made the largest signed message
			// unaffordable — so every size-boundary test had to run as Root, i.e. down the
			// one path that never pays.
			balances: sp_std::vec![(1, 100 * worst_case_fee()), (2, 100 * worst_case_fee())],
			..Default::default()
		},
		..Default::default()
	}
	.build_storage()
	.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
