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
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

parameter_types! {
	/// Mirrors the testnet build: Hyperbridge as a Kusama-anchored parachain.
	pub const Coprocessor: Option<StateMachine> = Some(StateMachine::Kusama(4009));
	pub const HostStateMachine: StateMachine = StateMachine::Substrate(*b"orbi");
	pub const TreasuryPalletId: PalletId = PalletId(*b"orb/ismp");
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
	type MigrationWeightInfo = ();
}

impl pallet_ismp_messaging::Config for Test {
	type DispatchOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxBodyLen = ConstU32<8192>;
	type WeightInfo = ();
}

/// Test externalities with block number 1, so events are collected.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
