//! The EVM's precompiles: Ethereum's (0x01–0x09), Frontier's extras (0x400–0x403) and
//! Orbinum's (0x801–0x802).

use core::marker::PhantomData;
use pallet_evm::{
	ExitError, IsPrecompileResult, Precompile, PrecompileFailure, PrecompileHandle,
	PrecompileResult, PrecompileSet,
};
use sp_core::H160;

use pallet_evm_precompile_balances::BalancesPrecompile;
use pallet_evm_precompile_blake2::Blake2F;
use pallet_evm_precompile_bn128::{Bn128Add, Bn128Mul, Bn128Pairing};
use pallet_evm_precompile_curve25519 as curve25519_precompile;
use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_shielded_pool::ShieldedPoolPrecompile;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};

/// Code stored at each non-Ethereum precompile address: `PUSH1 0 PUSH1 0 REVERT`.
///
/// Never executed, since the precompile runs instead. It gives the address a
/// non-zero code size, which Solidity checks before a high-level call to a
/// function that returns nothing; with no code such a call reverts before it
/// reaches the precompile.
pub const PRECOMPILE_CODE: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];

/// BN128 pairing (`0x08`) base cost, in gas. EIP-1108's 45 000 + 34 000 per pair
/// charges about a third of what a pairing takes here. Measured on the dev network
/// (wasm runtime, `eth_call`): ~2.4 ms + ~2.3 ms per pair; these prices are that
/// with a 1.5× margin, ~3.6 ms + ~3.5 ms per pair at 20 000 ps per gas. To be
/// replaced by the reference-hardware benchmark.
pub const PAIRING_BASE_GAS: u64 = 180_000;
/// BN128 pairing cost per pair, in gas. See [`PAIRING_BASE_GAS`].
pub const PAIRING_PER_PAIR_GAS: u64 = 175_000;

/// Size of one pairing input: a G1 and a G2 point.
const PAIRING_PAIR_BYTES: usize = 192;
/// What upstream's [`Bn128Pairing`] charges (EIP-1108).
const EIP1108_PAIRING_BASE_GAS: u64 = 45_000;
const EIP1108_PAIRING_PER_PAIR_GAS: u64 = 34_000;

/// Upstream's [`Bn128Pairing`] at [`PAIRING_BASE_GAS`] + [`PAIRING_PER_PAIR_GAS`] per
/// pair: it records the difference, then upstream records its own EIP-1108 cost and
/// computes. Outputs and errors are upstream's.
pub struct MeteredBn128Pairing;

impl Precompile for MeteredBn128Pairing {
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		let len = handle.input().len();
		if !len.is_multiple_of(PAIRING_PAIR_BYTES) {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("bad elliptic curve pairing size".into()),
			});
		}
		let pairs = (len / PAIRING_PAIR_BYTES) as u64;
		let extra = (PAIRING_BASE_GAS - EIP1108_PAIRING_BASE_GAS).saturating_add(
			pairs.saturating_mul(PAIRING_PER_PAIR_GAS - EIP1108_PAIRING_PER_PAIR_GAS),
		);
		handle.record_cost(extra)?;
		Bn128Pairing::execute(handle)
	}
}

/// BN128 addition (`0x06`), in gas. EIP-1108's 150 charges about a third of what
/// an addition takes here: ~5 µs measured on the dev network (wasm runtime,
/// `eth_call`). This is that with a 1.5× margin or more.
pub const ADD_GAS: u64 = 600;
/// BN128 scalar multiplication (`0x07`), in gas: ~365 µs measured against
/// EIP-1108's 6 000 (120 µs). See [`ADD_GAS`].
pub const MUL_GAS: u64 = 30_000;
const EIP1108_ADD_GAS: u64 = 150;
const EIP1108_MUL_GAS: u64 = 6_000;

/// Modexp (`0x05`) charges EIP-7883's price this many times: its cheapest inputs
/// (the 500-gas floor, small exponents) take up to ~2.4× what that price covers.
pub const MODEXP_GAS_FACTOR: u64 = 4;

/// Precompile addresses of the EVM's fork (Prague) this runtime does not provide:
/// KZG point evaluation (`0x0a`) and BLS12-381 (`0x0b`–`0x11`). A call to them
/// fails; otherwise it would reach an empty account and succeed with no output,
/// which a caller checking only the call's success reads as a valid proof.
pub const UNAVAILABLE: core::ops::RangeInclusive<u64> = 0x0a..=0x11;

/// Upstream precompile `P` at `GAS`: records the difference from upstream's own
/// fixed `UPSTREAM` cost, then runs it. Outputs and errors are upstream's.
pub struct Repriced<P, const GAS: u64, const UPSTREAM: u64>(PhantomData<P>);

impl<P: Precompile, const GAS: u64, const UPSTREAM: u64> Precompile for Repriced<P, GAS, UPSTREAM> {
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		handle.record_cost(GAS - UPSTREAM)?;
		P::execute(handle)
	}
}

/// A handle that charges `factor` times every cost recorded through it. A cost the
/// gas left cannot cover fails out of gas, which takes all of it, so upstream's
/// way of failing (recording all the gas left) still takes all of it.
struct Scaled<'a, H> {
	inner: &'a mut H,
	factor: u64,
}

impl<H: PrecompileHandle> PrecompileHandle for Scaled<'_, H> {
	fn call(
		&mut self,
		to: H160,
		transfer: Option<fp_evm::Transfer>,
		input: alloc::vec::Vec<u8>,
		gas_limit: Option<u64>,
		is_static: bool,
		context: &fp_evm::Context,
	) -> (fp_evm::ExitReason, alloc::vec::Vec<u8>) {
		self.inner
			.call(to, transfer, input, gas_limit, is_static, context)
	}
	fn record_cost(&mut self, cost: u64) -> Result<(), ExitError> {
		self.inner.record_cost(cost.saturating_mul(self.factor))
	}
	fn record_external_cost(
		&mut self,
		ref_time: Option<u64>,
		proof_size: Option<u64>,
		storage_growth: Option<u64>,
	) -> Result<(), ExitError> {
		self.inner
			.record_external_cost(ref_time, proof_size, storage_growth)
	}
	fn refund_external_cost(&mut self, ref_time: Option<u64>, proof_size: Option<u64>) {
		self.inner.refund_external_cost(ref_time, proof_size)
	}
	fn remaining_gas(&self) -> u64 {
		self.inner.remaining_gas()
	}
	fn log(
		&mut self,
		address: H160,
		topics: alloc::vec::Vec<sp_core::H256>,
		data: alloc::vec::Vec<u8>,
	) -> Result<(), ExitError> {
		self.inner.log(address, topics, data)
	}
	fn code_address(&self) -> H160 {
		self.inner.code_address()
	}
	fn input(&self) -> &[u8] {
		self.inner.input()
	}
	fn context(&self) -> &fp_evm::Context {
		self.inner.context()
	}
	fn origin(&self) -> H160 {
		self.inner.origin()
	}
	fn is_static(&self) -> bool {
		self.inner.is_static()
	}
	fn gas_limit(&self) -> Option<u64> {
		self.inner.gas_limit()
	}
	fn is_contract_being_constructed(&self, address: H160) -> bool {
		self.inner.is_contract_being_constructed(address)
	}
}

/// Upstream's [`Modexp`] at [`MODEXP_GAS_FACTOR`] times its price.
pub struct MeteredModexp;

impl Precompile for MeteredModexp {
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		Modexp::execute(&mut Scaled {
			inner: handle,
			factor: MODEXP_GAS_FACTOR,
		})
	}
}

/// Every precompile, by address.
pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 15] {
		[
			hash(1),
			hash(2),
			hash(3),
			hash(4),
			hash(5),
			hash(6),
			hash(7),
			hash(8),
			hash(9),
			hash(1024),
			hash(1025),
			hash(1026),
			hash(1027),
			hash(2049),
			hash(2050),
		]
	}

	/// The precompiles that carry [`PRECOMPILE_CODE`]: all but Ethereum's, which keep no
	/// code as on Ethereum.
	pub fn addresses_with_code() -> impl Iterator<Item = H160> {
		Self::used_addresses()
			.into_iter()
			.filter(|address| address.to_low_u64_be() >= 1024)
	}
}
impl<R> PrecompileSet for FrontierPrecompiles<R>
where
	R: pallet_evm::Config
		+ frame_system::Config
		+ pallet_shielded_pool::Config
		+ pallet_balances::Config,
	<R as frame_system::Config>::RuntimeCall: sp_runtime::traits::Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ frame_support::dispatch::GetDispatchInfo
		+ From<pallet_shielded_pool::Call<R>>
		+ From<pallet_balances::Call<R>>,
	<<R as frame_system::Config>::RuntimeCall as sp_runtime::traits::Dispatchable>::RuntimeOrigin:
		From<Option<<R as frame_system::Config>::AccountId>>,
	<<R as frame_system::Config>::RuntimeCall as sp_runtime::traits::Dispatchable>::PostInfo:
		core::fmt::Debug,
	<R as frame_system::Config>::AccountId: From<[u8; 32]>,
	pallet_evm::AccountIdOf<R>: Into<<R as frame_system::Config>::AccountId>,
	pallet_shielded_pool::BalanceOf<R>: TryFrom<u128>,
	<R as pallet_balances::Config>::Balance: TryFrom<u128>,
{
	fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
		match handle.code_address() {
			// Ethereum.
			a if a == hash(1) => Some(ECRecover::execute(handle)),
			a if a == hash(2) => Some(Sha256::execute(handle)),
			a if a == hash(3) => Some(Ripemd160::execute(handle)),
			a if a == hash(4) => Some(Identity::execute(handle)),
			a if a == hash(5) => Some(MeteredModexp::execute(handle)),
			a if a == hash(6) => Some(Repriced::<Bn128Add, ADD_GAS, EIP1108_ADD_GAS>::execute(
				handle,
			)),
			a if a == hash(7) => Some(Repriced::<Bn128Mul, MUL_GAS, EIP1108_MUL_GAS>::execute(
				handle,
			)),
			a if a == hash(8) => Some(MeteredBn128Pairing::execute(handle)),
			a if a == hash(9) => Some(Blake2F::execute(handle)),
			// Frontier extras.
			a if a == hash(1024) => Some(Sha3FIPS256::<
				R,
				crate::weights::pallet_evm_precompile_sha3fips::WeightInfo<R>,
			>::execute(handle)),
			a if a == hash(1025) => Some(ECRecoverPublicKey::execute(handle)),
			a if a == hash(1026) => Some(curve25519_precompile::Curve25519Add::<
				R,
				crate::weights::pallet_evm_precompile_curve25519::WeightInfo<R>,
			>::execute(handle)),
			a if a == hash(1027) => Some(curve25519_precompile::Curve25519ScalarMul::<
				R,
				crate::weights::pallet_evm_precompile_curve25519::WeightInfo<R>,
			>::execute(handle)),
			// Orbinum.
			a if a == hash(2049) => Some(ShieldedPoolPrecompile::<R>::execute(handle)),
			a if a == hash(2050) => Some(BalancesPrecompile::<R>::execute(handle)),
			a if is_unavailable(a) => Some(Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("precompile not available".into()),
			})),
			_ => None,
		}
	}

	fn is_precompile(&self, address: H160, _gas: u64) -> IsPrecompileResult {
		IsPrecompileResult::Answer {
			is_precompile: Self::used_addresses().contains(&address) || is_unavailable(address),
			extra_cost: 0,
		}
	}
}

fn hash(a: u64) -> H160 {
	H160::from_low_u64_be(a)
}

/// Whether `address` is one of the [`UNAVAILABLE`] precompiles.
pub fn is_unavailable(address: H160) -> bool {
	UNAVAILABLE.clone().any(|n| address == hash(n))
}
