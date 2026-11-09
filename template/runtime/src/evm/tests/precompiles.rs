//! The EVM precompile set: its address list matches what it executes, the Ethereum
//! precompiles return the consensus-test outputs through the EVM, the BN128 and
//! modexp precompiles charge their measured cost, and the fork's precompiles the
//! runtime lacks fail.

use crate::{
	configs::evm::{BlockGasLimit, WeightPerGas},
	evm::precompiles::{
		is_unavailable, FrontierPrecompiles, ADD_GAS, MODEXP_GAS_FACTOR, MUL_GAS, PAIRING_BASE_GAS,
		PAIRING_PER_PAIR_GAS, UNAVAILABLE,
	},
	test_utils::with_ext,
	Runtime,
};
use fp_evm::{
	Context, ExitError, ExitReason, ExitSucceed, PrecompileFailure, PrecompileHandle,
	PrecompileResult, Transfer,
};
use pallet_evm::{IsPrecompileResult, Precompile, PrecompileSet, Runner};
use pallet_evm_precompile_bn128::{Bn128Add, Bn128Mul, Bn128Pairing};
use pallet_evm_precompile_modexp::Modexp;
use sp_core::{H160, H256, U256};

/// A handle that refuses every cost, so each precompile stops at its first
/// charge: enough to see whether the set routes an address at all.
struct Probe {
	address: H160,
	context: Context,
}

impl Probe {
	fn new(address: H160) -> Self {
		Self {
			address,
			context: Context {
				address,
				caller: H160::repeat_byte(0x11),
				apparent_value: U256::zero(),
			},
		}
	}
}

impl PrecompileHandle for Probe {
	fn call(
		&mut self,
		_: H160,
		_: Option<Transfer>,
		_: Vec<u8>,
		_: Option<u64>,
		_: bool,
		_: &Context,
	) -> (ExitReason, Vec<u8>) {
		(ExitReason::Error(ExitError::OutOfGas), Vec::new())
	}
	fn record_cost(&mut self, _: u64) -> Result<(), ExitError> {
		Err(ExitError::OutOfGas)
	}
	fn record_external_cost(
		&mut self,
		_: Option<u64>,
		_: Option<u64>,
		_: Option<u64>,
	) -> Result<(), ExitError> {
		Err(ExitError::OutOfGas)
	}
	fn refund_external_cost(&mut self, _: Option<u64>, _: Option<u64>) {}
	fn remaining_gas(&self) -> u64 {
		0
	}
	fn log(&mut self, _: H160, _: Vec<H256>, _: Vec<u8>) -> Result<(), ExitError> {
		Err(ExitError::OutOfGas)
	}
	fn code_address(&self) -> H160 {
		self.address
	}
	fn input(&self) -> &[u8] {
		&[]
	}
	fn context(&self) -> &Context {
		&self.context
	}
	fn origin(&self) -> H160 {
		self.context.caller
	}
	fn is_static(&self) -> bool {
		false
	}
	fn gas_limit(&self) -> Option<u64> {
		Some(0)
	}
	fn is_contract_being_constructed(&self, _: H160) -> bool {
		false
	}
}

#[test]
fn the_address_list_matches_what_the_set_executes() {
	with_ext(|| {
		let set = FrontierPrecompiles::<Runtime>::new();
		let used = FrontierPrecompiles::<Runtime>::used_addresses();
		for n in 0..=4096u64 {
			let address = H160::from_low_u64_be(n);
			let listed = used.contains(&address) || is_unavailable(address);
			assert_eq!(
				set.execute(&mut Probe::new(address)).is_some(),
				listed,
				"{n}"
			);
			let IsPrecompileResult::Answer { is_precompile, .. } = set.is_precompile(address, 0)
			else {
				panic!("{n}: no answer");
			};
			assert_eq!(is_precompile, listed, "{n}");
		}
		assert!(used.iter().all(|a| a.to_low_u64_be() <= 4096));
	});
}

#[test]
fn every_ethereum_precompile_through_blake2f_is_present() {
	let used = FrontierPrecompiles::<Runtime>::used_addresses();
	for n in 1..=9u64 {
		assert!(used.contains(&H160::from_low_u64_be(n)), "{n}");
	}
}

fn from_hex(text: &str) -> Vec<u8> {
	(0..text.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
		.collect()
}

/// Calls `address` through the EVM with each vector's `Input` and checks its
/// output is `Expected`.
fn check_vectors(address: u64, json: &str) {
	let vectors: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
	assert!(!vectors.is_empty());
	with_ext(|| {
		for v in vectors {
			let name = v["Name"].as_str().unwrap();
			let info = <Runtime as pallet_evm::Config>::Runner::call(
				H160::repeat_byte(0x11),
				H160::from_low_u64_be(address),
				from_hex(v["Input"].as_str().unwrap()),
				U256::zero(),
				10_000_000,
				None,
				None,
				None,
				Vec::new(),
				Vec::new(),
				false,
				false,
				None,
				None,
				<Runtime as pallet_evm::Config>::config(),
			)
			.unwrap_or_else(|e| panic!("{name}: {:?}", e.error));
			assert_eq!(
				info.exit_reason,
				ExitReason::Succeed(ExitSucceed::Returned),
				"{name}"
			);
			assert_eq!(
				info.value,
				from_hex(v["Expected"].as_str().unwrap()),
				"{name}"
			);
		}
	});
}

macro_rules! vectors {
	($file:literal) => {
		include_str!(concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/../../frame/evm/precompile/testdata/",
			$file
		))
	};
}

#[test]
fn bn128_add_returns_the_consensus_vectors() {
	check_vectors(6, vectors!("common_bnadd.json"));
}

#[test]
fn bn128_mul_returns_the_consensus_vectors() {
	check_vectors(7, vectors!("common_bnmul.json"));
}

#[test]
fn bn128_pairing_returns_the_consensus_vectors() {
	check_vectors(8, vectors!("common_bnpair.json"));
}

#[test]
fn blake2f_returns_the_eip152_vectors() {
	check_vectors(9, vectors!("blake2F.json"));
}

/// A handle that adds up every cost recorded. A cost past its gas limit fails
/// out of gas and takes all of it, as the EVM's gasometer does.
struct Meter {
	address: H160,
	input: Vec<u8>,
	used: u64,
	limit: u64,
	context: Context,
}

const METER_GAS_LIMIT: u64 = 100_000_000;

impl Meter {
	fn new(address: H160, input: Vec<u8>) -> Self {
		Self::with_limit(address, input, METER_GAS_LIMIT)
	}

	fn with_limit(address: H160, input: Vec<u8>, limit: u64) -> Self {
		Self {
			address,
			input,
			used: 0,
			limit,
			context: Context {
				address,
				caller: H160::repeat_byte(0x11),
				apparent_value: U256::zero(),
			},
		}
	}
}

impl PrecompileHandle for Meter {
	fn call(
		&mut self,
		_: H160,
		_: Option<Transfer>,
		_: Vec<u8>,
		_: Option<u64>,
		_: bool,
		_: &Context,
	) -> (ExitReason, Vec<u8>) {
		unreachable!("the pairing makes no calls")
	}
	fn record_cost(&mut self, cost: u64) -> Result<(), ExitError> {
		match self.used.checked_add(cost) {
			Some(used) if used <= self.limit => {
				self.used = used;
				Ok(())
			}
			_ => {
				self.used = self.limit;
				Err(ExitError::OutOfGas)
			}
		}
	}
	fn record_external_cost(
		&mut self,
		_: Option<u64>,
		_: Option<u64>,
		_: Option<u64>,
	) -> Result<(), ExitError> {
		Ok(())
	}
	fn refund_external_cost(&mut self, _: Option<u64>, _: Option<u64>) {}
	fn remaining_gas(&self) -> u64 {
		self.limit - self.used
	}
	fn log(&mut self, _: H160, _: Vec<H256>, _: Vec<u8>) -> Result<(), ExitError> {
		Ok(())
	}
	fn code_address(&self) -> H160 {
		self.address
	}
	fn input(&self) -> &[u8] {
		&self.input
	}
	fn context(&self) -> &Context {
		&self.context
	}
	fn origin(&self) -> H160 {
		self.context.caller
	}
	fn is_static(&self) -> bool {
		true
	}
	fn gas_limit(&self) -> Option<u64> {
		Some(self.limit)
	}
	fn is_contract_being_constructed(&self, _: H160) -> bool {
		false
	}
}

/// EIP-197's generators, encoded as the pairing reads them: G1 as (x, y); G2 as
/// (x imaginary, x real, y imaginary, y real).
const G1: &str = "0000000000000000000000000000000000000000000000000000000000000001\
	0000000000000000000000000000000000000000000000000000000000000002";
/// -G1: (1, p - 2).
const NEG_G1: &str = "0000000000000000000000000000000000000000000000000000000000000001\
	30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
const G2: &str = "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
	1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
	090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
	12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

fn pair(g1: &str) -> Vec<u8> {
	from_hex(&format!("{g1}{G2}"))
}

/// Runs `input` through the set's `0x08` and through upstream's pairing: their
/// results and the gas each recorded.
fn pairing_both_ways(input: Vec<u8>) -> ((PrecompileResult, u64), (PrecompileResult, u64)) {
	let address = H160::from_low_u64_be(8);
	let mut ours = Meter::new(address, input.clone());
	let result = FrontierPrecompiles::<Runtime>::new()
		.execute(&mut ours)
		.expect("0x08 is a precompile");
	let mut upstream = Meter::new(address, input);
	let upstream_result = Bn128Pairing::execute(&mut upstream);
	((result, ours.used), (upstream_result, upstream.used))
}

fn word(value: u64) -> Vec<u8> {
	U256::from(value).to_big_endian().to_vec()
}

#[test]
fn pairing_charges_the_measured_cost() {
	with_ext(|| {
		// e(G1, G2) * e(-G1, G2) = 1, the generator check.
		let check = [pair(G1), pair(NEG_G1)].concat();
		let cases: [(Vec<u8>, u64, u64); 4] = [
			(Vec::new(), 0, 1),
			(pair(G1), 1, 0),
			(check.clone(), 2, 1),
			(check.repeat(4), 8, 1),
		];
		for (input, pairs, expected) in cases {
			let ((ours, gas), (upstream, upstream_gas)) = pairing_both_ways(input);
			assert_eq!(
				gas,
				PAIRING_BASE_GAS + PAIRING_PER_PAIR_GAS * pairs,
				"{pairs}"
			);
			assert_eq!(upstream_gas, 45_000 + 34_000 * pairs, "{pairs}");
			let output = ours.expect("valid input").output;
			assert_eq!(output, word(expected), "{pairs}");
			assert_eq!(output, upstream.expect("valid input").output, "{pairs}");
		}

		// Errors are upstream's: a bad size, and a point off the curve.
		let mut off_curve = pair(G1);
		off_curve[63] = 3;
		for input in [vec![0u8; 191], off_curve] {
			let ((ours, _), (upstream, _)) = pairing_both_ways(input);
			assert_eq!(ours.unwrap_err(), upstream.unwrap_err());
		}
	});
}

/// Measured on the dev network (wasm runtime, `eth_call`), in picoseconds.
const MEASURED_PAIRING_BASE_PS: u64 = 2_400_000_000;
const MEASURED_PAIRING_PER_PAIR_PS: u64 = 2_300_000_000;

fn measured_pairing_ps(pairs: u64) -> u64 {
	MEASURED_PAIRING_BASE_PS + MEASURED_PAIRING_PER_PAIR_PS * pairs
}

#[test]
fn pairing_gas_covers_block_budget() {
	let ps_per_gas = WeightPerGas::get().ref_time();
	assert_eq!(ps_per_gas, 20_000);
	let block_gas = BlockGasLimit::get().as_u64();

	// Every pairing a block can hold is priced at 1.5x its measured time or more.
	for pairs in 0..=block_gas / PAIRING_PER_PAIR_GAS {
		let priced = (PAIRING_BASE_GAS + PAIRING_PER_PAIR_GAS * pairs) * ps_per_gas;
		assert!(priced * 2 >= measured_pairing_ps(pairs) * 3, "{pairs}");
	}

	// A block of one pairing call as large as its gas allows computes within the
	// block's EVM budget.
	let pairs = (block_gas - PAIRING_BASE_GAS) / PAIRING_PER_PAIR_GAS;
	assert!(measured_pairing_ps(pairs) <= block_gas * ps_per_gas);
}

/// Runs `address` in the set and upstream's `P` on the same input: each result
/// with the gas it charged.
fn both_ways<P: Precompile>(
	address: u64,
	input: Vec<u8>,
) -> ((PrecompileResult, u64), (PrecompileResult, u64)) {
	let address = H160::from_low_u64_be(address);
	let mut ours = Meter::new(address, input.clone());
	let result = FrontierPrecompiles::<Runtime>::new()
		.execute(&mut ours)
		.expect("a precompile");
	let mut upstream = Meter::new(address, input);
	let upstream_result = P::execute(&mut upstream);
	((result, ours.used), (upstream_result, upstream.used))
}

fn modexp_input(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
	let len = |b: &[u8]| U256::from(b.len()).to_big_endian().to_vec();
	[
		len(base),
		len(exponent),
		len(modulus),
		base.to_vec(),
		exponent.to_vec(),
		modulus.to_vec(),
	]
	.concat()
}

/// BN128 addition and multiplication charge their measured prices; outputs and
/// errors stay upstream's.
#[test]
fn bn128_add_and_mul_charge_the_measured_cost() {
	with_ext(|| {
		let g1 = from_hex(G1);
		let ((ours, gas), (upstream, upstream_gas)) =
			both_ways::<Bn128Add>(6, [g1.clone(), g1.clone()].concat());
		assert_eq!((gas, upstream_gas), (ADD_GAS, 150));
		assert_eq!(ours.unwrap().output, upstream.unwrap().output);

		let scalar = [0xffu8; 32].to_vec();
		let ((ours, gas), (upstream, upstream_gas)) =
			both_ways::<Bn128Mul>(7, [g1, scalar].concat());
		assert_eq!((gas, upstream_gas), (MUL_GAS, 6_000));
		assert_eq!(ours.unwrap().output, upstream.unwrap().output);

		let mut off_curve = from_hex(G1);
		off_curve[63] = 3;
		let ((ours, _), (upstream, _)) =
			both_ways::<Bn128Add>(6, [off_curve.clone(), off_curve].concat());
		assert_eq!(ours.unwrap_err(), upstream.unwrap_err());
	});
}

/// Modexp charges `MODEXP_GAS_FACTOR` times EIP-7883's price, with upstream's
/// output; an input past EIP-7823's limit still takes all the gas, out of gas.
#[test]
fn modexp_charges_a_multiple_of_its_price() {
	with_ext(|| {
		let cases = [
			modexp_input(&[3], &[5], &[7]),
			modexp_input(&[0xff; 48], &[0xff], &[0xff; 48]),
			modexp_input(&[0xff; 64], &[0xff; 64], &[0xff; 64]),
		];
		for input in cases {
			let ((ours, gas), (upstream, upstream_gas)) = both_ways::<Modexp>(5, input);
			assert_eq!(gas, upstream_gas * MODEXP_GAS_FACTOR);
			assert_eq!(ours.unwrap().output, upstream.unwrap().output);
		}
		let too_long = modexp_input(&[1; 1025], &[1], &[7]);
		let ((ours, gas), (upstream, upstream_gas)) = both_ways::<Modexp>(5, too_long);
		assert_eq!((gas, upstream_gas), (METER_GAS_LIMIT, METER_GAS_LIMIT));
		assert!(upstream.is_err());
		assert!(matches!(
			ours.unwrap_err(),
			PrecompileFailure::Error {
				exit_status: ExitError::OutOfGas
			}
		));
	});
}

/// Gas for exactly EIP-7883's price is not enough: the factor applies however
/// much gas the caller forwards.
#[test]
fn modexp_with_exactly_its_upstream_price_runs_out_of_gas() {
	with_ext(|| {
		let input = modexp_input(&[0xff; 48], &[0xff], &[0xff; 48]);
		let (_, (_, price)) = both_ways::<Modexp>(5, input.clone());
		let run = |limit| {
			let mut meter = Meter::with_limit(H160::from_low_u64_be(5), input.clone(), limit);
			let result = FrontierPrecompiles::<Runtime>::new()
				.execute(&mut meter)
				.expect("a precompile");
			(result, meter.used)
		};
		let (result, used) = run(price);
		assert!(matches!(
			result,
			Err(PrecompileFailure::Error {
				exit_status: ExitError::OutOfGas
			})
		));
		assert_eq!(used, price);
		let (result, used) = run(price * MODEXP_GAS_FACTOR);
		assert!(result.is_ok());
		assert_eq!(used, price * MODEXP_GAS_FACTOR);
	});
}

/// Measured on the dev network (wasm runtime, `eth_call`, net of the calling
/// loop), in picoseconds: an addition, a multiplication by a 256-bit scalar, and
/// modexp's worst case per gas (48-byte base and modulus, one-byte exponent, 504
/// gas at EIP-7883).
const MEASURED_ADD_PS: u64 = 5_000_000;
const MEASURED_MUL_PS: u64 = 365_000_000;
const MEASURED_MODEXP_WORST_PS: u64 = 24_000_000;
const MODEXP_WORST_EIP7883_GAS: u64 = 504;

/// Every repriced precompile charges at least 1.5× its measured time.
#[test]
fn repriced_precompiles_cover_their_measured_time() {
	let ps_per_gas = WeightPerGas::get().ref_time();
	let covers = |gas: u64, measured: u64| gas * ps_per_gas * 2 >= measured * 3;
	assert!(covers(ADD_GAS, MEASURED_ADD_PS));
	assert!(covers(MUL_GAS, MEASURED_MUL_PS));
	assert!(covers(
		MODEXP_WORST_EIP7883_GAS * MODEXP_GAS_FACTOR,
		MEASURED_MODEXP_WORST_PS
	));
}

/// A call to a precompile address of the EVM's fork that the runtime does not
/// provide fails, instead of succeeding on an empty account.
#[test]
fn unavailable_precompiles_fail() {
	with_ext(|| {
		for n in UNAVAILABLE {
			let info = <Runtime as pallet_evm::Config>::Runner::call(
				H160::repeat_byte(0x11),
				H160::from_low_u64_be(n),
				vec![0u8; 192],
				U256::zero(),
				1_000_000,
				None,
				None,
				None,
				Vec::new(),
				Vec::new(),
				false,
				false,
				None,
				None,
				<Runtime as pallet_evm::Config>::config(),
			)
			.unwrap_or_else(|e| panic!("{n}: {:?}", e.error));
			assert!(
				matches!(info.exit_reason, ExitReason::Error(_)),
				"{n}: {:?}",
				info.exit_reason
			);
		}
	});
}
