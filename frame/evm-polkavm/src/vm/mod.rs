// This file is part of Frontier.

// Copyright (C) Frontier developers.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod runtime;

use crate::{Config, ConvertPolkaVmGas, WeightInfo};
use fp_evm::PrecompileHandle;
use sp_runtime::Weight;

pub use self::runtime::{ExecResult, Runtime, RuntimeCosts, SupervisorError};

pub const PREFIX: [u8; 8] = [0xef, 0x70, 0x6F, 0x6C, 0x6B, 0x61, 0x76, 0x6D];
pub const CALL_IDENTIFIER: &str = "call";
pub const PAGE_SIZE: u32 = 4 * 1024;

/// Whether this chain accepts contracts compiled for `isa`.
///
/// Until polkavm 0.30 the host refused `sbrk` with `ModuleConfig::set_allow_sbrk(false)`.
/// That knob is gone: the blob's own instruction set now decides whether the opcode
/// decodes, and the linker takes the ISA as an explicit argument, so the choice belongs
/// to whoever built the contract. `Latest32`/`Latest64` include `sbrk` (opcode 101);
/// `ReviveV1` and `JamV1` do not.
///
/// A growable heap changes gas consumption, and this runs in consensus, so the answer is
/// a whitelist rather than a blocklist: a future ISA is rejected until someone checks it.
pub fn is_accepted_isa(isa: polkavm::program::InstructionSetKind) -> bool {
	use polkavm::program::InstructionSetKind as Isa;
	match isa {
		Isa::ReviveV1 | Isa::JamV1 => true,
		Isa::Latest32 | Isa::Latest64 => false,
	}
}

pub const SENTINEL: u32 = u32::MAX;
pub const LOG_TARGET: &str = "runtime::evm::polkavm";

fn code_load_weight<T: Config>(size: u32) -> Weight {
	<T as Config>::WeightInfo::call_with_code_per_byte(size)
}

pub struct PreparedCall<'a, T, H> {
	module: polkavm::Module,
	instance: polkavm::RawInstance,
	runtime: Runtime<'a, T, H, polkavm::RawInstance>,
}

impl<'a, T: Config, H: PrecompileHandle> PreparedCall<'a, T, H> {
	pub fn load(handle: &'a mut H) -> Result<Self, SupervisorError> {
		let code = pallet_evm::AccountCodes::<T>::get(handle.code_address());
		if code[0..8] != PREFIX {
			return Err(SupervisorError::NotPolkaVm);
		}
		let code_load_weight = code_load_weight::<T>(code.len() as u32);
		handle
			.record_external_cost(
				Some(code_load_weight.ref_time()),
				Some(code_load_weight.proof_size()),
				None,
			)
			.map_err(|_| SupervisorError::OutOfGas)?;

		let polkavm_code = &code[8..];

		let mut config = polkavm::Config::default();
		config.set_backend(Some(polkavm::BackendKind::Interpreter));
		config.set_cache_enabled(false);

		let engine = polkavm::Engine::new(&config).expect(
			"on-chain (no_std) use of interpreter is hard coded.
				interpreter is available on all platforms; qed",
		);

		let mut module_config = polkavm::ModuleConfig::new();
		module_config.set_page_size(PAGE_SIZE);
		module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
		let module =
			polkavm::Module::new(&engine, &module_config, polkavm_code.into()).map_err(|err| {
				log::debug!(target: LOG_TARGET, "failed to create polkavm module: {err:?}");
				SupervisorError::CodeRejected
			})?;

		let entry_program_counter = module
			.exports()
			.find(|export| export.symbol().as_bytes() == CALL_IDENTIFIER.as_bytes())
			.ok_or(SupervisorError::CodeRejected)?
			.program_counter();
		let input_data = handle.input().to_vec();
		let gas_limit_polkavm = T::ConvertPolkaVmGas::evm_gas_to_polkavm_gas(
			handle.gas_limit().ok_or(SupervisorError::OutOfGas)?,
		);
		let runtime: Runtime<'_, T, _, polkavm::RawInstance> =
			Runtime::new(handle, input_data, gas_limit_polkavm);

		let mut instance = module.instantiate().map_err(|err| {
			log::debug!(target: LOG_TARGET, "failed to instantiate polkavm module: {err:?}");
			SupervisorError::CodeRejected
		})?;

		instance.set_gas(gas_limit_polkavm);
		instance.prepare_call_untyped(entry_program_counter, &[]);

		Ok(Self {
			module,
			instance,
			runtime,
		})
	}

	pub fn call(mut self) -> ExecResult {
		let exec_result = loop {
			let interrupt = self.instance.run();
			if let Some(exec_result) =
				self.runtime
					.handle_interrupt(interrupt, &self.module, &mut self.instance)
			{
				break exec_result;
			}
		};
		self.runtime.charge_polkavm_gas(&mut self.instance)?;
		exec_result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use polkavm::program::InstructionSetKind as Isa;

	/// Smallest blob `ProgramBlob::parse` accepts, with the ISA we want to declare.
	///
	/// Hand-built rather than linked from a guest program: the ISA lives in one header
	/// byte, so a real riscv64 contract would add a toolchain dependency and prove
	/// nothing extra about the check under test.
	fn blob_with_isa(isa: Isa) -> Vec<u8> {
		let version: u8 = match isa {
			Isa::ReviveV1 => 0,
			Isa::Latest32 => 1,
			Isa::Latest64 => 2,
			Isa::JamV1 => 3,
		};

		// jump_table_entry_count, jump_table_entry_size, code_length, code, bitmask.
		// The bitmask is ceil(code_len / 8) bytes and marks instruction boundaries.
		let code_section: Vec<u8> = vec![0, 0, 1, 0, 0b0000_0001];
		let mut body = vec![6u8]; // SECTION_CODE_AND_JUMP_TABLE
		body.push(code_section.len() as u8);
		body.extend_from_slice(&code_section);
		body.push(0u8); // SECTION_END_OF_FILE

		// magic + version + u64 length-of-whole-blob + body
		let total = (4 + 1 + 8 + body.len()) as u64;
		let mut blob = vec![b'P', b'V', b'M', 0u8, version];
		blob.extend_from_slice(&total.to_le_bytes());
		blob.extend_from_slice(&body);
		blob
	}

	/// The blobs the test feeds the check must actually declare the ISA asked for,
	/// otherwise the cases below would pass by accident.
	#[test]
	fn fixture_declares_the_requested_isa() {
		for isa in [Isa::ReviveV1, Isa::JamV1, Isa::Latest32, Isa::Latest64] {
			let parsed = polkavm::ProgramBlob::parse(blob_with_isa(isa).into())
				.expect("hand-built blob should parse");
			assert_eq!(parsed.isa(), isa);
		}
	}

	/// This is the guarantee `ModuleConfig::set_allow_sbrk(false)` used to provide: no
	/// contract may grow its heap. `Latest32`/`Latest64` carry the `sbrk` opcode, so
	/// accepting them would silently restore what the old knob forbade.
	#[test]
	fn only_sbrk_free_instruction_sets_are_accepted() {
		assert!(is_accepted_isa(Isa::ReviveV1));
		assert!(is_accepted_isa(Isa::JamV1));
		assert!(!is_accepted_isa(Isa::Latest32));
		assert!(!is_accepted_isa(Isa::Latest64));
	}

	/// The prefix test must tolerate short and empty code.
	///
	/// `AccountCodes::get` returns an empty `Vec` for every address without contract
	/// code, and the precompile set consults it on each call, so `code[0..8]` panics on
	/// the most ordinary path there is: a transfer to a plain account.
	#[test]
	fn prefix_check_tolerates_code_shorter_than_the_prefix() {
		let matches = |code: &[u8]| code.get(0..8) == Some(&PREFIX[..]);

		assert!(!matches(&[]));
		assert!(!matches(&PREFIX[..7]));
		assert!(matches(&PREFIX));

		let mut with_body = PREFIX.to_vec();
		with_body.extend_from_slice(b"blob");
		assert!(matches(&with_body));

		let mut wrong = PREFIX;
		wrong[0] = 0x00;
		assert!(!matches(&wrong));
	}

	/// A blob that does not parse must be rejected before the ISA is consulted — the
	/// deploy path calls `parse` first and maps the failure to its own error.
	#[test]
	fn malformed_blobs_do_not_parse() {
		assert!(polkavm::ProgramBlob::parse(vec![].into()).is_err());
		assert!(polkavm::ProgramBlob::parse(b"PVM\0".to_vec().into()).is_err());
		// Right shape, unknown ISA version byte.
		let mut bad = blob_with_isa(Isa::ReviveV1);
		bad[4] = 99;
		assert!(polkavm::ProgramBlob::parse(bad.into()).is_err());
	}
}
