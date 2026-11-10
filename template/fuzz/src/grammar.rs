// Copyright 2025 Security Research Labs GmbH
//
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

//! The input the fuzzer generates: one EVM transaction.

use arbitrary::{Arbitrary, Unstructured};

#[derive(Clone, Debug, Arbitrary)]
pub struct FuzzData {
	pub action: Action,
	pub value: u64,
	/// Halves the proof-size limit, so the PoV limit is hit more often.
	pub check_proof_size: bool,
}

#[derive(Clone, Debug, Arbitrary)]
pub enum Action {
	/// Calls a contract holding `code`.
	Call {
		code: Vec<Instruction>,
		input: Vec<u8>,
	},
	/// Deploys a contract from `init`.
	Create { init: Vec<Instruction> },
	/// Calls the precompile at `PRECOMPILES[index % len]`.
	Precompile { index: u8, input: Vec<u8> },
}

#[derive(Clone, Debug, Arbitrary)]
pub enum Instruction {
	Op(Opcode),
	Push(Push),
}

/// `PUSH0`..`PUSH32`: the immediate's length picks the opcode.
#[derive(Clone, Debug)]
pub struct Push(pub Vec<u8>);

impl<'a> Arbitrary<'a> for Push {
	fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
		let len = u.int_in_range(0..=32)?;
		Ok(Self(u.bytes(len)?.to_vec()))
	}
}

/// Assembles `code` into bytecode.
pub fn assemble(code: &[Instruction]) -> Vec<u8> {
	let mut out = Vec::new();
	for instruction in code {
		match instruction {
			Instruction::Op(op) => out.push(*op as u8),
			Instruction::Push(Push(data)) => {
				out.push(0x5F + data.len() as u8);
				out.extend_from_slice(data);
			}
		}
	}
	out
}

/// Every opcode without an immediate, by its byte.
#[derive(Clone, Copy, Debug, Arbitrary)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum Opcode {
	STOP = 0x00,
	ADD = 0x01,
	MUL = 0x02,
	SUB = 0x03,
	DIV = 0x04,
	SDIV = 0x05,
	MOD = 0x06,
	SMOD = 0x07,
	ADDMOD = 0x08,
	MULMOD = 0x09,
	EXP = 0x0A,
	SIGNEXTEND = 0x0B,
	LT = 0x10,
	GT = 0x11,
	SLT = 0x12,
	SGT = 0x13,
	EQ = 0x14,
	ISZERO = 0x15,
	AND = 0x16,
	OR = 0x17,
	XOR = 0x18,
	NOT = 0x19,
	BYTE = 0x1A,
	SHL = 0x1B,
	SHR = 0x1C,
	SAR = 0x1D,
	SHA3 = 0x20,
	ADDRESS = 0x30,
	BALANCE = 0x31,
	ORIGIN = 0x32,
	CALLER = 0x33,
	CALLVALUE = 0x34,
	CALLDATALOAD = 0x35,
	CALLDATASIZE = 0x36,
	CALLDATACOPY = 0x37,
	CODESIZE = 0x38,
	CODECOPY = 0x39,
	GASPRICE = 0x3A,
	EXTCODESIZE = 0x3B,
	EXTCODECOPY = 0x3C,
	RETURNDATASIZE = 0x3D,
	RETURNDATACOPY = 0x3E,
	EXTCODEHASH = 0x3F,
	BLOCKHASH = 0x40,
	COINBASE = 0x41,
	TIMESTAMP = 0x42,
	NUMBER = 0x43,
	DIFFICULTY = 0x44,
	GASLIMIT = 0x45,
	CHAINID = 0x46,
	SELFBALANCE = 0x47,
	BASEFEE = 0x48,
	BLOBHASH = 0x49,
	BLOBBASEFEE = 0x4A,
	POP = 0x50,
	MLOAD = 0x51,
	MSTORE = 0x52,
	MSTORE8 = 0x53,
	SLOAD = 0x54,
	SSTORE = 0x55,
	JUMP = 0x56,
	JUMPI = 0x57,
	PC = 0x58,
	MSIZE = 0x59,
	GAS = 0x5A,
	JUMPDEST = 0x5B,
	MCOPY = 0x5C,
	TLOAD = 0x5D,
	TSTORE = 0x5E,
	DUP1 = 0x80,
	DUP2 = 0x81,
	DUP3 = 0x82,
	DUP4 = 0x83,
	DUP5 = 0x84,
	DUP6 = 0x85,
	DUP7 = 0x86,
	DUP8 = 0x87,
	DUP9 = 0x88,
	DUP10 = 0x89,
	DUP11 = 0x8A,
	DUP12 = 0x8B,
	DUP13 = 0x8C,
	DUP14 = 0x8D,
	DUP15 = 0x8E,
	DUP16 = 0x8F,
	SWAP1 = 0x90,
	SWAP2 = 0x91,
	SWAP3 = 0x92,
	SWAP4 = 0x93,
	SWAP5 = 0x94,
	SWAP6 = 0x95,
	SWAP7 = 0x96,
	SWAP8 = 0x97,
	SWAP9 = 0x98,
	SWAP10 = 0x99,
	SWAP11 = 0x9A,
	SWAP12 = 0x9B,
	SWAP13 = 0x9C,
	SWAP14 = 0x9D,
	SWAP15 = 0x9E,
	SWAP16 = 0x9F,
	LOG0 = 0xA0,
	LOG1 = 0xA1,
	LOG2 = 0xA2,
	LOG3 = 0xA3,
	LOG4 = 0xA4,
	CREATE = 0xF0,
	CALL = 0xF1,
	CALLCODE = 0xF2,
	RETURN = 0xF3,
	DELEGATECALL = 0xF4,
	CREATE2 = 0xF5,
	STATICCALL = 0xFA,
	REVERT = 0xFD,
	INVALID = 0xFE,
	SELFDESTRUCT = 0xFF,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn push_emits_opcode_then_immediate() {
		let code = [
			Instruction::Push(Push(vec![])),
			Instruction::Op(Opcode::ADD),
			Instruction::Push(Push(vec![0xAB])),
			Instruction::Push(Push(vec![0xCD; 32])),
		];
		let mut expected = vec![0x5F, 0x01, 0x60, 0xAB, 0x7F];
		expected.extend_from_slice(&[0xCD; 32]);
		assert_eq!(assemble(&code), expected);
	}
}
