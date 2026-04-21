// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use ethereum::{eip2930, legacy, TransactionV3 as EthereumTransaction};
use ethereum_types::{H160, H256};
use jsonrpsee::types::ErrorObjectOwned;
// Substrate
use sp_core::hashing::keccak_256;
// Frontier
use fc_rpc_core::types::TransactionMessage;

use crate::internal_err;

/// A generic Ethereum signer.
pub trait EthSigner: Send + Sync {
	/// Available accounts from this signer.
	fn accounts(&self) -> Vec<H160>;
	/// Sign a transaction message using the given account in message.
	fn sign(
		&self,
		message: TransactionMessage,
		address: &H160,
	) -> Result<EthereumTransaction, ErrorObjectOwned>;
}

pub struct EthDevSigner {
	keys: Vec<libsecp256k1::SecretKey>,
}

impl EthDevSigner {
	pub fn new() -> Self {
		Self {
			keys: vec![libsecp256k1::SecretKey::parse(&[
				0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				0x11, 0x11, 0x11, 0x11,
			])
			.expect("Test key is valid; qed")],
		}
	}
}

fn secret_key_address(secret: &libsecp256k1::SecretKey) -> H160 {
	let public = libsecp256k1::PublicKey::from_secret_key(secret);
	public_key_address(&public)
}

fn public_key_address(public: &libsecp256k1::PublicKey) -> H160 {
	let mut res = [0u8; 64];
	res.copy_from_slice(&public.serialize()[1..65]);
	H160::from(H256::from(keccak_256(&res)))
}

// ---------------------------------------------------------------------------
// Dev signer — hardcoded key `0x1111…`
// ---------------------------------------------------------------------------

impl EthSigner for EthDevSigner {
	fn accounts(&self) -> Vec<H160> {
		self.keys.iter().map(secret_key_address).collect()
	}

	fn sign(
		&self,
		message: TransactionMessage,
		address: &H160,
	) -> Result<EthereumTransaction, ErrorObjectOwned> {
		let mut transaction = None;

		for secret in &self.keys {
			let key_address = secret_key_address(secret);

			if &key_address == address {
				match message {
					TransactionMessage::Legacy(m) => {
						let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
							.map_err(|_| internal_err("invalid signing message"))?;
						let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
						let v = match m.chain_id {
							None => 27 + recid.serialize() as u64,
							Some(chain_id) => 2 * chain_id + 35 + recid.serialize() as u64,
						};
						let rs = signature.serialize();
						let r = H256::from_slice(&rs[0..32]);
						let s = H256::from_slice(&rs[32..64]);
						transaction =
							Some(EthereumTransaction::Legacy(ethereum::LegacyTransaction {
								nonce: m.nonce,
								gas_price: m.gas_price,
								gas_limit: m.gas_limit,
								action: m.action,
								value: m.value,
								input: m.input,
								signature: legacy::TransactionSignature::new(v, r, s).ok_or_else(
									|| internal_err("signer generated invalid signature"),
								)?,
							}));
					}
					TransactionMessage::EIP2930(m) => {
						let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
							.map_err(|_| internal_err("invalid signing message"))?;
						let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
						let rs = signature.serialize();
						let r = H256::from_slice(&rs[0..32]);
						let s = H256::from_slice(&rs[32..64]);
						transaction =
							Some(EthereumTransaction::EIP2930(ethereum::EIP2930Transaction {
								chain_id: m.chain_id,
								nonce: m.nonce,
								gas_price: m.gas_price,
								gas_limit: m.gas_limit,
								action: m.action,
								value: m.value,
								input: m.input.clone(),
								access_list: m.access_list,
								signature: eip2930::TransactionSignature::new(
									recid.serialize() != 0,
									r,
									s,
								)
								.ok_or(internal_err("Invalid transaction signature format"))?,
							}));
					}
					TransactionMessage::EIP1559(m) => {
						let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
							.map_err(|_| internal_err("invalid signing message"))?;
						let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
						let rs = signature.serialize();
						let r = H256::from_slice(&rs[0..32]);
						let s = H256::from_slice(&rs[32..64]);
						transaction =
							Some(EthereumTransaction::EIP1559(ethereum::EIP1559Transaction {
								chain_id: m.chain_id,
								nonce: m.nonce,
								max_priority_fee_per_gas: m.max_priority_fee_per_gas,
								max_fee_per_gas: m.max_fee_per_gas,
								gas_limit: m.gas_limit,
								action: m.action,
								value: m.value,
								input: m.input.clone(),
								access_list: m.access_list,
								signature: eip2930::TransactionSignature::new(
									recid.serialize() != 0,
									r,
									s,
								)
								.ok_or(internal_err("Invalid transaction signature format"))?,
							}));
					}
					TransactionMessage::EIP7702(m) => {
						let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
							.map_err(|_| internal_err("invalid signing message"))?;
						let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
						let rs = signature.serialize();
						let r = H256::from_slice(&rs[0..32]);
						let s = H256::from_slice(&rs[32..64]);
						transaction =
							Some(EthereumTransaction::EIP7702(ethereum::EIP7702Transaction {
								chain_id: m.chain_id,
								nonce: m.nonce,
								max_priority_fee_per_gas: m.max_priority_fee_per_gas,
								max_fee_per_gas: m.max_fee_per_gas,
								gas_limit: m.gas_limit,
								destination: m.destination,
								value: m.value,
								data: m.data.clone(),
								access_list: m.access_list,
								authorization_list: m.authorization_list,
								signature: eip2930::TransactionSignature::new(
									recid.serialize() != 0,
									r,
									s,
								)
								.ok_or(internal_err("Invalid transaction signature format"))?,
							}));
					}
				}
				break;
			}
		}

		transaction.ok_or_else(|| internal_err("signer not available"))
	}
}

/// A signer that uses a single externally-configured key (e.g. from `--evm-relayer-key`).
pub struct EthValidatorSigner {
	key: libsecp256k1::SecretKey,
}

impl EthValidatorSigner {
	/// Parse a 32-byte hex-encoded private key (with or without `0x` prefix).
	pub fn from_hex(hex: &str) -> Result<Self, String> {
		let hex = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex).map_err(|e| format!("invalid hex key: {e}"))?;
		let key = libsecp256k1::SecretKey::parse_slice(&bytes)
			.map_err(|e| format!("invalid secp256k1 key: {e:?}"))?;
		Ok(Self { key })
	}

	/// Return the EVM address derived from this key.
	pub fn address(&self) -> H160 {
		secret_key_address(&self.key)
	}
}

impl EthSigner for EthValidatorSigner {
	fn accounts(&self) -> Vec<H160> {
		vec![secret_key_address(&self.key)]
	}

	fn sign(
		&self,
		message: TransactionMessage,
		address: &H160,
	) -> Result<EthereumTransaction, ErrorObjectOwned> {
		if &secret_key_address(&self.key) != address {
			return Err(internal_err("signer not available"));
		}
		let secret = &self.key;
		let transaction = match message {
			TransactionMessage::Legacy(m) => {
				let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
					.map_err(|_| internal_err("invalid signing message"))?;
				let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
				let v = match m.chain_id {
					None => 27 + recid.serialize() as u64,
					Some(chain_id) => 2 * chain_id + 35 + recid.serialize() as u64,
				};
				let rs = signature.serialize();
				let r = H256::from_slice(&rs[0..32]);
				let s = H256::from_slice(&rs[32..64]);
				EthereumTransaction::Legacy(ethereum::LegacyTransaction {
					nonce: m.nonce,
					gas_price: m.gas_price,
					gas_limit: m.gas_limit,
					action: m.action,
					value: m.value,
					input: m.input,
					signature: legacy::TransactionSignature::new(v, r, s)
						.ok_or_else(|| internal_err("signer generated invalid signature"))?,
				})
			}
			TransactionMessage::EIP2930(m) => {
				let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
					.map_err(|_| internal_err("invalid signing message"))?;
				let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
				let rs = signature.serialize();
				let r = H256::from_slice(&rs[0..32]);
				let s = H256::from_slice(&rs[32..64]);
				EthereumTransaction::EIP2930(ethereum::EIP2930Transaction {
					chain_id: m.chain_id,
					nonce: m.nonce,
					gas_price: m.gas_price,
					gas_limit: m.gas_limit,
					action: m.action,
					value: m.value,
					input: m.input.clone(),
					access_list: m.access_list,
					signature: eip2930::TransactionSignature::new(recid.serialize() != 0, r, s)
						.ok_or(internal_err("Invalid transaction signature format"))?,
				})
			}
			TransactionMessage::EIP1559(m) => {
				let signing_message = libsecp256k1::Message::parse_slice(&m.hash()[..])
					.map_err(|_| internal_err("invalid signing message"))?;
				let (signature, recid) = libsecp256k1::sign(&signing_message, secret);
				let rs = signature.serialize();
				let r = H256::from_slice(&rs[0..32]);
				let s = H256::from_slice(&rs[32..64]);
				EthereumTransaction::EIP1559(ethereum::EIP1559Transaction {
					chain_id: m.chain_id,
					nonce: m.nonce,
					max_priority_fee_per_gas: m.max_priority_fee_per_gas,
					max_fee_per_gas: m.max_fee_per_gas,
					gas_limit: m.gas_limit,
					action: m.action,
					value: m.value,
					input: m.input.clone(),
					access_list: m.access_list,
					signature: eip2930::TransactionSignature::new(recid.serialize() != 0, r, s)
						.ok_or(internal_err("Invalid transaction signature format"))?,
				})
			}
			_ => {
				return Err(internal_err(
					"unsupported transaction type for relay signer",
				))
			}
		};
		Ok(transaction)
	}
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	/// Private key for the genesis test account.
	/// Address: 0x6be02d1d3665660d22ff9624b7be0551ee1ac91b
	const GENESIS_KEY: &str = "99b3c12287537e38c90a9219d4cb074a89a16e9cdb20bf85728ebd97c343e342";
	const GENESIS_ADDR: &str = "6be02d1d3665660d22ff9624b7be0551ee1ac91b";

	fn expected_addr() -> H160 {
		GENESIS_ADDR.parse().expect("static hex address is valid")
	}

	// ── from_hex ────────────────────────────────────────────────────────────

	#[test]
	fn from_hex_without_prefix_derives_correct_address() {
		let signer = EthValidatorSigner::from_hex(GENESIS_KEY).unwrap();
		assert_eq!(signer.address(), expected_addr());
	}

	#[test]
	fn from_hex_with_0x_prefix_derives_correct_address() {
		let key = format!("0x{GENESIS_KEY}");
		let signer = EthValidatorSigner::from_hex(&key).unwrap();
		assert_eq!(signer.address(), expected_addr());
	}

	#[test]
	fn from_hex_uppercase_hex_chars_accepted() {
		let upper = GENESIS_KEY.to_uppercase();
		let signer = EthValidatorSigner::from_hex(&upper).unwrap();
		assert_eq!(signer.address(), expected_addr());
	}

	#[test]
	fn from_hex_invalid_characters_returns_err() {
		assert!(
			EthValidatorSigner::from_hex("xyz_not_valid_hex_zzzzzzzzzzzzzzzzzzzzzzzz").is_err()
		);
	}

	#[test]
	fn from_hex_too_short_returns_err() {
		assert!(EthValidatorSigner::from_hex("aabb").is_err());
	}

	#[test]
	fn from_hex_all_zeros_rejected_as_invalid_secp256k1_key() {
		// The all-zero scalar is not a valid secp256k1 private key
		assert!(EthValidatorSigner::from_hex(&"00".repeat(32)).is_err());
	}

	#[test]
	fn from_hex_empty_returns_err() {
		assert!(EthValidatorSigner::from_hex("").is_err());
	}

	// ── address / accounts ──────────────────────────────────────────────────

	#[test]
	fn address_matches_accounts_first_entry() {
		let signer = EthValidatorSigner::from_hex(GENESIS_KEY).unwrap();
		let accounts = signer.accounts();
		assert_eq!(accounts.len(), 1);
		assert_eq!(accounts[0], signer.address());
	}

	#[test]
	fn accounts_returns_exactly_one_entry() {
		let signer = EthValidatorSigner::from_hex(GENESIS_KEY).unwrap();
		assert_eq!(signer.accounts().len(), 1);
	}

	// ── sign ────────────────────────────────────────────────────────────────

	#[test]
	fn sign_rejects_wrong_address() {
		let signer = EthValidatorSigner::from_hex(GENESIS_KEY).unwrap();
		let wrong: H160 = "0000000000000000000000000000000000000001".parse().unwrap();
		let msg = TransactionMessage::EIP1559(ethereum::EIP1559TransactionMessage {
			chain_id: 42,
			nonce: ethereum_types::U256::zero(),
			max_priority_fee_per_gas: ethereum_types::U256::zero(),
			max_fee_per_gas: ethereum_types::U256::from(10_000_000_000u64),
			gas_limit: ethereum_types::U256::from(21_000u64),
			action: ethereum::TransactionAction::Call(wrong),
			value: ethereum_types::U256::zero(),
			input: vec![],
			access_list: vec![],
		});
		assert!(signer.sign(msg, &wrong).is_err());
	}

	#[test]
	fn sign_succeeds_for_correct_address() {
		let signer = EthValidatorSigner::from_hex(GENESIS_KEY).unwrap();
		let addr = signer.address();
		let msg = TransactionMessage::EIP1559(ethereum::EIP1559TransactionMessage {
			chain_id: 42,
			nonce: ethereum_types::U256::zero(),
			max_priority_fee_per_gas: ethereum_types::U256::zero(),
			max_fee_per_gas: ethereum_types::U256::from(10_000_000_000u64),
			gas_limit: ethereum_types::U256::from(21_000u64),
			action: ethereum::TransactionAction::Call(addr),
			value: ethereum_types::U256::zero(),
			input: vec![],
			access_list: vec![],
		});
		assert!(signer.sign(msg, &addr).is_ok());
	}
}
