//! Proof that the caller controls the EVM address it is claiming.
//!
//! A relay address is public — it is the `caller` of every relay transaction —
//! and the registry is first-come-first-served. Without these checks one approved
//! validator could claim another's address, divert its fees, and lock the owner
//! out permanently via `AlreadyRegistered`.

use crate::{Error, EvmSignature, RelayerRegistry, mock::*};
use frame_support::{assert_noop, assert_ok};
use sp_core::H160;

// ─── Proof of control over the EVM key ───────────────────────────────────────

#[test]
fn cannot_claim_an_address_without_its_key() {
	// The attack the proof exists to stop: validator 2 tries to squat the address
	// validator 1 controls, so that 1's relay fees would accrue to 2.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let victim_address = address_for_seed(1, seeds::ALICE);

		// Account 2 signs with its OWN key but names the victim's address.
		let (_, own_signature) = proof_for(2, seeds::BOB);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), victim_address, own_signature),
			Error::<Test>::BadEvmSignature,
		);

		// The victim can still register.
		set_mock_validator(1);
		let (evm, result) = register_with_proof(1, seeds::ALICE);
		assert_ok!(result);
		assert_eq!(evm, victim_address);
		assert_eq!(RelayerRegistry::<Test>::get(victim_address), Some(1u64));
	});
}

#[test]
fn a_signature_bound_to_another_account_is_rejected() {
	// Replay resistance: the proof account 1 published on-chain must not let
	// account 2 register the same address.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		set_mock_validator(2);
		let (evm, signature_for_1) = proof_for(1, seeds::ALICE);

		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(2), evm, signature_for_1),
			Error::<Test>::BadEvmSignature,
		);
	});
}

#[test]
fn a_malformed_signature_is_rejected() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let evm = address_for_seed(1, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), evm, EvmSignature([0u8; 65])),
			Error::<Test>::BadEvmSignature,
		);
	});
}

#[test]
fn a_tampered_signature_is_rejected() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, mut sig) = proof_for(1, seeds::ALICE);
		sig.0[0] ^= 0xff;
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), evm, sig),
			Error::<Test>::BadEvmSignature,
		);
	});
}

#[test]
fn an_out_of_range_recovery_id_is_rejected() {
	// v must be 0/1 or 27/28; anything else must fail cleanly rather than panic.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, mut sig) = proof_for(1, seeds::ALICE);
		sig.0[64] = 42;
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), evm, sig),
			Error::<Test>::BadEvmSignature,
		);
	});
}

#[test]
fn a_wallet_style_recovery_id_is_accepted() {
	// Wallets emit v as 27/28; the pallet normalises it.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (evm, mut sig) = proof_for(1, seeds::ALICE);
		sig.0[64] += 27;
		assert_ok!(Relayer::register_relayer(
			RuntimeOrigin::signed(1),
			evm,
			sig
		));
		assert_eq!(RelayerRegistry::<Test>::get(evm), Some(1u64));
	});
}

// ─── Reserved EVM addresses ──────────────────────────────────────────────────

#[test]
fn the_zero_address_is_rejected() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (_, sig) = proof_for(1, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), H160::zero(), sig),
			Error::<Test>::InvalidEvmAddress,
		);
	});
}

#[test]
fn precompile_addresses_are_rejected() {
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		// 0x0801 is the shielded-pool precompile in the runtime; the whole low
		// range is reserved because those "callers" are the runtime itself.
		for raw in [1u64, 5, 0x400, 0x801, 0xffff] {
			let (_, sig) = proof_for(1, seeds::ALICE);
			assert_noop!(
				Relayer::register_relayer(
					RuntimeOrigin::signed(1),
					H160::from_low_u64_be(raw),
					sig
				),
				Error::<Test>::InvalidEvmAddress,
			);
		}
	});
}

#[test]
fn the_first_address_above_the_reserved_range_is_allowed() {
	// Boundary: 0x10000 is one past the precompile ceiling.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let (_, sig) = proof_for(1, seeds::ALICE);
		// Signature will not match, but the address check must pass first.
		assert_noop!(
			Relayer::register_relayer(
				RuntimeOrigin::signed(1),
				H160::from_low_u64_be(0x10000),
				sig
			),
			Error::<Test>::BadEvmSignature,
		);
	});
}

#[test]
fn a_high_address_sharing_the_low_bytes_is_allowed() {
	// Only the whole 20-byte value counts as reserved, not its low 8 bytes.
	new_test_ext().execute_with(|| {
		set_mock_validator(1);
		let mut bytes = [0u8; 20];
		bytes[0] = 0x01; // high byte set -> not in the reserved range
		bytes[19] = 0x01; // low bytes look like precompile 0x1
		let (_, sig) = proof_for(1, seeds::ALICE);
		assert_noop!(
			Relayer::register_relayer(RuntimeOrigin::signed(1), H160(bytes), sig),
			Error::<Test>::BadEvmSignature,
		);
	});
}
