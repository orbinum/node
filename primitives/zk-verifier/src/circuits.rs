//! Known circuits: ids, base public-input counts, and the input layout a
//! verifying key's arity implies.

// ─── Circuit ids and arities ──────────────────────────────────────────────────

/// Circuit identifier for transfer operations.
pub const CIRCUIT_ID_TRANSFER: u8 = 1;
/// Circuit identifier for unshield (withdraw) operations.
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;

/// Number of public inputs for the transfer circuit.
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2, asset_id, fee]
pub const TRANSFER_PUBLIC_INPUTS: usize = 7;
/// Number of public inputs for the unshield circuit.
/// Public inputs: [merkle_root, nullifier, amount, recipient, asset_id, fee, change_commitment]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 7;

/// Public inputs a memo-bound version adds to its circuit's base layout:
/// `memo_hash`, appended last.
pub const MEMO_HASH_INPUTS: usize = 1;

// ─── Input layouts ────────────────────────────────────────────────────────────

/// Base public-input count for a known circuit id, or `None` if unknown. A VK
/// for the circuit has `gamma_abc_g1.len() == inputs + 1`, where `inputs` is this
/// base or, for a memo-bound version, one more — see [`input_layout`].
pub const fn expected_public_inputs(circuit_id: u8) -> Option<usize> {
	match circuit_id {
		CIRCUIT_ID_TRANSFER => Some(TRANSFER_PUBLIC_INPUTS),
		CIRCUIT_ID_UNSHIELD => Some(UNSHIELD_PUBLIC_INPUTS),
		_ => None,
	}
}

/// How a circuit version lays out its public inputs, read off its key's arity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputLayout {
	/// The circuit's original layout.
	Base,
	/// The base layout plus `memo_hash` last. How each public value maps to a
	/// field element per layout is the pallet's encoding.
	MemoBound,
}

/// The layout a key of `arity` public inputs implies for `circuit_id`, or `None`
/// when the arity fits neither. Unknown ids carry no expected arity: any key is
/// taken as [`InputLayout::Base`].
pub const fn input_layout(circuit_id: u8, arity: usize) -> Option<InputLayout> {
	match expected_public_inputs(circuit_id) {
		None => Some(InputLayout::Base),
		Some(base) if arity == base => Some(InputLayout::Base),
		Some(base) if arity == base + MEMO_HASH_INPUTS => Some(InputLayout::MemoBound),
		Some(_) => None,
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::MAX_PUBLIC_INPUTS;

	#[test]
	fn test_circuit_ids_are_stable() {
		assert_eq!(CIRCUIT_ID_TRANSFER, 1);
		assert_eq!(CIRCUIT_ID_UNSHIELD, 2);
	}

	#[test]
	fn test_public_input_counts_are_expected() {
		assert_eq!(TRANSFER_PUBLIC_INPUTS, 7);
		assert_eq!(UNSHIELD_PUBLIC_INPUTS, 7);
	}

	#[test]
	fn expected_public_inputs_maps_known_circuits() {
		assert_eq!(expected_public_inputs(CIRCUIT_ID_TRANSFER), Some(7));
		assert_eq!(expected_public_inputs(CIRCUIT_ID_UNSHIELD), Some(7));
		// Circuit 6 (retired value_proof) is unknown, so its keys can be purged.
		assert_eq!(expected_public_inputs(6), None);
		// Unknown / unmapped circuit ids (e.g. shield=3) return None.
		assert_eq!(expected_public_inputs(3), None);
		// Circuit 5 (retired private-link) is unknown: a VK registered under that
		// id gets no arity check.
		assert_eq!(expected_public_inputs(5), None);
		assert_eq!(expected_public_inputs(0), None);
		assert_eq!(expected_public_inputs(99), None);
	}

	#[test]
	fn input_layout_follows_the_key_arity() {
		for id in [CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD] {
			assert_eq!(input_layout(id, 7), Some(InputLayout::Base));
			assert_eq!(
				input_layout(id, 7 + MEMO_HASH_INPUTS),
				Some(InputLayout::MemoBound)
			);
			assert_eq!(input_layout(id, 6), None);
			assert_eq!(input_layout(id, 9), None);
		}
		assert_eq!(input_layout(200, 3), Some(InputLayout::Base));
	}

	/// Every circuit in use sits far below the cap, so enforcing it cannot break
	/// a real verification.
	///
	/// A `const` block rather than a `#[test]`: these are all constants, so the
	/// comparison is decided at compile time either way — this way raising a
	/// circuit's arity past the cap fails the build instead of a test run.
	const _: () = {
		assert!(
			TRANSFER_PUBLIC_INPUTS * 4 < MAX_PUBLIC_INPUTS,
			"transfer arity is too close to MAX_PUBLIC_INPUTS"
		);
		assert!(
			UNSHIELD_PUBLIC_INPUTS * 4 < MAX_PUBLIC_INPUTS,
			"unshield arity is too close to MAX_PUBLIC_INPUTS"
		);
	};
}
