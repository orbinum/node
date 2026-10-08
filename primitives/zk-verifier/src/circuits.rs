//! Known circuits: ids, base public-input counts, and the input layout a
//! verifying key's arity implies.

// ─── Circuit ids and arities ──────────────────────────────────────────────────

/// Circuit identifier for transfer operations.
pub const CIRCUIT_ID_TRANSFER: u8 = 1;
/// Circuit identifier for unshield (withdraw) operations.
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;
/// Circuit identifier for shield (deposit) operations.
pub const CIRCUIT_ID_SHIELD: u8 = 3;

/// Number of public inputs for the transfer circuit.
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2, asset_id, fee]
pub const TRANSFER_PUBLIC_INPUTS: usize = 7;
/// Number of public inputs for the unshield circuit.
/// Public inputs: [merkle_root, nullifier, amount, recipient, asset_id, fee, change_commitment]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 7;
/// Number of public inputs for the shield circuit.
/// Public inputs: [commitment, value, asset_id]
pub const SHIELD_PUBLIC_INPUTS: usize = 3;

/// Public inputs a memo-bound version adds to its circuit's base layout:
/// `memo_hash`, appended last.
pub const MEMO_HASH_INPUTS: usize = 1;

/// Public inputs a cross-tree transfer adds to the memo-bound layout: a second
/// Merkle root, right after the first, so each input has its own.
pub const CROSS_TREE_INPUTS: usize = 1;

// ─── Input layouts ────────────────────────────────────────────────────────────

/// Base public-input count for a known circuit id, or `None` if unknown. A VK
/// for the circuit has `gamma_abc_g1.len() == inputs + 1`, where `inputs` is this
/// base or, for a memo-bound version, one more — see [`input_layout`].
pub const fn expected_public_inputs(circuit_id: u8) -> Option<usize> {
	match circuit_id {
		CIRCUIT_ID_TRANSFER => Some(TRANSFER_PUBLIC_INPUTS),
		CIRCUIT_ID_UNSHIELD => Some(UNSHIELD_PUBLIC_INPUTS),
		CIRCUIT_ID_SHIELD => Some(SHIELD_PUBLIC_INPUTS),
		_ => None,
	}
}

/// Whether `circuit_id` has a memo-bound layout: only the spend circuits carry
/// memos. A shield is a signed deposit, so its memo needs no binding.
pub const fn has_memo_layout(circuit_id: u8) -> bool {
	matches!(circuit_id, CIRCUIT_ID_TRANSFER | CIRCUIT_ID_UNSHIELD)
}

/// Whether `circuit_id` has a cross-tree layout: only a transfer spends two notes,
/// so only it can take them from two trees.
pub const fn has_cross_tree_layout(circuit_id: u8) -> bool {
	circuit_id == CIRCUIT_ID_TRANSFER
}

/// How a circuit version lays out its public inputs, read off its key's arity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputLayout {
	/// The circuit's original layout.
	Base,
	/// The base layout plus `memo_hash` last. How each public value maps to a
	/// field element per layout is the pallet's encoding.
	MemoBound,
	/// The memo-bound layout with one Merkle root per input
	/// (`merkle_roots[0], merkle_roots[1]` in place of `merkle_root`), so the two
	/// notes may come from different trees. Transfer only.
	CrossTree,
}

/// The layout a key of `arity` public inputs implies for `circuit_id`, or `None`
/// when the arity fits none. Unknown ids carry no expected arity: any key is
/// taken as [`InputLayout::Base`].
pub const fn input_layout(circuit_id: u8, arity: usize) -> Option<InputLayout> {
	match expected_public_inputs(circuit_id) {
		None => Some(InputLayout::Base),
		Some(base) if arity == base => Some(InputLayout::Base),
		Some(base) if arity == base + MEMO_HASH_INPUTS && has_memo_layout(circuit_id) => {
			Some(InputLayout::MemoBound)
		}
		Some(base)
			if arity == base + MEMO_HASH_INPUTS + CROSS_TREE_INPUTS
				&& has_cross_tree_layout(circuit_id) =>
		{
			Some(InputLayout::CrossTree)
		}
		Some(_) => None,
	}
}

/// Public inputs of `circuit_id`'s widest layout, or `None` if unknown. The one
/// place that adds up the layouts, so weights and caps follow a new one.
pub const fn max_public_inputs(circuit_id: u8) -> Option<usize> {
	let Some(base) = expected_public_inputs(circuit_id) else {
		return None;
	};
	Some(if has_cross_tree_layout(circuit_id) {
		base + MEMO_HASH_INPUTS + CROSS_TREE_INPUTS
	} else if has_memo_layout(circuit_id) {
		base + MEMO_HASH_INPUTS
	} else {
		base
	})
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
		assert_eq!(CIRCUIT_ID_SHIELD, 3);
	}

	#[test]
	fn test_public_input_counts_are_expected() {
		assert_eq!(TRANSFER_PUBLIC_INPUTS, 7);
		assert_eq!(UNSHIELD_PUBLIC_INPUTS, 7);
		assert_eq!(SHIELD_PUBLIC_INPUTS, 3);
	}

	#[test]
	fn expected_public_inputs_maps_known_circuits() {
		assert_eq!(expected_public_inputs(CIRCUIT_ID_TRANSFER), Some(7));
		assert_eq!(expected_public_inputs(CIRCUIT_ID_UNSHIELD), Some(7));
		assert_eq!(expected_public_inputs(CIRCUIT_ID_SHIELD), Some(3));
		// Circuit 6 (retired value_proof) is unknown, so its keys can be purged.
		assert_eq!(expected_public_inputs(6), None);
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
			assert_eq!(input_layout(id, 10), None);
		}
		assert_eq!(input_layout(200, 3), Some(InputLayout::Base));
	}

	#[test]
	fn only_a_transfer_has_the_cross_tree_layout() {
		assert_eq!(
			input_layout(CIRCUIT_ID_TRANSFER, 9),
			Some(InputLayout::CrossTree)
		);
		assert_eq!(input_layout(CIRCUIT_ID_UNSHIELD, 9), None);
		assert_eq!(input_layout(CIRCUIT_ID_SHIELD, 5), None);
	}

	#[test]
	fn max_public_inputs_is_each_circuits_widest_layout() {
		assert_eq!(max_public_inputs(CIRCUIT_ID_TRANSFER), Some(9));
		assert_eq!(max_public_inputs(CIRCUIT_ID_UNSHIELD), Some(8));
		assert_eq!(max_public_inputs(CIRCUIT_ID_SHIELD), Some(3));
		assert_eq!(max_public_inputs(200), None);
		for id in [CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, CIRCUIT_ID_SHIELD] {
			let widest = max_public_inputs(id).unwrap();
			assert!(input_layout(id, widest).is_some());
			assert_eq!(input_layout(id, widest + 1), None);
		}
	}

	#[test]
	fn shield_has_only_the_base_layout() {
		assert!(!has_memo_layout(CIRCUIT_ID_SHIELD));
		assert_eq!(input_layout(CIRCUIT_ID_SHIELD, 3), Some(InputLayout::Base));
		// One input more is memo-bound for a spend circuit, nothing for shield.
		assert_eq!(input_layout(CIRCUIT_ID_SHIELD, 4), None);
		assert_eq!(input_layout(CIRCUIT_ID_SHIELD, 2), None);
	}

	/// Every layout in use, each circuit's widest included, sits well below the
	/// cap, so enforcing it cannot break a real verification.
	///
	/// A `const` block rather than a `#[test]`: these are all constants, so the
	/// comparison is decided at compile time either way — this way raising a
	/// circuit's arity past the cap fails the build instead of a test run.
	const _: () = {
		let ids = [CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, CIRCUIT_ID_SHIELD];
		let mut i = 0;
		while i < ids.len() {
			match max_public_inputs(ids[i]) {
				Some(widest) => assert!(
					widest * 3 < MAX_PUBLIC_INPUTS,
					"a circuit's arity is too close to MAX_PUBLIC_INPUTS"
				),
				None => panic!("a known circuit has no arity"),
			}
			i += 1;
		}
	};
}
