pragma circom 2.0.0;

include "./note.circom";
include "./merkle_tree.circom";
include "./poseidon_wrapper.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Unshield circuit - converts private note to public tokens
// Proves ownership of a note in the Merkle tree and reveals amount
// for withdrawal to a public address
//
// This circuit:
// 1. Verifies the note exists in the Merkle tree
// 2. Verifies the nullifier is computed correctly (prevents double-spend)
// 3. Reveals the amount being withdrawn (public for balance tracking)
// 4. Reveals the recipient address (public for token transfer)
//
template Unshield(tree_depth) {
    // ========== PUBLIC INPUTS ==========
    // These are revealed on-chain
    signal input merkle_root;      // Current merkle root (verified against historic roots)
    signal input nullifier;        // Nullifier to prevent double-spend
    signal input amount;           // Amount being withdrawn (publicly revealed)
    signal input recipient;        // Recipient address (publicly revealed)
    signal input asset_id;         // Asset ID being unshielded (publicly revealed for validation)

    // ========== PRIVATE INPUTS ==========
    // These remain hidden - only prover knows them
    signal input note_value;       // Value in the note (must equal amount)
    signal input note_asset_id;    // Asset ID in note (must match public asset_id)
    signal input note_owner;       // Owner public key
    signal input note_blinding;    // Random blinding factor
    signal input spending_key;     // Secret key to compute nullifier

    // Merkle proof
    signal input path_elements[tree_depth];  // Sibling hashes
    signal input path_indices[tree_depth];   // Path directions (0=left, 1=right)

    // ========== CONSTRAINT 1: AMOUNT MUST MATCH NOTE VALUE ==========
    // The publicly revealed amount must equal the note's value
    // This ensures user cannot withdraw more than they deposited
    amount === note_value;

    // ========== CONSTRAINT 2: RANGE CHECK ==========
    // Ensure note_value is within u64 range (0 to 2^64-1)
    // This prevents overflow attacks and ensures value is valid u64
    component value_range_check = Num2Bits(64);
    value_range_check.in <== note_value;

    // ========== CONSTRAINT 3: COMPUTE NOTE COMMITMENT ==========
    // Compute the commitment that should be in the Merkle tree
    component commitment_computer = NoteCommitment();
    commitment_computer.value <== note_value;
    commitment_computer.asset_id <== note_asset_id;
    commitment_computer.owner_pubkey <== note_owner;
    commitment_computer.blinding <== note_blinding;

    signal computed_commitment;
    computed_commitment <== commitment_computer.commitment;

    // ========== CONSTRAINT 4: VERIFY MERKLE MEMBERSHIP ==========
    // Prove the commitment exists in the Merkle tree
    component merkle_verifier = MerkleTreeVerifier(tree_depth);
    merkle_verifier.leaf <== computed_commitment;

    for (var i = 0; i < tree_depth; i++) {
        merkle_verifier.path_elements[i] <== path_elements[i];
        merkle_verifier.path_index[i] <== path_indices[i];
    }

    // The computed root must match the public merkle_root
    merkle_verifier.root === merkle_root;

    // ========== CONSTRAINT 5: VERIFY NULLIFIER ==========
    // Compute nullifier and verify it matches the public input
    // This links the spending to this specific note
    component nullifier_computer = Nullifier();
    nullifier_computer.commitment <== computed_commitment;
    nullifier_computer.spending_key <== spending_key;

    // The computed nullifier must match the public nullifier
    nullifier_computer.nullifier === nullifier;

    // ========== CONSTRAINT 6: ASSET ID CONSISTENCY ==========
    // Ensure the note's asset_id matches the public asset_id
    // This prevents unshielding notes with a different asset than declared
    note_asset_id === asset_id;
    
    // Note: The runtime still validates that asset_id exists and is authorized

    // Note: Recipient validation (recipient != 0) is performed in the runtime
    // to prevent burning tokens by sending to address zero. This is more
    // efficient than constraining it in the circuit.
}

// Main component with tree depth of 20 (matches pallet MAX_TREE_DEPTH)
// asset_id added as public input for multi-asset security
component main {public [merkle_root, nullifier, amount, recipient, asset_id]} = Unshield(20);
