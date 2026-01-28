pragma circom 2.0.0;

include "./note.circom";
include "./merkle_tree.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Main transfer circuit
// Proves private token transfer with 2 inputs and 2 outputs
// Now with EdDSA signature verification for ownership proof
template Transfer(tree_depth) {
    // ========== PUBLIC INPUTS ==========
    signal input merkle_root;
    signal input nullifiers[2];
    signal input commitments[2];

    // ========== PRIVATE INPUTS ==========
    // Input notes (being spent)
    signal input input_values[2];
    signal input input_asset_ids[2];
    signal input input_blindings[2];
    signal input spending_keys[2];

    // EdDSA public keys (Ax, Ay) for each input note owner
    signal input input_owner_Ax[2];
    signal input input_owner_Ay[2];

    // EdDSA signatures for ownership proof
    // Each signature consists of (R8x, R8y, S)
    signal input input_sig_R8x[2];
    signal input input_sig_R8y[2];
    signal input input_sig_S[2];

    // Merkle proofs for inputs
    signal input input_path_elements[2][tree_depth];
    signal input input_path_indices[2][tree_depth];

    // Output notes (being created)
    signal input output_values[2];
    signal input output_asset_ids[2];
    signal input output_owner_pubkeys[2];
    signal input output_blindings[2];

    // ========== CONSTRAINT 1: MERKLE MEMBERSHIP ==========
    // Prove each input note exists in the commitment tree

    // Compute owner_pubkey from Ax (x-coordinate of EdDSA public key)
    // This links the EdDSA key pair to the note commitment
    signal input_owner_pubkeys[2];
    input_owner_pubkeys[0] <== input_owner_Ax[0];
    input_owner_pubkeys[1] <== input_owner_Ax[1];

    component input_commitments[2];
    component merkle_verifiers[2];

    for (var i = 0; i < 2; i++) {
        // Compute input note commitment
        input_commitments[i] = NoteCommitment();
        input_commitments[i].value <== input_values[i];
        input_commitments[i].asset_id <== input_asset_ids[i];
        input_commitments[i].owner_pubkey <== input_owner_pubkeys[i];
        input_commitments[i].blinding <== input_blindings[i];

        // Verify commitment is in Merkle tree
        merkle_verifiers[i] = MerkleTreeVerifier(tree_depth);
        merkle_verifiers[i].leaf <== input_commitments[i].commitment;

        for (var j = 0; j < tree_depth; j++) {
            merkle_verifiers[i].path_elements[j] <== input_path_elements[i][j];
            merkle_verifiers[i].path_index[j] <== input_path_indices[i][j];
        }

        // Constrain computed root equals public merkle_root
        merkle_verifiers[i].root === merkle_root;
    }

    // ========== CONSTRAINT 2: NULLIFIER CORRECTNESS ==========
    // Ensure nullifiers are computed correctly from commitments and spending keys

    component nullifier_computers[2];

    for (var i = 0; i < 2; i++) {
        nullifier_computers[i] = Nullifier();
        nullifier_computers[i].commitment <== input_commitments[i].commitment;
        nullifier_computers[i].spending_key <== spending_keys[i];

        // Constrain computed nullifier equals public nullifier
        nullifier_computers[i].nullifier === nullifiers[i];
    }

    // ========== CONSTRAINT 3: EDDSA OWNERSHIP VERIFICATION ==========
    // Verify EdDSA signature over the commitment to prove note ownership
    // The message signed is the note commitment itself
    // This ensures only the owner (who knows the private key) can spend the note

    component eddsa_verifiers[2];

    for (var i = 0; i < 2; i++) {
        eddsa_verifiers[i] = EdDSAPoseidonVerifier();
        eddsa_verifiers[i].enabled <== 1;  // Always enabled

        // Public key (Ax, Ay)
        eddsa_verifiers[i].Ax <== input_owner_Ax[i];
        eddsa_verifiers[i].Ay <== input_owner_Ay[i];

        // Signature (R8x, R8y, S)
        eddsa_verifiers[i].R8x <== input_sig_R8x[i];
        eddsa_verifiers[i].R8y <== input_sig_R8y[i];
        eddsa_verifiers[i].S <== input_sig_S[i];

        // Message: the note commitment being spent
        eddsa_verifiers[i].M <== input_commitments[i].commitment;
    }

    // ========== CONSTRAINT 4: OUTPUT COMMITMENTS ==========
    // Ensure output commitments are computed correctly

    component output_commitment_computers[2];

    for (var i = 0; i < 2; i++) {
        output_commitment_computers[i] = NoteCommitment();
        output_commitment_computers[i].value <== output_values[i];
        output_commitment_computers[i].asset_id <== output_asset_ids[i];
        output_commitment_computers[i].owner_pubkey <== output_owner_pubkeys[i];
        output_commitment_computers[i].blinding <== output_blindings[i];

        // Constrain computed commitment equals public commitment
        output_commitment_computers[i].commitment === commitments[i];
    }

    // ========== CONSTRAINT 5: BALANCE CONSERVATION ==========
    // Prove sum(inputs) == sum(outputs)

    signal input_sum;
    signal output_sum;

    input_sum <== input_values[0] + input_values[1];
    output_sum <== output_values[0] + output_values[1];

    input_sum === output_sum;

    // ========== CONSTRAINT 6: RANGE CHECKS ==========
    // Ensure all values are within u64 range (0 to 2^64-1)
    // This prevents overflow attacks and ensures values are valid u64

    component input_range_checks[2];
    component output_range_checks[2];

    for (var i = 0; i < 2; i++) {
        // Range check input values
        input_range_checks[i] = Num2Bits(64);
        input_range_checks[i].in <== input_values[i];

        // Range check output values
        output_range_checks[i] = Num2Bits(64);
        output_range_checks[i].in <== output_values[i];
    }

    // ========== CONSTRAINT 7: ASSET CONSISTENCY ==========
    // Ensure all notes in a transfer use the same asset_id
    // This prevents mixing different assets in a single transaction
    // Users can transfer any asset, but all inputs/outputs must match

    input_asset_ids[0] === input_asset_ids[1];
    input_asset_ids[0] === output_asset_ids[0];
    input_asset_ids[0] === output_asset_ids[1];
    
    // Note: asset_id can be any value (0 = native token, >0 = other assets)
    // The runtime manages which asset_ids are valid
}

// Main component: 2 inputs, 2 outputs, 20-level tree
component main {public [merkle_root, nullifiers, commitments]} = Transfer(20);
