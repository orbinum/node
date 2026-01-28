pragma circom 2.0.0;

include "./poseidon_wrapper.circom";

// Computes note commitment: Poseidon(value, asset_id, owner_pubkey, blinding)
template NoteCommitment() {
    signal input value;
    signal input asset_id;
    signal input owner_pubkey;
    signal input blinding;
    signal output commitment;

    component hasher = Poseidon4();
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== asset_id;
    hasher.inputs[2] <== owner_pubkey;
    hasher.inputs[3] <== blinding;

    commitment <== hasher.out;
}

// Computes nullifier: Poseidon(commitment, spending_key)
template Nullifier() {
    signal input commitment;
    signal input spending_key;
    signal output nullifier;

    component hasher = Poseidon2();
    hasher.inputs[0] <== commitment;
    hasher.inputs[1] <== spending_key;

    nullifier <== hasher.out;
}
