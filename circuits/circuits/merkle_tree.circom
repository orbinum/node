pragma circom 2.0.0;

include "./poseidon_wrapper.circom";

// Selects between two inputs based on selector bit
template Selector() {
    signal input in[2];
    signal input s;  // 0 or 1
    signal output out;

    out <== (in[1] - in[0]) * s + in[0];
}

// Merkle tree membership proof verifier
// Proves that a leaf is part of a Merkle tree with a given root
template MerkleTreeVerifier(levels) {
    signal input leaf;
    signal input path_elements[levels];
    signal input path_index[levels];  // 0 = left, 1 = right
    signal output root;

    component hashers[levels];
    component selectors[levels];
    signal current_hash[levels + 1];

    current_hash[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Constraint: path_index must be binary (0 or 1)
        // This prevents malicious Merkle proofs with invalid path indices
        path_index[i] * (path_index[i] - 1) === 0;

        selectors[i] = Selector();
        selectors[i].in[0] <== current_hash[i];
        selectors[i].in[1] <== path_elements[i];
        selectors[i].s <== path_index[i];

        hashers[i] = Poseidon2();

        // Standard Merkle tree convention:
        // path_index[i] == 0: current is LEFT child  -> hash(current, sibling)
        // path_index[i] == 1: current is RIGHT child -> hash(sibling, current)
        //
        // selectors[i].out = path_index==0 ? current : sibling
        // So: inputs[0] = selectors[i].out (the LEFT element)
        //     inputs[1] = the other one (the RIGHT element)
        hashers[i].inputs[0] <== selectors[i].out;
        hashers[i].inputs[1] <== current_hash[i] + path_elements[i] - selectors[i].out;

        current_hash[i + 1] <== hashers[i].out;
    }

    root <== current_hash[levels];
}
