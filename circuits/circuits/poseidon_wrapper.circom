pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Wrapper for Poseidon hash with 2 inputs
template Poseidon2() {
    signal input inputs[2];
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== inputs[0];
    hasher.inputs[1] <== inputs[1];

    out <== hasher.out;
}

// Wrapper for Poseidon hash with 4 inputs (for note commitments)
template Poseidon4() {
    signal input inputs[4];
    signal output out;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== inputs[0];
    hasher.inputs[1] <== inputs[1];
    hasher.inputs[2] <== inputs[2];
    hasher.inputs[3] <== inputs[3];

    out <== hasher.out;
}
