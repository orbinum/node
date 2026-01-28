pragma circom 2.0.0;

include "./note.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// ============================================================================
// Selective Disclosure Circuit
// ============================================================================
//
// Prueba: "Conozco un memo que genera este commitment y revelo
//          selectivamente algunos campos según disclosure mask"
//
// Security Properties:
// - Soundness: No se puede falsificar un proof sin conocer el memo real
// - Privacy: Campos no revelados permanecen criptográficamente ocultos
// - Binding: Proof está vinculado al commitment específico
//
// ============================================================================

/// Helper: Selector condicional
/// Si condition = 1: output = true_value
/// Si condition = 0: output = false_value
template Selector() {
    signal input condition;      // 0 o 1
    signal input true_value;     // Valor si condition = 1
    signal input false_value;    // Valor si condition = 0
    signal output out;
    
    // Constraint 1: condition debe ser booleano (0 o 1)
    condition * (condition - 1) === 0;
    
    // Constraint 2: out = condition * true_value + (1 - condition) * false_value
    // Reformulado para ser cuadrático:
    signal inv_condition;
    inv_condition <== 1 - condition;
    
    signal term1;
    signal term2;
    term1 <== condition * true_value;
    term2 <== inv_condition * false_value;
    
    out <== term1 + term2;
}

/// Main Selective Disclosure Circuit
template SelectiveDisclosure() {
    // ========== PUBLIC INPUTS ==========
    // Estos valores son visibles on-chain y verificables públicamente
    
    /// El commitment del note (ya existe on-chain)
    signal input commitment;
    
    /// Campos revelados (0 si oculto, valor real si revelado)
    signal input revealed_value;       // u64: monto revelado o 0
    signal input revealed_asset_id;    // u32: asset revelado o 0
    signal input revealed_owner_hash;  // hash(owner) revelado o 0
    
    // ========== PRIVATE INPUTS ==========
    // Estos valores solo los conoce el prover (usuario)
    
    /// Memo data real (privado)
    signal input value;          // u64: monto real del memo
    signal input asset_id;       // u32: asset ID real del memo
    signal input owner_pubkey;   // Campo scalar del owner public key
    signal input blinding;       // u256: blinding factor para commitment
    
    /// Viewing key para probar ownership del memo
    signal input viewing_key;
    
    /// Disclosure mask (1 = revelar, 0 = ocultar)
    signal input disclose_value;     // bool: revelar value?
    signal input disclose_asset_id;  // bool: revelar asset_id?
    signal input disclose_owner;     // bool: revelar owner?
    
    // ========== CONSTRAINT 1: COMMITMENT VERIFICATION ==========
    // Probar que el memo privado genera el commitment público
    // commitment = Poseidon([value, asset_id, owner_pubkey, blinding])
    
    component note_commitment = NoteCommitment();
    note_commitment.value <== value;
    note_commitment.asset_id <== asset_id;
    note_commitment.owner_pubkey <== owner_pubkey;
    note_commitment.blinding <== blinding;
    
    // Constrain: computed commitment debe igualar public commitment
    note_commitment.commitment === commitment;
    
    // ========== CONSTRAINT 2: VIEWING KEY VERIFICATION ==========
    // Probar que el prover conoce la viewing key correcta
    // viewing_key = Poseidon(owner_pubkey)
    // Esto previene que terceros generen disclosure proofs sin permiso
    
    component vk_hasher = Poseidon(1);
    vk_hasher.inputs[0] <== owner_pubkey;
    
    // Constraint: viewing_key debe coincidir con Poseidon(owner_pubkey)
    vk_hasher.out === viewing_key;
    
    // ========== CONSTRAINT 3: BOOLEAN CONSTRAINTS ==========
    // Verificar que las máscaras de disclosure sean booleanas (0 o 1)
    
    disclose_value * (disclose_value - 1) === 0;
    disclose_asset_id * (disclose_asset_id - 1) === 0;
    disclose_owner * (disclose_owner - 1) === 0;
    
    // ========== CONSTRAINT 4: SELECTIVE REVEAL - VALUE ==========
    // Si disclose_value = 1: revealed_value debe ser value
    // Si disclose_value = 0: revealed_value debe ser 0
    
    component value_selector = Selector();
    value_selector.condition <== disclose_value;
    value_selector.true_value <== value;
    value_selector.false_value <== 0;
    
    revealed_value === value_selector.out;
    
    // ========== CONSTRAINT 5: SELECTIVE REVEAL - ASSET ID ==========
    // Similar a value, pero para asset_id
    
    component asset_selector = Selector();
    asset_selector.condition <== disclose_asset_id;
    asset_selector.true_value <== asset_id;
    asset_selector.false_value <== 0;
    
    revealed_asset_id === asset_selector.out;
    
    // ========== CONSTRAINT 6: SELECTIVE REVEAL - OWNER ==========
    // Si disclose_owner = 1: revealed_owner_hash = Poseidon([owner_pubkey])
    // Si disclose_owner = 0: revealed_owner_hash = 0
    // 
    // Nota: Revelamos HASH del owner, no el owner completo,
    //       para preservar privacidad adicional
    
    component owner_hasher = Poseidon(1);
    owner_hasher.inputs[0] <== owner_pubkey;
    
    signal owner_hash_computed;
    owner_hash_computed <== owner_hasher.out;
    
    component owner_selector = Selector();
    owner_selector.condition <== disclose_owner;
    owner_selector.true_value <== owner_hash_computed;
    owner_selector.false_value <== 0;
    
    revealed_owner_hash === owner_selector.out;
    
    // Note: Asset ID can be any value (0 = native token, >0 = other assets)
    // The runtime manages which asset_ids are valid
    // No constraint needed here - selective disclosure works for any asset
}

// ============================================================================
// Main Component
// ============================================================================
// Define cuáles son los public inputs (resto son private)
component main {public [commitment, revealed_value, revealed_asset_id, revealed_owner_hash]} = SelectiveDisclosure();
