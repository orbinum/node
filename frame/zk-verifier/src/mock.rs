//! Mock runtime and storage helpers for testing pallet-zk-verifier.

use crate as pallet_zk_verifier;
use crate::{
	CircuitId, VkBytes,
	pallet::{ActiveCircuitVersion, VerificationKeys},
	types::{ProofSystem, VerificationKeyInfo},
};
use frame_support::{derive_impl, parameter_types};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ZkVerifier: pallet_zk_verifier,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const MaxProofSize: u32 = 256;
	pub const MaxPublicInputs: u32 = 16;
}

impl pallet_zk_verifier::Config for Test {
	type MaxProofSize = MaxProofSize;
	type MaxPublicInputs = MaxPublicInputs;
	type WeightInfo = crate::weights::SubstrateWeight<Test>;
}

/// Empty storage at block 1: events are only deposited past block 0.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.expect("mock storage should build");
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
	ext
}

/// A serialized BN254 Groth16 key with `arity` public inputs. It deserializes
/// like a real one; tests never check a pairing (`do_verify` is stubbed).
pub fn real_vk(arity: usize) -> VkBytes {
	use ark_bn254::{Bn254, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	use ark_groth16::VerifyingKey as ArkVk;

	let vk = ArkVk::<Bn254> {
		alpha_g1: G1Affine::generator(),
		beta_g2: G2Affine::generator(),
		gamma_g2: G2Affine::generator(),
		delta_g2: G2Affine::generator(),
		gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
	};
	orbinum_zk_verifier::VerifyingKey::from_ark_vk(&vk)
		.unwrap()
		.bytes
		.try_into()
		.expect("serialized VK fits in MAX_VK_BYTES")
}

/// Store `key_data` for `(circuit_id, version)` directly, skipping registration checks.
pub fn insert_key(circuit_id: CircuitId, version: u32, key_data: VkBytes) {
	VerificationKeys::<Test>::insert(
		circuit_id,
		version,
		VerificationKeyInfo {
			key_data,
			system: ProofSystem::Groth16,
			registered_at: 0u64,
		},
	);
}

/// Store a well-formed key of `arity` public inputs for `(circuit_id, version)`.
pub fn insert_vk(circuit_id: CircuitId, version: u32, arity: usize) {
	insert_key(circuit_id, version, real_vk(arity));
}

/// Set the active version directly, without the extrinsic's checks or event.
pub fn activate(circuit_id: CircuitId, version: u32) {
	ActiveCircuitVersion::<Test>::insert(circuit_id, version);
}
