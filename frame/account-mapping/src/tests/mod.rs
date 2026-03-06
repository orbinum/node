mod alias;
mod alias_sale;
mod chain_links;
mod evm_mapping;
mod private_dispatch;
mod private_links;

pub(super) fn make_commitment(chain_id: u32, address: &[u8], blinding: &[u8; 32]) -> [u8; 32] {
	use orbinum_zk_core::infrastructure::host_interface::poseidon_host_interface;

	let mut chain_id_bytes = [0u8; 32];
	chain_id_bytes[..4].copy_from_slice(&chain_id.to_le_bytes());

	let mut addr_padded = [0u8; 32];
	let copy_len = address.len().min(32);
	addr_padded[..copy_len].copy_from_slice(&address[..copy_len]);

	let inner = poseidon_host_interface::poseidon_hash_2(&chain_id_bytes, &addr_padded);
	let computed = poseidon_host_interface::poseidon_hash_2(&inner, blinding);
	computed
		.try_into()
		.expect("Poseidon output must be 32 bytes")
}
