//! ZK Verifier Port (Interface)
//!
//! Este trait define el puerto (en términos de arquitectura hexagonal) para
//! la verificación de pruebas ZK. Otros pallets pueden usar este trait
//! como dependencia sin acoplarse a la implementación concreta.

use sp_runtime::DispatchError;

/// Puerto de dominio para verificación de pruebas ZK
///
/// Este trait sigue los principios de Clean Architecture + DDD:
/// - Define la interfaz en la capa de dominio
/// - Las implementaciones están en la capa de infraestructura
/// - Otros pallets dependen de la abstracción, no de la implementación
pub trait ZkVerifierPort {
	/// Verificar una prueba de transferencia privada
	///
	/// # Argumentos
	/// * `proof` - Bytes de la prueba serializada
	/// * `merkle_root` - Raíz del Merkle tree usado en la prueba
	/// * `nullifiers` - Nullifiers de las notas consumidas
	/// * `commitments` - Commitments de las nuevas notas creadas
	///
	/// # Retorna
	/// * `Ok(true)` si la prueba es válida
	/// * `Ok(false)` si la prueba es inválida
	/// * `Err` si ocurre un error durante la verificación
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verificar una prueba de unshield (retiro del pool)
	///
	/// # Argumentos
	/// * `proof` - Bytes de la prueba serializada
	/// * `merkle_root` - Raíz del Merkle tree usado en la prueba
	/// * `nullifier` - Nullifier de la nota consumida
	/// * `amount` - Cantidad a retirar (parte del input público)
	/// * `version` - Versión del circuito (None para la versión activa)
	///
	/// # Retorna
	/// * `Ok(true)` si la prueba es válida
	/// * `Ok(false)` si la prueba es inválida
	/// * `Err` si ocurre un error durante la verificación
	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verificar una prueba de disclosure (selective disclosure)
	///
	/// # Argumentos
	/// * `proof` - Bytes de la prueba Groth16 serializada
	/// * `public_signals` - Public signals del disclosure
	/// * `version` - Versión del circuito (None para la versión activa)
	///
	/// # Retorna
	/// * `Ok(true)` si la prueba es válida
	/// * `Ok(false)` si la prueba es inválida
	/// * `Err` si ocurre un error durante la verificación
	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, DispatchError>;

	/// Verificar múltiples pruebas de disclosure en batch (optimizado)
	///
	/// # Argumentos
	/// * `proofs` - Vector de pruebas Groth16 serializadas
	/// * `public_signals` - Vector de public signals (uno por proof)
	/// * `version` - Versión del circuito (None para la versión activa)
	///   ...
	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;
}
