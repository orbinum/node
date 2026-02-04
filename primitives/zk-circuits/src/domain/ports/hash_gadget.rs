//! Hash Gadget Port
//!
//! Abstract interface for hash function gadgets in circuits.

use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Port for hash function gadgets
///
/// Abstracts over different hash implementations (Poseidon, Pedersen, etc.).
pub trait HashGadgetPort {
	/// Hash two field elements
	fn hash_2(
		&self,
		left: &FpVar<Bn254Fr>,
		right: &FpVar<Bn254Fr>,
	) -> Result<FpVar<Bn254Fr>, SynthesisError>;

	/// Hash four field elements
	fn hash_4(&self, inputs: &[FpVar<Bn254Fr>; 4]) -> Result<FpVar<Bn254Fr>, SynthesisError>;

	/// Hash variable number of inputs
	fn hash_var(&self, inputs: &[FpVar<Bn254Fr>]) -> Result<FpVar<Bn254Fr>, SynthesisError>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::alloc::AllocVar;
	use ark_r1cs_std::R1CSVar;
	use ark_relations::r1cs::ConstraintSystem;
	extern crate alloc;
	use alloc::{boxed::Box, vec, vec::Vec};

	// Mock implementation for testing
	struct MockHashGadget;

	impl HashGadgetPort for MockHashGadget {
		fn hash_2(
			&self,
			left: &FpVar<Bn254Fr>,
			right: &FpVar<Bn254Fr>,
		) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			// Simple mock: add the two inputs
			let result = left + right;
			Ok(result)
		}

		fn hash_4(&self, inputs: &[FpVar<Bn254Fr>; 4]) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			// Simple mock: sum all inputs
			let mut result = inputs[0].clone();
			for input in &inputs[1..] {
				result += input;
			}
			Ok(result)
		}

		fn hash_var(&self, inputs: &[FpVar<Bn254Fr>]) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			if inputs.is_empty() {
				return Err(SynthesisError::MalformedVerifyingKey);
			}
			// Simple mock: sum all inputs
			let mut result = inputs[0].clone();
			for input in &inputs[1..] {
				result += input;
			}
			Ok(result)
		}
	}

	// Error-returning mock for error tests
	struct ErrorHashGadget;

	impl HashGadgetPort for ErrorHashGadget {
		fn hash_2(
			&self,
			_left: &FpVar<Bn254Fr>,
			_right: &FpVar<Bn254Fr>,
		) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			Err(SynthesisError::UnconstrainedVariable)
		}

		fn hash_4(&self, _inputs: &[FpVar<Bn254Fr>; 4]) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			Err(SynthesisError::UnconstrainedVariable)
		}

		fn hash_var(&self, _inputs: &[FpVar<Bn254Fr>]) -> Result<FpVar<Bn254Fr>, SynthesisError> {
			Err(SynthesisError::UnconstrainedVariable)
		}
	}

	// ===== hash_2 Tests =====

	#[test]
	fn test_hash_2_basic() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(10u64))).unwrap();
		let right = FpVar::new_witness(cs, || Ok(Bn254Fr::from(20u64))).unwrap();

		let gadget = MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
		let hash = result.unwrap();
		assert_eq!(hash.value().unwrap(), Bn254Fr::from(30u64));
	}

	#[test]
	fn test_hash_2_zero_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let right = FpVar::new_witness(cs, || Ok(Bn254Fr::from(0u64))).unwrap();

		let gadget = MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_hash_2_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let right = FpVar::new_witness(cs, || Ok(Bn254Fr::from(u64::MAX - 1))).unwrap();

		let gadget = MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
	}

	#[test]
	fn test_hash_2_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_constant(cs.clone(), Bn254Fr::from(5u64)).unwrap();
		let right = FpVar::new_constant(cs, Bn254Fr::from(15u64)).unwrap();

		let gadget = MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(20u64));
	}

	#[test]
	fn test_hash_2_mixed_witness_constant() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(7u64))).unwrap();
		let right = FpVar::new_constant(cs, Bn254Fr::from(3u64)).unwrap();

		let gadget = MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(10u64));
	}

	#[test]
	fn test_hash_2_error() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let right = FpVar::new_witness(cs, || Ok(Bn254Fr::from(2u64))).unwrap();

		let gadget = ErrorHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_err());
	}

	#[test]
	fn test_hash_2_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let left1 = FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let right1 = FpVar::new_witness(cs1, || Ok(Bn254Fr::from(200u64))).unwrap();

		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
		let left2 = FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let right2 = FpVar::new_witness(cs2, || Ok(Bn254Fr::from(200u64))).unwrap();

		let gadget = MockHashGadget;
		let result1 = gadget.hash_2(&left1, &right1).unwrap();
		let result2 = gadget.hash_2(&left2, &right2).unwrap();

		assert_eq!(result1.value().unwrap(), result2.value().unwrap());
	}

	// ===== hash_4 Tests =====

	#[test]
	fn test_hash_4_basic() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(4u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(10u64));
	}

	#[test]
	fn test_hash_4_zero_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(0u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_hash_4_large_values() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1000u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2000u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3000u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(4000u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(10000u64));
	}

	#[test]
	fn test_hash_4_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_constant(cs.clone(), Bn254Fr::from(10u64)).unwrap(),
			FpVar::new_constant(cs.clone(), Bn254Fr::from(20u64)).unwrap(),
			FpVar::new_constant(cs.clone(), Bn254Fr::from(30u64)).unwrap(),
			FpVar::new_constant(cs, Bn254Fr::from(40u64)).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(100u64));
	}

	#[test]
	fn test_hash_4_mixed_types() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(5u64))).unwrap(),
			FpVar::new_constant(cs.clone(), Bn254Fr::from(10u64)).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(15u64))).unwrap(),
			FpVar::new_constant(cs, Bn254Fr::from(20u64)).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(50u64));
	}

	#[test]
	fn test_hash_4_error() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(4u64))).unwrap(),
		];

		let gadget = ErrorHashGadget;
		let result = gadget.hash_4(&inputs);

		assert!(result.is_err());
	}

	#[test]
	fn test_hash_4_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs1 = [
			FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs1, || Ok(Bn254Fr::from(4u64))).unwrap(),
		];

		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs2 = [
			FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs2, || Ok(Bn254Fr::from(4u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result1 = gadget.hash_4(&inputs1).unwrap();
		let result2 = gadget.hash_4(&inputs2).unwrap();

		assert_eq!(result1.value().unwrap(), result2.value().unwrap());
	}

	// ===== hash_var Tests =====

	#[test]
	fn test_hash_var_single_input() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![FpVar::new_witness(cs, || Ok(Bn254Fr::from(42u64))).unwrap()];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(42u64));
	}

	#[test]
	fn test_hash_var_two_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(10u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(20u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(30u64));
	}

	#[test]
	fn test_hash_var_multiple_inputs() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(4u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(5u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(15u64));
	}

	#[test]
	fn test_hash_var_empty_inputs() {
		let inputs: Vec<FpVar<Bn254Fr>> = vec![];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_err());
	}

	#[test]
	fn test_hash_var_constants() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_constant(cs.clone(), Bn254Fr::from(100u64)).unwrap(),
			FpVar::new_constant(cs.clone(), Bn254Fr::from(200u64)).unwrap(),
			FpVar::new_constant(cs, Bn254Fr::from(300u64)).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(600u64));
	}

	#[test]
	fn test_hash_var_mixed_types() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(50u64))).unwrap(),
			FpVar::new_constant(cs.clone(), Bn254Fr::from(25u64)).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(25u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(100u64));
	}

	#[test]
	fn test_hash_var_large_count() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs: Vec<_> = (0..10)
			.map(|i| FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(i))).unwrap())
			.collect();

		let gadget = MockHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(45u64)); // 0+1+2+...+9=45
	}

	#[test]
	fn test_hash_var_error() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(2u64))).unwrap(),
		];

		let gadget = ErrorHashGadget;
		let result = gadget.hash_var(&inputs);

		assert!(result.is_err());
	}

	#[test]
	fn test_hash_var_deterministic() {
		let cs1 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs1 = vec![
			FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(10u64))).unwrap(),
			FpVar::new_witness(cs1.clone(), || Ok(Bn254Fr::from(20u64))).unwrap(),
			FpVar::new_witness(cs1, || Ok(Bn254Fr::from(30u64))).unwrap(),
		];

		let cs2 = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs2 = vec![
			FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(10u64))).unwrap(),
			FpVar::new_witness(cs2.clone(), || Ok(Bn254Fr::from(20u64))).unwrap(),
			FpVar::new_witness(cs2, || Ok(Bn254Fr::from(30u64))).unwrap(),
		];

		let gadget = MockHashGadget;
		let result1 = gadget.hash_var(&inputs1).unwrap();
		let result2 = gadget.hash_var(&inputs2).unwrap();

		assert_eq!(result1.value().unwrap(), result2.value().unwrap());
	}

	// ===== Integration Tests =====

	#[test]
	fn test_trait_object() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let left = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(5u64))).unwrap();
		let right = FpVar::new_witness(cs, || Ok(Bn254Fr::from(10u64))).unwrap();

		let gadget: &dyn HashGadgetPort = &MockHashGadget;
		let result = gadget.hash_2(&left, &right);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(15u64));
	}

	#[test]
	fn test_boxed_trait_object() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let inputs = [
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
			FpVar::new_witness(cs, || Ok(Bn254Fr::from(4u64))).unwrap(),
		];

		let gadget: Box<dyn HashGadgetPort> = Box::new(MockHashGadget);
		let result = gadget.hash_4(&inputs);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().value().unwrap(), Bn254Fr::from(10u64));
	}

	#[test]
	fn test_hash_consistency_across_methods() {
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let val1 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(10u64))).unwrap();
		let val2 = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(20u64))).unwrap();

		let gadget = MockHashGadget;

		// hash_2 and hash_var should produce same result for 2 inputs
		let result_2 = gadget.hash_2(&val1, &val2).unwrap();
		let result_var = gadget.hash_var(&[val1, val2]).unwrap();

		assert_eq!(result_2.value().unwrap(), result_var.value().unwrap());
	}
}
