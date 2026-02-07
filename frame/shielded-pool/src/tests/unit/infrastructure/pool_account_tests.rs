//! Pool account tests
//!
//! Tests for pool account ID generation and management.

use crate::mock::*;

// ============================================================================

#[test]
fn pool_account_is_derived_correctly() {
	new_test_ext().execute_with(|| {
		let pool_account = ShieldedPool::pool_account_id();
		// Just verify it's a valid account
		assert!(pool_account != 0);
	});
}

// ============================================================================
