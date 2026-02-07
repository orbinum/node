//! Tests for disclosure_condition

use crate::domain::value_objects::audit::DisclosureCondition;

type Balance = u128;
type BlockNumber = u64;

#[test]
fn always_condition_is_always_met() {
	let condition = DisclosureCondition::<Balance, BlockNumber>::Always;
	assert!(condition.is_time_delay_met(100));
	assert!(condition.is_amount_threshold_met(1000));
}

#[test]
fn time_delay_checks_work() {
	let condition = DisclosureCondition::<Balance, BlockNumber>::TimeDelay { after_block: 100 };

	assert!(!condition.is_time_delay_met(99));
	assert!(condition.is_time_delay_met(100));
	assert!(condition.is_time_delay_met(101));
}

#[test]
fn amount_threshold_checks_work() {
	let condition =
		DisclosureCondition::<Balance, BlockNumber>::AmountThreshold { min_amount: 1000 };

	assert!(!condition.is_amount_threshold_met(999));
	assert!(condition.is_amount_threshold_met(1000));
	assert!(condition.is_amount_threshold_met(1001));
}

#[test]
fn judicial_order_identification_works() {
	let condition = DisclosureCondition::<Balance, BlockNumber>::JudicialOrder {
		court_id: [1u8; 32],
		case_id: [2u8; 32],
	};

	assert!(condition.is_judicial_order());
	assert!(!DisclosureCondition::<Balance, BlockNumber>::Always.is_judicial_order());
}
