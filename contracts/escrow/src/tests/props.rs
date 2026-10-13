//! 15. fuzz (FermataEscrow.t.sol `testFuzz_*`) as proptest properties, at Foundry's 512 runs.

use ed25519_dalek::SigningKey;
use proptest::prelude::*;

use super::setup::*;
use crate::{Status, MAX_PRICE, OUTCOME_DELIVERED, OUTCOME_FAILED};

/// Ordinary prices, and prices up to the bound where `price × fee_bps` would overflow.
fn price() -> impl Strategy<Value = i128> {
    prop_oneof![
        1i128..=1_000_000_000_000_000_000,
        (MAX_PRICE - 1_000_000_000)..=MAX_PRICE,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// `testFuzz_feeSplitIsExact`: the vendor and the treasury together receive exactly the
    /// price, the treasury exactly `floor(price × bps / 10 000)`, and the escrow keeps nothing.
    #[test]
    fn fee_split_is_exact(price in price(), fee in 0u32..=500) {
        let f = Fixture::new();
        f.escrow.set_fee_bps(&fee);
        let service = f.register("fuzz", &f.token.address, price);
        f.token.mint(&f.agent, price);
        let id = call(&f.env, 1);
        f.hold_on(&service, &id);
        let mut v = f.verdict(&id, OUTCOME_DELIVERED);
        v.service_id = service;
        let sig = f.sign(&v);
        f.escrow.settle(&id, &v, &sig);
        let (paid, fee_paid) = (f.token.balance(&f.payout), f.token.balance(&f.treasury));
        prop_assert_eq!(paid + fee_paid, price);
        prop_assert_eq!(fee_paid, price * i128::from(fee) / 10_000);
        prop_assert!(fee_paid >= 0 && fee_paid <= price);
        prop_assert_eq!(f.token.balance(&f.escrow_id()), 0);
    }

    /// `testFuzz_foreignSignerNeverSettles`: no key but the service's verifier settles a hold,
    /// for either outcome.
    #[test]
    fn foreign_signer_never_settles(seed in any::<[u8; 32]>(), delivered in any::<bool>()) {
        prop_assume!(seed != VERIFIER_SEED);
        let f = Fixture::new();
        let id = call(&f.env, 1);
        f.hold(&id);
        let outcome = if delivered { OUTCOME_DELIVERED } else { OUTCOME_FAILED };
        let v = f.verdict(&id, outcome);
        let sig = f.sign_with(&SigningKey::from_bytes(&seed), &v);
        prop_assert_eq!(f.settle_raw(&id, &v, &sig), Err(trapped()));
        prop_assert_eq!(f.status(&id), Some(Status::Held));
        prop_assert_eq!(f.token.balance(&f.escrow_id()), PRICE);
    }
}
