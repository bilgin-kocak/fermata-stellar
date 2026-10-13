//! 1. register (FermataEscrow.t.sol tests 1–7).

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Event as _,
};

use super::setup::*;
use crate::{Error, Service, ServiceRegistered, MAX_PRICE, MAX_WINDOW};

/// Test 1: `test_register_storesServiceAndEmits`
#[test]
fn register_stores_service_and_emits() {
    let f = Fixture::new();
    let env = &f.env;
    let second = label(env, "second");
    let verifier = public_key(env, &f.verifier);
    let id = f.escrow.register_service(
        &f.vendor,
        &second,
        &f.payout,
        &f.token.address,
        &5_000,
        &60,
        &verifier,
        &b32(env, PREDICATE),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    let events = env.events().all().filter_by_contract(&f.escrow_id());
    assert_eq!(
        events,
        [ServiceRegistered {
            service_id: id.clone(),
            owner: f.vendor.clone(),
            token: f.token.address.clone(),
            label: second.clone(),
            payout: f.payout.clone(),
            verifier: verifier.clone(),
            price_per_call: 5_000,
            settlement_window: 60,
        }
        .to_xdr(env, &f.escrow_id())]
    );
    // the id is the documented derivation, and the off-chain crate agrees
    assert_eq!(id, f.escrow.service_id(&f.vendor, &second));
    let owner = fermata_verdict::Owner::Contract(contract_id(&f.vendor));
    let expected = fermata_verdict::service_id(&owner, &second.to_array());
    assert_eq!(id.to_array(), expected);

    assert_eq!(
        f.escrow.get_service(&id),
        Some(Service {
            owner: f.vendor.clone(),
            label: second,
            settlement_window: 60,
            payout: f.payout.clone(),
            token: f.token.address.clone(),
            verifier,
            price_per_call: 5_000,
            predicate_hash: b32(env, PREDICATE),
            origin_hash: b32(env, ORIGIN),
            notary_key_hash: b32(env, NOTARY),
        })
    );
}

/// Test 2: `test_register_revertsOnDuplicate`
#[test]
fn register_reverts_on_duplicate() {
    let f = Fixture::new();
    let env = &f.env;
    let r = f.escrow.try_register_service(
        &f.vendor,
        &label(env, "quote"),
        &f.payout,
        &f.token.address,
        &PRICE,
        &WINDOW,
        &public_key(env, &f.verifier),
        &b32(env, PREDICATE),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    expect_error(r, Error::ServiceExists);
}

// Test 3: `test_register_revertsOnZeroId`: not applicable. Ids are derived from the owner and the
// label, so a zero id cannot be requested.

/// Test 4: `test_register_revertsWhenIdNotPrefixedBySender`, adapted: an id belongs to its owner.
/// Registering for another owner needs that owner's authorization, and the same label under two
/// owners gives two different ids, so no one can squat a vendor's future id.
#[test]
fn register_needs_the_owners_authorization() {
    let f = Fixture::new();
    let env = &f.env;
    let squatter = Address::generate(env);
    // squatting the vendor's future id: only the squatter signs
    env.set_auths(&[]);
    let r = f.escrow.try_register_service(
        &f.vendor,
        &label(env, "future"),
        &squatter,
        &f.token.address,
        &PRICE,
        &WINDOW,
        &public_key(env, &f.verifier),
        &b32(env, PREDICATE),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    expect_abort(r);
    env.mock_all_auths();
    // the squatter's own "future" is a different id from the vendor's "future"
    let theirs = f.escrow.register_service(
        &squatter,
        &label(env, "future"),
        &squatter,
        &f.token.address,
        &PRICE,
        &WINDOW,
        &public_key(env, &f.verifier),
        &b32(env, PREDICATE),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    let vendors = f.escrow.service_id(&f.vendor, &label(env, "future"));
    assert_ne!(theirs, vendors);
    assert_eq!(f.escrow.get_service(&vendors), None);
    assert_eq!(f.escrow.get_service(&theirs).unwrap().owner, squatter);
}

/// Test 5: `test_register_revertsOnZeroAddresses`, adapted: Stellar addresses cannot be zero; the
/// verifier key can, and a service with it could never settle.
#[test]
fn register_reverts_on_zero_verifier_key() {
    let f = Fixture::new();
    let env = &f.env;
    let r = f.escrow.try_register_service(
        &f.vendor,
        &label(env, "z"),
        &f.payout,
        &f.token.address,
        &PRICE,
        &WINDOW,
        &b32(env, [0; 32]),
        &b32(env, PREDICATE),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    expect_error(r, Error::InvalidVerifier);
}

/// Test 6: `test_register_revertsOnBadPriceOrWindow`, plus negative prices and the overflow bound.
#[test]
fn register_reverts_on_bad_price_or_window() {
    let f = Fixture::new();
    let env = &f.env;
    let register = |price: i128, window: u32| {
        f.escrow.try_register_service(
            &f.vendor,
            &label(env, "w"),
            &f.payout,
            &f.token.address,
            &price,
            &window,
            &public_key(env, &f.verifier),
            &b32(env, PREDICATE),
            &b32(env, ORIGIN),
            &b32(env, NOTARY),
        )
    };
    for (price, window) in [
        (0, WINDOW),
        (-1, WINDOW),
        (i128::MIN, WINDOW),
        (MAX_PRICE + 1, WINDOW),
        (i128::MAX, WINDOW),
        (PRICE, 0),
        (PRICE, MAX_WINDOW + 1),
    ] {
        expect_error(register(price, window), Error::InvalidService);
    }
    // the bounds themselves are accepted
    assert!(register(MAX_PRICE, MAX_WINDOW).is_ok());
    assert!(f
        .escrow
        .try_register_service(
            &f.vendor,
            &label(env, "w2"),
            &f.payout,
            &f.token.address,
            &1,
            &1,
            &public_key(env, &f.verifier),
            &b32(env, PREDICATE),
            &b32(env, ORIGIN),
            &b32(env, NOTARY),
        )
        .is_ok());
}

/// Test 7: `test_register_revertsOnUnpayablePayout`, adapted: the escrow itself, and the service's
/// token contract (the Stellar counterpart of Tempo's TIP-20 addresses).
#[test]
fn register_reverts_on_unpayable_payout() {
    let f = Fixture::new();
    let env = &f.env;
    for payout in [f.escrow_id(), f.token.address.clone()] {
        let r = f.escrow.try_register_service(
            &f.vendor,
            &label(env, "p"),
            &payout,
            &f.token.address,
            &PRICE,
            &WINDOW,
            &public_key(env, &f.verifier),
            &b32(env, PREDICATE),
            &b32(env, ORIGIN),
            &b32(env, NOTARY),
        );
        expect_error(r, Error::InvalidRecipient);
    }
}
