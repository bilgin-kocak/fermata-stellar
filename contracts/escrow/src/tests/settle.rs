//! 4.–9. settle outcomes, signatures, binding fields and other domains (FermataEscrow.t.sol
//! tests 18–27, and AttestVector.t.sol's "a verdict cannot settle another call").

use ed25519_dalek::SigningKey;
use fermata_verdict as fv;
use soroban_sdk::{testutils::Events as _, Bytes, Event as _, IntoVal, Symbol, Val};

use super::setup::*;
use crate::{Error, HoldView, Refunded, Released, Status, OUTCOME_DELIVERED, OUTCOME_FAILED};

/// Test 18: `test_settle_delivered_paysVendorMinusFee`, settled with no authorization at all
/// (anyone can relay a verdict).
#[test]
fn settle_delivered_pays_vendor_minus_fee() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    let fee = PRICE * i128::from(FEE_BPS) / 10_000;

    env.set_auths(&[]);
    f.escrow.settle(&id, &v, &sig);

    let events = env.events().all().filter_by_contract(&f.escrow_id());
    assert_eq!(
        events,
        [Released {
            call_id: id.clone(),
            service_id: f.service_id.clone(),
            payout: f.payout.clone(),
            amount: PRICE,
            fee,
            presentation_hash: v.presentation_hash.clone(),
        }
        .to_xdr(env, &f.escrow_id())]
    );
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![
            (f.escrow_id(), f.payout.clone(), PRICE - fee),
            (f.escrow_id(), f.treasury.clone(), fee),
        ]
    );
    assert_eq!(f.token.balance(&f.payout), PRICE - fee);
    assert_eq!(f.token.balance(&f.treasury), fee);
    assert_eq!(f.token.balance(&f.escrow_id()), 0);
    // the record stays, with its data (difference 9 in PORTING_NOTES); amount and deadline are
    // reported only while Held, as on Tempo
    assert_eq!(
        f.escrow.get_hold(&id),
        Some(HoldView {
            agent: f.agent.clone(),
            service_id: f.service_id.clone(),
            request_hash: f.request(),
            amount: 0,
            held_at: START,
            deadline: 0,
            fee_bps: FEE_BPS,
            status: Status::Released,
        })
    );
    assert_eq!(f.escrow.settlement_deadline(&id), 0);
}

/// Test 19: `test_settle_delivered_feeRoundsToZero_singleTransfer`
#[test]
fn settle_delivered_fee_rounds_to_zero_single_transfer() {
    let f = Fixture::new();
    let env = &f.env;
    let cheap = f.register("cheap", &f.token.address, 199);
    let id = call(env, 1);
    f.hold_on(&cheap, &id);
    let mut v = f.verdict(&id, OUTCOME_DELIVERED);
    v.service_id = cheap;
    let sig = f.sign(&v);
    f.escrow.settle(&id, &v, &sig);
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![(f.escrow_id(), f.payout.clone(), 199)]
    );
    assert_eq!(f.token.balance(&f.payout), 199);
    assert_eq!(f.token.balance(&f.treasury), 0);
}

/// Test 20: `test_settle_delivered_zeroFee`
#[test]
fn settle_delivered_zero_fee() {
    let f = Fixture::new();
    let env = &f.env;
    f.escrow.set_fee_bps(&0);
    let id = call(env, 1);
    f.hold(&id);
    f.settle(&id, OUTCOME_DELIVERED);
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![(f.escrow_id(), f.payout.clone(), PRICE)]
    );
    assert_eq!(f.token.balance(&f.payout), PRICE);
    assert_eq!(f.token.balance(&f.treasury), 0);
}

/// Test 21: `test_settle_failed_refundsAgentInFull`
#[test]
fn settle_failed_refunds_agent_in_full() {
    let f = Fixture::new();
    let env = &f.env;
    let agent_before = f.token.balance(&f.agent);
    let id = call(env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_FAILED);
    let sig = f.sign(&v);
    f.escrow.settle(&id, &v, &sig);

    let events = env.events().all().filter_by_contract(&f.escrow_id());
    assert_eq!(
        events,
        [Refunded {
            call_id: id.clone(),
            service_id: f.service_id.clone(),
            agent: f.agent.clone(),
            amount: PRICE,
            presentation_hash: v.presentation_hash.clone(),
        }
        .to_xdr(env, &f.escrow_id())]
    );
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![(f.escrow_id(), f.agent.clone(), PRICE)]
    );
    assert_eq!(f.token.balance(&f.agent), agent_before);
    assert_eq!(f.token.balance(&f.treasury), 0);
    assert_eq!(f.token.balance(&f.payout), 0);
    assert_eq!(f.status(&id), Some(Status::Refunded));
}

/// Test 22: `test_settle_revertsOnWrongVerifier`: the host's Ed25519 check fails the call.
#[test]
fn settle_reverts_on_wrong_verifier() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign_with(&SigningKey::from_bytes(&[0xba; 32]), &v);
    assert_eq!(f.settle_raw(&id, &v, &sig), Err(trapped()));
    expect_abort(f.escrow.try_settle(&id, &v, &sig));
    assert_eq!(f.status(&id), Some(Status::Held));
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE);
    // control: the service's own verifier settles the same verdict
    f.escrow.settle(&id, &v, &f.sign(&v));
    assert_eq!(f.status(&id), Some(Status::Released));
}

/// Test 23: `test_settle_revertsOnMalformedSignatures`, adapted to Ed25519: zeroed, bit-flipped and
/// non-canonical (`S + L`) signatures fail the strict check; a signature of the wrong length
/// cannot even be passed (the argument is `BytesN<64>`).
#[test]
fn settle_reverts_on_malformed_signatures() {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let good = f.sign(&v).to_array();

    let mut flipped = good;
    flipped[10] ^= 1;
    let mut high_s = good;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(high_s[32 + i]) + u16::from(L[i]) + carry;
        high_s[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    let mut zero_r = good;
    zero_r[..32].fill(0);
    for bad in [[0u8; 64], flipped, high_s, zero_r] {
        let sig = soroban_sdk::BytesN::from_array(env, &bad);
        assert_eq!(f.settle_raw(&id, &v, &sig), Err(trapped()));
    }

    for len in [0usize, 63, 65] {
        let sig = Bytes::from_slice(env, &[7u8; 65][..len]);
        let args = (id.clone(), v.clone(), sig).into_val(env);
        let r = env.try_invoke_contract::<Val, soroban_sdk::Error>(
            &f.escrow_id(),
            &Symbol::new(env, "settle"),
            args,
        );
        assert!(r.is_err(), "a {len}-byte signature must be rejected");
    }
    assert_eq!(f.status(&id), Some(Status::Held));
}

/// Test 24: `test_settle_revertsOnMismatchedFields`: correctly signed verdicts whose fields do not
/// match the hold or the service, each with the Solidity error, in the Solidity check order.
#[test]
fn settle_reverts_on_mismatched_fields() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    f.hold(&id);
    let other_service = f.escrow.service_id(&f.vendor, &label(env, "other"));
    type Mutation = fn(&mut crate::Verdict, &soroban_sdk::BytesN<32>, &soroban_sdk::Env);
    let cases: [(Mutation, Error); 7] = [
        (
            |v, other, _| v.service_id = other.clone(),
            Error::ServiceMismatch,
        ),
        (
            |v, _, env| v.request_hash = hash(env, &[b"GET /v1/other"]),
            Error::RequestMismatch,
        ),
        (
            |v, _, env| v.predicate_hash = hash(env, &[b"weaker-predicate.json"]),
            Error::PredicateMismatch,
        ),
        (
            |v, _, env| v.call_id = hash(env, &[b"another-call"]),
            Error::CallIdMismatch,
        ),
        (|v, _, _| v.outcome = 0, Error::InvalidOutcome),
        (|v, _, _| v.outcome = 3, Error::InvalidOutcome),
        (
            |v, _, env| v.presentation_hash = b32(env, [0; 32]),
            Error::InvalidPresentation,
        ),
    ];
    for (mutate, expected) in cases {
        let mut v = f.verdict(&id, OUTCOME_DELIVERED);
        mutate(&mut v, &other_service, env);
        let sig = f.sign(&v);
        expect_error(f.escrow.try_settle(&id, &v, &sig), expected);
    }
    // nothing moved
    assert_eq!(f.status(&id), Some(Status::Held));
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE);
}

/// The brief's "tampered verdict, each field separately": a verdict signed by the verifier and
/// changed afterwards never settles. Fields the contract compares fail their check first; the
/// rest (outcome, presentation and response hashes, issue time) fail the signature.
#[test]
fn settle_rejects_each_field_tampered_after_signing() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);

    let mut t = v.clone();
    t.call_id = call(env, 2);
    expect_error(f.escrow.try_settle(&id, &t, &sig), Error::CallIdMismatch);
    let mut t = v.clone();
    t.service_id = f.escrow.service_id(&f.vendor, &label(env, "other"));
    expect_error(f.escrow.try_settle(&id, &t, &sig), Error::ServiceMismatch);
    let mut t = v.clone();
    t.request_hash = hash(env, &[b"tampered"]);
    expect_error(f.escrow.try_settle(&id, &t, &sig), Error::RequestMismatch);
    let mut t = v.clone();
    t.predicate_hash = hash(env, &[b"tampered"]);
    expect_error(f.escrow.try_settle(&id, &t, &sig), Error::PredicateMismatch);

    let mut t = v.clone();
    t.outcome = OUTCOME_FAILED;
    assert_eq!(f.settle_raw(&id, &t, &sig), Err(trapped()));
    let mut t = v.clone();
    t.presentation_hash = hash(env, &[b"tampered"]);
    assert_eq!(f.settle_raw(&id, &t, &sig), Err(trapped()));
    let mut t = v.clone();
    t.response_hash = hash(env, &[b"tampered"]);
    assert_eq!(f.settle_raw(&id, &t, &sig), Err(trapped()));
    let mut t = v.clone();
    t.issued_at += 1;
    assert_eq!(f.settle_raw(&id, &t, &sig), Err(trapped()));

    assert_eq!(f.status(&id), Some(Status::Held));
    // the untampered verdict still settles
    f.escrow.settle(&id, &v, &sig);
    assert_eq!(f.status(&id), Some(Status::Released));
}

/// AttestVector.t.sol `test_attestorVerdictCannotSettleAnotherCall`: a valid verdict for one call
/// cannot settle a second call on the same service and request, as is or re-targeted.
#[test]
fn verdict_cannot_settle_another_call() {
    let f = Fixture::new();
    let env = &f.env;
    let (a, b) = (call(env, 1), call(env, 2));
    f.hold(&a);
    let v = f.verdict(&a, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    // an unknown call
    expect_error(f.escrow.try_settle(&call(env, 3), &v, &sig), Error::NotHeld);
    f.hold(&b);
    expect_error(f.escrow.try_settle(&b, &v, &sig), Error::CallIdMismatch);
    let mut retargeted = v.clone();
    retargeted.call_id = b.clone();
    assert_eq!(f.settle_raw(&b, &retargeted, &sig), Err(trapped()));
    assert_eq!(f.status(&b), Some(Status::Held));
}

/// Test 25: `test_settle_revertsForVerdictSignedForAnotherEscrow`
#[test]
fn settle_reverts_for_verdict_signed_for_another_escrow() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let mut other = f.domain();
    other.contract_id[0] ^= 0xff;
    let sig = f.sign_for(&f.verifier, &other, &v);
    assert_eq!(f.settle_raw(&id, &v, &sig), Err(trapped()));
}

/// Test 26: `test_settle_revertsForVerdictSignedForAnotherChain`: other Stellar networks.
#[test]
fn settle_reverts_for_verdict_signed_for_another_network() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    for passphrase in [
        fv::MAINNET_PASSPHRASE,
        fv::FUTURENET_PASSPHRASE,
        fv::STANDALONE_PASSPHRASE,
    ] {
        let domain = fv::Domain {
            network_id: fv::network_id(passphrase),
            contract_id: f.domain().contract_id,
        };
        let sig = f.sign_for(&f.verifier, &domain, &v);
        assert_eq!(f.settle_raw(&id, &v, &sig), Err(trapped()));
    }
    assert_eq!(f.status(&id), Some(Status::Held));
}

/// Test 27: `test_digestMatchesIndependentImplementation`: the contract's message equals
/// `fermata-verdict`'s, byte for byte.
#[test]
fn verdict_message_matches_the_offchain_encoding() {
    let f = Fixture::new();
    let env = &f.env;
    for outcome in [OUTCOME_DELIVERED, OUTCOME_FAILED, 0, u32::MAX] {
        let mut v = f.verdict(&call(env, outcome), outcome);
        v.issued_at = u64::MAX - u64::from(outcome);
        let onchain = f.escrow.verdict_message(&v);
        let offchain = fv::message(&f.domain(), &offchain(&v));
        assert_eq!(onchain.len() as usize, fv::MESSAGE_LEN);
        assert_eq!(onchain, Bytes::from_slice(env, &offchain));
    }
}

// The cause of each rejected signature is the host's Ed25519 check, not something else.

#[test]
#[should_panic(expected = "HostError: Error(Crypto, InvalidInput)")]
fn a_wrong_verifier_fails_the_ed25519_check() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign_with(&SigningKey::from_bytes(&[0xba; 32]), &v);
    f.escrow.settle(&id, &v, &sig);
}

#[test]
#[should_panic(expected = "HostError: Error(Crypto, InvalidInput)")]
fn another_network_fails_the_ed25519_check() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let domain = fv::Domain {
        network_id: fv::network_id(fv::MAINNET_PASSPHRASE),
        contract_id: f.domain().contract_id,
    };
    f.escrow
        .settle(&id, &v, &f.sign_for(&f.verifier, &domain, &v));
}

#[test]
#[should_panic(expected = "HostError: Error(Crypto, InvalidInput)")]
fn a_tampered_outcome_fails_the_ed25519_check() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    let mut t = v;
    t.outcome = OUTCOME_FAILED;
    f.escrow.settle(&id, &t, &sig);
}
