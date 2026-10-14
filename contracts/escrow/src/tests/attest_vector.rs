//! Milestone 1 acceptance: verdicts the attestor signed for real TLSNotary presentations of the
//! demo vendor (a 200 quote: DELIVERED; an authenticated 500: FAILED) settle on the escrow.
//! `test-vectors/attest-v1.json` is written by `apps/attestor/tests/attest.rs`, which signs for the
//! escrow at the vector's contract id on testnet. Ports Fermata's `AttestVector.t.sol` @ d7cc642:
//! the three tests deferred in Milestone 0 and its request-hash check.

use std::format;

use fermata_verdict as fv;
use serde_json::Value;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Bytes, BytesN, Env, Event as _,
};

use super::setup::*;
use crate::{
    Error, FermataEscrow, FermataEscrowClient, Released, Status, OUTCOME_DELIVERED, OUTCOME_FAILED,
};

const VECTOR: &str = include_str!("../../../../test-vectors/attest-v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("test-vectors/attest-v1.json parses")
}

fn text<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} missing"))
}

fn bytes<const N: usize>(v: &Value, pointer: &str) -> [u8; N] {
    fv::parse_hex::<N>(text(v, pointer)).unwrap()
}

/// One case of the vector, set up as on a real network: the escrow at the vector's contract id on
/// testnet, the service registered exactly as the vendor registered it (its three pinned hashes
/// and the attestor's key), and the agent's payment held for the verdict's call.
struct Case {
    env: Env,
    escrow: FermataEscrowClient<'static>,
    token: Token,
    price: i128,
    agent: Address,
    payout: Address,
    treasury: Address,
    service_id: BytesN<32>,
    verdict: fv::Verdict,
    signature: BytesN<64>,
}

fn setup(case: &str) -> Case {
    let v = vector();
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = START;
        l.sequence_number = START_LEDGER;
        l.network_id = bytes::<32>(&v, "/network_id");
    });
    let at = Address::from_str(&env, text(&v, "/contract"));
    let (owner, treasury) = (Address::generate(&env), Address::generate(&env));
    env.register_at(&at, FermataEscrow, (owner, treasury.clone(), FEE_BPS));
    let escrow = FermataEscrowClient::new(&env, &at);

    let token = Token::new(&env);
    let payout = Address::generate(&env);
    let price: i128 = text(&v, "/price_per_call").parse().unwrap();
    let window = u32::try_from(v["settlement_window"].as_u64().unwrap()).unwrap();
    let service_id = escrow.register_service(
        &Address::from_str(&env, text(&v, "/owner")),
        &BytesN::from_array(&env, &bytes::<12>(&v, &format!("/{case}/label"))),
        &payout,
        &token.address,
        &price,
        &window,
        &b32(&env, bytes(&v, "/signer/public_key")),
        &b32(&env, bytes(&v, "/predicate_hash")),
        &b32(&env, bytes(&v, &format!("/{case}/origin_hash"))),
        &b32(&env, bytes(&v, "/notary_key_hash")),
    );
    assert_eq!(
        service_id.to_array(),
        bytes::<32>(&v, &format!("/{case}/service_id"))
    );

    let verdict: fv::Verdict = serde_json::from_value(v[case]["verdict"].clone()).unwrap();
    let agent = Address::generate(&env);
    token.mint(&agent, price);
    escrow.hold(
        &agent,
        &b32(&env, verdict.call_id),
        &service_id,
        &b32(&env, verdict.request_hash),
    );
    let signature = BytesN::from_array(&env, &bytes::<64>(&v, &format!("/{case}/signature")));
    Case {
        env,
        escrow,
        token,
        price,
        agent,
        payout,
        treasury,
        service_id,
        verdict,
        signature,
    }
}

impl Case {
    fn call_id(&self) -> BytesN<32> {
        b32(&self.env, self.verdict.call_id)
    }

    fn settle(&self) {
        self.escrow.settle(
            &self.call_id(),
            &onchain(&self.env, &self.verdict),
            &self.signature,
        );
    }
}

/// `test_requestHashIsTheProvedRequest`: the hold's request hash is the request the vendor
/// received, recomputed here with the host's SHA-256.
#[test]
fn request_hash_is_the_proved_request() {
    let v = vector();
    let env = Env::default();
    let sha = |bytes: &[u8]| {
        env.crypto()
            .sha256(&Bytes::from_slice(&env, bytes))
            .to_array()
    };
    let target = text(&v, "/target");
    for case in ["delivered", "failed"] {
        let verdict: fv::Verdict = serde_json::from_value(v[case]["verdict"].clone()).unwrap();
        let request = [
            &verdict.service_id[..],
            b"GET",
            target.as_bytes(),
            &sha(b""),
        ]
        .concat();
        assert_eq!(verdict.request_hash, sha(&request), "{case}");
    }
}

/// The 294 bytes the attestor signed are the ones the contract rebuilds for these verdicts.
#[test]
fn the_contract_rebuilds_the_attestor_messages() {
    let v = vector();
    for case in ["delivered", "failed"] {
        let c = setup(case);
        let message = c.escrow.verdict_message(&onchain(&c.env, &c.verdict));
        let expected = hex::decode(text(&v, &format!("/{case}/message"))).unwrap();
        assert_eq!(message, Bytes::from_slice(&c.env, &expected), "{case}");
    }
}

/// `test_attestorDeliveredVerdictReleases`
#[test]
fn attestor_delivered_verdict_releases() {
    let c = setup("delivered");
    assert_eq!(c.verdict.outcome, OUTCOME_DELIVERED);
    let fee = c.price * i128::from(FEE_BPS) / 10_000;
    c.settle();
    let events = c.env.events().all().filter_by_contract(&c.escrow.address);
    assert_eq!(
        events,
        [Released {
            call_id: c.call_id(),
            service_id: c.service_id.clone(),
            payout: c.payout.clone(),
            amount: c.price,
            fee,
            presentation_hash: b32(&c.env, c.verdict.presentation_hash),
        }
        .to_xdr(&c.env, &c.escrow.address)]
    );
    assert_eq!(
        c.escrow.get_hold(&c.call_id()).unwrap().status,
        Status::Released
    );
    assert_eq!(c.token.balance(&c.payout), c.price - fee);
    assert_eq!(c.token.balance(&c.treasury), fee);
    assert_eq!(c.token.balance(&c.escrow.address), 0);
}

/// `test_attestorFailedVerdictRefunds`
#[test]
fn attestor_failed_verdict_refunds() {
    let c = setup("failed");
    assert_eq!(c.verdict.outcome, OUTCOME_FAILED);
    c.settle();
    assert_eq!(
        c.escrow.get_hold(&c.call_id()).unwrap().status,
        Status::Refunded
    );
    assert_eq!(c.token.balance(&c.agent), c.price);
    assert_eq!(c.token.balance(&c.payout), 0);
    assert_eq!(c.token.balance(&c.escrow.address), 0);
}

/// `test_attestorVerdictCannotSettleAnotherCall`: the signed verdict names its call; it settles
/// neither a call that was never held nor a held call it does not name. The genuine pair still
/// settles afterwards.
#[test]
fn attestor_verdict_cannot_settle_another_call() {
    let c = setup("delivered");
    let mut other = c.verdict.clone();
    other.call_id = fv::hashes::sha256(b"another call");
    let other_id = b32(&c.env, other.call_id);
    expect_error(
        c.escrow
            .try_settle(&other_id, &onchain(&c.env, &other), &c.signature),
        Error::NotHeld,
    );
    expect_error(
        c.escrow
            .try_settle(&c.call_id(), &onchain(&c.env, &other), &c.signature),
        Error::CallIdMismatch,
    );
    c.settle();
    assert_eq!(
        c.escrow.get_hold(&c.call_id()).unwrap().status,
        Status::Released
    );
}
