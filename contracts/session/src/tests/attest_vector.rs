//! Phase 1 acceptance: a batch statement the attestor signed settles on the session contract. The
//! attestor proved two calls of the session with TLSNotary against the demo vendor (a 200 quote:
//! DELIVERED; a 404: FAILED), recorded a third UNANSWERED, and signed the statement over the
//! three; the agent's ticket for call 3 covers all three requests.
//! `test-vectors/session-attest-v1.json` is written by `apps/attestor/tests/attest.rs`
//! (`session_calls_end_to_end`), which signs for the session contract at the vector's id on
//! testnet, as `contracts/escrow/src/tests/attest_vector.rs` does for verdicts.

use fermata_escrow::{FermataEscrow, FermataEscrowClient};
use fermata_verdict::{self as fv, session as fs};
use serde_json::Value;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, BytesN, Env,
};

use super::setup::{b32, expect_abort, transfers, DAY, FEE_BPS, START, START_LEDGER};
use crate::{FermataSession, FermataSessionClient, SessionStatus};

const VECTOR: &str = include_str!("../../../../test-vectors/session-attest-v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("test-vectors/session-attest-v1.json parses")
}

fn text<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} missing"))
}

fn bytes<const N: usize>(v: &Value, pointer: &str) -> [u8; N] {
    fv::parse_hex::<N>(text(v, pointer)).unwrap()
}

fn number(v: &Value, pointer: &str) -> u32 {
    u32::try_from(v.pointer(pointer).and_then(Value::as_u64).unwrap()).unwrap()
}

struct Case {
    env: Env,
    session: FermataSessionClient<'static>,
    token: TokenClient<'static>,
    agent: Address,
    payout: Address,
    treasury: Address,
    price: i128,
    session_id: BytesN<32>,
    request_hashes: Bytes,
    entries: std::vec::Vec<fs::Entry>,
}

/// The escrow with the vendor's service registered exactly as in the vector, the session contract
/// at the vector's id on testnet, and the agent's session opened with the vector's ticket key.
fn setup(contract: &str) -> Case {
    let v = vector();
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = START;
        l.sequence_number = START_LEDGER;
        l.network_id = bytes::<32>(&v, "/network_id");
    });
    let treasury = Address::generate(&env);
    let escrow_id = env.register(FermataEscrow, (Address::generate(&env), &treasury, FEE_BPS));
    let escrow = FermataEscrowClient::new(&env, &escrow_id);
    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let payout = Address::generate(&env);
    let price: i128 = text(&v, "/price_per_call").parse().unwrap();
    let service_id = escrow.register_service(
        &Address::from_str(&env, text(&v, "/owner")),
        &BytesN::from_array(&env, &bytes::<12>(&v, "/label")),
        &payout,
        &sac.address(),
        &price,
        &number(&v, "/settlement_window"),
        &b32(&env, bytes(&v, "/verifier/public_key")),
        &b32(&env, bytes(&v, "/predicate_hash")),
        &b32(&env, bytes(&v, "/origin_hash")),
        &b32(&env, bytes(&v, "/notary_key_hash")),
    );
    assert_eq!(hex::encode(service_id.to_array()), text(&v, "/service_id"));

    let at = Address::from_str(&env, contract);
    env.register_at(&at, FermataSession, (&escrow_id,));
    let session = FermataSessionClient::new(&env, &at);
    let agent = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&agent, &(100 * price));
    let session_id = b32(&env, bytes(&v, "/session_id"));
    session.open_session(
        &agent,
        &session_id,
        &service_id,
        &number(&v, "/max_calls"),
        &b32(&env, bytes(&v, "/ticket_key/public_key")),
        &1,
        &number(&v, "/batch_size"),
        &b32(&env, [0; 32]),
        &(START + DAY),
    );

    let calls = v["calls"].as_array().unwrap();
    let mut request_hashes = std::vec::Vec::new();
    let mut entries = std::vec::Vec::new();
    for c in calls {
        request_hashes.extend(fv::parse_hex::<32>(c["request_hash"].as_str().unwrap()).unwrap());
        entries.push(serde_json::from_value::<fs::Entry>(c["entry"].clone()).unwrap());
    }
    Case {
        request_hashes: Bytes::from_slice(&env, &request_hashes),
        token: TokenClient::new(&env, &sac.address()),
        env,
        session,
        agent,
        payout,
        treasury,
        price,
        session_id,
        entries,
    }
}

fn entries_bytes(env: &Env, entries: &[fs::Entry]) -> Bytes {
    Bytes::from_slice(
        env,
        &entries
            .iter()
            .flat_map(|e| e.bytes())
            .collect::<std::vec::Vec<u8>>(),
    )
}

#[test]
fn the_attestors_statement_settles_its_batch() {
    let v = vector();
    let c = setup(text(&v, "/contract"));
    let results: std::vec::Vec<u32> = c.entries.iter().map(|e| e.result).collect();
    assert_eq!(
        results,
        [
            fs::RESULT_DELIVERED,
            fs::RESULT_FAILED,
            fs::RESULT_UNANSWERED
        ]
    );
    let env = &c.env;
    // The contract rebuilds the statement the attestor signed.
    let message = c.session.statement_message(
        &c.session_id,
        &b32(env, bytes(&v, "/service_id")),
        &b32(env, bytes(&v, "/predicate_hash")),
        &0,
        &3,
        &b32(env, bytes(&v, "/statement/chain")),
        &b32(env, [0; 32]),
        &entries_bytes(env, &c.entries),
    );
    assert_eq!(
        message,
        Bytes::from_slice(env, &hex::decode(text(&v, "/message")).unwrap())
    );

    c.session.settle_batch(
        &c.session_id,
        &3,
        &c.request_hashes,
        &BytesN::from_array(env, &bytes::<64>(&v, "/ticket")),
        &b32(env, [0; 32]),
        &entries_bytes(env, &c.entries),
        &BytesN::from_array(env, &bytes::<64>(&v, "/signature")),
    );
    let fee = c.price * i128::from(FEE_BPS) / 10_000;
    let me = c.session.address.clone();
    assert_eq!(
        transfers(env, &c.token.address),
        [
            (me.clone(), c.payout.clone(), c.price - fee),
            (me.clone(), c.treasury.clone(), fee),
            (me, c.agent.clone(), 2 * c.price),
        ]
    );
    let s = c.session.get_session(&c.session_id).unwrap();
    assert_eq!(s.settled, 3);
    assert_eq!(s.chain.to_array(), bytes::<32>(&v, "/statement/chain"));
    assert_eq!(s.status, SessionStatus::Open);
}

/// The statement covers its entries and its contract: changed entries, or the same signature on
/// a session contract elsewhere, do not settle.
#[test]
fn the_statement_settles_nothing_else() {
    let v = vector();
    let c = setup(text(&v, "/contract"));
    let mut flipped = c.entries.clone();
    flipped[0].result = fs::RESULT_FAILED;
    let settle = |c: &Case, entries: &[fs::Entry]| {
        c.session.try_settle_batch(
            &c.session_id,
            &3,
            &c.request_hashes,
            &BytesN::from_array(&c.env, &bytes::<64>(&v, "/ticket")),
            &b32(&c.env, [0; 32]),
            &entries_bytes(&c.env, entries),
            &BytesN::from_array(&c.env, &bytes::<64>(&v, "/signature")),
        )
    };
    expect_abort(settle(&c, &flipped));
    let elsewhere = setup(&fv::keys::contract_address(&[0x77; 32]));
    expect_abort(settle(&elsewhere, &elsewhere.entries));
    assert_eq!(c.session.get_session(&c.session_id).unwrap().settled, 0);
}
