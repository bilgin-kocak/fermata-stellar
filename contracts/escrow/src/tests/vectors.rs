//! Golden vectors (`test-vectors/verdict-v1.json`) asserted on-chain: the contract rebuilds every
//! message byte for byte and settles holds with the recorded signatures. The counterpart of
//! Fermata's `Vectors.t.sol` (`test_rustSignedVerdictSettles`, `test_digestMatchesRust`).

use fermata_verdict::{parse_hex, vectors::Document};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Bytes, BytesN, Env,
};

use super::setup::*;
use crate::{FermataEscrow, FermataEscrowClient, Status};

const VECTORS: &str = include_str!("../../../../test-vectors/verdict-v1.json");

fn doc() -> Document {
    serde_json::from_str(VECTORS).expect("test-vectors/verdict-v1.json parses")
}

/// An escrow deployed at the vector's contract id on the vector's network.
fn deploy(env: &Env, network_id: &str, contract: &str) -> FermataEscrowClient<'static> {
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = START;
        l.sequence_number = START_LEDGER;
        l.network_id = parse_hex::<32>(network_id).unwrap();
    });
    let at = Address::from_str(env, contract);
    let (owner, treasury) = (Address::generate(env), Address::generate(env));
    env.register_at(&at, FermataEscrow, (owner, treasury, FEE_BPS));
    FermataEscrowClient::new(env, &at)
}

/// Registers the vector's service (owner, label, verifier, predicate) and holds the vector's
/// call; returns the escrow and the token.
fn deploy_and_hold(env: &Env, doc: &Document, i: usize) -> (FermataEscrowClient<'static>, Token) {
    let v = &doc.verdicts[i];
    let escrow = deploy(env, &v.network_id, &v.contract);
    let token = Token::new(env);
    let owner = Address::from_str(env, &doc.service.owner);
    let label = BytesN::from_array(env, &parse_hex::<12>(&doc.service.label).unwrap());
    let verifier = BytesN::from_array(env, &parse_hex::<32>(&doc.signer.public_key).unwrap());
    let service_id = escrow.register_service(
        &owner,
        &label,
        &Address::generate(env),
        &token.address,
        &PRICE,
        &WINDOW,
        &verifier,
        &b32(env, v.verdict.predicate_hash),
        &b32(env, ORIGIN),
        &b32(env, NOTARY),
    );
    assert_eq!(service_id.to_array(), v.verdict.service_id);
    let agent = Address::generate(env);
    token.mint(&agent, PRICE);
    escrow.hold(
        &agent,
        &b32(env, v.verdict.call_id),
        &service_id,
        &b32(env, v.verdict.request_hash),
    );
    (escrow, token)
}

fn signature(env: &Env, hex: &str) -> BytesN<64> {
    BytesN::from_array(env, &parse_hex::<64>(hex).unwrap())
}

#[test]
fn contract_rebuilds_every_vector_message() {
    let doc = doc();
    for v in &doc.verdicts {
        let env = Env::default();
        let escrow = deploy(&env, &v.network_id, &v.contract);
        let message = escrow.verdict_message(&onchain(&env, &v.verdict));
        let expected = hex::decode(&v.message).unwrap();
        assert_eq!(message, Bytes::from_slice(&env, &expected), "{}", v.name);
    }
}

#[test]
fn contract_derives_the_vector_service_id() {
    let doc = doc();
    let env = Env::default();
    let escrow = deploy(&env, &doc.verdicts[0].network_id, &doc.verdicts[0].contract);
    let owner = Address::from_str(&env, &doc.service.owner);
    let label = BytesN::from_array(&env, &parse_hex::<12>(&doc.service.label).unwrap());
    assert_eq!(
        hex::encode(escrow.service_id(&owner, &label).to_array()),
        doc.service.service_id
    );
}

/// `test_rustSignedVerdictSettles`: the signature in the file, made off-chain, settles on-chain.
#[test]
fn vector_signatures_settle() {
    let doc = doc();
    for (i, expected) in [(0, Status::Released), (1, Status::Refunded)] {
        let env = Env::default();
        let (escrow, token) = deploy_and_hold(&env, &doc, i);
        let v = &doc.verdicts[i];
        let call_id = b32(&env, v.verdict.call_id);
        escrow.settle(
            &call_id,
            &onchain(&env, &v.verdict),
            &signature(&env, &v.signature),
        );
        assert_eq!(escrow.get_hold(&call_id).unwrap().status, expected);
        assert_eq!(token.balance(&escrow.address), 0);
    }
}

/// The vectors for another network and another escrow carry valid signatures over the same
/// verdict, and neither settles on the testnet escrow; the testnet vector does.
#[test]
fn vectors_for_other_domains_do_not_settle_here() {
    let doc = doc();
    let env = Env::default();
    let (escrow, _) = deploy_and_hold(&env, &doc, 0);
    let v = &doc.verdicts[0];
    let call_id = b32(&env, v.verdict.call_id);
    let verdict = onchain(&env, &v.verdict);
    for other in [&doc.verdicts[2], &doc.verdicts[3]] {
        assert_eq!(other.verdict, v.verdict);
        let r = escrow.try_settle(&call_id, &verdict, &signature(&env, &other.signature));
        expect_abort(r);
    }
    escrow.settle(&call_id, &verdict, &signature(&env, &v.signature));
    assert_eq!(escrow.get_hold(&call_id).unwrap().status, Status::Released);
}
