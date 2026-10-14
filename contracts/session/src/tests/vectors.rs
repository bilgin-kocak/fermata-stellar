//! Golden vectors (`test-vectors/session-v1.json`) asserted on-chain: the contract, deployed at the
//! vectors' contract id on their network, rebuilds every ticket, statement and call id byte for
//! byte, samples the same calls, and settles the recorded batches with the recorded signatures.

use fermata_verdict::{
    keys, parse_hex, session as fs,
    session_vectors::{BatchVector, Document, SessionVector},
    vectors::{LABEL, OWNER_PUBLIC_KEY},
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, BytesN, Env, Event,
};

use super::setup::{b32, transfers, DAY, FEE_BPS, PRICE, START, START_LEDGER, WINDOW};
use crate::{BatchSettled, FermataSession, FermataSessionClient, SessionStatus};
use fermata_escrow::{FermataEscrow, FermataEscrowClient};

const VECTORS: &str = include_str!("../../../../test-vectors/session-v1.json");

fn doc() -> Document {
    serde_json::from_str(VECTORS).expect("test-vectors/session-v1.json parses")
}

fn h32(env: &Env, hex: &str) -> BytesN<32> {
    b32(env, parse_hex::<32>(hex).unwrap())
}

fn h64(env: &Env, hex: &str) -> BytesN<64> {
    BytesN::from_array(env, &parse_hex::<64>(hex).unwrap())
}

struct Deployment {
    env: Env,
    session: FermataSessionClient<'static>,
    token: TokenClient<'static>,
    agent: Address,
    payout: Address,
    treasury: Address,
    service_id: BytesN<32>,
}

/// An escrow with the vectors' service (owner, label, verifier, predicate) and the session
/// contract at the vectors' contract id, on the vectors' network.
fn deploy(doc: &Document) -> Deployment {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.timestamp = START;
        l.sequence_number = START_LEDGER;
        l.network_id = parse_hex::<32>(&doc.network_id).unwrap();
    });
    let treasury = Address::generate(&env);
    let escrow_id = env.register(FermataEscrow, (Address::generate(&env), &treasury, FEE_BPS));
    let escrow = FermataEscrowClient::new(&env, &escrow_id);
    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let payout = Address::generate(&env);
    let owner = Address::from_str(&env, &keys::account_address(&OWNER_PUBLIC_KEY));
    let label = fermata_verdict::service::label(LABEL).unwrap();
    let service_id = escrow.register_service(
        &owner,
        &BytesN::from_array(&env, &label),
        &payout,
        &sac.address(),
        &PRICE,
        &WINDOW,
        &h32(&env, &doc.verifier.public_key),
        &h32(&env, &doc.predicate_hash),
        &b32(&env, [0x0a; 32]),
        &b32(&env, [0x0b; 32]),
    );
    assert_eq!(hex::encode(service_id.to_array()), doc.service_id);
    let at = Address::from_str(&env, &doc.contract);
    env.register_at(&at, FermataSession, (&escrow_id,));
    let agent = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&agent, &(1_000 * PRICE));
    Deployment {
        session: FermataSessionClient::new(&env, &at),
        token: TokenClient::new(&env, &sac.address()),
        env,
        agent,
        payout,
        treasury,
        service_id,
    }
}

impl Deployment {
    /// Opens the vector session for `max_calls` calls, with the vector ticket key and seed.
    fn open(&self, doc: &Document, v: &SessionVector, max_calls: u32) -> BytesN<32> {
        let id = h32(&self.env, &v.session_id);
        self.session.open_session(
            &self.agent,
            &id,
            &self.service_id,
            &max_calls,
            &h32(&self.env, &doc.ticket_key.public_key),
            &v.sample_k,
            &v.batch_size,
            &h32(&self.env, &v.seeds[0]),
            &(START + DAY),
        );
        id
    }

    fn settle(&self, id: &BytesN<32>, v: &SessionVector, b: &BatchVector) {
        let env = &self.env;
        let calls = &v.calls[b.from as usize..b.to as usize];
        let mut request_hashes = std::vec::Vec::new();
        for c in calls {
            request_hashes.extend(parse_hex::<32>(&c.request_hash).unwrap());
        }
        let entries: std::vec::Vec<u8> = b.entries.iter().flat_map(|e| e.bytes()).collect();
        self.session.settle_batch(
            id,
            &b.to,
            &Bytes::from_slice(env, &request_hashes),
            &h64(env, &calls.last().unwrap().ticket_signature),
            &h32(env, &b.seed),
            &Bytes::from_slice(env, &entries),
            &h64(env, &b.statement_signature),
        );
    }
}

#[test]
fn contract_rebuilds_every_ticket_and_call_id() {
    let doc = doc();
    let d = deploy(&doc);
    for v in &doc.sessions {
        let id = h32(&d.env, &v.session_id);
        for c in &v.calls {
            let message = d.session.ticket_message(&id, &c.n, &h32(&d.env, &c.chain));
            let expected = hex::decode(&c.ticket_message).unwrap();
            assert_eq!(
                message,
                Bytes::from_slice(&d.env, &expected),
                "{} call {}",
                v.name,
                c.n
            );
            assert_eq!(
                hex::encode(d.session.call_id(&id, &c.n).to_array()),
                c.call_id
            );
        }
    }
}

#[test]
fn contract_rebuilds_every_statement_and_sample() {
    let doc = doc();
    let d = deploy(&doc);
    for v in &doc.sessions {
        for b in &v.batches {
            let s = &b.statement;
            let entries: std::vec::Vec<u8> = b.entries.iter().flat_map(|e| e.bytes()).collect();
            let message = d.session.statement_message(
                &b32(&d.env, s.session_id),
                &b32(&d.env, s.service_id),
                &b32(&d.env, s.predicate_hash),
                &s.from,
                &s.to,
                &b32(&d.env, s.chain),
                &b32(&d.env, s.seed),
                &Bytes::from_slice(&d.env, &entries),
            );
            let expected = hex::decode(&b.statement_message).unwrap();
            assert_eq!(
                message,
                Bytes::from_slice(&d.env, &expected),
                "{} {}..{}",
                v.name,
                b.from,
                b.to
            );
            for (i, &expected) in b.sampled.iter().enumerate() {
                let n = b.from + 1 + i as u32;
                assert_eq!(
                    d.session.sampled(&h32(&d.env, &b.seed), &n, &v.sample_k),
                    expected
                );
            }
        }
    }
}

/// The signatures in the file, made off-chain, settle every batch on-chain, and each batch pays
/// the vendor for the calls the file says.
#[test]
fn vector_batches_settle_with_the_recorded_signatures() {
    let doc = doc();
    for v in &doc.sessions {
        let d = deploy(&doc);
        // The k = 1 session ends on its last call; the sampled one on its shorter last batch.
        let max_calls = if v.sample_k == 1 {
            v.calls.len() as u32
        } else {
            2 * v.batch_size
        };
        let id = d.open(&doc, v, max_calls);
        let fee_unit = PRICE * i128::from(FEE_BPS) / 10_000;
        let mut paid_total = 0i128;
        for b in &v.batches {
            d.settle(&id, v, b);
            let moved = transfers(&d.env, &d.token.address);
            let events = d.env.events().all().filter_by_contract(&d.session.address);
            let paid = i128::from(b.paid_calls);
            let refund = i128::from(b.to - b.from) * PRICE - paid * PRICE;
            let settled = BatchSettled {
                session_id: id.clone(),
                service_id: d.service_id.clone(),
                from: b.from,
                to: b.to,
                delivered: count(b, fs::RESULT_DELIVERED),
                failed: count(b, fs::RESULT_FAILED),
                answered: count(b, fs::RESULT_ANSWERED),
                unanswered: count(b, fs::RESULT_UNANSWERED),
                paid: b.paid_calls,
                payout_amount: paid * (PRICE - fee_unit),
                fee: paid * fee_unit,
                refund,
                chain: b32(&d.env, b.statement.chain),
                entries_hash: h32(&d.env, &b.entries_hash),
            };
            assert_eq!(
                events.events()[0],
                settled.to_xdr(&d.env, &d.session.address)
            );
            // The last batch also returns the calls never made (none for the k = 1 session).
            let last = b.to == v.calls.len() as u32;
            let rest = if last {
                i128::from(max_calls - b.to) * PRICE
            } else {
                0
            };
            let me = d.session.address.clone();
            let mut expected = std::vec::Vec::new();
            if paid > 0 {
                expected.push((me.clone(), d.payout.clone(), paid * (PRICE - fee_unit)));
                expected.push((me.clone(), d.treasury.clone(), paid * fee_unit));
            }
            if refund + rest > 0 {
                expected.push((me.clone(), d.agent.clone(), refund + rest));
            }
            assert_eq!(moved, expected, "{} {}..{}", v.name, b.from, b.to);
            paid_total += paid;
            let s = d.session.get_session(&id).unwrap();
            assert_eq!((s.settled, s.chain.to_array()), (b.to, b.statement.chain));
            let seed = if v.sample_k == 1 {
                [0; 32]
            } else {
                parse_hex::<32>(&b.seed).unwrap()
            };
            assert_eq!(s.seed.to_array(), seed);
        }
        let s = d.session.get_session(&id).unwrap();
        assert_eq!(s.status, SessionStatus::Closed, "{}", v.name);
        assert_eq!(d.token.balance(&d.session.address), 0);
        assert_eq!(d.token.balance(&d.payout), paid_total * (PRICE - fee_unit));
        assert_eq!(
            d.token.balance(&d.agent),
            1_000 * PRICE - paid_total * PRICE,
            "{}",
            v.name
        );
    }
}

fn count(b: &BatchVector, result: u32) -> u32 {
    b.entries.iter().filter(|e| e.result == result).count() as u32
}
