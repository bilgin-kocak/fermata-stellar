//! `settle_batch`: what each result pays, what the ticket and the statement bind, the batch rules
//! for k = 1 and for sampled sessions, and the cost of a large batch.

use ed25519_dalek::SigningKey;
use fermata_verdict::{self as fv, session as fs};
use soroban_sdk::{testutils::Events as _, Bytes, Event};

use super::setup::*;
use crate::{BatchSettled, Error, SessionClosed, SessionStatus, ENTRY_LEN, MAX_BATCH};

fn requests(from: u32, to: u32) -> std::vec::Vec<[u8; 32]> {
    (from + 1..=to).map(request).collect()
}

// ------------------------------------------------------------------------- every call proved

#[test]
fn pays_delivered_and_refunds_failed_and_unanswered_calls() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let b = f.next_batch(
        &id,
        &requests(0, 3),
        [0; 32],
        &[delivered(1), failed(2), unanswered()],
    );
    f.settle(&id, &b);
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [
            (f.session.address.clone(), f.payout.clone(), PRICE - FEE),
            (f.session.address.clone(), f.treasury.clone(), FEE),
            (f.session.address.clone(), f.agent.clone(), 2 * PRICE),
        ]
    );
    let s = f.get(&id);
    assert_eq!(s.settled, 3);
    assert_eq!(
        s.chain.to_array(),
        fs::chain(&id.to_array(), &requests(0, 3))
    );
    assert_eq!(s.status, SessionStatus::Open);
    assert_eq!(f.balance(&f.session.address), PRICE);
}

#[test]
fn emits_batch_settled_with_the_counts_and_amounts() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let entries = [delivered(1), delivered(2), failed(3)];
    let b = f.next_batch(&id, &requests(0, 3), [0; 32], &entries);
    f.settle(&id, &b);
    let expected = BatchSettled {
        session_id: id.clone(),
        service_id: f.service_id.clone(),
        from: 0,
        to: 3,
        delivered: 2,
        failed: 1,
        answered: 0,
        unanswered: 0,
        paid: 2,
        payout_amount: 2 * (PRICE - FEE),
        fee: 2 * FEE,
        refund: PRICE,
        chain: b32(&f.env, fs::chain(&id.to_array(), &requests(0, 3))),
        entries_hash: b32(&f.env, fs::entries_hash(&entries)),
    };
    let events = f.env.events().all().filter_by_contract(&f.session.address);
    assert_eq!(
        events.events(),
        [expected.to_xdr(&f.env, &f.session.address)]
    );
}

#[test]
fn settling_the_last_call_closes_the_session() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    f.settle(
        &id,
        &f.next_batch(&id, &requests(0, 1), [0; 32], &[delivered(1)]),
    );
    let b = f.next_batch(&id, &requests(1, 2), [0; 32], &[delivered(2)]);
    f.settle(&id, &b);
    let events = f.env.events().all().filter_by_contract(&f.session.address);
    let closed = SessionClosed {
        session_id: id.clone(),
        service_id: f.service_id.clone(),
        agent: f.agent.clone(),
        refund: 0,
    };
    assert_eq!(
        events.events().last().unwrap(),
        &closed.to_xdr(&f.env, &f.session.address)
    );
    assert_eq!(f.get(&id).status, SessionStatus::Closed);
    assert_eq!(f.balance(&f.session.address), 0);
    expect_error(f.session.try_close_session(&id), Error::NotOpen);
}

#[test]
fn batches_take_any_size_up_to_b_when_every_call_is_proved() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 20);
    for (from, to) in [(0, 1), (1, 4), (4, 4 + B)] {
        let entries: std::vec::Vec<_> = (from + 1..=to).map(delivered).collect();
        f.settle(
            &id,
            &f.next_batch(&id, &requests(from, to), [0; 32], &entries),
        );
        assert_eq!(f.get(&id).settled, to);
    }
    let over: std::vec::Vec<_> = (13..=13 + B).map(delivered).collect();
    let b = f.next_batch(&id, &requests(12, 13 + B), [0; 32], &over);
    expect_error(f.try_settle(&id, &b), Error::InvalidBatch);
}

#[test]
fn anyone_can_settle() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    let b = f.next_batch(&id, &requests(0, 1), [0; 32], &[delivered(1)]);
    f.env.set_auths(&[]);
    f.settle(&id, &b);
    assert_eq!(f.get(&id).settled, 1);
}

#[test]
fn a_settled_batch_cannot_be_replayed() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let b = f.next_batch(&id, &requests(0, 2), [0; 32], &[delivered(1), delivered(2)]);
    f.settle(&id, &b);
    expect_error(f.try_settle(&id, &b), Error::InvalidBatch);
    assert_eq!(f.balance(&f.session.address), 2 * PRICE);
}

// ----------------------------------------------------------------------- what the ticket binds

/// The ticket commits the agent to each request: a request it did not sign breaks the chain, and
/// the ticket no longer verifies.
#[test]
fn a_request_the_agent_did_not_sign_does_not_settle() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let mut b = f.next_batch(&id, &requests(0, 2), [0; 32], &[delivered(1), delivered(2)]);
    b.request_hashes = Bytes::from_slice(&f.env, &[request(1), [0x99; 32]].concat());
    expect_abort(f.try_settle(&id, &b));
    // In another order, the same requests do not verify either.
    b.request_hashes = Bytes::from_slice(&f.env, &[request(2), request(1)].concat());
    expect_abort(f.try_settle(&id, &b));
    assert_eq!(f.get(&id).settled, 0);
}

#[test]
fn a_ticket_from_another_key_session_or_contract_does_not_settle() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let reqs = requests(0, 1);
    let entries = [delivered(1)];
    let id0 = id.to_array();
    let other_domain = fv::Domain {
        contract_id: [0x77; 32],
        ..f.domain()
    };
    // Each case: a ticket made differently, and the verifier's statement as usual.
    let good = f.next_batch(&id, &reqs, [0; 32], &entries);
    let tickets = [
        fs::sign_ticket(
            &SigningKey::from_bytes(&[3; 32]),
            &f.domain(),
            &id0,
            1,
            &fs::chain(&id0, &reqs),
        ),
        fs::sign_ticket(
            &f.ticket_key,
            &f.domain(),
            &[0x5d; 32],
            1,
            &fs::chain(&id0, &reqs),
        ),
        fs::sign_ticket(
            &f.ticket_key,
            &other_domain,
            &id0,
            1,
            &fs::chain(&id0, &reqs),
        ),
        fs::sign_ticket(&f.ticket_key, &f.domain(), &id0, 2, &fs::chain(&id0, &reqs)),
    ];
    for t in tickets {
        let mut b = good.clone();
        b.ticket = soroban_sdk::BytesN::from_array(&f.env, &t);
        expect_abort(f.try_settle(&id, &b));
    }
    f.settle(&id, &good);
}

// -------------------------------------------------------------------- what the statement binds

#[test]
fn a_statement_from_another_key_or_contract_does_not_settle() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let reqs = requests(0, 1);
    let other = fv::Domain {
        contract_id: [0x77; 32],
        ..f.domain()
    };
    let by_other_key = f.batch_with(
        &f.ticket_key,
        &SigningKey::from_bytes(&[3; 32]),
        &f.domain(),
        &id,
        0,
        id.to_array(),
        &reqs,
        [0; 32],
        &[delivered(1)],
    );
    expect_abort(f.try_settle(&id, &by_other_key));
    // The ticket is fine; the statement names another contract.
    let mut for_other_contract = f.next_batch(&id, &reqs, [0; 32], &[delivered(1)]);
    let elsewhere = f.batch_with(
        &f.ticket_key,
        &f.verifier,
        &other,
        &id,
        0,
        id.to_array(),
        &reqs,
        [0; 32],
        &[delivered(1)],
    );
    for_other_contract.statement = elsewhere.statement;
    expect_abort(f.try_settle(&id, &for_other_contract));
}

/// Entries changed after the verifier signed (here, FAILED turned into DELIVERED) do not settle.
#[test]
fn entries_changed_after_signing_do_not_settle() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let mut b = f.next_batch(&id, &requests(0, 2), [0; 32], &[delivered(1), failed(2)]);
    let flipped = [
        delivered(1),
        fs::Entry {
            result: fs::RESULT_DELIVERED,
            ..failed(2)
        },
    ];
    b.entries = Bytes::from_slice(
        &f.env,
        &flipped
            .iter()
            .flat_map(|e| e.bytes())
            .collect::<std::vec::Vec<u8>>(),
    );
    expect_abort(f.try_settle(&id, &b));
    assert_eq!(f.balance(&f.session.address), 4 * PRICE);
}

// ------------------------------------------------------------------------------- batch rules

#[test]
fn a_batch_must_settle_at_least_one_call_and_no_more_than_max_calls() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    let empty = f.next_batch(&id, &[], [0; 32], &[]);
    expect_error(f.try_settle(&id, &empty), Error::InvalidBatch);
    let entries: std::vec::Vec<_> = (1..=3).map(delivered).collect();
    let too_far = f.next_batch(&id, &requests(0, 3), [0; 32], &entries);
    expect_error(f.try_settle(&id, &too_far), Error::InvalidBatch);
}

#[test]
fn request_hashes_and_entries_must_match_the_number_of_calls() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let good = f.next_batch(&id, &requests(0, 2), [0; 32], &[delivered(1), delivered(2)]);
    let mut short_requests = good.clone();
    short_requests.request_hashes = Bytes::from_slice(&f.env, &request(1));
    expect_error(f.try_settle(&id, &short_requests), Error::LengthMismatch);
    let mut short_entries = good.clone();
    short_entries.entries = good.entries.slice(0..ENTRY_LEN);
    expect_error(f.try_settle(&id, &short_entries), Error::LengthMismatch);
    let mut long_entries = good.clone();
    long_entries
        .entries
        .append(&Bytes::from_array(&f.env, &[0u8; 1]));
    expect_error(f.try_settle(&id, &long_entries), Error::LengthMismatch);
    f.settle(&id, &good);
}

#[test]
fn with_k_1_the_seed_must_be_zero() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let b = f.next_batch(&id, &requests(0, 1), [0x5c; 32], &[delivered(1)]);
    expect_error(f.try_settle(&id, &b), Error::InvalidSeed);
}

#[test]
fn entries_must_follow_the_rules() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let bad = [
        // With k = 1 every call is sampled, so ANSWERED (unproved) is not allowed.
        answered(),
        // A proved result needs a presentation hash.
        fs::Entry {
            presentation_hash: [0; 32],
            ..delivered(1)
        },
        // An unproved result carries no hashes.
        fs::Entry {
            response_hash: [1; 32],
            ..unanswered()
        },
        fs::Entry {
            presentation_hash: [1; 32],
            ..unanswered()
        },
        // Unknown results.
        fs::Entry {
            result: 0,
            ..delivered(1)
        },
        fs::Entry {
            result: 5,
            ..delivered(1)
        },
    ];
    for e in bad {
        let b = f.next_batch(&id, &requests(0, 1), [0; 32], &[e]);
        expect_error(f.try_settle(&id, &b), Error::InvalidEntry);
    }
    // A failed call with no response hash is still a proof (the presentation hash is what counts).
    let b = f.next_batch(
        &id,
        &requests(0, 1),
        [0; 32],
        &[fs::Entry {
            response_hash: [0; 32],
            ..failed(1)
        }],
    );
    f.settle(&id, &b);
}

#[test]
fn batches_are_accepted_until_the_deadline_and_not_after() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let deadline = f.get(&id).deadline;
    f.warp(deadline - f.now());
    f.settle(
        &id,
        &f.next_batch(&id, &requests(0, 1), [0; 32], &[delivered(1)]),
    );
    f.warp(1);
    let late = f.next_batch(&id, &requests(1, 2), [0; 32], &[delivered(2)]);
    expect_error(f.try_settle(&id, &late), Error::WindowClosed);
}

#[test]
fn an_unknown_or_closed_session_cannot_be_settled() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    let unknown = f.batch_with(
        &f.ticket_key,
        &f.verifier,
        &f.domain(),
        &id,
        0,
        id.to_array(),
        &requests(0, 1),
        [0; 32],
        &[delivered(1)],
    );
    expect_error(f.try_settle(&id, &unknown), Error::NotOpen);
    f.open_plain(&id, 4);
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.session.close_session(&id);
    expect_error(f.try_settle(&id, &unknown), Error::NotOpen);
}

/// With no fee there is no treasury transfer; a treasury that is the session contract is refused.
#[test]
fn the_treasury_is_paid_only_a_non_zero_fee_and_never_to_this_contract() {
    let f = Fixture::new();
    f.escrow.set_fee_bps(&0);
    let free = sid(&f.env, 1);
    f.open_plain(&free, 2);
    f.settle(
        &free,
        &f.next_batch(&free, &requests(0, 1), [0; 32], &[delivered(1)]),
    );
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [(f.session.address.clone(), f.payout.clone(), PRICE)]
    );

    f.escrow.set_fee_bps(&FEE_BPS);
    let id = sid(&f.env, 2);
    f.open_plain(&id, 2);
    f.escrow.set_treasury(&f.session.address);
    let b = f.next_batch(&id, &requests(0, 1), [0; 32], &[delivered(1)]);
    expect_error(f.try_settle(&id, &b), Error::InvalidRecipient);
    f.escrow.set_treasury(&f.treasury);
    f.settle(&id, &b);
}

// --------------------------------------------------------------------------- sampled sessions

/// A secret whose seed chain samples between `lo` and `hi` of the first batch's calls (k = 4,
/// B = 8), so the tests below have proved and unproved calls to work with.
fn secret_with_sampled(lo: usize, hi: usize) -> ([u8; 32], std::vec::Vec<[u8; 32]>) {
    for i in 0..1_000u32 {
        let secret = fs_hash(b"secret", i);
        let seeds = fs::seed_chain(&secret, 3);
        let n = (1..=B).filter(|&c| fs::sampled(&seeds[1], c, 4)).count();
        if (lo..=hi).contains(&n) {
            return (secret, seeds);
        }
    }
    panic!("no secret found");
}

fn sampled_entries(
    seed: &[u8; 32],
    from: u32,
    to: u32,
    k: u32,
    failures: usize,
) -> std::vec::Vec<fs::Entry> {
    let mut failed_left = failures;
    (from + 1..=to)
        .map(|n| {
            if fs::sampled(seed, n, k) {
                if failed_left > 0 {
                    failed_left -= 1;
                    failed(n)
                } else {
                    delivered(n)
                }
            } else {
                answered()
            }
        })
        .collect()
}

#[test]
fn a_sampled_batch_pays_answered_and_delivered_calls_minus_k_1_per_proved_failure() {
    let f = Fixture::new();
    let (_, seeds) = secret_with_sampled(2, 4);
    let id = sid(&f.env, 1);
    f.open(&id, 16, 4, B, seeds[0]);
    let entries = sampled_entries(&seeds[1], 0, B, 4, 1);
    let paid = fermata_verdict::session_vectors::paid_calls(&entries, 4);
    let answered_n = entries
        .iter()
        .filter(|e| e.result == fs::RESULT_ANSWERED)
        .count() as u32;
    let delivered_n = entries
        .iter()
        .filter(|e| e.result == fs::RESULT_DELIVERED)
        .count() as u32;
    assert_eq!(paid, answered_n + delivered_n - 3);
    f.settle(&id, &f.next_batch(&id, &requests(0, B), seeds[1], &entries));
    let p = i128::from(paid);
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [
            (
                f.session.address.clone(),
                f.payout.clone(),
                p * (PRICE - FEE)
            ),
            (f.session.address.clone(), f.treasury.clone(), p * FEE),
            (
                f.session.address.clone(),
                f.agent.clone(),
                i128::from(B - paid) * PRICE
            ),
        ]
    );
    let s = f.get(&id);
    assert_eq!(
        (s.settled, s.seed.to_array(), s.status),
        (B, seeds[1], SessionStatus::Open)
    );
}

#[test]
fn the_penalty_never_takes_a_batch_below_zero() {
    let f = Fixture::new();
    let (_, seeds) = secret_with_sampled(3, 8);
    let id = sid(&f.env, 1);
    f.open(&id, 16, 4, B, seeds[0]);
    // Every sampled call failed: answered − 3 × failed is below zero, so nothing is paid.
    let entries = sampled_entries(&seeds[1], 0, B, 4, B as usize);
    assert_eq!(fermata_verdict::session_vectors::paid_calls(&entries, 4), 0);
    f.settle(&id, &f.next_batch(&id, &requests(0, B), seeds[1], &entries));
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [(
            f.session.address.clone(),
            f.agent.clone(),
            i128::from(B) * PRICE
        )]
    );
}

#[test]
fn seeds_are_revealed_in_chain_order() {
    let f = Fixture::new();
    let (_, seeds) = secret_with_sampled(1, 8);
    let id = sid(&f.env, 1);
    f.open(&id, 3 * B, 4, B, seeds[0]);
    // Revealing a later seed, or the commitment itself, is refused.
    for wrong in [seeds[2], seeds[0], [0; 32]] {
        let entries = sampled_entries(&wrong, 0, B, 4, 0);
        let b = f.next_batch(&id, &requests(0, B), wrong, &entries);
        expect_error(f.try_settle(&id, &b), Error::InvalidSeed);
    }
    for (j, seed) in (1u32..).zip(&seeds[1..]) {
        let (from, to) = ((j - 1) * B, j * B);
        let entries = sampled_entries(seed, from, to, 4, 0);
        f.settle(
            &id,
            &f.next_batch(&id, &requests(from, to), *seed, &entries),
        );
        assert_eq!(f.get(&id).seed.to_array(), *seed);
    }
    assert_eq!(f.get(&id).status, SessionStatus::Closed);
}

#[test]
fn entries_must_follow_the_sample() {
    let f = Fixture::new();
    let (_, seeds) = secret_with_sampled(1, 7);
    let id = sid(&f.env, 1);
    f.open(&id, 16, 4, B, seeds[0]);
    let good = sampled_entries(&seeds[1], 0, B, 4, 0);
    let s = (1..=B).position(|n| fs::sampled(&seeds[1], n, 4)).unwrap();
    let u = (1..=B).position(|n| !fs::sampled(&seeds[1], n, 4)).unwrap();
    let mut answered_on_sampled = good.clone();
    answered_on_sampled[s] = answered();
    let mut proof_on_unsampled = good.clone();
    proof_on_unsampled[u] = delivered(u as u32 + 1);
    for entries in [answered_on_sampled, proof_on_unsampled] {
        let b = f.next_batch(&id, &requests(0, B), seeds[1], &entries);
        expect_error(f.try_settle(&id, &b), Error::InvalidEntry);
    }
    // UNANSWERED is allowed on any call: a sampled call with no answer has nothing to prove.
    let mut unanswered_everywhere = good.clone();
    unanswered_everywhere[s] = unanswered();
    unanswered_everywhere[u] = unanswered();
    f.settle(
        &id,
        &f.next_batch(&id, &requests(0, B), seeds[1], &unanswered_everywhere),
    );
}

/// A shorter batch is a sampled session's last: its seed exposes the sample of the rest of the
/// batch, so no call may follow, and the rest of the deposit goes back to the agent.
#[test]
fn a_short_batch_ends_a_sampled_session() {
    let f = Fixture::new();
    let (_, seeds) = secret_with_sampled(1, 8);
    let id = sid(&f.env, 1);
    f.open(&id, 3 * B, 4, B, seeds[0]);
    let entries = sampled_entries(&seeds[1], 0, 3, 4, 0);
    f.settle(&id, &f.next_batch(&id, &requests(0, 3), seeds[1], &entries));
    let moved = transfers(&f.env, &f.token.address);
    let paid = i128::from(fermata_verdict::session_vectors::paid_calls(&entries, 4));
    let agent_back = (3 - paid) * PRICE + i128::from(3 * B - 3) * PRICE;
    assert_eq!(
        moved.last().unwrap(),
        &(f.session.address.clone(), f.agent.clone(), agent_back)
    );
    let s = f.get(&id);
    assert_eq!((s.settled, s.status), (3, SessionStatus::Closed));
    assert_eq!(f.balance(&f.session.address), 0);
    let more = f.batch_with(
        &f.ticket_key,
        &f.verifier,
        &f.domain(),
        &id,
        3,
        s.chain.to_array(),
        &requests(3, 4),
        seeds[2],
        &sampled_entries(&seeds[2], 3, 4, 4, 0),
    );
    expect_error(f.try_settle(&id, &more), Error::NotOpen);
}

// ------------------------------------------------------------------------------- largest batch

/// A batch of `MAX_BATCH` calls settles and, being the session's last call, closes it. What such a
/// batch costs is measured on the wasm in `cost.rs`.
#[test]
fn a_batch_of_max_batch_calls_settles() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open(&id, MAX_BATCH, 1, MAX_BATCH, [0; 32]);
    let entries: std::vec::Vec<_> = (1..=MAX_BATCH).map(delivered).collect();
    f.settle(
        &id,
        &f.next_batch(&id, &requests(0, MAX_BATCH), [0; 32], &entries),
    );
    let s = f.get(&id);
    assert_eq!((s.settled, s.status), (MAX_BATCH, SessionStatus::Closed));
    assert_eq!(f.balance(&f.payout), i128::from(MAX_BATCH) * (PRICE - FEE));
}
