//! The session checks, the book and statements, offline: a mock chain, fabricated proved calls
//! (no MPC) and a book in a temporary directory. `tests/attest.rs` proves session calls for real.

use std::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::SigningKey;
use fermata_verdict::{TESTNET_PASSPHRASE, session as fs};

use super::*;
use crate::{
    chain::MockChain,
    hashes::Origin,
    http_raw::{RawRequest, RawResponse},
};

const T: u64 = 1_700_000_000;
const DAY: u64 = 86_400;
const WINDOW: u32 = 120;
const CONTRACT: [u8; 32] = [0x5e; 32];
const SESSION: [u8; 32] = [0x5a; 32];
const SERVICE: [u8; 32] = [0x22; 32];
const NOTARY_KEY: [u8; 33] = [0x02; 33];
const TARGET: &str = "/v1/quote?symbol=BTC-USD";
const PREDICATE: &[u8] = include_bytes!("../../../../predicates/quote-v1.json");

fn verifier() -> SigningKey {
    SigningKey::from_bytes(&[0x0b; 32])
}

fn ticket_key() -> SigningKey {
    SigningKey::from_bytes(&[0x7c; 32])
}

fn target() -> SessionTarget {
    SessionTarget::new(TESTNET_PASSPHRASE, CONTRACT)
}

fn origin() -> Origin {
    Origin::new("vendor.fermata.test", 8443).unwrap()
}

fn service() -> ServiceInfo {
    ServiceInfo {
        settlement_window: WINDOW,
        verifier: verifier().verifying_key().to_bytes(),
        price_per_call: 100_000,
        predicate_hash: predicate_hash(PREDICATE),
        origin_hash: origin().hash(),
        notary_key_hash: notary_key_hash(&NOTARY_KEY),
        ..ServiceInfo::default()
    }
}

fn session() -> SessionInfo {
    SessionInfo {
        service_id: SERVICE,
        price: 100_000,
        fee_bps: 50,
        verifier: verifier().verifying_key().to_bytes(),
        predicate_hash: predicate_hash(PREDICATE),
        ticket_key: ticket_key().verifying_key().to_bytes(),
        max_calls: 6,
        sample_k: 1,
        batch_size: 4,
        opened_at: T,
        deadline: T + DAY + u64::from(WINDOW),
        settled: 0,
        chain: SESSION,
        seed: [0; 32],
        status: SESSION_OPEN,
        ..SessionInfo::default()
    }
}

async fn chain_with(s: SessionInfo) -> MockChain {
    let chain = MockChain::default();
    chain.services.lock().await.insert(SERVICE, service());
    chain.sessions.lock().await.insert((CONTRACT, SESSION), s);
    *chain.now.lock().await = T + 10;
    chain
}

/// A book in a fresh temporary directory.
fn books() -> (Books, PathBuf) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "fermata-books-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    (Books::new(&dir), dir)
}

fn target_of(n: u32) -> String {
    format!("{TARGET}&call={n}")
}

/// Call n of the session, its ticket signed by `key` over `prev` extended by its request.
fn call(n: u32, prev: [u8; 32], key: &SigningKey) -> CallRequest {
    let request_target = target_of(n);
    let rh = request_hash(&SERVICE, "GET", &request_target, b"");
    let chain = fs::chain_next(&prev, &rh);
    let ticket = fs::sign_ticket(key, &target().domain, &SESSION, n, &chain);
    CallRequest {
        session_id: to_hex(&SESSION),
        n,
        ticket: to_hex(&ticket),
        method: "GET".into(),
        target: request_target,
        body: vec![],
    }
}

/// A proved call as `verify_presentation` would return it, for `a`'s call header and request.
fn proved(a: &Admitted, status: u16) -> VerifiedCall {
    let body = br#"{"price":64231.5,"timestamp":1700000005}"#.to_vec();
    VerifiedCall {
        presentation_hash: [0x9a; 32],
        notary_key: NOTARY_KEY.to_vec(),
        server_name: "vendor.fermata.test".into(),
        time: T + 5,
        sent: b"GET ... (fabricated)".to_vec(),
        received: [b"HTTP/1.1 200 OK\r\n\r\n".as_slice(), &body].concat(),
        request: RawRequest {
            method: "GET".into(),
            target: target_of(a.n),
            headers: vec![
                ("host".into(), "vendor.fermata.test:8443".into()),
                ("x-fermata-call".into(), hex0x(&a.call_id)),
            ],
            body: vec![],
        },
        response: Ok(RawResponse {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        }),
        redacted: vec![],
    }
}

fn check_of(r: Refusal) -> Check {
    match r {
        Refusal::Check(v) => v.check,
        other => panic!("expected a binding check, got {other:?}"),
    }
}

fn book_error(r: Refusal) -> String {
    match r {
        Refusal::Book(b) => b.0,
        other => panic!("expected a book refusal, got {other:?}"),
    }
}

#[allow(non_snake_case)]
fn ME() -> [u8; 32] {
    verifier().verifying_key().to_bytes()
}

/// Admits, records and decides calls 1..=results.len() with these response statuses (0: no
/// proof, recorded UNANSWERED).
async fn record_calls(chain: &MockChain, books: &Books, statuses: &[u16]) -> Vec<CallRecord> {
    let mut prev = SESSION;
    let mut out = Vec::new();
    for (i, &status) in statuses.iter().enumerate() {
        let n = i as u32 + 1;
        let a = admit(
            chain,
            &target(),
            &ME(),
            books,
            &call(n, prev, &ticket_key()),
            true,
        )
        .await
        .unwrap();
        books
            .reserve(&SESSION, &a.session, a.record())
            .await
            .unwrap()
            .unwrap();
        let entry = if status == 0 {
            Entry::unanswered()
        } else {
            decide_call(&proved(&a, status), &a, PREDICATE, T + 10)
                .unwrap()
                .0
        };
        out.push(books.complete(&SESSION, n, entry).await.unwrap());
        prev = a.chain;
    }
    out
}

// ------------------------------------------------------------------------------- admitting

#[tokio::test]
async fn admits_the_next_call_with_a_ticket_for_its_request() {
    let chain = chain_with(session()).await;
    let (books, dir) = books();
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(1, SESSION, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    assert_eq!(a.call_id, fs::call_id(&CONTRACT, &SESSION, 1));
    assert_eq!(
        a.request_hash,
        request_hash(&SERVICE, "GET", &target_of(1), b"")
    );
    assert_eq!(a.chain, fs::chain_next(&SESSION, &a.request_hash));
    assert_eq!(a.expires_at, T + DAY);
    books
        .reserve(&SESSION, &a.session, a.record())
        .await
        .unwrap()
        .unwrap();
    // Call 2 chains on call 1, which is still being proved.
    let b = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(2, a.chain, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    assert_eq!(b.chain, fs::chain_next(&a.chain, &b.request_hash));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn refuses_a_ticket_that_does_not_cover_the_request() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    let by_another_key = call(1, SESSION, &SigningKey::from_bytes(&[3; 32]));
    let r = admit(&chain, &target(), &ME(), &books, &by_another_key, true).await;
    assert_eq!(check_of(r.unwrap_err()), Check::Ticket);
    // A valid ticket, but for another request than the one to prove.
    let mut other_request = call(1, SESSION, &ticket_key());
    other_request.target = format!("{TARGET}&call=99");
    let r = admit(&chain, &target(), &ME(), &books, &other_request, true).await;
    assert_eq!(check_of(r.unwrap_err()), Check::Ticket);
    // A ticket for another session contract.
    let mut elsewhere = call(1, SESSION, &ticket_key());
    let rh = request_hash(&SERVICE, "GET", &target_of(1), b"");
    let other = SessionTarget::new(TESTNET_PASSPHRASE, [0x77; 32]);
    elsewhere.ticket = to_hex(&fs::sign_ticket(
        &ticket_key(),
        &other.domain,
        &SESSION,
        1,
        &fs::chain_next(&SESSION, &rh),
    ));
    let r = admit(&chain, &target(), &ME(), &books, &elsewhere, true).await;
    assert_eq!(check_of(r.unwrap_err()), Check::Ticket);
}

#[tokio::test]
async fn takes_calls_in_order_once_each() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    let skip = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(2, SESSION, &ticket_key()),
        true,
    )
    .await;
    assert!(book_error(skip.unwrap_err()).contains("not the next call"));
    record_calls(&chain, &books, &[200]).await;
    let again = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(1, SESSION, &ticket_key()),
        true,
    )
    .await;
    assert!(book_error(again.unwrap_err()).contains("already attested"));
    let beyond = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(7, SESSION, &ticket_key()),
        true,
    )
    .await;
    assert!(book_error(beyond.unwrap_err()).contains("outside"));
    // Settled calls are the contract's: call 3 follows them, not the book.
    let settled = SessionInfo {
        settled: 2,
        chain: [0x33; 32],
        ..session()
    };
    let chain = chain_with(settled).await;
    let r = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(2, SESSION, &ticket_key()),
        true,
    )
    .await;
    assert!(book_error(r.unwrap_err()).contains("already settled"));
    admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(3, [0x33; 32], &ticket_key()),
        true,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn refuses_sessions_it_cannot_prove() {
    let (books, _) = books();
    let first = call(1, SESSION, &ticket_key());
    for (s, why) in [
        (
            SessionInfo {
                status: 2,
                ..session()
            },
            "not Open",
        ),
        (
            SessionInfo {
                status: 0,
                ..session()
            },
            "no session",
        ),
        (
            SessionInfo {
                verifier: [9; 32],
                ..session()
            },
            "verifier",
        ),
        (
            SessionInfo {
                sample_k: 4,
                ..session()
            },
            "k = 1",
        ),
    ] {
        let chain = chain_with(s).await;
        match admit(&chain, &target(), &ME(), &books, &first, true).await {
            Err(Refusal::Check(v)) => {
                assert_eq!(v.check, Check::Session);
                assert!(v.detail.contains(why), "{}", v.detail);
            }
            other => panic!("{why}: {other:?}"),
        }
    }
}

/// Calls are proved until the session's expiry; a call can be recorded as unanswered until the
/// deadline, when its batch can still settle.
#[tokio::test]
async fn proves_until_the_expiry_and_records_unanswered_calls_until_the_deadline() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    *chain.now.lock().await = T + DAY + 1;
    let first = call(1, SESSION, &ticket_key());
    let r = admit(&chain, &target(), &ME(), &books, &first, true).await;
    assert_eq!(check_of(r.unwrap_err()), Check::Session);
    admit(&chain, &target(), &ME(), &books, &first, false)
        .await
        .unwrap();
    *chain.now.lock().await = T + DAY + u64::from(WINDOW) + 1;
    let r = admit(&chain, &target(), &ME(), &books, &first, false).await;
    assert_eq!(check_of(r.unwrap_err()), Check::Session);
}

// --------------------------------------------------------------------------- proved calls

#[tokio::test]
async fn a_proved_call_binds_to_its_ticket_and_session() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(1, SESSION, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    let (entry, failures) = decide_call(&proved(&a, 200), &a, PREDICATE, T + 10).unwrap();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(entry.result, fs::RESULT_DELIVERED);
    assert_eq!(entry.presentation_hash, [0x9a; 32]);
    assert_eq!(entry.response_hash, keccak256(&proved(&a, 200).received));
    let (failed, failures) = decide_call(&proved(&a, 500), &a, PREDICATE, T + 10).unwrap();
    assert_eq!(failed.result, fs::RESULT_FAILED);
    assert!(failures.iter().any(|f| f.contains("500")), "{failures:?}");
}

#[tokio::test]
async fn every_binding_check_fails_closed() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(1, SESSION, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    let check = |v: &VerifiedCall, a: &Admitted, predicate: &[u8], now: u64| {
        check_session_bindings(v, a, predicate, now)
            .unwrap_err()
            .check
    };
    let good = proved(&a, 200);
    check_session_bindings(&good, &a, PREDICATE, T + 10).unwrap();

    let other_notary = VerifiedCall {
        notary_key: vec![3; 33],
        ..good.clone()
    };
    assert_eq!(check(&other_notary, &a, PREDICATE, T + 10), Check::Notary);
    let mut other_origin = good.clone();
    other_origin.server_name = "evil.test".into();
    other_origin.request.headers[0].1 = "evil.test:8443".into();
    assert_eq!(check(&other_origin, &a, PREDICATE, T + 10), Check::Origin);
    let mut other_request = good.clone();
    other_request.request.target = format!("{TARGET}&call=99");
    assert_eq!(check(&other_request, &a, PREDICATE, T + 10), Check::Request);
    assert_eq!(check(&good, &a, b"{}", T + 10), Check::Predicate);
    assert_eq!(
        check(&good, &a, PREDICATE, a.session.deadline + 1),
        Check::Session
    );
    let mut other_call = good.clone();
    other_call.request.headers[1].1 = hex0x(&fs::call_id(&CONTRACT, &SESSION, 2));
    assert_eq!(check(&other_call, &a, PREDICATE, T + 10), Check::Call);
    let early = VerifiedCall {
        time: T - SESSION_SKEW_SECS - 1,
        ..good.clone()
    };
    assert_eq!(check(&early, &a, PREDICATE, T + 10), Check::Time);
    let late = VerifiedCall {
        time: a.session.deadline + 1,
        ..good
    };
    assert_eq!(check(&late, &a, PREDICATE, T + 10), Check::Time);
}

// ---------------------------------------------------------------------------- the book

#[tokio::test]
async fn the_book_survives_a_restart_and_a_call_cut_off_is_unanswered() {
    let chain = chain_with(session()).await;
    let (books, dir) = books();
    let recorded = record_calls(&chain, &books, &[200]).await;
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(2, recorded[0].chain, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    books
        .reserve(&SESSION, &a.session, a.record())
        .await
        .unwrap()
        .unwrap();
    // The attestor stops while call 2 is being proved.
    let reopened = Books::new(&dir);
    let calls = reopened.calls(&SESSION).await.unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], recorded[0]);
    assert_eq!(calls[1].entry, Some(Entry::unanswered()));
    assert_eq!(calls[1].chain, a.chain);
    // The resolution was written down: a third reader agrees.
    assert_eq!(Books::new(&dir).calls(&SESSION).await.unwrap(), calls);
    std::fs::remove_dir_all(dir).unwrap();
}

// ---------------------------------------------------------------------------- statements

#[tokio::test]
async fn signs_a_statement_the_contract_accepts() {
    let chain = chain_with(session()).await;
    let (books, dir) = books();
    let recorded = record_calls(&chain, &books, &[200, 500, 0]).await;
    let signed = sign_statement(&chain, &target(), &verifier(), &books, SESSION, 3)
        .await
        .unwrap();
    assert_eq!((signed.from, signed.to), (0, 3));
    let results: Vec<u32> = signed.entries.iter().map(|e| e.result).collect();
    assert_eq!(
        results,
        [
            fs::RESULT_DELIVERED,
            fs::RESULT_FAILED,
            fs::RESULT_UNANSWERED
        ]
    );
    assert_eq!(signed.statement.chain, recorded[2].chain);
    assert_eq!(
        signed.statement.entries_hash,
        fs::entries_hash(&signed.entries)
    );
    assert_eq!(signed.ticket, recorded[2].ticket);
    assert_eq!(
        signed.request_hashes,
        recorded
            .iter()
            .map(|r| to_hex(&r.request_hash))
            .collect::<Vec<_>>()
    );
    let signature = fermata_verdict::parse_hex::<64>(&signed.signature).unwrap();
    fs::verify_statement(&ME(), &target().domain, &signed.statement, &signature).unwrap();
    // The ticket for call 3 covers the whole batch's chain.
    let ticket = fermata_verdict::parse_hex::<64>(&signed.ticket).unwrap();
    let ticket_public = ticket_key().verifying_key().to_bytes();
    fs::verify_ticket(
        &ticket_public,
        &target().domain,
        &SESSION,
        3,
        &signed.statement.chain,
        &ticket,
    )
    .unwrap();

    // Once the contract has settled calls 1-3, the next statement starts at 3.
    chain.sessions.lock().await.insert(
        (CONTRACT, SESSION),
        SessionInfo {
            settled: 3,
            chain: recorded[2].chain,
            ..session()
        },
    );
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(4, recorded[2].chain, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    books
        .reserve(&SESSION, &a.session, a.record())
        .await
        .unwrap()
        .unwrap();
    books
        .complete(&SESSION, 4, Entry::unanswered())
        .await
        .unwrap();
    let next = sign_statement(&chain, &target(), &verifier(), &books, SESSION, 4)
        .await
        .unwrap();
    assert_eq!((next.from, next.to, next.entries.len()), (3, 4, 1));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn refuses_statements_it_cannot_stand_behind() {
    let chain = chain_with(session()).await;
    let (books, _) = books();
    let recorded = record_calls(&chain, &books, &[200, 200]).await;
    let (here, key) = (target(), verifier());
    let sign = |to: u32| sign_statement(&chain, &here, &key, &books, SESSION, to);
    // Beyond the book, or empty.
    assert!(book_error(sign(3).await.unwrap_err()).contains("not in this attestor's book"));
    assert!(book_error(sign(0).await.unwrap_err()).contains("a batch must"));
    // A call still being proved.
    let a = admit(
        &chain,
        &target(),
        &ME(),
        &books,
        &call(3, recorded[1].chain, &ticket_key()),
        true,
    )
    .await
    .unwrap();
    books
        .reserve(&SESSION, &a.session, a.record())
        .await
        .unwrap()
        .unwrap();
    assert!(book_error(sign(3).await.unwrap_err()).contains("still being proved"));
    books
        .complete(&SESSION, 3, Entry::unanswered())
        .await
        .unwrap();
    // More than B calls (B = 4) is refused; 3 is fine.
    sign(3).await.unwrap();
    // Another key's statement is not this attestor's to sign.
    let other = sign_statement(
        &chain,
        &target(),
        &SigningKey::from_bytes(&[4; 32]),
        &books,
        SESSION,
        3,
    )
    .await;
    assert!(book_error(other.unwrap_err()).contains("only for sessions it verifies"));
    // The contract's chain disagrees with the book: someone settled other calls.
    chain.sessions.lock().await.insert(
        (CONTRACT, SESSION),
        SessionInfo {
            chain: [0x99; 32],
            ..session()
        },
    );
    assert!(book_error(sign(2).await.unwrap_err()).contains("does not extend"));
    // After the deadline nothing is signed.
    chain
        .sessions
        .lock()
        .await
        .insert((CONTRACT, SESSION), session());
    *chain.now.lock().await = T + DAY + u64::from(WINDOW) + 1;
    assert!(book_error(sign(2).await.unwrap_err()).contains("deadline"));
}

#[tokio::test]
async fn refuses_a_batch_longer_than_b() {
    let chain = chain_with(SessionInfo {
        batch_size: 2,
        ..session()
    })
    .await;
    let (books, _) = books();
    record_calls(&chain, &books, &[200, 200, 200]).await;
    let r = sign_statement(&chain, &target(), &verifier(), &books, SESSION, 3).await;
    assert!(book_error(r.unwrap_err()).contains("B = 2"));
    sign_statement(&chain, &target(), &verifier(), &books, SESSION, 2)
        .await
        .unwrap();
}
