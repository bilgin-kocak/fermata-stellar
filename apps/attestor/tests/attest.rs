//! Integration test: real MPC-TLS proofs against the demo vendor (`apps/vendor`, Node, TLS 1.2)
//! through a notary process, verified against a mock chain; one negative case per binding check.
//! Writes the acceptance vector the escrow settles in `contracts/escrow/src/tests/attest_vector.rs`.
//!
//!   cargo test --release -- --ignored --nocapture      (needs node and openssl on PATH)
//!
//! The vector goes to `out/attest-v1.json`; with `FERMATA_UPDATE_VECTORS=1` it also replaces the
//! committed `test-vectors/attest-v1.json`.
//!
//! Ported from Fermata `apps/attestor/tests/attest.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! Apache-2.0): the same sessions, cases and assertions. Changed: verdicts are Ed25519 signatures
//! for a Stellar escrow, checked with `fermata-verdict::verify` instead of `ecrecover`; services
//! are identified by an owner address and a label; the vector replaces Fermata's Foundry fixture.

use std::{
    net::TcpListener as StdListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use fermata_attest::{
    chain::{ChainView, HoldInfo, MockChain, STATUS_HELD, ServiceInfo},
    config::load_roots,
    hashes::{Origin, hex0x, keccak256, notary_key_hash, predicate_hash, request_hash, to_hex},
    notary,
    prove::{self, ProveRequest, default_redactions},
    verify::{self, Check, Expected, SignedVerdict, VerifyError},
};
use fermata_verdict::{
    Domain, OUTCOME_DELIVERED, OUTCOME_FAILED, Owner, TESTNET_PASSPHRASE,
    keys::{account_address, contract_address},
    network_id, parse_hex,
    service::label,
    service_id,
};
use serde_json::json;
use tlsn::webpki::CertificateDer;

const NOTARY_KEY: [u8; 32] = [0x22; 32];
const OTHER_NOTARY_KEY: [u8; 32] = [0x33; 32];
/// The verifier's Ed25519 seed (test only).
const VERIFIER_SEED: [u8; 32] = [0x0b; 32];
/// The escrow the vector is signed for: `attest_vector.rs` registers the contract at this id.
const ESCROW: [u8; 32] = {
    let mut id = [0u8; 32];
    id[30] = 0xfe;
    id[31] = 0x1a;
    id
};
/// The vendor's account (owner and payout of every service here).
const VENDOR: [u8; 32] = [0xbe; 32];
const TOKEN: [u8; 32] = [0x20; 32];
const PRICE: i128 = 100_000;
const WINDOW: u32 = 120;
const TARGET: &str = "/v1/quote?symbol=BTC-USD";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn verifier() -> SigningKey {
    SigningKey::from_bytes(&VERIFIER_SEED)
}

fn domain() -> Domain {
    Domain::new(TESTNET_PASSPHRASE, ESCROW)
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_port(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listening on {port}");
}

async fn vendor(chaos: &str) -> (Proc, u16) {
    let port = free_port();
    let child = Command::new("node")
        .arg(root().join("apps/vendor/server.mjs"))
        .env("PORT", port.to_string())
        .env("CHAOS", chaos)
        .stdout(Stdio::null())
        .spawn()
        .expect("node on PATH");
    wait_port(port).await;
    (Proc(child), port)
}

/// The notary runs as its own process, as in production: prover and notary MPC in one tokio
/// runtime starve each other and a session can stall (seen in Fermata; never with two processes).
async fn spawn_notary(key: [u8; 32], ca: &Path) -> (Proc, String) {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_fermata-attest"))
        .args(["notary", "--listen", &format!("127.0.0.1:{port}"), "--ca"])
        .arg(ca)
        .env("NOTARY_PRIVATE_KEY", hex0x(&key))
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_port(port).await;
    (Proc(child), format!("127.0.0.1:{port}"))
}

fn origin(port: u16) -> Origin {
    Origin::new("vendor.fermata.test", port).unwrap()
}

fn request(
    notary: &str,
    port: u16,
    roots: &[CertificateDer],
    call_id: [u8; 32],
    redact: Vec<String>,
) -> ProveRequest {
    ProveRequest {
        notary: notary.to_string(),
        connect: format!("127.0.0.1:{port}"),
        origin: origin(port),
        roots: roots.to_vec(),
        method: "GET".into(),
        target: TARGET.into(),
        headers: vec![
            ("authorization".into(), "Bearer sk_live_do_not_leak".into()),
            ("accept".into(), "application/json".into()),
        ],
        body: vec![],
        call_id,
        max_sent: 4096,
        max_recv: 16384,
        redact,
        setup_timeout: Duration::from_secs(5),
        proxy: None,
    }
}

async fn prove_ok(req: &ProveRequest) -> Vec<u8> {
    prove_counted(req).await.presentation
}

async fn prove_counted(req: &ProveRequest) -> prove::ProveOutput {
    let out = prove::prove(req, 3, Duration::from_secs(15))
        .await
        .expect("prove");
    println!(
        "proved {} in {} ms ({} attempt(s)), MPC traffic {} B sent / {} B received",
        req.connect, out.prove_ms, out.attempts, out.notary_bytes.sent, out.notary_bytes.received
    );
    assert!(
        out.notary_bytes.sent > 100_000 && out.notary_bytes.received > 100_000,
        "MPC traffic not counted"
    );
    out
}

/// A service the vendor registers under `label` for the vendor on `port`, as `get_service` would
/// return it, with its id.
fn register(
    services: &mut Vec<(ServiceInfo, [u8; 32])>,
    name: &str,
    port: u16,
    predicate: &[u8],
) -> ([u8; 32], ServiceInfo) {
    let label = label(name).unwrap();
    let sid = service_id(&Owner::Account(VENDOR), &label);
    let svc = ServiceInfo {
        owner: account_address(&VENDOR),
        label,
        settlement_window: WINDOW,
        payout: account_address(&VENDOR),
        token: contract_address(&TOKEN),
        verifier: verifier().verifying_key().to_bytes(),
        price_per_call: PRICE,
        predicate_hash: predicate_hash(predicate),
        origin_hash: origin(port).hash(),
        notary_key_hash: notary_key_hash(&notary::public_key(&NOTARY_KEY).unwrap()),
    };
    services.push((svc.clone(), sid));
    (sid, svc)
}

fn hold_for(sid: [u8; 32], now: u64) -> HoldInfo {
    HoldInfo {
        agent: account_address(&[0xa9; 32]),
        service_id: sid,
        request_hash: request_hash(&sid, "GET", TARGET, b""),
        amount: PRICE,
        held_at: now - 5,
        deadline: now + 300,
        fee_bps: 50,
        status: STATUS_HELD,
    }
}

fn check_of(e: anyhow::Error) -> Check {
    e.downcast_ref::<VerifyError>()
        .unwrap_or_else(|| panic!("not a VerifyError: {e:#}"))
        .check
}

/// The signature verifies under the verifier's key for this escrow on this network, exactly as
/// the escrow's `ed25519_verify` checks it, and the reported message is the signed one.
fn assert_signed(signed: &SignedVerdict) {
    let public = verifier().verifying_key().to_bytes();
    let signature = parse_hex::<64>(&signed.signature).unwrap();
    fermata_verdict::verify(&public, &domain(), &signed.verdict, &signature)
        .expect("signature verifies");
    assert_eq!(
        signed.message,
        to_hex(&fermata_verdict::message(&domain(), &signed.verdict))
    );
    assert_eq!(signed.signer, account_address(&public));
    assert_eq!(signed.signer_key, to_hex(&public));
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn gen_other_ca(dir: &Path) -> PathBuf {
    let key = dir.join("other-ca-key.pem");
    let cert = dir.join("other-ca.pem");
    let ok = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "openssl ecparam -name prime256v1 -genkey -noout -out {k} && openssl req -x509 -new -key {k} -sha256 -days 2 -subj /CN=Other -out {c}",
            k = key.display(),
            c = cert.display()
        ))
        .status()
        .unwrap()
        .success();
    assert!(ok, "openssl");
    cert
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs node + openssl; run with --ignored"]
async fn attestor_end_to_end() {
    let vendor_dir = root().join("apps/vendor");
    if !vendor_dir.join("certs/ca.pem").exists() {
        assert!(
            Command::new("bash")
                .arg(vendor_dir.join("gen-certs.sh"))
                .status()
                .unwrap()
                .success()
        );
    }
    let roots = load_roots(&vendor_dir.join("certs/ca.pem")).unwrap();
    let predicate = std::fs::read(root().join("predicates/quote-v1.json")).unwrap();

    let (_ok, ok_port) = vendor("").await;
    let (_e500, port_500) = vendor("500").await;
    let (_trunc, port_trunc) = vendor("truncate").await;
    let (_hang, port_hang) = vendor("hang").await;
    let ca = vendor_dir.join("certs/ca.pem");
    let (_notary, notary_addr) = spawn_notary(NOTARY_KEY, &ca).await;
    let (_other, other_notary) = spawn_notary(OTHER_NOTARY_KEY, &ca).await;

    let mut services = Vec::new();
    let (sid_ok, svc_ok) = register(&mut services, "attest-ok", ok_port, &predicate);
    let (sid_500, svc_500) = register(&mut services, "attest-500", port_500, &predicate);
    let (sid_trunc, _) = register(&mut services, "attest-trunc", port_trunc, &predicate);

    // Holds exist before the calls are proved, as in production (check 7 compares the TLS session
    // time with the hold window).
    let t = now();
    let call_ok = [0xc1; 32];
    let call_500 = [0xc2; 32];
    let call_trunc = [0xc3; 32];
    let req_ok = request(&notary_addr, ok_port, &roots, call_ok, default_redactions());
    let t0 = std::time::Instant::now();
    let first = prove_counted(&req_ok).await;
    let ok_ms = t0.elapsed().as_millis();
    // An attempt that stalls in MPC setup is cut off after the setup timeout and retried
    // (prove.rs), so each retried attempt may add that much. Any other stall takes the attempt's
    // full 15 s and breaks the bound.
    let bound = 10_000 + u128::from(first.attempts - 1) * req_ok.setup_timeout.as_millis();
    assert!(
        ok_ms < bound,
        "first prove took {ok_ms} ms in {} attempt(s), bound {bound} ms (stalled session?)",
        first.attempts
    );
    let p_ok = first.presentation;
    let p_500 = prove_ok(&request(
        &notary_addr,
        port_500,
        &roots,
        call_500,
        default_redactions(),
    ))
    .await;
    let p_trunc = prove_ok(&request(
        &notary_addr,
        port_trunc,
        &roots,
        call_trunc,
        default_redactions(),
    ))
    .await;
    let p_other_notary = prove_ok(&request(
        &other_notary,
        ok_port,
        &roots,
        call_ok,
        default_redactions(),
    ))
    .await;
    let mut bad_redact = default_redactions();
    bad_redact.push("x-fermata-call".into());
    let p_bad_redact = prove_ok(&request(&notary_addr, ok_port, &roots, call_ok, bad_redact)).await;
    println!(
        "proved 5 sessions (first {ok_ms} ms, presentation {} bytes)",
        p_ok.len()
    );

    let chain = MockChain::default();
    for (svc, sid) in &services {
        chain.services.lock().await.insert(*sid, svc.clone());
    }
    for (call, sid) in [
        (call_ok, sid_ok),
        (call_500, sid_500),
        (call_trunc, sid_trunc),
    ] {
        chain.holds.lock().await.insert(call, hold_for(sid, t));
    }
    *chain.now.lock().await = t;
    let predicates = |h: &[u8; 32]| (*h == predicate_hash(&predicate)).then(|| predicate.clone());
    let key = verifier();
    let attest = |bytes: Vec<u8>, call: [u8; 32]| {
        let chain = &chain;
        let roots = &roots;
        let key = &key;
        async move { verify::attest(&bytes, call, roots, chain, predicates, &domain(), key, t).await }
    };

    // ---------------------------------------------------------------- outcomes
    let delivered = attest(p_ok.clone(), call_ok)
        .await
        .expect("ok presentation attests");
    assert_eq!(
        delivered.verdict.outcome, OUTCOME_DELIVERED,
        "{:?}",
        delivered.failures
    );
    assert_signed(&delivered);
    assert_eq!(
        delivered.verdict.request_hash,
        request_hash(&sid_ok, "GET", TARGET, b"")
    );
    assert_eq!(delivered.verdict.presentation_hash, keccak256(&p_ok));

    // offline re-verification recomputes exactly what the verdict committed to
    let rv = verify::reverify(&p_ok, &roots, call_ok, Some(sid_ok), Some(&predicate)).unwrap();
    assert_eq!(rv["outcome"], "DELIVERED");
    assert_eq!(rv["requestHash"], to_hex(&delivered.verdict.request_hash));
    assert_eq!(
        rv["presentationHash"],
        to_hex(&delivered.verdict.presentation_hash)
    );
    assert_eq!(rv["responseHash"], to_hex(&delivered.verdict.response_hash));
    assert_eq!(rv["originHash"], to_hex(&svc_ok.origin_hash));
    assert_eq!(rv["callHeaderMatches"], true);
    assert!(!rv["request"].as_str().unwrap().contains("sk_live"));

    let failed_500 = attest(p_500, call_500).await.expect("500 attests");
    assert_eq!(failed_500.verdict.outcome, OUTCOME_FAILED);
    assert_signed(&failed_500);
    assert!(
        failed_500.failures.iter().any(|f| f.contains("status 500")),
        "{:?}",
        failed_500.failures
    );
    let failed_trunc = attest(p_trunc, call_trunc)
        .await
        .expect("truncated attests");
    assert_eq!(failed_trunc.verdict.outcome, OUTCOME_FAILED);
    assert!(
        failed_trunc
            .failures
            .iter()
            .any(|f| f.contains("not valid JSON")),
        "{:?}",
        failed_trunc.failures
    );

    // The secret never appears in the presentation.
    let v = verify::verify_presentation(&p_ok, &roots).unwrap();
    assert!(
        !String::from_utf8_lossy(&v.sent).contains("sk_live"),
        "token leaked"
    );
    assert!(
        !p_ok.windows(7).any(|w| w == b"sk_live"),
        "token bytes in presentation"
    );
    assert_eq!(v.redacted.len(), 1);

    // ---------------------------------------------------------------- negatives: no verdict, right check
    let base = Expected {
        call_id: call_ok,
        hold: hold_for(sid_ok, t),
        service: svc_ok.clone(),
        predicate_bytes: predicate.clone(),
        now: t,
    };
    let expect = |mutate: &dyn Fn(&mut Expected), check: Check| {
        let mut e = base.clone();
        mutate(&mut e);
        let err = verify::check_bindings(&v, &e).expect_err("must fail");
        assert_eq!(err.check, check, "{err}");
    };
    // 1. notary
    expect(&|e| e.service.notary_key_hash = [9; 32], Check::Notary);
    assert_eq!(
        check_of(attest(p_other_notary, call_ok).await.unwrap_err()),
        Check::Notary
    );
    // 2. origin
    expect(
        &|e| e.service.origin_hash = origin(ok_port + 1).hash(),
        Check::Origin,
    );
    let mut wrong_host = v.clone();
    wrong_host.request.headers.retain(|(k, _)| k != "host");
    wrong_host
        .request
        .headers
        .push(("host".into(), "evil.example:443".into()));
    assert_eq!(
        verify::check_bindings(&wrong_host, &base)
            .unwrap_err()
            .check,
        Check::Origin
    );
    let tmp = std::env::temp_dir().join(format!("fermata-attest-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let other_roots = load_roots(&gen_other_ca(&tmp)).unwrap();
    assert_eq!(
        verify::verify_presentation(&p_ok, &other_roots)
            .unwrap_err()
            .check,
        Check::Presentation
    );
    // 3. request
    expect(&|e| e.hold.request_hash = [7; 32], Check::Request);
    assert_eq!(
        verify::verify_presentation(&p_bad_redact, &roots)
            .unwrap_err()
            .check,
        Check::Request
    );
    // 4. predicate
    expect(
        &|e| e.predicate_bytes = b"{\"version\":1,\"status\":[200,500]}".to_vec(),
        Check::Predicate,
    );
    // 5. hold
    expect(&|e| e.hold.status = 3, Check::Hold);
    expect(&|e| e.now = e.hold.deadline + 1, Check::Hold);
    chain.holds.lock().await.get_mut(&call_ok).unwrap().status = 2;
    assert_eq!(
        check_of(attest(p_ok.clone(), call_ok).await.unwrap_err()),
        Check::Hold
    );
    chain.holds.lock().await.get_mut(&call_ok).unwrap().status = STATUS_HELD;
    // an unknown call (get_hold returned None)
    assert_eq!(
        check_of(attest(p_ok.clone(), [0xcc; 32]).await.unwrap_err()),
        Check::Hold
    );
    // 6. call: an old proof for an identical request cannot unlock another hold
    let call_new = [0xc9; 32];
    chain
        .holds
        .lock()
        .await
        .insert(call_new, hold_for(sid_ok, t));
    assert_eq!(
        check_of(attest(p_ok.clone(), call_new).await.unwrap_err()),
        Check::Call
    );
    // 7. time
    expect(
        &|e| e.hold.held_at = v.time + verify::SESSION_SKEW_SECS + 1,
        Check::Time,
    );
    expect(
        &|e| {
            e.hold.deadline = v.time - 1;
            e.now = v.time - 2;
        },
        Check::Time,
    );
    // tampering
    let mut tampered = p_ok.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    assert_eq!(
        check_of(attest(tampered, call_ok).await.unwrap_err()),
        Check::Presentation
    );
    assert_eq!(
        check_of(
            attest(b"not a presentation".to_vec(), call_ok)
                .await
                .unwrap_err()
        ),
        Check::Presentation
    );
    // no transcript: a vendor that never answers yields an error, never a verdict
    let hang = prove::prove(
        &request(
            &notary_addr,
            port_hang,
            &roots,
            [0xcf; 32],
            default_redactions(),
        ),
        1,
        Duration::from_secs(5),
    )
    .await;
    assert!(hang.is_err());
    // the chain view works through the trait the same way
    assert_eq!(chain.hold(call_ok).await.unwrap().status, STATUS_HELD);

    // ---------------------------------------------------------------- acceptance vector for the escrow
    let case = |name: &str, svc: &ServiceInfo, sid: [u8; 32], signed: &SignedVerdict| {
        json!({
            "label": to_hex(&svc.label),
            "label_text": name,
            "service_id": to_hex(&sid),
            "origin": origin(if name == "attest-ok" { ok_port } else { port_500 }).canonical(),
            "origin_hash": to_hex(&svc.origin_hash),
            "verdict": signed.verdict,
            "message": signed.message,
            "signature": signed.signature,
        })
    };
    let vector = json!({
        "note": "Generated by apps/attestor/tests/attest.rs: verdicts the attestor signed for real TLSNotary presentations of the demo vendor (a 200 quote and an authenticated 500). Hex has no 0x prefix.",
        "network_passphrase": TESTNET_PASSPHRASE,
        "network_id": to_hex(&network_id(TESTNET_PASSPHRASE)),
        "contract": contract_address(&ESCROW),
        "contract_id": to_hex(&ESCROW),
        "owner": account_address(&VENDOR),
        "owner_xdr": to_hex(&Owner::Account(VENDOR).sc_val_xdr()),
        "signer": {
            "public_key": delivered.signer_key,
            "address": delivered.signer,
        },
        "notary_key_hash": to_hex(&svc_ok.notary_key_hash),
        "predicate_hash": to_hex(&svc_ok.predicate_hash),
        "price_per_call": PRICE.to_string(),
        "settlement_window": WINDOW,
        "target": TARGET,
        "delivered": case("attest-ok", &svc_ok, sid_ok, &delivered),
        "failed": case("attest-500", &svc_500, sid_500, &failed_500),
    });
    let text = serde_json::to_string_pretty(&vector).unwrap() + "\n";
    let out = root().join("out/attest-v1.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, &text).unwrap();
    println!("wrote {}", out.display());
    if std::env::var("FERMATA_UPDATE_VECTORS").as_deref() == Ok("1") {
        let committed = root().join("test-vectors/attest-v1.json");
        std::fs::write(&committed, &text).unwrap();
        println!("wrote {}", committed.display());
    }
}

// ------------------------------------------------------------------------------------ sessions

/// The session contract the session vector is signed for: `attest_vector.rs` in
/// `contracts/session` registers the contract at this id.
const SESSION_CONTRACT: [u8; 32] = {
    let mut id = [0u8; 32];
    id[30] = 0x5e;
    id[31] = 0x1a;
    id
};
const SESSION_ID: [u8; 32] = [0x5d; 32];
/// The agent's ticket key (test only).
const TICKET_SEED: [u8; 32] = [0x7c; 32];

fn session_request(
    notary: &str,
    port: u16,
    roots: &[CertificateDer],
    call_id: [u8; 32],
    target: &str,
) -> ProveRequest {
    ProveRequest {
        target: target.into(),
        ..request(notary, port, roots, call_id, default_redactions())
    }
}

/// Session calls (phase 1, every call proved) proved for real against the demo vendor: the
/// agent's tickets checked before proving, a DELIVERED call, a FAILED one (an unknown symbol, 404)
/// and one recorded UNANSWERED, then the batch statement over the three, which
/// `contracts/session/src/tests/attest_vector.rs` settles. Also two refusals: a ticket that does
/// not cover the request (before any proof), and a proof of another call's header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs node + openssl; run with --ignored"]
async fn session_calls_end_to_end() {
    use fermata_attest::{
        chain::{SESSION_OPEN, SessionInfo},
        session::{self, Books, CallRequest, Refusal, SessionTarget},
    };
    use fermata_verdict::session as fs;

    let vendor_dir = root().join("apps/vendor");
    if !vendor_dir.join("certs/ca.pem").exists() {
        assert!(
            Command::new("bash")
                .arg(vendor_dir.join("gen-certs.sh"))
                .status()
                .unwrap()
                .success()
        );
    }
    let roots = load_roots(&vendor_dir.join("certs/ca.pem")).unwrap();
    let predicate = std::fs::read(root().join("predicates/quote-v1.json")).unwrap();
    let (_vendor, port) = vendor("").await;
    let (_notary, notary_addr) = spawn_notary(NOTARY_KEY, &vendor_dir.join("certs/ca.pem")).await;
    let mut services = Vec::new();
    let (sid, svc) = register(&mut services, "session", port, &predicate);

    let t = now();
    let ticket_key = SigningKey::from_bytes(&TICKET_SEED);
    let target = SessionTarget::new(TESTNET_PASSPHRASE, SESSION_CONTRACT);
    let chain = MockChain::default();
    chain.services.lock().await.insert(sid, svc.clone());
    let opened = SessionInfo {
        agent: account_address(&[0xa9; 32]),
        service_id: sid,
        token: contract_address(&TOKEN),
        payout: account_address(&VENDOR),
        price: PRICE,
        fee_bps: 50,
        verifier: verifier().verifying_key().to_bytes(),
        predicate_hash: predicate_hash(&predicate),
        ticket_key: ticket_key.verifying_key().to_bytes(),
        max_calls: 4,
        sample_k: 1,
        batch_size: 4,
        opened_at: t - 5,
        deadline: t + 300 + u64::from(WINDOW),
        settled: 0,
        chain: SESSION_ID,
        seed: [0; 32],
        status: SESSION_OPEN,
    };
    chain
        .sessions
        .lock()
        .await
        .insert((SESSION_CONTRACT, SESSION_ID), opened);
    *chain.now.lock().await = t;
    let dir = std::env::temp_dir().join(format!("fermata-session-books-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let books = Books::new(&dir);
    let me = verifier().verifying_key().to_bytes();

    // Call n with the agent's ticket over the chain so far.
    let call = |n: u32, prev: [u8; 32], target_path: &str| {
        let rh = request_hash(&sid, "GET", target_path, b"");
        let chain_n = fs::chain_next(&prev, &rh);
        CallRequest {
            session_id: to_hex(&SESSION_ID),
            n,
            ticket: to_hex(&fs::sign_ticket(
                &ticket_key,
                &target.domain,
                &SESSION_ID,
                n,
                &chain_n,
            )),
            method: "GET".into(),
            target: target_path.into(),
            body: vec![],
        }
    };

    let mut prev = SESSION_ID;
    let mut calls = Vec::new();
    for (n, path, expected) in [
        (1u32, TARGET, fs::RESULT_DELIVERED),
        (2, "/v1/quote?symbol=NOPE-USD", fs::RESULT_FAILED),
    ] {
        let a = session::admit(&chain, &target, &me, &books, &call(n, prev, path), true)
            .await
            .unwrap();
        books
            .reserve(&SESSION_ID, &a.session, a.record())
            .await
            .unwrap()
            .unwrap();
        let p = prove_ok(&session_request(
            &notary_addr,
            port,
            &roots,
            a.call_id,
            path,
        ))
        .await;
        let v = verify::verify_presentation(&p, &roots).unwrap();
        let (entry, failures) = session::decide_call(&v, &a, &predicate, t).unwrap();
        assert_eq!(entry.result, expected, "call {n}: {failures:?}");
        assert_eq!(entry.presentation_hash, keccak256(&p));
        let r = books.complete(&SESSION_ID, n, entry).await.unwrap();
        calls.push(json!({
            "n": n,
            "target": path,
            "call_id": to_hex(&a.call_id),
            "request_hash": to_hex(&a.request_hash),
            "chain": to_hex(&a.chain),
            "entry": r.entry,
        }));
        prev = a.chain;
    }
    // Call 3 gets no proof (here: the gateway reports it unanswered).
    let path3 = "/v1/quote?symbol=ETH-USD";
    let a3 = session::admit(&chain, &target, &me, &books, &call(3, prev, path3), false)
        .await
        .unwrap();
    books
        .reserve(&SESSION_ID, &a3.session, a3.record())
        .await
        .unwrap()
        .unwrap();
    books
        .complete(&SESSION_ID, 3, fs::Entry::unanswered())
        .await
        .unwrap();
    calls.push(json!({
        "n": 3,
        "target": path3,
        "call_id": to_hex(&a3.call_id),
        "request_hash": to_hex(&a3.request_hash),
        "chain": to_hex(&a3.chain),
        "entry": fs::Entry::unanswered(),
    }));

    // Refused before proving: a ticket that does not cover the request.
    let mut forged = call(4, a3.chain, TARGET);
    forged.target = "/v1/quote?symbol=SOL-USD".into();
    match session::admit(&chain, &target, &me, &books, &forged, true).await {
        Err(Refusal::Check(v)) => assert_eq!(v.check, Check::Ticket),
        other => panic!("expected a ticket refusal, got {other:?}"),
    }
    // A proof made for another call's header does not bind to call 4.
    let a4 = session::admit(
        &chain,
        &target,
        &me,
        &books,
        &call(4, a3.chain, TARGET),
        true,
    )
    .await
    .unwrap();
    let other_call = fs::call_id(&SESSION_CONTRACT, &SESSION_ID, 5);
    let p = prove_ok(&session_request(
        &notary_addr,
        port,
        &roots,
        other_call,
        TARGET,
    ))
    .await;
    let v = verify::verify_presentation(&p, &roots).unwrap();
    assert_eq!(
        session::decide_call(&v, &a4, &predicate, t)
            .unwrap_err()
            .check,
        Check::Call
    );

    // The statement over calls 1-3: what settle_batch takes.
    let signed = session::sign_statement(&chain, &target, &verifier(), &books, SESSION_ID, 3)
        .await
        .unwrap();
    let results: Vec<u32> = signed.entries.iter().map(|e| e.result).collect();
    assert_eq!(
        results,
        [
            fs::RESULT_DELIVERED,
            fs::RESULT_FAILED,
            fs::RESULT_UNANSWERED
        ]
    );
    let signature = parse_hex::<64>(&signed.signature).unwrap();
    fs::verify_statement(&me, &target.domain, &signed.statement, &signature).unwrap();
    assert_eq!(signed.statement.chain, a3.chain);
    std::fs::remove_dir_all(&dir).unwrap();

    // ------------------------------------------------- acceptance vector for the session contract
    let vector = json!({
        "note": "Generated by apps/attestor/tests/attest.rs (session_calls_end_to_end): a batch statement the attestor signed over two calls proved with TLSNotary against the demo vendor (a 200 quote and a 404) and one call recorded unanswered. Hex has no 0x prefix.",
        "network_passphrase": TESTNET_PASSPHRASE,
        "network_id": to_hex(&network_id(TESTNET_PASSPHRASE)),
        "contract": contract_address(&SESSION_CONTRACT),
        "contract_id": to_hex(&SESSION_CONTRACT),
        "owner": account_address(&VENDOR),
        "owner_xdr": to_hex(&Owner::Account(VENDOR).sc_val_xdr()),
        "label": to_hex(&svc.label),
        "label_text": "session",
        "service_id": to_hex(&sid),
        "origin": origin(port).canonical(),
        "origin_hash": to_hex(&svc.origin_hash),
        "notary_key_hash": to_hex(&svc.notary_key_hash),
        "predicate_hash": to_hex(&svc.predicate_hash),
        "price_per_call": PRICE.to_string(),
        "settlement_window": WINDOW,
        "verifier": { "public_key": to_hex(&me), "address": account_address(&me) },
        "ticket_key": { "public_key": to_hex(&ticket_key.verifying_key().to_bytes()) },
        "session_id": to_hex(&SESSION_ID),
        "max_calls": 4,
        "batch_size": 4,
        "calls": calls,
        "statement": signed.statement,
        "message": signed.message,
        "signature": signed.signature,
        "ticket": signed.ticket,
    });
    let text = serde_json::to_string_pretty(&vector).unwrap() + "\n";
    let out = root().join("out/session-attest-v1.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, &text).unwrap();
    println!("wrote {}", out.display());
    if std::env::var("FERMATA_UPDATE_VECTORS").as_deref() == Ok("1") {
        let committed = root().join("test-vectors/session-attest-v1.json");
        std::fs::write(&committed, &text).unwrap();
        println!("wrote {}", committed.display());
    }
}

/// Soak: N sequential proofs from one long-lived process (the `serve` situation). Reports how many
/// attempts each needed.   SOAK=20 cargo test --release soak -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak test; run with --ignored"]
async fn soak() {
    let n: usize = std::env::var("SOAK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let vendor_dir = root().join("apps/vendor");
    let ca = vendor_dir.join("certs/ca.pem");
    let roots = load_roots(&ca).unwrap();
    let (_v, port) = vendor("").await;
    let (_n, notary_addr) = spawn_notary(NOTARY_KEY, &ca).await;
    let mut attempts = Vec::new();
    let mut ms = Vec::new();
    for i in 0..n {
        let out = prove::prove(
            &request(
                &notary_addr,
                port,
                &roots,
                [i as u8; 32],
                default_redactions(),
            ),
            3,
            Duration::from_secs(15),
        )
        .await
        .expect("prove");
        attempts.push(out.attempts);
        ms.push(out.prove_ms);
    }
    println!("soak {n}: attempts {attempts:?}\nms {ms:?}");
}

/// A real third-party vendor: registry.npmjs.org, proved through our notary with Mozilla's roots,
/// over the internet (through `FERMATA_UPSTREAM_PROXY` / `HTTPS_PROXY` when set, else directly).
/// Checks a genuine 200 and a genuine 404, and that the proof does not verify against a dev CA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs internet access to registry.npmjs.org; run with --ignored"]
async fn real_vendor_npm() {
    use fermata_attest::{config::trust_roots, tunnel::Proxy};
    let mozilla = trust_roots(&[], true).unwrap();
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_fermata-attest"))
        .args([
            "notary",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--roots",
            "mozilla",
        ])
        .env("NOTARY_PRIVATE_KEY", hex0x(&NOTARY_KEY))
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let _notary = Proc(child);
    wait_port(port).await;
    let proxy = std::env::var("FERMATA_UPSTREAM_PROXY")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .ok()
        .map(|p| Proxy::parse(&p).unwrap());
    let req = |target: &str| ProveRequest {
        notary: format!("127.0.0.1:{port}"),
        connect: "registry.npmjs.org:443".into(),
        origin: Origin::new("registry.npmjs.org", 443).unwrap(),
        roots: mozilla.clone(),
        method: "GET".into(),
        target: target.into(),
        headers: vec![("accept".into(), "application/json".into())],
        body: vec![],
        call_id: [0x77; 32],
        max_sent: 4096,
        max_recv: 16384,
        redact: default_redactions(),
        setup_timeout: Duration::from_secs(10),
        proxy: proxy.clone(),
    };

    let out = prove::prove(
        &req("/-/package/mppx/dist-tags"),
        3,
        Duration::from_secs(40),
    )
    .await
    .expect("prove npm");
    println!(
        "npm proved in {} ms, MPC {} B",
        out.prove_ms,
        out.notary_bytes.sent + out.notary_bytes.received
    );
    let v = verify::verify_presentation(&out.presentation, &mozilla)
        .expect("verifies with Mozilla roots");
    assert_eq!(v.server_name, "registry.npmjs.org");
    let res = v.response.expect("HTTP response");
    assert_eq!(res.status, 200);
    assert!(String::from_utf8_lossy(&res.body).contains("\"latest\""));

    let dev_ca = load_roots(&root().join("apps/vendor/certs/ca.pem"));
    if let Ok(dev_ca) = dev_ca {
        assert!(
            verify::verify_presentation(&out.presentation, &dev_ca).is_err(),
            "must not verify against a dev CA"
        );
    }

    let missing = prove::prove(
        &req("/-/package/no-such-package-fermata-zz/dist-tags"),
        3,
        Duration::from_secs(40),
    )
    .await
    .expect("prove npm 404");
    let v = verify::verify_presentation(&missing.presentation, &mozilla).unwrap();
    assert_eq!(v.response.expect("HTTP response").status, 404);
}
